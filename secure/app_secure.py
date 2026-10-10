"""SecureNotes -- HARDENED VERSION (Week 5). Same routes/behaviour as the original, with the
vulnerabilities fixed. Requires: cryptography (Fernet) for encryption at rest.

Configuration (environment variables):
  APP_SECRET_KEY  session-signing key (random per process if unset -> sessions end on restart)
  APP_ENC_KEY     Fernet key for note bodies (random per process if unset -> use a persistent key
                  whenever a file database is used!)  Generate: python -c "from cryptography.fernet
                  import Fernet; print(Fernet.generate_key().decode())"
  APP_ADMIN_PASSWORD  creates the 'admin' account at start-up (no default admin exists)
"""
import argparse, base64, hashlib, hmac, html, ipaddress, json, logging, os, re, secrets
import sqlite3, ssl, subprocess, time, uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from cryptography.fernet import Fernet, InvalidToken

log = logging.getLogger("notes.secure")

MAX_BODY = 64 * 1024
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
FILE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$")
HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                     r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")      # control chars (newline/tab allowed in bodies)
COMMON_PASSWORDS = {"password", "password123", "123456789012", "qwertyuiop12", "admin123456", "letmein1234"}

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-origin",
}


# ---------------------------------------------------------------- crypto helpers
def _b64(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def hash_password(password):
    """scrypt (memory-hard) with a unique random 16-byte salt."""
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return "scrypt$16384$8$1$%s$%s" % (_b64(salt), _b64(dk))


def verify_password(password, stored):
    try:
        algo, n, r, p, salt, dk = stored.split("$")
        if algo != "scrypt":
            return False
        calc = hashlib.scrypt(password.encode(), salt=_unb64(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(calc, _unb64(dk))
    except (ValueError, TypeError):
        return False


_DUMMY_HASH = hash_password("dummy-password-for-timing")


def safe_log(value):
    """Neutralise log injection: JSON-escape (kills CR/LF), truncate."""
    return json.dumps(str(value)[:64])


def validate_password(pw):
    if not 10 <= len(pw) <= 128:
        return "Password must be 10-128 characters."
    if pw.lower() in COMMON_PASSWORDS or pw.isdigit() or pw.isalpha():
        return "Password is too weak (mix letters and non-letters, avoid common passwords)."
    return None


class LoginLimiter:
    """Sliding-window failed-login limiter keyed by account name and client address."""

    def __init__(self, max_failures=5, window=60, ip_max=25, clock=time.monotonic):
        self.max, self.window, self.ip_max, self.clock = max_failures, window, ip_max, clock
        self.fails = {}

    def _prune(self, key):
        now = self.clock()
        self.fails[key] = [t for t in self.fails.get(key, []) if now - t < self.window]
        return self.fails[key]

    def locked(self, user_key, ip):
        return len(self._prune("u:" + user_key)) >= self.max or len(self._prune("ip:" + ip)) >= self.ip_max

    def retry_after(self, user_key):
        f = self._prune("u:" + user_key)
        return max(1, int(self.window - (self.clock() - f[0]))) if f else 1

    def failure(self, user_key, ip):
        now = self.clock()
        self.fails.setdefault("u:" + user_key, []).append(now)
        self.fails.setdefault("ip:" + ip, []).append(now)

    def success(self, user_key):
        self.fails.pop("u:" + user_key, None)


class App:
    def __init__(self, db_path=":memory:", files_dir="files", admin_password=None, enc_key=None,
                 secret_key=None, session_ttl=3600, secure_cookies=True, max_failures=5, lock_window=60):
        sk = secret_key or os.environ.get("APP_SECRET_KEY")
        self.secret = sk.encode() if isinstance(sk, str) else (sk or secrets.token_bytes(32))
        ek = enc_key or os.environ.get("APP_ENC_KEY")
        if not ek:
            log.warning("APP_ENC_KEY not set: using an ephemeral encryption key (data unreadable after restart)")
            ek = Fernet.generate_key()
        self.fernet = Fernet(ek)
        self.files_dir = Path(files_dir)
        self.session_ttl, self.secure_cookies = session_ttl, secure_cookies
        self.limiter = LoginLimiter(max_failures, lock_window)
        self.audit = []
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')));
            CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, owner INTEGER NOT NULL REFERENCES users(id),
                title TEXT NOT NULL, body TEXT NOT NULL);""")
        admin_password = admin_password or os.environ.get("APP_ADMIN_PASSWORD")
        if admin_password:
            err = validate_password(admin_password)
            if err:
                raise ValueError("APP_ADMIN_PASSWORD rejected: " + err)
            self.db.execute("INSERT OR IGNORE INTO users(username,password_hash,role) VALUES('admin',?, 'admin')",
                            (hash_password(admin_password),))
            self.db.commit()

    def event(self, msg):
        self.audit.append(msg)
        del self.audit[:-1000]
        log.info(msg)

    # ----- signed, expiring session tokens (HMAC-SHA256) -----
    def sign(self, payload):
        raw = _b64(json.dumps(payload, separators=(",", ":")).encode())
        return raw + "." + _b64(hmac.new(self.secret, raw.encode(), hashlib.sha256).digest())

    def verify(self, token):
        try:
            raw, sig = token.split(".")
            good = _b64(hmac.new(self.secret, raw.encode(), hashlib.sha256).digest())
            if not hmac.compare_digest(sig, good):
                return None
            payload = json.loads(_unb64(raw))
            return payload if payload["exp"] > time.time() else None
        except (ValueError, KeyError, TypeError):
            return None


class Handler(BaseHTTPRequestHandler):
    timeout = 10                       # drop slow / stalled clients
    server_version = "SecureNotes"
    sys_version = ""

    def log_message(self, *a):
        pass

    def send(self, status, body, ctype="text/html; charset=utf-8", headers=()):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def jerr(self, status, msg, headers=()):
        self.send(status, json.dumps({"error": msg}), "application/json", headers)

    def form(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None, (400, "Bad request")
        if n < 0 or n > MAX_BODY:
            self.close_connection = True
            return None, (413, "Request too large")
        try:
            raw = parse_qs(self.rfile.read(n).decode("utf-8"), max_num_fields=20)
        except (UnicodeDecodeError, ValueError):
            return None, (400, "Bad request")
        return {k: v[0] for k, v in raw.items()}, None

    def session(self):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "session":
                p = self.server.app.verify(v)
                if p:
                    row = self.server.app.db.execute("SELECT id, username, role FROM users WHERE id=?",
                                                     (p.get("uid"),)).fetchone()
                    if row:                       # role is always re-read from the DB, never from the token
                        return {"uid": row[0], "user": row[1], "role": row[2], "csrf": p.get("csrf", "")}
        return None

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def route(self, method):
        rid = uuid.uuid4().hex[:8]
        try:
            self._route(method)
        except Exception:
            log.exception("unhandled error request_id=%s", rid)                  # details stay server-side
            self.jerr(500, "Internal server error (request id %s)" % rid)

    def _route(self, method):
        app, db = self.server.app, self.server.app.db
        u = urlparse(self.path)
        path, q = u.path, {k: v[0] for k, v in parse_qs(u.query, max_num_fields=20).items()}
        ip = self.client_address[0]

        if method == "POST":
            origin = self.headers.get("Origin")
            if origin and urlparse(origin).netloc != self.headers.get("Host"):
                app.event("CSRF BLOCKED origin=%s path=%s" % (safe_log(origin), safe_log(path)))
                return self.jerr(403, "Cross-origin request rejected")

        if method == "POST" and path == "/register":
            f, err = self.form()
            if err:
                return self.jerr(*err)
            username, password = f.get("username", ""), f.get("password", "")
            if not USERNAME_RE.match(username):
                return self.jerr(400, "Username must be 3-32 characters: letters, digits, underscore.")
            msg = validate_password(password)
            if msg:
                return self.jerr(400, msg)
            try:
                db.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,'user')",
                           (username, hash_password(password)))
                db.commit()
            except sqlite3.IntegrityError:
                return self.jerr(409, "Username unavailable")
            app.event("REGISTER user=%s" % safe_log(username))
            return self.send(201, '{"ok":true}', "application/json")

        if method == "POST" and path == "/login":
            f, err = self.form()
            if err:
                return self.jerr(*err)
            username, password = f.get("username", ""), f.get("password", "")
            key = username.lower()[:64]
            if app.limiter.locked(key, ip):
                app.event("LOGIN LOCKED user=%s ip=%s" % (safe_log(username), ip))
                return self.jerr(429, "Too many failed attempts. Try again later.",
                                 [("Retry-After", str(app.limiter.retry_after(key)))])
            row = db.execute("SELECT id, password_hash, role FROM users WHERE username=?", (username,)).fetchone() \
                if USERNAME_RE.match(username) else None
            ok = verify_password(password, row[1] if row else _DUMMY_HASH)      # same work either way
            if not (row and ok):
                app.limiter.failure(key, ip)
                app.event("LOGIN FAILED user=%s ip=%s" % (safe_log(username), ip))
                return self.jerr(401, "Invalid username or password")           # identical for both cases
            app.limiter.success(key)
            csrf = secrets.token_urlsafe(32)
            token = app.sign({"uid": row[0], "csrf": csrf, "exp": time.time() + app.session_ttl})
            cookie = "session=%s; HttpOnly; SameSite=Strict; Path=/; Max-Age=%d" % (token, app.session_ttl)
            if app.secure_cookies:
                cookie += "; Secure"
            app.event("LOGIN SUCCESS user=%s" % safe_log(username))
            return self.send(200, json.dumps({"ok": True, "csrf": csrf}), "application/json", [("Set-Cookie", cookie)])

        me = self.session()
        if me is None:
            return self.jerr(401, "Login required")

        if method == "POST":                                                    # CSRF token on every state change
            if not hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), me["csrf"]):
                app.event("CSRF REJECTED user=%s" % safe_log(me["user"]))
                return self.jerr(403, "Missing or invalid CSRF token")

        if method == "POST" and path == "/notes":
            f, err = self.form()
            if err:
                return self.jerr(*err)
            title, body = f.get("title", "").strip(), f.get("body", "")
            if not 1 <= len(title) <= 100 or CTRL_RE.search(title) or "\n" in title:
                return self.jerr(400, "Title must be 1-100 printable characters.")
            if not 1 <= len(body) <= 5000 or CTRL_RE.search(body):
                return self.jerr(400, "Body must be 1-5000 characters.")
            cur = db.execute("INSERT INTO notes(owner,title,body) VALUES(?,?,?)",
                             (me["uid"], title, app.fernet.encrypt(body.encode()).decode()))   # encrypted at rest
            db.commit()
            return self.send(201, json.dumps({"id": cur.lastrowid}), "application/json")

        m = re.fullmatch(r"/notes/(\d{1,9})", path)
        if method == "GET" and m:
            row = db.execute("SELECT title, body FROM notes WHERE id=? AND owner=?",
                             (int(m.group(1)), me["uid"])).fetchone()          # ownership enforced in the query
            if not row:
                return self.jerr(404, "Not found")                             # same answer for missing / not yours
            try:
                body = app.fernet.decrypt(row[1].encode()).decode()
            except InvalidToken:
                log.error("note %s failed decryption", m.group(1))
                return self.jerr(500, "Internal server error")
            return self.send(200, "<h1>%s</h1><p>%s</p>" % (html.escape(row[0]), html.escape(body)))

        if method == "GET" and path == "/search":
            term = q.get("q", "")
            if len(term) > 100:
                return self.jerr(400, "Search term too long")
            like = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            rows = db.execute("SELECT id, title FROM notes WHERE owner=? AND title LIKE ? ESCAPE '\\'",
                              (me["uid"], "%" + like + "%")).fetchall()        # parameterised
            items = "".join("<li><a href='/notes/%d'>%s</a></li>" % (r[0], html.escape(r[1])) for r in rows)
            return self.send(200, "<h1>Results for %s</h1><ul>%s</ul>" % (html.escape(term), items))

        if method == "GET" and path == "/download":
            name = q.get("file", "")
            if not FILE_RE.match(name) or ".." in name:                        # allow-list of file names
                return self.jerr(400, "Invalid file name")
            base = app.files_dir.resolve()
            target = (base / name).resolve()
            if base not in target.parents or not target.is_file():             # defence in depth (symlinks etc.)
                return self.jerr(404, "Not found")
            return self.send(200, target.read_bytes(), "application/octet-stream",
                             [("Content-Disposition", 'attachment; filename="%s"' % name)])

        if method == "GET" and path == "/ping":
            host = q.get("host", "")
            valid = bool(HOST_RE.match(host))
            if not valid:
                try:
                    ipaddress.ip_address(host)
                    valid = True
                except ValueError:
                    pass
            if not valid:
                return self.jerr(400, "Invalid host")
            try:                                                               # argument list, no shell
                r = subprocess.run(["/bin/ping", "-c", "1", "-W", "1", host], capture_output=True, text=True,
                                   timeout=5, shell=False)                     # nosec B603 B607 - fixed absolute path
                return self.send(200, r.stdout[:2000], "text/plain; charset=utf-8")
            except (FileNotFoundError, subprocess.TimeoutExpired):
                return self.jerr(503, "Ping unavailable")

        if method == "GET" and path == "/admin":
            if me["role"] != "admin":
                app.event("ADMIN DENIED user=%s" % safe_log(me["user"]))
                return self.jerr(403, "Forbidden")
            rows = db.execute("SELECT username, role FROM users").fetchall()   # never expose hashes
            return self.send(200, "\n".join(":".join(r) for r in rows), "text/plain; charset=utf-8")

        return self.jerr(404, "Not found")


def create_server(db_path=":memory:", host="127.0.0.1", port=0, files_dir="files", **kw):
    srv = HTTPServer((host, port), Handler)
    srv.app = App(db_path, files_dir, **kw)
    return srv


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--certfile")
    ap.add_argument("--keyfile")
    ap.add_argument("--db", default="notes.db")
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    s = create_server(db_path=a.db, host=a.host, port=a.port, secure_cookies=bool(a.certfile))
    if a.certfile:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(a.certfile, a.keyfile)
        s.socket = ctx.wrap_socket(s.socket, server_side=True)
    print("SecureNotes on %s:%d (%s)" % (a.host, a.port, "TLS" if a.certfile else "plain HTTP - use a TLS proxy"))
    s.serve_forever()
