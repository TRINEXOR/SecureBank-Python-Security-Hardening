"""SecureNotes -- ORIGINAL VERSION (INTENTIONALLY VULNERABLE, for the Week 5 security audit).

DO NOT DEPLOY. Every weakness here is deliberate and documented in the audit report.
Pure standard library: http.server + sqlite3.
"""
import argparse, base64, hashlib, json, logging, os, sqlite3, threading, traceback
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

SECRET_KEY = "supersecret123"                 # VULN: hard-coded secret
DEFAULT_ADMIN = ("admin", "admin123")         # VULN: default admin credentials
log = logging.getLogger("notes")


def md5(s):                                    # VULN: fast, unsalted hash for passwords
    return hashlib.md5(s.encode()).hexdigest()


class App:
    def __init__(self, db_path=":memory:", files_dir="files", **_ignored):
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.files_dir = files_dir
        self.audit = []
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE,
                                             password_hash TEXT, role TEXT);
            CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, owner INTEGER, title TEXT, body TEXT);""")
        if not self.db.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
            self.db.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                            (DEFAULT_ADMIN[0], md5(DEFAULT_ADMIN[1]), "admin"))
            self.db.commit()

    # VULN: cookie = base64(json) + md5(SECRET_KEY + data); key is hard-coded, hash is not an HMAC
    def make_cookie(self, uid, username, role):
        data = base64.b64encode(json.dumps({"uid": uid, "user": username, "role": role}).encode()).decode()
        return data + "." + hashlib.md5((SECRET_KEY + data).encode()).hexdigest()

    def read_cookie(self, value):
        try:
            data, sig = value.rsplit(".", 1)
            if hashlib.md5((SECRET_KEY + data).encode()).hexdigest() != sig:
                return None
            return json.loads(base64.b64decode(data))
        except Exception:
            return None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    # ---------- helpers ----------
    def send(self, status, body, ctype="text/html", headers=()):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def form(self):
        n = int(self.headers.get("Content-Length", 0))          # VULN: no size limit
        raw = parse_qs(self.rfile.read(n).decode())
        return {k: v[0] for k, v in raw.items()}

    def user(self):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "session":
                return self.server.app.read_cookie(v)
        return None

    # ---------- routing ----------
    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def route(self, method):
        app, db = self.server.app, self.server.app.db
        try:
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            path = u.path
            if method == "POST" and path == "/register":
                f = self.form()
                try:
                    db.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?, 'user')",
                               (f["username"], md5(f["password"])))
                    db.commit()
                except sqlite3.IntegrityError:
                    return self.send(409, '{"error":"username already exists"}', "application/json")
                return self.send(201, '{"ok":true}', "application/json")

            if method == "POST" and path == "/login":
                f = self.form()
                username, password = f["username"], f["password"]
                # VULN: SQL injection (string formatting) + user enumeration
                exists = db.execute("SELECT id FROM users WHERE username='%s'" % username).fetchone()
                if not exists:
                    app.audit.append("LOGIN FAILED user=%s" % username)      # VULN: log injection
                    return self.send(401, '{"error":"No such user"}', "application/json")
                row = db.execute("SELECT id, username, role FROM users WHERE username='%s' AND password_hash='%s'"
                                 % (username, md5(password))).fetchone()
                if not row:
                    app.audit.append("LOGIN FAILED user=%s" % username)
                    return self.send(401, '{"error":"Wrong password"}', "application/json")
                app.audit.append("LOGIN SUCCESS user=%s" % row[1])
                return self.send(200, '{"ok":true}', "application/json",
                                 [("Set-Cookie", "session=" + app.make_cookie(*row))])   # VULN: no cookie flags

            me = self.user()
            if me is None:
                return self.send(401, '{"error":"login required"}', "application/json")

            if method == "POST" and path == "/notes":                  # VULN: no CSRF protection
                f = self.form()
                cur = db.execute("INSERT INTO notes(owner,title,body) VALUES(?,?,?)",
                                 (me["uid"], f["title"], f["body"]))   # VULN: plaintext at rest
                db.commit()
                return self.send(201, json.dumps({"id": cur.lastrowid}), "application/json")

            if method == "GET" and path.startswith("/notes/"):
                row = db.execute("SELECT title, body FROM notes WHERE id=%d" % int(path[7:])).fetchone()  # VULN: IDOR
                if not row:
                    return self.send(404, "not found")
                return self.send(200, "<h1>%s</h1><p>%s</p>" % row)                  # VULN: stored XSS

            if method == "GET" and path == "/search":
                term = q.get("q", "")
                sql = "SELECT id, title FROM notes WHERE owner=%d AND title LIKE '%%%s%%'" % (me["uid"], term)
                rows = db.execute(sql).fetchall()                                    # VULN: SQL injection
                items = "".join("<li><a href='/notes/%s'>%s</a></li>" % r for r in rows)
                return self.send(200, "<h1>Results for %s</h1><ul>%s</ul>" % (term, items))  # VULN: reflected XSS

            if method == "GET" and path == "/download":
                name = q.get("file", "")
                with open(os.path.join(app.files_dir, name), "rb") as fh:            # VULN: path traversal
                    return self.send(200, fh.read(), "application/octet-stream")

            if method == "GET" and path == "/ping":
                host = q.get("host", "")
                out = os.popen("ping -c 1 -W 1 " + host + " 2>&1").read()            # VULN: command injection
                return self.send(200, out, "text/plain")

            if method == "GET" and path == "/admin":
                if me.get("role") != "admin":                                        # role trusted from cookie
                    return self.send(403, '{"error":"admins only"}', "application/json")
                rows = db.execute("SELECT username, password_hash, role FROM users").fetchall()
                return self.send(200, "\n".join(":".join(r) for r in rows), "text/plain")   # VULN: leaks hashes
            return self.send(404, "not found")
        except Exception:
            # VULN: full stack trace (incl. source lines & SQL) returned to the client
            self.send(500, "<pre>" + traceback.format_exc() + "</pre>")


def create_server(db_path=":memory:", host="127.0.0.1", port=0, files_dir="files", **kw):
    srv = HTTPServer((host, port), Handler)
    srv.app = App(db_path, files_dir, **kw)
    return srv


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")      # VULN: listens on all interfaces
    ap.add_argument("--port", type=int, default=8000)
    a = ap.parse_args()
    s = create_server(host=a.host, port=a.port)
    print("VULNERABLE app on %s:%d (do not expose)" % (a.host, a.port))
    s.serve_forever()
