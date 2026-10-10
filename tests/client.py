"""Tiny HTTP client + test environment (no third-party libraries)."""
import http.client, importlib.util, json, os, shutil, tempfile, threading
from urllib.parse import urlencode

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
APP_PATHS = {"vulnerable": "vulnerable/app_vulnerable.py", "secure": "secure/app_secure.py"}
PW = {"alice": "Alice-Passw0rd!x", "bob": "Bob-Passw0rd!xyz", "mallory": "Mallory-Passw0rd!1"}
ADMIN_PW = "Adm1n-Secret-Pass!"


def load_app(kind):
    spec = importlib.util.spec_from_file_location("app_" + kind, os.path.join(ROOT, APP_PATHS[kind]))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class Resp:
    def __init__(self, status, headers, body):
        self.status, self.headers, self.text = status, headers, body

    def json(self):
        return json.loads(self.text)


class Client:
    def __init__(self, port):
        self.port, self.cookie, self.csrf = port, None, None

    def request(self, method, path, data=None, headers=None, raw=None, cookie=None, auto_csrf=True):
        h = dict(headers or {})
        c = cookie if cookie is not None else self.cookie
        if c:
            h["Cookie"] = "session=" + c
        if self.csrf and auto_csrf and method == "POST":
            h.setdefault("X-CSRF-Token", self.csrf)
        body = raw if raw is not None else (urlencode(data) if data is not None else None)
        if method == "POST":
            h.setdefault("Content-Type", "application/x-www-form-urlencoded")
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            conn.request(method, path, body=body, headers=h)
            r = conn.getresponse()
            text = r.read().decode("utf-8", "replace")
            return Resp(r.status, {k.lower(): v for k, v in r.getheaders()}, text)
        finally:
            conn.close()

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, data=None, **kw):
        return self.request("POST", path, data=data, **kw)

    def register(self, u, p):
        return self.post("/register", {"username": u, "password": p})

    def login(self, u, p):
        r = self.post("/login", {"username": u, "password": p})
        sc = r.headers.get("set-cookie", "")
        if r.status == 200 and sc.startswith("session="):
            self.cookie = sc.split(";")[0][len("session="):]
            try:
                self.csrf = r.json().get("csrf")
            except ValueError:
                self.csrf = None
        return r


class Env:
    """A fresh server (own in-memory DB, temp files dir) for one test or attack."""

    def __init__(self, kind, **kw):
        self.kind, self.module = kind, load_app(kind)
        self.tmp = tempfile.mkdtemp(prefix="sec_")
        self.files = os.path.join(self.tmp, "files")
        os.makedirs(self.files)
        with open(os.path.join(self.files, "welcome.txt"), "w") as f:
            f.write("Welcome to SecureNotes")
        with open(os.path.join(self.tmp, "secret.txt"), "w") as f:
            f.write("TOP-SECRET-OUTSIDE-FILES-DIR")
        kw.setdefault("admin_password", ADMIN_PW)
        if kind == "secure":
            from cryptography.fernet import Fernet
            kw.setdefault("enc_key", Fernet.generate_key())
        self.server = self.module.create_server(files_dir=self.files, **kw)
        self.port = self.server.server_address[1]
        self.app = self.server.app
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def client(self, user=None):
        c = Client(self.port)
        if user:
            c.register(user, PW[user])
            r = c.login(user, PW[user])
            assert r.status == 200, (user, r.status, r.text)
        return c

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.app.db.close()
        shutil.rmtree(self.tmp, ignore_errors=True)
