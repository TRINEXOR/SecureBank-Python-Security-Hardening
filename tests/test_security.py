"""Security tests: every attack must succeed on the original and fail on the hardened app,
plus unit tests of the individual security controls."""
import base64, json, os, re, sqlite3, time, unittest
import attacks
from tests.client import Env, Client, PW, ADMIN_PW, load_app


class TestAttackSimulations(unittest.TestCase):
    def test_original_is_exploitable_and_hardened_is_not(self):
        for vid, name, fn in attacks.ATTACKS:
            for kind, expected in (("vulnerable", True), ("secure", False)):
                with self.subTest(vuln=vid, app=kind):
                    env = Env(kind)
                    try:
                        ok, evidence = fn(env)
                    finally:
                        env.close()
                    self.assertEqual(ok, expected, "%s %s on %s: %s" % (vid, name, kind, evidence))


class TestControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_app("secure")

    def setUp(self):
        self.env = Env("secure")

    def tearDown(self):
        self.env.close()

    def test_password_hash_is_salted_scrypt(self):
        h1, h2 = self.mod.hash_password("Same-Passw0rd!!"), self.mod.hash_password("Same-Passw0rd!!")
        self.assertNotEqual(h1, h2)
        self.assertTrue(h1.startswith("scrypt$"))
        self.assertTrue(self.mod.verify_password("Same-Passw0rd!!", h1))
        self.assertFalse(self.mod.verify_password("wrong", h1))
        self.assertFalse(self.mod.verify_password("x", "garbage"))

    def test_password_policy(self):
        c = Client(self.env.port)
        for bad in ("short1!", "1234567890123", "onlylettersonly", "password123"):
            self.assertEqual(c.register("carol", bad).status, 400, bad)
        self.assertEqual(c.register("carol", "G00d-enough-pass").status, 201)

    def test_username_validation(self):
        c = Client(self.env.port)
        for bad in ("a", "x" * 40, "bob'--", "<script>", "a b", "a\nb"):
            self.assertEqual(c.register(bad, "G00d-enough-pass").status, 400, repr(bad))

    def test_session_token_tamper_and_expiry(self):
        app = self.env.app
        good = app.sign({"uid": 1, "csrf": "x", "exp": time.time() + 60})
        self.assertIsNotNone(app.verify(good))
        self.assertIsNone(app.verify(good[:-2] + ("AA" if not good.endswith("AA") else "BB")))
        self.assertIsNone(app.verify(app.sign({"uid": 1, "csrf": "x", "exp": time.time() - 1})))
        self.assertIsNone(app.verify("not-a-token"))
        self.assertIsNone(app.verify(""))

    def test_expired_session_rejected_by_server(self):
        token = self.env.app.sign({"uid": 1, "csrf": "x", "exp": time.time() - 5})
        self.assertEqual(Client(self.env.port).get("/admin", cookie=token).status, 401)

    def test_csrf_token_required_and_checked(self):
        c = self.env.client("alice")
        self.assertEqual(c.post("/notes", {"title": "a", "body": "b"}, auto_csrf=False).status, 403)
        self.assertEqual(c.post("/notes", {"title": "a", "body": "b"}, headers={"X-CSRF-Token": "wrong"},
                                auto_csrf=False).status, 403)
        self.assertEqual(c.post("/notes", {"title": "a", "body": "b"}).status, 201)

    def test_csrf_token_bound_to_session(self):
        a, b = self.env.client("alice"), self.env.client("bob")
        r = a.post("/notes", {"title": "a", "body": "b"}, headers={"X-CSRF-Token": b.csrf}, auto_csrf=False)
        self.assertEqual(r.status, 403)

    def test_lockout_blocks_even_correct_password_then_other_users_unaffected(self):
        c = Client(self.env.port)
        for _ in range(5):
            self.assertEqual(c.login("admin", "wrong-password").status, 401)
        r = c.login("admin", ADMIN_PW)
        self.assertEqual(r.status, 429)
        self.assertIn("retry-after", r.headers)
        self.assertEqual(self.env.client("alice").get("/search?q=a").status, 200)

    def test_limiter_window_expiry(self):
        t = [0.0]
        lim = self.mod.LoginLimiter(max_failures=3, window=10, clock=lambda: t[0])
        for _ in range(3):
            lim.failure("bob", "1.2.3.4")
        self.assertTrue(lim.locked("bob", "1.2.3.4"))
        t[0] = 11
        self.assertFalse(lim.locked("bob", "1.2.3.4"))

    def test_encryption_at_rest(self):
        c = self.env.client("alice")
        c.post("/notes", {"title": "t", "body": "very-secret-body"})
        raw = self.env.app.db.execute("SELECT body FROM notes").fetchone()[0]
        self.assertNotIn("very-secret-body", raw)
        self.assertEqual(self.env.app.fernet.decrypt(raw.encode()).decode(), "very-secret-body")

    def test_tampered_ciphertext_does_not_crash_or_leak(self):
        c = self.env.client("alice")
        nid = c.post("/notes", {"title": "t", "body": "body"}).json()["id"]
        self.env.app.db.execute("UPDATE notes SET body='corrupted' WHERE id=?", (nid,))
        r = c.get("/notes/%d" % nid)
        self.assertEqual(r.status, 500)
        self.assertNotIn("Traceback", r.text)

    def test_sql_metacharacters_are_data(self):
        c = self.env.client("alice")
        c.post("/notes", {"title": "it's 100% fine_ok", "body": "b"})
        c.post("/notes", {"title": "plain title", "body": "b"})
        self.assertEqual(c.get("/search?q=%25").text.count("<li>"), 1)      # '%' is literal, not a wildcard
        self.assertEqual(c.get("/search?q=_").text.count("<li>"), 1)        # '_' is literal, not a wildcard
        self.assertEqual(c.get("/search?q=it%27s").text.count("<li>"), 1)   # quote handled safely
        self.assertEqual(c.get("/search?q=" + "'%20OR%201=1--").text.count("<li>"), 0)

    def test_html_output_escaped(self):
        c = self.env.client("alice")
        nid = c.post("/notes", {"title": "<b>x</b>", "body": "<script>1</script>"}).json()["id"]
        t = c.get("/notes/%d" % nid).text
        self.assertNotIn("<script>", t)
        self.assertNotIn("<b>", t)
        self.assertIn("&lt;script&gt;", t)

    def test_security_headers_on_every_response(self):
        c = self.env.client("alice")
        for r in (c.get("/search?q=a"), c.get("/nope"), Client(self.env.port).get("/admin")):
            for h in ("content-security-policy", "x-content-type-options", "x-frame-options", "cache-control"):
                self.assertIn(h, r.headers)
        self.assertNotIn("Python", c.get("/nope").headers.get("server", ""))

    def test_cookie_flags(self):
        r = Client(self.env.port).login("admin", ADMIN_PW)
        sc = r.headers["set-cookie"]
        for flag in ("HttpOnly", "SameSite=Strict", "Secure", "Max-Age"):
            self.assertIn(flag, sc)

    def test_ping_input_validation(self):
        c = self.env.client("alice")
        for bad in ("-f", "a b", "$(id)", "x;ls", "a|b", "`id`", "-c5", "", "a" * 300, "127.0.0.1&&id"):
            self.assertEqual(c.get("/ping?host=" + bad.replace("&", "%26").replace(";", "%3B")
                                   .replace("|", "%7C").replace(" ", "%20").replace("`", "%60")
                                   .replace("$", "%24")).status, 400, repr(bad))

    def test_download_allowlist(self):
        c = self.env.client("alice")
        for bad in ("../secret.txt", "..\\secret.txt", "/etc/passwd", "a/b", ".hidden/..", "%00", "welcome.txt%00.png"):
            self.assertIn(c.get("/download?file=" + bad).status, (400, 404), bad)
        self.assertEqual(c.get("/download?file=nonexistent.txt").status, 404)

    def test_symlink_escape_blocked(self):
        os.symlink(os.path.join(self.env.tmp, "secret.txt"), os.path.join(self.env.files, "link.txt"))
        r = self.env.client("alice").get("/download?file=link.txt")
        self.assertEqual(r.status, 404)
        self.assertNotIn("TOP-SECRET", r.text)

    def test_idor_returns_same_response_as_missing(self):
        a, b = self.env.client("alice"), self.env.client("bob")
        nid = a.post("/notes", {"title": "t", "body": "b"}).json()["id"]
        self.assertEqual((b.get("/notes/%d" % nid).status, b.get("/notes/99999").status), (404, 404))

    def test_input_length_limits(self):
        c = self.env.client("alice")
        self.assertEqual(c.post("/notes", {"title": "t" * 101, "body": "b"}).status, 400)
        self.assertEqual(c.post("/notes", {"title": "t", "body": "b" * 5001}).status, 400)
        self.assertEqual(c.post("/notes", {"title": "", "body": "b"}).status, 400)
        self.assertEqual(c.post("/notes", {"title": "t", "body": "bad\x00byte"}).status, 400)

    def test_audit_log_has_no_raw_newlines_or_passwords(self):
        Client(self.env.port).login("evil\r\nuser", "SuperSecret-pass1")
        joined = "\n".join(self.env.app.audit)
        self.assertEqual(len(self.env.app.audit), 1)
        self.assertNotIn("SuperSecret", joined)

    def test_no_default_admin_without_configuration(self):
        env = Env("secure", admin_password=None)
        try:
            self.assertEqual(Client(env.port).login("admin", "admin123").status, 401)
        finally:
            env.close()

    def test_weak_admin_password_rejected_at_startup(self):
        with self.assertRaises(ValueError):
            self.mod.create_server(admin_password="admin")

    def test_error_page_hides_internals(self):
        self.env.app.db.execute("DROP TABLE notes")
        r = self.env.client("alice").get("/search?q=a")
        self.assertEqual(r.status, 500)
        self.assertRegex(r.text, r"request id [0-9a-f]{8}")
        for leak in ("Traceback", "sqlite", "notes", "SELECT"):
            self.assertNotIn(leak, r.text)


if __name__ == "__main__":
    unittest.main()
