"""Functional tests: legitimate behaviour must work in BOTH the original and the hardened app."""
import unittest
from tests.client import Env, Client, PW, ADMIN_PW


class FunctionalMixin:
    kind = None

    def setUp(self):
        self.env = Env(self.kind)

    def tearDown(self):
        self.env.close()

    def test_register_and_login(self):
        c = Client(self.env.port)
        self.assertEqual(c.register("alice", PW["alice"]).status, 201)
        self.assertEqual(c.login("alice", PW["alice"]).status, 200)
        self.assertEqual(Client(self.env.port).login("alice", "totally-wrong-pw").status, 401)

    def test_duplicate_registration(self):
        c = Client(self.env.port)
        c.register("alice", PW["alice"])
        self.assertEqual(c.register("alice", PW["alice"]).status, 409)

    def test_notes_roundtrip(self):
        c = self.env.client("alice")
        r = c.post("/notes", {"title": "Shopping", "body": "milk & eggs"})
        self.assertEqual(r.status, 201)
        page = c.get("/notes/%d" % r.json()["id"])
        self.assertEqual(page.status, 200)
        self.assertIn("Shopping", page.text)
        self.assertIn("milk", page.text)

    def test_search_finds_own_notes_only(self):
        a, b = self.env.client("alice"), self.env.client("bob")
        a.post("/notes", {"title": "alpha plan", "body": "x"})
        b.post("/notes", {"title": "alpha secret", "body": "y"})
        res = a.get("/search?q=alpha").text
        self.assertIn("alpha plan", res)
        self.assertNotIn("alpha secret", res)

    def test_login_required(self):
        c = Client(self.env.port)
        for path in ("/notes/1", "/search?q=a", "/download?file=welcome.txt", "/admin"):
            self.assertEqual(c.get(path).status, 401, path)

    def test_download_legit_file(self):
        c = self.env.client("alice")
        r = c.get("/download?file=welcome.txt")
        self.assertEqual((r.status, r.text), (200, "Welcome to SecureNotes"))

    def test_admin_access(self):
        admin = Client(self.env.port)
        pw = "admin123" if self.kind == "vulnerable" else ADMIN_PW
        self.assertEqual(admin.login("admin", pw).status, 200)
        self.assertEqual(admin.get("/admin").status, 200)
        self.assertEqual(self.env.client("alice").get("/admin").status, 403)

    def test_ping_valid_host_does_not_crash(self):
        c = self.env.client("alice")
        self.assertIn(c.get("/ping?host=127.0.0.1").status, (200, 503))   # 503: no ping binary installed

    def test_unknown_route(self):
        self.assertEqual(self.env.client("alice").get("/nope").status, 404)


class TestOriginalFunctional(FunctionalMixin, unittest.TestCase):
    kind = "vulnerable"


class TestHardenedFunctional(FunctionalMixin, unittest.TestCase):
    kind = "secure"


if __name__ == "__main__":
    unittest.main()
