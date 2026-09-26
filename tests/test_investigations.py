"""Tests for investigation visibility (hide / unhide).

Hiding is list-level only: the investigation, its runs, artifacts and history
all survive, and the detail endpoint keeps working. Run with:
``python3 -m unittest discover -s tests -t .``
"""
import os
import tempfile
import unittest

os.environ.setdefault("AKM_DATABASE_URL", "sqlite:///" + os.path.join(
    tempfile.mkdtemp(prefix="akm-hide-test-"), "test.db"))

from app import agent as agent_mod  # noqa: E402
from app import database  # noqa: E402
from app import main as main_mod  # noqa: E402

# Keep the product path offline: these tests are about visibility plumbing.
agent_mod._plan_queries = lambda inv: {"rationale": "s", "queries": []}
agent_mod._run_searches = lambda q, s: []
agent_mod._analyze_batch = lambda i, b, e: []
agent_mod._map_relationships = lambda *a, **k: 0
main_mod.launch_run = lambda *a, **k: None
database.init_db()


class TestInvestigationVisibility(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        cls.client = TestClient(main_mod.app)
        cls.n = 0

    def _create(self, title):
        type(self).n += 1
        title = f"{title}-{type(self).n}"
        r = self.client.post("/api/investigations",
                             json={"title": title, "keywords": "k",
                                   "description": "d", "sources": "web"})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def _list(self, **params):
        r = self.client.get("/api/investigations", params=params)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["items"]

    def test_hidden_excluded_from_default_list(self):
        vis = self._create("vis")
        hid = self._create("hid")
        r = self.client.patch(f"/api/investigations/{hid['id']}/hidden",
                              json={"hidden": True})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["hidden"])
        titles = self._titles_default()
        self.assertIn(vis["title"], titles)
        self.assertNotIn(hid["title"], titles)

    def _titles_default(self):
        return [i["title"] for i in self._list()]

    def test_include_hidden_shows_the_flag(self):
        hid = self._create("flagged")
        self.client.patch(f"/api/investigations/{hid['id']}/hidden",
                          json={"hidden": True})
        rows = {i["title"]: i for i in self._list(include_hidden="true")}
        self.assertIn(hid["title"], rows)
        self.assertTrue(rows[hid["title"]]["hidden"])

    def test_unhide_restores_the_listing(self):
        hid = self._create("restored")
        self.client.patch(f"/api/investigations/{hid['id']}/hidden",
                          json={"hidden": True})
        self.assertNotIn(hid["title"], self._titles_default())
        r = self.client.patch(f"/api/investigations/{hid['id']}/hidden",
                              json={"hidden": False})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertFalse(r.json()["hidden"])
        self.assertIn(hid["title"], self._titles_default())

    def test_missing_investigation_is_404(self):
        r = self.client.patch("/api/investigations/999999/hidden",
                              json={"hidden": True})
        self.assertEqual(r.status_code, 404)

    def test_hidden_keeps_its_data_and_detail(self):
        hid = self._create("kept")
        self.client.patch(f"/api/investigations/{hid['id']}/hidden",
                          json={"hidden": True})
        r = self.client.get(f"/api/investigations/{hid['id']}")
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertTrue(body["hidden"])
        self.assertIn("recent_runs", body)


if __name__ == "__main__":
    unittest.main()
