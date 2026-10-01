"""Tests for investigation visibility (hide / unhide).

Hiding is list-level only: the investigation, its runs, artifacts and history
all survive, and the detail endpoint keeps working. Run with:
``python3 -m unittest discover -s tests -t .``
"""
import os
import tempfile
import unittest


# Pin the database before app.database is imported: a module that omits
# this can inherit data/akm.db and write test rows into the live store.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-investigations-"), "test.db"))

from app import agent as agent_mod  # noqa: E402
from app import database  # noqa: E402
from app import main as main_mod  # noqa: E402

# Keep the product path offline: these tests are about visibility plumbing.
agent_mod._plan_queries = lambda inv: {"rationale": "s", "queries": []}
agent_mod._run_searches = lambda q, s: []
agent_mod._analyze_batch = lambda i, b, e, *a, **k: []
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


class TestCollectionOverview(unittest.TestCase):
    """The Artifacts tab: timeline position, purpose, and actor shares."""

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        cls.client = TestClient(main_mod.app)
        cls.n = 0

    def _seed(self):
        from datetime import datetime, timezone
        from app.database import SessionLocal
        from app.models import Investigation, Artifact, AgentRun
        import json as _json
        type(self).n += 1
        db = SessionLocal()
        try:
            inv = Investigation(title=f"collection-{type(self).n}", keywords="k",
                                description="d", sources="web")
            db.add(inv)
            db.commit()
            iid = inv.id
            r1 = AgentRun(investigation_id=iid, status="done", trigger="manual")
            r2 = AgentRun(investigation_id=iid, status="done", trigger="schedule",
                          plan=_json.dumps({"goal": "gap goal"}))
            db.add_all([r1, r2])
            db.commit()
            r1id, r2id = r1.id, r2.id
            db.add_all([
                Artifact(investigation_id=iid, run_id=r1id, title="Agent item",
                         relevance=0.9, relevance_reason="why-1", review="pending",
                         origin="agent",
                         created_at=datetime(2026, 9, 20, tzinfo=timezone.utc)),
                Artifact(investigation_id=iid, run_id=r2id, title="Sched item",
                         review="accepted", origin="agent",
                         created_at=datetime(2026, 9, 21, tzinfo=timezone.utc)),
                Artifact(investigation_id=iid, title="Hand item", review="pending",
                         origin="manual",
                         created_at=datetime(2026, 9, 21, tzinfo=timezone.utc)),
                Artifact(investigation_id=iid, title="Expl item", author="explainer",
                         review="pending", origin="agent",
                         created_at=datetime(2026, 9, 22, tzinfo=timezone.utc)),
            ])
            db.commit()
            return iid
        finally:
            db.close()

    def test_overview_shape_and_actor_math(self):
        iid = self._seed()
        r = self.client.get(f"/api/investigations/{iid}/artifacts/overview")
        self.assertEqual(r.status_code, 200, r.text)
        ov = r.json()
        self.assertEqual(ov["total"], 4)
        actors = {a["actor"]: a for a in ov["by_actor"]}
        self.assertEqual(actors["agent · manual run"]["count"], 1)
        self.assertEqual(actors["agent · scheduled"]["count"], 1)
        self.assertEqual(actors["human"]["count"], 1)
        self.assertEqual(actors["explainer"]["count"], 1)
        self.assertAlmostEqual(sum(a["pct"] for a in ov["by_actor"]), 100.0)
        self.assertEqual([b["day"] for b in ov["timeline"]],
                         ["2026-09-20", "2026-09-21", "2026-09-22"])
        self.assertEqual([b["count"] for b in ov["timeline"]], [1, 2, 1])

    def test_purpose_prefers_evidence_then_fallbacks(self):
        iid = self._seed()
        items = {i["title"]: i for i in self.client.get(
            f"/api/investigations/{iid}/artifacts/overview").json()["items"]}
        self.assertEqual(items["Agent item"]["purpose"], "why-1")
        self.assertEqual(items["Sched item"]["purpose"], "agent run goal: gap goal")
        self.assertEqual(items["Hand item"]["purpose"], "added by hand")
        self.assertEqual(items["Expl item"]["purpose"], "saved from an explanation")

    def test_overview_missing_is_404(self):
        r = self.client.get("/api/investigations/999999/artifacts/overview")
        self.assertEqual(r.status_code, 404)


class TestShortGoal(unittest.TestCase):
    def test_short_goal_is_untouched(self):
        self.assertEqual(agent_mod._short_goal("abc"), "abc")

    def test_long_goal_ends_on_a_word_boundary_with_an_ellipsis(self):
        """A hard slice cut "...are transmitted" down to "...are transmit",
        which reads like a broken error in the run log."""
        goal = ("Investigate open questions from an explanation: "
                "No documented data-flow architecture: where prompts/outputs "
                "are transmitted and stored")
        short = agent_mod._short_goal(goal)
        self.assertTrue(short.endswith("…"), short)
        self.assertLessEqual(len(short), 121)
        # The cut lands on a word boundary: the next character in the original
        # is a space (or the end), never the middle of "transmitted".
        body = short[:-1]
        self.assertTrue(goal.startswith(body))
        self.assertIn(goal[len(body):len(body) + 1], (" ", ""))
        self.assertNotIn("transmit ", body + " ", "cut mid-word")

    def test_empty_goal_is_safe(self):
        self.assertEqual(agent_mod._short_goal(""), "")


if __name__ == "__main__":
    unittest.main()
