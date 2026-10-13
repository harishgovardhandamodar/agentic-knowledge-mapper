"""Research council: seats propose, the critic disposes.

Every investigation plans through the council: source seats propose
query families only when relevant, the critic dedupes and tops up
uncovered seats within the cap, and the record travels with the plan.
Pin header required suite-wide (see tests/test_db_isolation.py).
"""
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-council-"),
                                "test.db"))

from app import research_council as rc  # noqa: E402


def _inv(**over):
    base = {"title": "Probe product", "keywords": "ProbeCorp",
            "description": "A product brief.", "sources": "web,rss"}
    base.update(over)
    return SimpleNamespace(**base)


class SubjectCase(unittest.TestCase):
    def test_first_keyword_wins(self):
        self.assertEqual(rc.subject_of(_inv(keywords="Acme, other")),
                         "Acme")

    def test_title_fallback(self):
        self.assertEqual(rc.subject_of(_inv(keywords="")), "Probe product")


class ReviewCase(unittest.TestCase):
    def test_llm_queries_gain_seat_tags(self):
        clean = [{"text": "acme pricing", "sources": ["web"]}]
        out, record = rc.review(_inv(), clean, {"web", "rss"})
        self.assertEqual(out[0]["seat"], "llm")
        self.assertTrue(any(s["id"] == "news" for s in record["seats"]))

    def test_exact_duplicates_dropped_and_noted(self):
        clean = [{"text": "Acme pricing", "sources": ["web"]},
                 {"text": "acme pricing ", "sources": ["rss"]}]
        out, record = rc.review(_inv(), clean, {"web", "rss"})
        self.assertEqual(len(record["critic"]["dropped"]), 1)
        texts = [q["text"].strip().lower() for q in out]
        self.assertEqual(len(texts), len(set(texts)))

    def test_incident_seat_tops_up(self):
        inv = _inv(title="Acme outage timeline",
                   keywords="Acme, incident_reconstruction",
                   description="Incident reconstruction brief.")
        clean = [{"text": "acme pricing", "sources": ["web"]}]
        out, record = rc.review(inv, clean, {"web", "rss"})
        seats = {s["id"]: s for s in record["seats"]}
        self.assertTrue(seats["incident"]["relevant"])
        added = [q for q in out if q.get("seat") == "incident"]
        self.assertTrue(added)
        self.assertLessEqual(len(out), rc.MAX_QUERIES)

    def test_full_cap_records_gaps_not_queries(self):
        inv = _inv(title="Acme outage timeline",
                   keywords="Acme, incident_reconstruction",
                   description="Incident reconstruction brief.")
        clean = [{"text": f"q{i}", "sources": ["web"]} for i in range(6)]
        out, record = rc.review(inv, clean, {"web", "rss"})
        self.assertEqual(len(out), 6)
        self.assertTrue(any("incident" in g
                            for g in record["critic"]["gaps"]))

    def test_irrelevant_seats_stay_quiet(self):
        out, record = rc.review(_inv(), [], {"web"})
        seats = {s["id"]: s for s in record["seats"]}
        self.assertFalse(seats["papers"]["relevant"])
        self.assertFalse(seats["incident"]["relevant"])
        self.assertTrue(seats["news"]["relevant"])


class PlanIntegrationCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import importlib

        from app import agent as agent_mod
        # Sibling modules replace _plan_queries globally at import time;
        # reload to test the real planner (same convention as
        # TestVendorDocQuery), then restore afterwards.
        cls._patched = agent_mod._plan_queries
        importlib.reload(agent_mod)

    @classmethod
    def tearDownClass(cls):
        from app import agent as agent_mod
        agent_mod._plan_queries = cls._patched

    def test_plan_carries_council_record(self):
        from app import agent as _agent
        inv = _inv()
        canned = {"rationale": "canned",
                  "queries": [{"text": "acme pricing",
                               "sources": ["web"]}]}
        with mock.patch("app.agent.llm.chat_json", return_value=canned):
            plan = _agent._plan_queries(inv)
        self.assertIn("council", plan)
        seats = {s["id"]: s for s in plan["council"]["seats"]}
        self.assertIn("news", seats)
        self.assertIn("covered", seats["news"])
        tagged = [q.get("seat") for q in plan["queries"]]
        self.assertIn("llm", tagged)

    def test_fallback_path_still_councilled(self):
        from app import agent as _agent
        inv = _inv()
        with mock.patch("app.agent.llm.chat_json",
                        return_value={"junk": True}):
            plan = _agent._plan_queries(inv)
        self.assertIn("council", plan)
        self.assertTrue(plan["queries"])


if __name__ == "__main__":
    unittest.main()
