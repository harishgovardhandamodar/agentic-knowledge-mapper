"""Tests for the AI Agents Patterns tab backend (app/patterns_kb.py).

The tab indexes the sibling ../AI-Agents-Patterns catalog. Three things have
to hold for it to be worth having:

* the summary counts what is actually on disk (patterns, scenarios,
  cascades, traces), never a hard-coded number;
* the search is a lexical index into that catalog -- an empty query returns
  nothing, and a hit names its kind and id so the tab can link to it;
* a missing sibling directory is an explained state, not a 500, because a
  minimal image may legitimately not ship the sibling checkout.
"""

import json
import os
import tempfile
import unittest

# Pin the database before app.database is imported: a module that omits
# this can inherit data/akm.db and write test rows into the live store.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-patterns-kb-"), "test.db")
)

from fastapi.testclient import TestClient  # noqa: E402

from app import database  # noqa: E402
from app import patterns_kb as pk  # noqa: E402
from app.main import app  # noqa: E402

database.init_db()


def _write_catalog(root: str) -> None:
    data = os.path.join(root, "data")
    os.makedirs(data)
    with open(os.path.join(root, "index.html"), "w", encoding="utf-8") as fh:
        fh.write("<html></html>")
    with open(os.path.join(data, "patterns.json"), "w", encoding="utf-8") as fh:
        json.dump(
            {
                "patterns": [
                    {
                        "id": "p1",
                        "name": "Spend guard",
                        "summary": "cap money movement",
                    },
                    {
                        "id": "p2",
                        "name": "Dual control",
                        "summary": "two-person approval",
                    },
                ]
            },
            fh,
        )
    with open(os.path.join(data, "scenarios.json"), "w", encoding="utf-8") as fh:
        json.dump(
            {
                "scenarios": [
                    {
                        "id": "s1",
                        "title": "Prompt injection moves money",
                        "severity": "critical",
                        "domain": "finance",
                        "description": "injection steers a payment agent",
                    },
                ]
            },
            fh,
        )
    with open(os.path.join(data, "cascades.json"), "w", encoding="utf-8") as fh:
        json.dump(
            {
                "cascades": [
                    {
                        "id": "c1",
                        "name": "Retry amplifies exfil",
                        "cls": "cascading",
                        "domain": "finance",
                        "summary": "retry loop",
                    },
                ]
            },
            fh,
        )
    with open(os.path.join(data, "traces.json"), "w", encoding="utf-8") as fh:
        json.dump({"traces": [{"id": "t1", "name": "Blocked spend"}]}, fh)
    with open(os.path.join(data, "coverage.json"), "w", encoding="utf-8") as fh:
        json.dump({"domains": [], "by_domain": {}, "totals": {}}, fh)


class PatternsKbTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="akm-patterns-")
        _write_catalog(self.tmp)
        self._old = os.environ.get("AKM_PATTERNS_DIR")
        os.environ["AKM_PATTERNS_DIR"] = self.tmp
        pk._cache["mtime"] = None
        pk._cache["payload"] = None

    def tearDown(self):
        if self._old is None:
            os.environ.pop("AKM_PATTERNS_DIR", None)
        else:
            os.environ["AKM_PATTERNS_DIR"] = self._old
        pk._cache["mtime"] = None
        pk._cache["payload"] = None

    def test_summary_counts_what_is_on_disk(self):
        s = pk.summary()
        self.assertTrue(s["available"])
        self.assertEqual(s["counts"]["patterns"], 2)
        self.assertEqual(s["counts"]["scenarios"], 1)
        self.assertEqual(s["counts"]["cascades"], 1)
        self.assertEqual(s["counts"]["traces"], 1)
        self.assertEqual(s["counts"]["severities"], {"critical": 1})
        self.assertEqual(s["counts"]["cascade_classes"], {"cascading": 1})
        self.assertTrue(all(s["files"].values()))

    def test_search_is_lexical_and_kind_tagged(self):
        r = pk.search("money")
        self.assertTrue(r["available"])
        kinds = {(i["kind"], i["id"]) for i in r["items"]}
        # "money movement" (pattern p1) and "moves money" (scenario s1) match.
        self.assertIn(("pattern", "p1"), kinds)
        self.assertIn(("scenario", "s1"), kinds)
        # Kind filter narrows to one pool.
        r2 = pk.search("money", kind="cascades")
        self.assertEqual(r2["items"], [])

    def test_empty_query_returns_nothing(self):
        r = pk.search("   ")
        self.assertTrue(r["available"])
        self.assertEqual(r["items"], [])

    def test_missing_directory_is_explained(self):
        os.environ["AKM_PATTERNS_DIR"] = os.path.join(self.tmp, "absent")
        pk._cache["mtime"] = None
        pk._cache["payload"] = None
        self.assertFalse(pk.available()["available"])
        s = pk.summary()
        self.assertFalse(s["available"])
        self.assertIn("reason", s)
        r = pk.search("money")
        self.assertFalse(r["available"])
        self.assertEqual(r["items"], [])

    def test_one_bad_file_does_not_sink_the_rest(self):
        with open(
            os.path.join(self.tmp, "data", "scenarios.json"), "w", encoding="utf-8"
        ) as fh:
            fh.write("{not json")
        pk._cache["mtime"] = None
        pk._cache["payload"] = None
        s = pk.summary()
        self.assertTrue(s["available"])
        self.assertEqual(s["counts"]["patterns"], 2)
        self.assertEqual(s["counts"]["scenarios"], 0)
        self.assertFalse(s["files"]["scenarios.json"])


class PatternsApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_status_and_summary_endpoints(self):
        r = self.client.get("/api/patterns/status")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertIn("available", body)
        r = self.client.get("/api/patterns/summary")
        self.assertEqual(r.status_code, 200)
        self.assertIn("counts", r.json())

    def test_search_endpoint(self):
        r = self.client.get("/api/patterns/search", params={"q": "injection"})
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertIn("items", body)


if __name__ == "__main__":
    unittest.main()
