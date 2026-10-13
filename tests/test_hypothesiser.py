"""Hypothesiser: inherent scenarios, derived compositions, provenance.

Every scenario must cite where it came from (artifact ids, claim, or
parent scenarios plus the composition rule); single-source scenarios
are flagged fragile, and an empty collection returns
insufficient_evidence instead of a cast. Pin header required suite-wide.
"""
import os
import tempfile
import unittest

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-hypo-"),
                                "test.db"))

from app import database as _db  # noqa: E402
from app import hypothesiser as hy  # noqa: E402
from app.models import Artifact, Investigation, Relationship  # noqa: E402

_db.init_db()


def _inv(title="Probe product", keywords="ProbeCorp"):
    db = _db.SessionLocal()
    try:
        inv = Investigation(title=title, keywords=keywords,
                            description="d", sources="web")
        db.add(inv)
        db.commit()
        db.refresh(inv)
        return inv.id
    finally:
        db.close()


def _art(inv_id, title, description="", tags="", relevance=0.8):
    db = _db.SessionLocal()
    try:
        a = Artifact(investigation_id=inv_id, title=title,
                     description=description, tags=tags,
                     relevance=relevance)
        db.add(a)
        db.commit()
        db.refresh(a)
        return a.id
    finally:
        db.close()


def _pack(inv_id):
    db = _db.SessionLocal()
    try:
        return hy.enumerate_scenarios(db, inv_id)
    finally:
        db.close()


class InherentCase(unittest.TestCase):
    def test_one_scenario_per_finding_with_provenance(self):
        iid = _inv()
        a1 = _art(iid, "Vendor stores prompts for training",
                  "Docs say prompts may train models.", relevance=0.9)
        a2 = _art(iid, "Status page shows outage",
                  "Downtime reported.", relevance=0.5)
        pack = _pack(iid)
        self.assertEqual(pack["verdict"]["key"], "enumerated")
        self.assertEqual(len(pack["inherent"]), 2)
        prov = [s["provenance"].get("artifacts", []) for s in
                pack["inherent"]]
        self.assertIn([a1], prov)
        self.assertIn([a2], prov)
        conf = {s["confidence"] for s in pack["inherent"]}
        self.assertIn("high", conf)
        self.assertIn("medium", conf)
        self.assertTrue(all(s["fragile"] for s in pack["inherent"]))

    def test_empty_is_insufficient_not_a_cast(self):
        pack = _pack(_inv())
        self.assertEqual(pack["verdict"]["key"], "insufficient_evidence")
        self.assertEqual(pack["inherent"], [])
        self.assertEqual(pack["derived"], [])
        self.assertTrue(pack["gaps"])


class DerivedCase(unittest.TestCase):
    def test_shared_subject_composes(self):
        iid = _inv()
        _art(iid, "Training data retention", "Keeps prompts.",
             tags="training-data, retention, api")
        _art(iid, "Retention window undisclosed", "No deletion date.",
             tags="training-data, retention, deletion")
        pack = _pack(iid)
        rules = [d["provenance"]["rule"] for d in pack["derived"]]
        self.assertIn("shared-subject", rules)
        combo = next(d for d in pack["derived"]
                     if d["provenance"]["rule"] == "shared-subject")
        self.assertEqual(len(combo["provenance"]["parents"]), 2)

    def test_recorded_edge_chains(self):
        iid = _inv()
        a1 = _art(iid, "First finding", "Alpha event.")
        a2 = _art(iid, "Second finding", "Beta event.")
        db = _db.SessionLocal()
        try:
            db.add(Relationship(investigation_id=iid, source_id=a1,
                                target_id=a2,
                                relationship_type="leads_to"))
            db.commit()
        finally:
            db.close()
        pack = _pack(iid)
        rules = [d["provenance"]["rule"] for d in pack["derived"]]
        self.assertIn("recorded-edge", rules)

    def test_caps_hold(self):
        iid = _inv()
        for i in range(30):
            _art(iid, f"Finding {i}", "Some reported content here.",
                 tags="shared-a, shared-b")
        pack = _pack(iid)
        self.assertLessEqual(len(pack["inherent"]), 20)
        self.assertLessEqual(len(pack["derived"]), 20)


class PersistCase(unittest.TestCase):
    def test_store_idempotent_and_fenced(self):
        iid = _inv()
        _art(iid, "Finding one", "Content here for the map.")
        db = _db.SessionLocal()
        try:
            first = hy.store_scenarios(db, iid)
            second = hy.store_scenarios(db, iid)
        finally:
            db.close()
        self.assertFalse(first["existing"])
        self.assertTrue(second["existing"])
        self.assertEqual(first["artifact_id"], second["artifact_id"])
        md = hy.render_markdown(first["pack"])
        self.assertIn("```mermaid scenarios", md)
        self.assertIn("flowchart LR",
                      first["pack"]["diagrams"]["scenario_map"])

    def test_endpoints_round_trip(self):
        from fastapi.testclient import TestClient

        from app.main import app
        iid = _inv()
        _art(iid, "Finding one", "Content here for the map.")
        with TestClient(app) as c:
            r = c.post(f"/api/investigations/{iid}/scenarios")
            self.assertEqual(r.status_code, 200, r.text[:300])
            body = r.json()
            self.assertIn("artifact_id", body)
            g = c.get(f"/api/investigations/{iid}/scenarios")
            self.assertEqual(g.status_code, 200, g.text[:300])
            self.assertEqual(
                g.json()["pack"]["verdict"]["key"],
                body["pack"]["verdict"]["key"])
            n = c.get("/api/plugins")
            self.assertEqual(n.status_code, 200, n.text[:200])
            keys = [p["key"] for p in n.json()["plugins"]]
            self.assertEqual(keys, ["adoption", "security",
                                    "vulnerability", "writeup",
                                    "hypothesis"])


if __name__ == "__main__":
    unittest.main()
