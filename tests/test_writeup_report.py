"""Write-up summaries: the report leads with prose, not scores.

An investigation whose work is explanations must show them: the latest
write-ups with summaries, key points, and provenance, their figures
collected into the report diagrams, plus workflow/activity/interaction
figures derived from stored rows. Pin header required suite-wide.
"""
import json
import os
import tempfile
import unittest
from datetime import UTC, datetime

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-writeup-"),
                                "test.db"))

from app import database as _db  # noqa: E402
from app import run_summary as _rs  # noqa: E402
from app.models import (  # noqa: E402
    AgentRun,
    Artifact,
    Explanation,
    Investigation,
    Relationship,
    SecurityAssessment,
)

_db.init_db()

NOW = datetime.now(UTC).replace(tzinfo=None)


def _inv(**over):
    base = {"title": "Probe writeup", "keywords": "Probe",
            "description": "d", "sources": "web", "status": "ready"}
    base.update(over)
    db = _db.SessionLocal()
    try:
        inv = Investigation(**base)
        db.add(inv)
        db.commit()
        db.refresh(inv)
        return inv.id
    finally:
        db.close()


def _seed(iid):
    db = _db.SessionLocal()
    try:
        db.add(AgentRun(investigation_id=iid, status="done",
                        trigger="manual",
                        stats=json.dumps({"rounds": 2,
                                          "artifacts_kept": 5}),
                        started_at=NOW, finished_at=NOW))
        db.add(AgentRun(investigation_id=iid, status="done",
                        trigger="security", stats=json.dumps({}),
                        started_at=NOW, finished_at=NOW))
        db.add(SecurityAssessment(
            investigation_id=iid, product_name="Widget",
            exposure="public", overall_pct=10.0, inherent_pct=10.0,
            residual_pct=10.0, markdown="# stub",
            threat_pack_version="2024.1",
            assurance_decision="accept"))
        db.add(Explanation(
            investigation_id=iid, question="What happened?",
            status="done", mode="deep_dive",
            answer=json.dumps({
                "summary": "A full account of events.",
                "key_points": ["first", "second"],
                "diagram": {"title": "Chain",
                            "mermaid": "flowchart TD\n    A[x] --> B[y]",
                            "caption": "cap"}}),
            trace=json.dumps({"queries": ["a", "b"],
                              "hits": [{}, {}, {}],
                              "fetched": [{}, {}]}),
            finished_at=NOW))
        db.add(Explanation(investigation_id=iid, question="Follow-up?",
                           status="running", mode="explain"))
        a1 = Artifact(investigation_id=iid, title="Report one")
        a2 = Artifact(investigation_id=iid, title="Report two")
        db.add(a1)
        db.add(a2)
        db.commit()
        db.refresh(a1)
        db.refresh(a2)
        db.add(Relationship(investigation_id=iid, source_id=a1.id,
                            target_id=a2.id,
                            relationship_type="relates_to"))
        db.commit()
    finally:
        db.close()


def _section(iid):
    db = _db.SessionLocal()
    try:
        return _rs._inv_section(db, iid)
    finally:
        db.close()


class WriteupCase(unittest.TestCase):
    def test_writeup_section_leads_with_prose(self):
        iid = _inv()
        _seed(iid)
        sec = _section(iid)
        text = "\n".join(sec["writeup"])
        self.assertIn("What happened?", text)
        self.assertIn("A full account of events.", text)
        self.assertIn("first", text)
        self.assertIn("2 queries", text)
        self.assertIn("deep_dive", text)

    def test_explainer_figures_collected(self):
        iid = _inv()
        _seed(iid)
        sec = _section(iid)
        origins = [d.get("origin") for d in sec["diagrams"]]
        self.assertTrue(any(str(o).startswith("write-up")
                            for o in origins))
        self.assertTrue(any((d.get("source") or "").startswith(
            "flowchart") for d in sec["diagrams"]))

    def test_process_figures_present_and_gated(self):
        from app.explainer import _validate_mermaid
        iid = _inv()
        _seed(iid)
        sec = _section(iid)
        proc = [d for d in sec["diagrams"] if d.get("origin") == "process"]
        kinds = sorted(d.get("key") for d in proc)
        self.assertEqual(kinds, ["activity", "interaction", "workflow"])
        for d in proc:
            self.assertIsNotNone(
                _validate_mermaid(d["source"]),
                f"{d['key']} must be parser-safe")
        heads = [d["source"].splitlines()[0] for d in proc]
        self.assertTrue(any(h.startswith("flowchart") for h in heads))
        self.assertTrue(any(h.startswith("stateDiagram") for h in heads))
        self.assertTrue(any(h.startswith("sequenceDiagram") for h in heads))

    def test_empty_investigation_stays_graceful(self):
        sec = _section(_inv())
        self.assertEqual(sec["writeup"], [])
        proc = [d for d in sec["diagrams"] if d.get("origin") == "process"]
        self.assertEqual(len(proc), 3)
        blob = "\n".join(d["source"] for d in proc)
        self.assertIn("not started", blob)
        # A stored row always carries its opening exchange.
        self.assertIn("brief opened", blob)


class ReportCase(unittest.TestCase):
    def test_report_has_writeup_and_figures(self):
        iid = _inv()
        _seed(iid)
        db = _db.SessionLocal()
        try:
            report = _rs.investigation_report(db, iid)
        finally:
            db.close()
        self.assertIn("## Write-up", report["markdown"])
        self.assertIn("```mermaid", report["markdown"])
        self.assertIn("Investigation workflow", report["markdown"])
        self.assertGreater(report["counts"]["writeups"], 0)
        self.assertGreaterEqual(report["counts"]["diagrams"], 4)

    def test_endpoint_serves_writeup(self):
        from fastapi.testclient import TestClient

        from app.main import app
        iid = _inv()
        _seed(iid)
        with TestClient(app) as c:
            r = c.get(f"/api/investigations/{iid}/summary-report")
            self.assertEqual(r.status_code, 200, r.text[:300])
            md = r.json()["markdown"]
            self.assertIn("## Write-up", md)
            self.assertIn("What happened?", md)


if __name__ == "__main__":
    unittest.main()
