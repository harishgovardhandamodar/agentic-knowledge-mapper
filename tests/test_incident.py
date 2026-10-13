"""Incident post-mortem track: intent, plan, reconstruction, endpoints.

An incident question ("what really happened on the X outage, what
triggered it? root cause, explain with mermaid diagrams") must come
back as a timeline/trigger/root-cause reconstruction with incident
figures -- never as CVE lists with residual scores, and never invented
when the artifacts hold no event evidence. Pin header required
suite-wide (see tests/test_db_isolation.py).
"""
import os
import tempfile
import unittest
from types import SimpleNamespace

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-incident-"),
                                "test.db"))

from app import database as _db  # noqa: E402
from app import incident as inc  # noqa: E402
from app.models import Artifact, Investigation  # noqa: E402

_db.init_db()

RUN50 = ("what really happened on OpenAI - Huggingface incident, what "
         "triggered it? root cause, explain with mermaid diagrams")


def _inv(title="Probe incident", keywords="OpenAI Huggingface"):
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


def _art(inv_id, title, description="", content="", url="",
         relevance=0.7, date_published=None):
    db = _db.SessionLocal()
    try:
        a = Artifact(investigation_id=inv_id, title=title,
                     description=description, content=content, url=url,
                     relevance=relevance, date_published=date_published)
        db.add(a)
        db.commit()
        db.refresh(a)
        return a.id
    finally:
        db.close()


def _pack(inv_id):
    db = _db.SessionLocal()
    try:
        return inc.analyze(db, inv_id)
    finally:
        db.close()


class IntentCase(unittest.TestCase):
    def test_run50_command_is_incident(self):
        self.assertTrue(inc.is_incident_command(RUN50))

    def test_outage_breach_postmortem_are_incident(self):
        for q in ("AWS us-east-1 outage timeline",
                  "postmortem of the npm breach",
                  "the service went down yesterday, why"):
            self.assertTrue(inc.is_incident_command(q), q)

    def test_security_questions_stay_generic(self):
        for q in ("assess the security risk of adopting Collibra",
                  "root cause of insecure defaults in web apps",
                  "threat model for the billing API"):
            self.assertFalse(inc.is_incident_command(q), q)

    def test_incident_brief_marker(self):
        plan = inc.incident_plan(RUN50)
        first = plan["topics"][0]
        self.assertTrue(inc.is_incident_brief(
            first["title"], first["keywords"], first["description"]))
        self.assertFalse(inc.is_incident_brief(
            "Collibra data posture", "collibra", "residual scoring brief"))


class PlanCase(unittest.TestCase):
    def test_run50_subject_and_shape(self):
        plan = inc.incident_plan(RUN50)
        self.assertTrue(plan["incident"])
        self.assertEqual(plan["parsed_by"], "incident-template")
        self.assertEqual(len(plan["topics"]), 5)
        subjects = {t["subject"] for t in plan["topics"]}
        self.assertEqual(subjects, {"OpenAI - Huggingface"})
        tasks = {t["task"] for t in plan["topics"]}
        self.assertEqual(tasks, {"incident_reconstruction"})
        titles = " ".join(t["title"] for t in plan["topics"]).lower()
        for word in ("timeline", "trigger", "root cause", "impact",
                     "response"):
            self.assertIn(word, titles)

    def test_non_incident_is_none(self):
        self.assertIsNone(inc.incident_plan(
            "assess the security risk of adopting Collibra"))

    def test_manager_routes_without_network(self):
        from app import manager as _mgr
        plan = _mgr.parse_command(RUN50)
        self.assertTrue(plan.get("incident"))
        self.assertEqual(plan["parsed_by"], "incident-template")
        self.assertEqual(len(plan["topics"]), 5)


class AnalyzeCase(unittest.TestCase):
    def test_reconstructed_from_dated_evidence(self):
        iid = _inv()
        _art(iid, "OpenAI status: elevated errors on inference API",
             "On 2026-03-04 OpenAI reported elevated errors. Users unable "
             "to reach the API for 3 hours.",
             url="https://status.openai.com")
        _art(iid, "Hugging Face confirms inference outage",
             "Hugging Face confirmed downtime on 2026-03-05, triggered by "
             "a faulty config deployment during maintenance.",
             url="https://status.huggingface.co")
        _art(iid, "Postmortem: root cause was a bad config push",
             "The postmortem says the root cause was a config push that "
             "bypassed canary. Service restored 2026-03-06.",
             url="https://blog.example.com/postmortem")
        pack = _pack(iid)
        self.assertEqual(pack["verdict"]["key"], "reconstructed")
        days = [e["date"] for e in pack["dated_events"]]
        self.assertEqual(days, sorted(days))
        self.assertGreaterEqual(len(days), 3)
        self.assertIsNotNone(pack["trigger"])
        self.assertIn("config", pack["trigger"]["text"].lower())
        self.assertIsNotNone(pack["root_cause"])
        tl = pack["diagrams"]["timeline"]
        self.assertTrue(tl.startswith("timeline"))
        self.assertIn("2026-03-04", tl)
        causal = pack["diagrams"]["causal"]
        self.assertTrue(causal.startswith("flowchart TD"))
        self.assertNotIn("unknown: no trigger evidence", causal)

    def test_future_dates_excluded(self):
        iid = _inv()
        _art(iid, "Scheduled maintenance 2099-01-01",
             "Planned window far in the future, unrelated.")
        pack = _pack(iid)
        self.assertNotIn("2099-01-01",
                         [e["date"] for e in pack["dated_events"]])

    def test_trigger_without_dates_is_partial(self):
        iid = _inv()
        _art(iid, "Users report errors reaching the API",
             "Widespread errors; the outage was triggered by a faulty "
             "deploy, per user reports. No dates given.")
        pack = _pack(iid)
        self.assertEqual(pack["verdict"]["key"], "partial")
        self.assertEqual(pack["dated_events"], [])
        self.assertIsNotNone(pack["trigger"])
        self.assertTrue(pack["gaps"])

    def test_nothing_at_all_is_insufficient(self):
        iid = _inv()
        _art(iid, "Vendor homepage", "Marketing copy, no event content.")
        pack = _pack(iid)
        self.assertEqual(pack["verdict"]["key"], "insufficient_evidence")

    def test_empty_collection_is_insufficient(self):
        iid = _inv()
        pack = _pack(iid)
        self.assertEqual(pack["verdict"]["key"], "insufficient_evidence")
        self.assertIn("causal", pack["diagrams"])
        self.assertIn("unknown", pack["diagrams"]["causal"])

    def test_store_is_idempotent(self):
        iid = _inv()
        _art(iid, "Outage noted", "Service went down hard.")
        db = _db.SessionLocal()
        try:
            first = inc.store_analysis(db, iid)
            second = inc.store_analysis(db, iid)
        finally:
            db.close()
        self.assertFalse(first["existing"])
        self.assertTrue(second["existing"])
        self.assertEqual(first["artifact_id"], second["artifact_id"])

    def test_markdown_fences_figures(self):
        iid = _inv()
        _art(iid, "Outage 2026-02-01", "The API went down on 2026-02-01.")
        pack = _pack(iid)
        md = inc.render_markdown(pack)
        self.assertEqual(md.count("```mermaid"), 2)
        self.assertIn("Incident reconstruction", md)


class EnsurerCase(unittest.TestCase):
    def test_incident_brief_gets_event_queries(self):
        plan = inc.incident_plan(RUN50)
        inv = SimpleNamespace(
            title=plan["topics"][0]["title"],
            keywords=plan["topics"][0]["keywords"],
            description=plan["topics"][0]["description"])
        from app import agent as _agent
        clean: list = []
        _agent._ensure_incident_queries(inv, clean, {"web", "rss"})
        self.assertTrue(clean)
        blob = " ".join(q["text"] for q in clean).lower()
        self.assertIn("timeline", blob)
        self.assertIn("status", blob)
        self.assertLessEqual(len(clean), 6)

    def test_generic_brief_untouched(self):
        inv = SimpleNamespace(title="Collibra posture", keywords="x",
                              description="residual scoring")
        from app import agent as _agent
        clean: list = [{"text": "collibra docs", "sources": ["web"]}]
        _agent._ensure_incident_queries(inv, clean, {"web"})
        self.assertEqual(len(clean), 1)


class EndpointCase(unittest.TestCase):
    def test_post_then_get(self):
        from fastapi.testclient import TestClient

        from app.main import app
        iid = _inv()
        _art(iid, "Outage 2026-02-01", "The API went down on 2026-02-01.")
        with TestClient(app) as c:
            r = c.post(f"/api/investigations/{iid}/incident-analysis")
            self.assertEqual(r.status_code, 200, r.text[:300])
            body = r.json()
            self.assertIn("artifact_id", body)
            self.assertIn("pack", body)
            g = c.get(f"/api/investigations/{iid}/incident-analysis")
            self.assertEqual(g.status_code, 200, g.text[:300])
            self.assertEqual(g.json()["pack"]["verdict"]["key"],
                             body["pack"]["verdict"]["key"])

    def test_missing_investigation_is_404(self):
        from fastapi.testclient import TestClient

        from app.main import app
        with TestClient(app) as c:
            r = c.get("/api/investigations/999999/incident-analysis")
            self.assertEqual(r.status_code, 404)


class CompileCase(unittest.TestCase):
    """An incident run compiles the reconstruction into the synthesis and
    the report diagrams (LLM synthesis mocked; everything else is real)."""

    def _incident_run(self):
        import json

        from app.models import AgentRun, Investigation, ManagerRun, SecurityAssessment
        db = _db.SessionLocal()
        try:
            cmd = RUN50
            plan = inc.incident_plan(cmd)
            topic = plan["topics"][0]
            inv = Investigation(title=topic["title"],
                                keywords=topic["keywords"],
                                description=topic["description"],
                                sources="web", status="ready")
            db.add(inv)
            db.commit()
            db.refresh(inv)
            topic["investigation_id"] = inv.id
            plan["topics"] = [topic]
            summ = Investigation(title="summary", keywords="k",
                                 description="d", sources="web")
            db.add(summ)
            db.commit()
            db.refresh(summ)
            db.add(AgentRun(investigation_id=inv.id, status="done",
                            trigger="manual", plan="{}"))
            db.add(SecurityAssessment(
                investigation_id=inv.id, product_name="X",
                exposure="public", overall_pct=10.0, inherent_pct=10.0,
                residual_pct=10.0, markdown="# stub",
                threat_pack_version="2024.1"))
            db.commit()
            run = ManagerRun(command=cmd, plan_json=json.dumps(plan),
                             status="running",
                             summary_investigation_id=summ.id)
            db.add(run)
            db.commit()
            db.refresh(run)
            run_id, inv_id = run.id, inv.id
        finally:
            db.close()
        _art(inv_id, "Outage 2026-02-01", "The API went down on 2026-02-01.")
        _art(inv_id, "Trigger found 2026-02-02",
             "The outage was triggered by a bad deploy.")
        return run_id, inv_id

    def test_compile_embeds_reconstruction(self):
        from unittest import mock

        from app import manager as _mgr
        run_id, inv_id = self._incident_run()
        with mock.patch.object(_mgr.llm, "chat",
                               return_value="synth") as _c:
            out = _mgr.compile_run(_db.SessionLocal(), run_id)
        self.assertFalse(out["existing"])
        md = out["markdown"]
        self.assertIn("## Incident reconstruction", md)
        self.assertIn("```mermaid timeline", md)
        self.assertIn("```mermaid causal", md)
        self.assertIn("## Synthesis", md)
        db = _db.SessionLocal()
        try:
            from app.models import Artifact
            n = db.query(Artifact).filter(
                Artifact.investigation_id == inv_id,
                Artifact.tags.like("%incident-reconstruction%")).count()
        finally:
            db.close()
        self.assertEqual(n, 1)

    def test_report_collects_incident_figures(self):
        from unittest import mock

        from app import manager as _mgr
        from app import run_summary as _rs
        run_id, _ = self._incident_run()
        with mock.patch.object(_mgr.llm, "chat", return_value="synth"):
            _mgr.compile_run(_db.SessionLocal(), run_id)
        db = _db.SessionLocal()
        try:
            report = _rs.manager_run_report(db, run_id)
        finally:
            db.close()
        kinds = [d.get("source", "") for d in report["diagrams"]]
        self.assertTrue(any(s.startswith("timeline")
                            for s in kinds))
        self.assertTrue(any(s.startswith("flowchart")
                            for s in kinds))


if __name__ == "__main__":
    unittest.main()
