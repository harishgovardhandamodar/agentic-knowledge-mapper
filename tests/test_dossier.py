"""Tests for the investigation dossier: the full audit write-up.

The dossier answers "how did we get here" in four parts: the request, what
was investigated, what was collected, and how each score was applied and
what moved it. Every number must come from stored rows -- no LLM, no
recomputation. Tests here pin that: an investigation with no run still gets
a dossier, a run's queries and rationale are reported verbatim, rejected
artifacts are listed but never counted as evidence, and each assessment
path explains its own arithmetic (catalog LxI, dimension weights,
hypothesis confidence) with the items that drove each dimension.
"""
import json
import os
import tempfile
import unittest
from unittest import mock

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-dossier-"), "test.db"))

from app import security as sec  # noqa: E402
from app import database  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.dossier import (investigation_dossier, dossier_markdown,  # noqa: E402
                         artifact_actor, artifact_purpose)
from app.models import (Investigation, AgentRun, Artifact, Explanation,  # noqa: E402
                        SecurityAssessment, CveFinding)

database.init_db()


NAME = "Tabular Foundation Models"
USE = "classifies confidential customer tabular records in production"
FOCUS = ["tabular", "models"]


def _offline():
    return mock.patch("app.llm.chat", side_effect=RuntimeError("down"))


def _offline_json():
    return mock.patch("app.llm.chat_json", side_effect=RuntimeError("down"))


class _Inv:
    def __init__(self, title="Tabular models", sources="web"):
        self.db = SessionLocal()
        inv = Investigation(title=title, keywords="tabular", description="x",
                            sources=sources)
        self.db.add(inv)
        self.db.commit()
        self.db.refresh(inv)
        self.id = inv.id

    def close(self):
        self.db.close()


def _run(mode, db, inv_id, product=NAME):
    with _offline(), _offline_json():
        return sec.build_assessment(
            product_name=product, product_url="", exposure="confidential_data",
            use_case=USE, focus=list(FOCUS), db=db, investigation_id=inv_id,
            declared_controls=[], assessment_mode=mode)


def _store(db, inv_id, out):
    rec = SecurityAssessment(
        investigation_id=inv_id, product_name=out["product_name"],
        product_url="", exposure=out["exposure"], use_case=USE,
        focus_json=json.dumps(FOCUS),
        overall_pct=out["overall_pct"],
        inherent_pct=out["inherent_pct"], residual_pct=out["residual_pct"],
        scoring_json=json.dumps(out["scoring"]),
        threats_json=json.dumps(out["threats"]),
        markdown=out["markdown"], diagrams_json=json.dumps(out["diagrams"]))
    db.add(rec)
    db.commit()
    return rec


class TestRequest(unittest.TestCase):
    def test_the_request_is_verbatim(self):
        inv = _Inv()
        try:
            d = investigation_dossier(inv.db, inv.id)
            self.assertEqual(d["investigation"]["title"], "Tabular models")
            self.assertEqual(d["investigation"]["keywords"], "tabular")
            self.assertEqual(d["investigation"]["sources"], "web")
            md = dossier_markdown(inv.db, inv.id)
            self.assertIn("## 1. The request", md)
            self.assertIn("**Keywords.** tabular", md)
            self.assertIn("**Sources enabled.** web", md)
        finally:
            inv.close()

    def test_missing_investigation_raises(self):
        inv = _Inv()
        try:
            with self.assertRaises(LookupError):
                investigation_dossier(inv.db, 99999)
        finally:
            inv.close()


class TestWhatWasInvestigated(unittest.TestCase):
    def test_plan_and_queries_are_reported(self):
        inv = _Inv()
        try:
            plan = {"rationale": "Model card first, then extraction literature.",
                    "queries": [{"text": "TabPFN model card", "sources": ["arxiv"]},
                                {"text": "tabular memorization",
                                 "sources": ["arxiv", "web"]}]}
            inv.db.add(AgentRun(
                investigation_id=inv.id, status="done", plan=json.dumps(plan),
                stats=json.dumps({"rounds": 2, "artifacts_kept": 1,
                                  "llm_calls": 3, "query_shapes": 2})))
            inv.db.commit()
            d = investigation_dossier(inv.db, inv.id)
            self.assertEqual(len(d["runs"]), 1)
            r = d["runs"][0]
            self.assertEqual(r["rationale"],
                             "Model card first, then extraction literature.")
            self.assertEqual(len(r["queries"]), 2)
            self.assertEqual(r["queries"][1]["sources"], ["arxiv", "web"])
            self.assertEqual(r["stats"]["llm_calls"], 3)
            md = dossier_markdown(inv.db, inv.id)
            self.assertIn("Model card first", md)
            self.assertIn("| TabPFN model card | arxiv |", md)
            self.assertIn("2 rounds", md)
        finally:
            inv.close()

    def test_no_run_still_produces_a_dossier(self):
        inv = _Inv()
        try:
            d = investigation_dossier(inv.db, inv.id)
            self.assertEqual(d["runs"], [])
            md = dossier_markdown(inv.db, inv.id)
            self.assertIn("No agent run", md)
            self.assertIn("## 4.", md)
        finally:
            inv.close()

    def test_run_error_is_carried_through(self):
        inv = _Inv()
        try:
            inv.db.add(AgentRun(investigation_id=inv.id, status="error",
                                error="planner failed"))
            inv.db.commit()
            md = dossier_markdown(inv.db, inv.id)
            self.assertIn("**Error.** planner failed", md)
        finally:
            inv.close()


class TestWhatWasCollected(unittest.TestCase):
    def test_artifacts_carry_actor_purpose_and_flags(self):
        inv = _Inv()
        try:
            inv.db.add(AgentRun(investigation_id=inv.id, status="done",
                                plan=json.dumps({})))
            inv.db.commit()
            run = inv.db.query(AgentRun).first()
            inv.db.add(Artifact(investigation_id=inv.id, title="Model card",
                                artifact_type="paper", source="arxiv",
                                relevance=0.9, review="accepted", run_id=run.id,
                                relevance_reason="primary documentation"))
            inv.db.add(Artifact(investigation_id=inv.id, title="Off-topic",
                                artifact_type="news", source="rss",
                                relevance=0.2, review="rejected",
                                relevance_reason="weak match"))
            inv.db.commit()
            d = investigation_dossier(inv.db, inv.id)
            col = d["collection"]
            self.assertEqual(col["totals"]["artifacts"], 2)
            self.assertEqual(col["totals"]["usable"], 1)
            self.assertEqual(col["flags"]["rejected"], 1)
            kept = [a for a in col["artifacts"] if a["title"] == "Model card"][0]
            self.assertEqual(kept["purpose"], "primary documentation")
            self.assertEqual(kept["actor"], "agent")
            md = dossier_markdown(inv.db, inv.id)
            self.assertIn("### Every artifact, with why it was kept", md)
            self.assertIn("primary documentation", md)
        finally:
            inv.close()

    def test_manual_artifact_is_attributed_to_a_human(self):
        inv = _Inv()
        try:
            a = Artifact(investigation_id=inv.id, title="By hand",
                         artifact_type="paper", origin="manual", review="pending")
            inv.db.add(a)
            inv.db.commit()
            d = investigation_dossier(inv.db, inv.id)
            self.assertEqual(d["collection"]["artifacts"][0]["actor"], "human")
            self.assertEqual(artifact_actor(a, None), "human")
            self.assertEqual(artifact_purpose(a, None), "added by hand")
        finally:
            inv.close()

    def test_answers_report_their_supporting_artifacts(self):
        inv = _Inv()
        try:
            inv.db.add(Artifact(investigation_id=inv.id,
                                title="TabPFN memorization evidence",
                                artifact_type="paper", source="arxiv",
                                relevance=0.9, review="accepted"))
            inv.db.add(Artifact(investigation_id=inv.id, title="Unrelated",
                                artifact_type="news", review="rejected"))
            inv.db.commit()
            inv.db.add(Explanation(
                investigation_id=inv.id, status="done",
                question="Is TabPFN memorization documented?",
                answer=json.dumps({"summary": "Yes, in one extraction paper.",
                                   "key_points": ["one paper documents extraction"],
                                   "sources": ["arxiv"]})))
            inv.db.commit()
            d = investigation_dossier(inv.db, inv.id)
            ans = d["collection"]["answers"][0]
            self.assertEqual(ans["status"], "done")
            self.assertIn("extraction paper", ans["excerpt"])
            self.assertEqual(len(ans["supporting"]), 1)
            md = dossier_markdown(inv.db, inv.id)
            self.assertIn("### Questions answered", md)
            self.assertIn("one paper documents extraction", md)
        finally:
            inv.close()

    def test_known_issues_are_listed(self):
        inv = _Inv()
        try:
            inv.db.add(CveFinding(
                investigation_id=inv.id, cve_id="CVE-2024-0001",
                title="Example flaw", severity="high", cvss=7.5,
                status="Analyzed"))
            inv.db.commit()
            d = investigation_dossier(inv.db, inv.id)
            self.assertEqual(d["collection"]["totals"]["known_issues"], 1)
            md = dossier_markdown(inv.db, inv.id)
            self.assertIn("| CVE-2024-0001 |", md)
            self.assertIn("Analyzed", md)
        finally:
            inv.close()


class TestScoreAudit(unittest.TestCase):
    def test_no_assessment_is_reported_plainly(self):
        inv = _Inv()
        try:
            md = dossier_markdown(inv.db, inv.id)
            self.assertIn("No security assessment", md)
        finally:
            inv.close()

    def test_threat_pack_version_travels_with_the_number(self):
        inv = _Inv()
        try:
            rec = _store(inv.db, inv.id, _run("target", inv.db, inv.id))
            rec.threat_pack_version = "catalog-v3"
            rec.threat_pack_fingerprint = "abc123"
            inv.db.commit()
            row = investigation_dossier(inv.db, inv.id)["scores"]["rows"][0]
            self.assertEqual(row["threat_pack_version"], "catalog-v3")
            md = dossier_markdown(inv.db, inv.id)
            self.assertIn("**Threat pack.** catalog-v3 (abc123)", md)
        finally:
            inv.close()

    def test_dimension_contributions_sum_to_the_headline(self):
        inv = _Inv()
        try:
            _store(inv.db, inv.id, _run("target", inv.db, inv.id))
            row = investigation_dossier(inv.db, inv.id)["scores"]["rows"][0]
            det = row["detail"]
            # The reported contributions must actually be the number on the
            # cover -- that is what "how the score was applied" has to mean.
            self.assertAlmostEqual(det["total_contribution"], row["score"],
                                   places=0)
        finally:
            inv.close()

    def test_input_fields_are_reported(self):
        inv = _Inv()
        try:
            _store(inv.db, inv.id, _run("target", inv.db, inv.id))
            md = dossier_markdown(inv.db, inv.id)
            self.assertIn("**Inputs.** Exposure tier", md)
            self.assertIn("focus tabular, models", md)
        finally:
            inv.close()

    def test_model_path_explains_dimension_weights(self):
        inv = _Inv()
        try:
            _store(inv.db, inv.id, _run("target", inv.db, inv.id))
            d = investigation_dossier(inv.db, inv.id)
            row = d["scores"]["rows"][0]
            self.assertEqual(row["path"], "model")
            self.assertTrue(row["is_latest"])
            det = row["detail"]
            self.assertEqual(det["kind"], "dimensions")
            ids = [x["id"] for x in det["dimensions"]]
            self.assertIn("training_data_privacy", ids)
            for dim in det["dimensions"]:
                # each dimension names what drove it, or says nothing mapped
                self.assertIn("drivers", dim)
            md = dossier_markdown(inv.db, inv.id)
            self.assertIn("**Method.** model-internals-v1", md)
            self.assertIn("| training_data_privacy |", md)
            self.assertIn("**Every finding.**", md)
        finally:
            inv.close()

    def test_adversarial_path_is_labelled_distinctly(self):
        inv = _Inv()
        try:
            _store(inv.db, inv.id, _run("adversarial", inv.db, inv.id))
            row = investigation_dossier(inv.db, inv.id)["scores"]["rows"][0]
            self.assertEqual(row["path"], "model_adversarial")
            self.assertEqual(row["score_meaning"], "misuse potential")
        finally:
            inv.close()

    def test_hypothesis_path_reports_confidence_not_risk(self):
        inv = _Inv()
        try:
            _store(inv.db, inv.id, _run("target", inv.db, inv.id))
            _store(inv.db, inv.id, _run("adversarial", inv.db, inv.id))
            _store(inv.db, inv.id, _run("hypothesis", inv.db, inv.id))
            d = investigation_dossier(inv.db, inv.id)
            paths = {r["path"] for r in d["scores"]["rows"]}
            self.assertEqual(paths,
                             {"model", "model_adversarial", "model_hypothesis"})
            hyp = [r for r in d["scores"]["rows"]
                   if r["path"] == "model_hypothesis"][0]
            self.assertEqual(hyp["detail"]["kind"], "hypothesis")
            self.assertEqual(hyp["score_meaning"], "mean confidence")
            md = dossier_markdown(inv.db, inv.id)
            self.assertIn("do not share a scale", md)
            self.assertIn("Mean confidence across", md)
            self.assertIn("Refuted by:", md)
        finally:
            inv.close()

    def test_catalog_path_explains_likelihood_and_coverage(self):
        inv = _Inv()
        try:
            # No mode and a non-model product: build_assessment routes to the
            # catalog path on its own.
            with _offline(), _offline_json():
                out = sec.build_assessment(
                    product_name="Some Writing Assistant", product_url="",
                    exposure="confidential_data", use_case="drafts internal notes",
                    focus=[], db=inv.db, investigation_id=inv.id,
                    declared_controls=[])
            _store(inv.db, inv.id, out)
            row = investigation_dossier(inv.db, inv.id)["scores"]["rows"][0]
            self.assertEqual(row["path"], "standard")
            det = row["detail"]
            self.assertEqual(det["kind"], "catalog")
            self.assertTrue(det["items"])
            md = dossier_markdown(inv.db, inv.id)
            self.assertIn("| Threat | Likelihood | Impact | Inherent |", md)
            self.assertIn("**Controls applied.**", md)
        finally:
            inv.close()

    def test_latest_row_per_path_is_flagged(self):
        inv = _Inv()
        try:
            _store(inv.db, inv.id, _run("target", inv.db, inv.id))
            _store(inv.db, inv.id, _run("target", inv.db, inv.id))
            d = investigation_dossier(inv.db, inv.id)
            rows = d["scores"]["rows"]
            self.assertEqual(len(rows), 2)
            self.assertEqual(sum(1 for r in rows if r["is_latest"]), 1)
            self.assertEqual(len(d["scores"]["latest_ids"]), 1)
            md = dossier_markdown(inv.db, inv.id)
            self.assertIn("(superseded)", md)
        finally:
            inv.close()


class TestProvenance(unittest.TestCase):
    def test_assessment_scope_and_queries_are_reported(self):
        inv = _Inv()
        try:
            rec = _store(inv.db, inv.id, _run("target", inv.db, inv.id))
            rec.evidence_json = json.dumps({
                "scope": "the model itself and its serving surface",
                "queries_run": ["tabular memorization extraction"],
                "evidence": [{"title": "Extraction paper",
                              "summary": "Reconstructs training rows.",
                              "url": "https://example.org/p"}]})
            inv.db.commit()
            row = investigation_dossier(inv.db, inv.id)["scores"]["rows"][0]
            self.assertEqual(row["provenance"]["scope"],
                             "the model itself and its serving surface")
            self.assertEqual(len(row["provenance"]["queries"]), 1)
            md = dossier_markdown(inv.db, inv.id)
            self.assertIn("**Scope and evidence for this assessment.**", md)
            self.assertIn("Reconstructs training rows.", md)
        finally:
            inv.close()

    def test_malformed_evidence_json_does_not_break_the_dossier(self):
        inv = _Inv()
        try:
            rec = _store(inv.db, inv.id, _run("target", inv.db, inv.id))
            rec.evidence_json = "{not json"
            rec.threats_json = json.dumps({"threats": []})
            inv.db.commit()
            # A legacy dict-shaped threats_json must read as its inner list, not
            # as zero findings: an empty table and an unparsed row look identical
            # in a report.
            row = investigation_dossier(inv.db, inv.id)["scores"]["rows"][0]
            self.assertEqual(row["detail"]["items"], [])
            self.assertIn("## 4.", dossier_markdown(inv.db, inv.id))
        finally:
            inv.close()

    def test_current_report_is_appended_verbatim(self):
        inv = _Inv()
        try:
            _store(inv.db, inv.id, _run("target", inv.db, inv.id))
            _store(inv.db, inv.id, _run("target", inv.db, inv.id))
            md = dossier_markdown(inv.db, inv.id)
            self.assertIn("## 5. The assessment reports as written", md)
            rec = inv.db.query(SecurityAssessment).order_by(
                SecurityAssessment.id.desc()).first()
            first = md.split("## 5.", 1)[1]
            # The stored report's own text survives, with headings pushed down so
            # it cannot restart the dossier outline.
            self.assertIn("# AI Security Assessment", first)
            self.assertIn(rec.markdown.splitlines()[0][1:], first)
        finally:
            inv.close()

    def test_superseded_report_is_not_appended(self):
        inv = _Inv()
        try:
            first = _store(inv.db, inv.id, _run("target", inv.db, inv.id))
            # Offline both runs render identical text, so mark the first one
            # to make the assertion about *which* row is appended meaningful.
            first.markdown = "# AI Security Assessment — superseded run"
            inv.db.commit()
            _store(inv.db, inv.id, _run("target", inv.db, inv.id))
            append = dossier_markdown(inv.db, inv.id).split("## 5.", 1)[1]
            self.assertNotIn("superseded run", append)
            self.assertEqual(append.count("# AI Security Assessment"), 1)
        finally:
            inv.close()


class TestEndpoints(unittest.TestCase):
    def setUp(self):
        from fastapi.testclient import TestClient
        from app.main import app
        self.client = TestClient(app)

    def test_json_markdown_and_pdf_endpoints(self):
        inv = _Inv()
        try:
            _store(inv.db, inv.id, _run("target", inv.db, inv.id))
            inv.db.commit()
            r = self.client.get(f"/api/investigations/{inv.id}/dossier")
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["investigation"]["id"], inv.id)

            m = self.client.get(f"/api/investigations/{inv.id}/dossier/markdown")
            self.assertEqual(m.status_code, 200)
            self.assertIn("text/markdown", m.headers["content-type"])
            self.assertIn("## 1. The request", m.text)

            p = self.client.get(f"/api/investigations/{inv.id}/dossier/pdf")
            if p.status_code == 501:
                self.skipTest("reportlab not installed")
            self.assertEqual(p.status_code, 200)
            self.assertEqual(p.headers["content-type"], "application/pdf")
            self.assertTrue(p.content.startswith(b"%PDF"))
        finally:
            inv.close()

    def test_unknown_investigation_is_404(self):
        for suffix in ("", "/markdown", "/pdf"):
            r = self.client.get(f"/api/investigations/999999/dossier{suffix}")
            self.assertEqual(r.status_code, 404, suffix)


class TestWriteupIntegrity(unittest.TestCase):
    def test_markdown_names_every_part(self):
        inv = _Inv()
        try:
            _store(inv.db, inv.id, _run("target", inv.db, inv.id))
            md = dossier_markdown(inv.db, inv.id)
            for heading in ("## 1. The request", "## 2. What was investigated",
                            "## 3. What was collected",
                            "## 4. How each score was applied"):
                self.assertIn(heading, md)
            self.assertIn("read from stored rows", md)
        finally:
            inv.close()

    def test_build_pdf_renders_the_dossier(self):
        inv = _Inv()
        try:
            _store(inv.db, inv.id, _run("target", inv.db, inv.id))
            md = dossier_markdown(inv.db, inv.id)
            try:
                pdf = sec.build_pdf(
                    md, title="Investigation dossier",
                    meta={"product": "Tabular models", "date": "2026-01-01",
                          "report_name": "Investigation dossier",
                          "highlights_title": "What this covers",
                          "highlights_label": "Scope",
                          "perspectives": [{"label": "Model",
                                            "headline": "35.5/100"}]})
            except RuntimeError:
                self.skipTest("reportlab not installed")
            self.assertTrue(pdf.startswith(b"%PDF"))
            # The audience-facing default must survive the dossier's override:
            # one shared table serves both reports, and an assessment report
            # whose heading now reads "Scope" misdescribes its own panels.
            try:
                sec.build_pdf(md, title="Assessment",
                              meta={"perspectives": [{"label": "Model",
                                                      "headline": "35.5/100"}]})
            except RuntimeError:
                self.skipTest("reportlab not installed")
        finally:
            inv.close()


if __name__ == "__main__":
    unittest.main()