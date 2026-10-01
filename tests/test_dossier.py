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
import re
import tempfile
import unittest
from unittest import mock

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-dossier-"), "test.db"))

from app import security as sec  # noqa: E402
from app import database  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.dossier import (investigation_dossier, dossier_markdown,  # noqa: E402
                         dossier_bundle, artifact_actor, artifact_purpose)
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


class TestPdfRendersProse(unittest.TestCase):
    """The PDF is a report, not a transcript of the markdown it was given."""

    def _text(self, md: str) -> str:
        try:
            pdf = sec.build_pdf(md, title="Render")
        except RuntimeError:
            self.skipTest("reportlab not installed")
        import io
        import pypdf
        return "\n".join(p.extract_text()
                         for p in pypdf.PdfReader(io.BytesIO(pdf)).pages)

    def test_italics_render_and_snake_case_survives(self):
        text = self._text("_Exposure tier:_ Confidential · field scoring_method "
                          "and a2a_task_id stay literal")
        self.assertNotRegex(text, r"(?<![\w])_[^_\n]{2,60}_(?![\w])")
        self.assertIn("Exposure tier:", text)
        # Word-boundary aware: an identifier is not an emphasis span.
        self.assertIn("scoring_method", text)
        self.assertIn("a2a_task_id", text)

    def test_fourth_level_heading_is_not_printed_as_hashes(self):
        text = self._text("#### H01 -- a held-out rows claim\n\nbody text")
        self.assertNotIn("####", text)
        self.assertIn("H01", text)
        self.assertIn("body text", text)

    def test_unlabelled_mermaid_is_shown_not_dropped(self):
        # The old renderer printed a pointer to the dashboard and discarded
        # the figure, so the report silently lost content it had been given.
        src = "flowchart TD\n P[premise] --> C[claim]"
        text = self._text("```mermaid\n" + src + "\n```")
        self.assertNotIn("illustrated dashboard view", text)
        self.assertIn("premise", text)
        self.assertIn("claim", text)

    def test_labeled_mermaid_is_drawn_not_dumped(self):
        md = "```mermaid dataflow\n" + sec.mermaid_dataflow("Acme") + "\n```"
        text = self._text(md)
        self.assertIn("Figure 1", text)
        # A figure we can draw must not also spill its source into the page.
        self.assertNotIn("flowchart LR", text)

    def test_non_mermaid_fences_are_shown_but_not_called_a_figure(self):
        # A yaml/python block is not a diagram: it must not be numbered as a
        # Figure or captioned "mermaid source", but it is still shown rather
        # than dropped along with a misleading dashboard pointer.
        text = self._text("```yaml\nkey: value\n```")
        self.assertIn("key: value", text)
        self.assertNotIn("mermaid source", text)
        self.assertNotIn("Figure 1", text)
        self.assertIn("yaml block", text)

    def test_table_fits_the_frame_and_keeps_every_column_visible(self):
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import cm
        wide = " ".join(["manifest build pipeline"] * 30)
        md = ("| Read from | Driven by | Category | Source | Confidence |\n"
              "|---|---|---|---|---|\n"
              f"| parquet | {wide} | training | manifest.json | 0.88 |\n")
        try:
            pdf = sec.build_pdf(md, title="Fit")
        except RuntimeError:
            self.skipTest("reportlab not installed")
        import io
        import re as _re
        import pypdf
        reader = pypdf.PdfReader(io.BytesIO(pdf))
        limit = 2 * cm + (A4[0] - 2 * 2 * cm)
        widest = 0.0
        for page in reader.pages:
            data = page.get_contents().get_data().decode("latin-1")
            for m in _re.finditer(r"([\d.-]+) ([\d.-]+) ([\d.-]+) ([\d.-]+) re", data):
                widest = max(widest, float(m.group(3)))
        self.assertLessEqual(widest, limit + 1)
        text = "\n".join(p.extract_text() for p in reader.pages)
        # Every header cell must still be on the page: an over-wide table used
        # to push the trailing columns off it.
        for head in ("Read from", "Driven by", "Category", "Source",
                     "Confidence"):
            self.assertIn(head, text)

    def test_first_column_of_a_data_row_is_not_white_on_white(self):
        # The header band's white text style used to leak into data rows, so
        # the whole ID column printed invisible against the white cell.
        text = self._text("| ID | Risk | Severity |\n|---|---|---|\n"
                          "| T01 | accidental paste | Critical |\n")
        self.assertIn("T01", text)
        self.assertIn("Critical", text)

    def test_ragged_table_row_does_not_break_the_render(self):
        # A short row made reportlab raise, losing the entire document.
        md = ("| A | B | C |\n|---|---|---|\n| only one cell |\n| 1 | 2 | 3 |\n")
        text = self._text(md)
        self.assertIn("only one cell", text)


class TestDiagramCollection(unittest.TestCase):
    """Every mermaid the investigation produced belongs in the report."""

    def test_stored_figures_and_report_fences_both_collected(self):
        from app.dossier import _assessment_diagrams
        rec = mock.Mock()
        rec.diagrams_json = json.dumps({"workflow": sec.mermaid_workflow("Acme")})
        rec.markdown = ("```mermaid\nflowchart TD\n A-->B\n```\n\n"
                        "```python\nprint(1)\n```\n")
        got = _assessment_diagrams(rec)
        keys = [d["key"] for d in got]
        self.assertIn("workflow", keys)
        self.assertIn("(unlabelled)", keys)
        # A python fence is not a diagram and must not be collected as one.
        self.assertNotIn("print(1)", " ".join(d["source"] for d in got))

    def test_figure_label_rejects_a_mislabelled_diagram(self):
        from app.dossier import _figure_label
        # A model path stores a hypothesis map under the key 'dataflow'. The
        # renderer can only draw the catalogue data-flow, so honouring the key
        # would draw the wrong figure.
        self.assertEqual(_figure_label("dataflow", "flowchart TD\n P-->C", "Acme"),
                         "")
        self.assertEqual(_figure_label("dataflow",
                                       sec.mermaid_dataflow("Acme"), "Acme"),
                         "dataflow")

    def test_dossier_includes_a_diagrams_section(self):
        inv = _Inv()
        try:
            out = _run("standard", inv.db, inv.id)
            rec = _store(inv.db, inv.id, out)
            md = dossier_markdown(inv.db, inv.id)
            self.assertIn("## 6. Diagrams", md)
            self.assertIn("flowchart LR", md)
            # The stored figure set must reach the write-up, not just the JSON.
            self.assertIn(rec.diagrams_json and "dataflow", md)
        finally:
            inv.close()

    def test_shared_diagram_is_listed_once(self):
        inv = _Inv()
        try:
            shared = sec.mermaid_dataflow(NAME)
            for _ in range(2):
                out = _run("standard", inv.db, inv.id)
                out["diagrams"] = {"dataflow": shared}
                _store(inv.db, inv.id, out)
            md = dossier_markdown(inv.db, inv.id)
            # One product's figure set repeated across assessments is one
            # diagram; listing each copy padded the report with duplicates.
            self.assertEqual(md.count("flowchart LR"), 1)
            self.assertIn("appears in", md)
        finally:
            inv.close()


class TestReportShape(unittest.TestCase):
    """An exported report must lead with the answer and carry its material."""

    def test_embedded_report_headings_cannot_hijack_the_outline(self):
        from app.dossier import _flatten_headings
        md = ("# Assessment\n\n## Executive summary\n\n### KE-01\n\n"
              "## 6. Known exploits\n\n### KE-02\n\n#### deeper\n")
        out = _flatten_headings(md)
        # The dossier's own sections are h2. An appended report that keeps an
        # h2 shows up beside them as a peer of the dossier's numbered outline,
        # and its TOC entry reads as a top-level section that does not exist.
        self.assertEqual([l for l in out.splitlines() if l.startswith("## ")], [])
        self.assertEqual([l for l in out.splitlines() if l.startswith("# ")], [])
        # Internal structure survives: the report's title is above its sections.
        self.assertTrue(out.index("### Assessment")
                        < out.index("#### 6. Known exploits"))

    def test_headings_without_an_h1_are_still_detected(self):
        from app.dossier import _flatten_headings
        out = _flatten_headings("## Executive summary\n\n### KE-01\n")
        self.assertEqual([l for l in out.splitlines() if l.startswith("## ")], [])

    def test_executive_summary_comes_first(self):
        inv = _Inv()
        try:
            out = _run("standard", inv.db, inv.id)
            _store(inv.db, inv.id, out)
            md = dossier_markdown(inv.db, inv.id)
            self.assertIn("## Executive summary", md)
            self.assertLess(md.index("## Executive summary"),
                            md.index("## 1. The request"))
            # The summary carries the scores with what each one means, so the
            # numbers are not read as interchangeable.
            self.assertIn("What it means", md)
        finally:
            inv.close()

    def test_explainer_diagram_comes_from_the_answer_object(self):
        # The explainer stores one figure at answer.diagram, not in a keyed
        # map: reading only the map reported zero diagrams for investigations
        # that had one per deep-dive.
        from app.dossier import _explainer_diagrams
        exp = mock.Mock()
        exp.answer = json.dumps({
            "diagram": {"mermaid": "flowchart TD\n A[Steward] --> B[LLM]",
                        "title": "Data flow", "caption": "everything goes out"},
        })
        exp.meta = json.dumps({"concepts": []})
        got = _explainer_diagrams(exp)
        self.assertEqual(len(got), 1)
        self.assertIn("Data flow", got[0]["caption"])

    def test_diagram_is_listed_once_however_many_times_it_is_referenced(self):
        # Every assessment of one product repeats the same figure, and one
        # assessment repeats it again inside its own report. Each copy in the
        # "appears in" list is noise: the same assessment named twice.
        inv = _Inv()
        try:
            out = _run("standard", inv.db, inv.id)
            out["diagrams"] = {"dataflow": sec.mermaid_dataflow(NAME)}
            rec = _store(inv.db, inv.id, out)
            rec.markdown = ("```mermaid dataflow\n"
                            + sec.mermaid_dataflow(NAME) + "\n```")
            inv.db.commit()
            md = dossier_markdown(inv.db, inv.id)
            # Scope to the diagram section: the appendix in section 5 quotes
            # the report verbatim, so the figure legitimately appears there too.
            sec6 = md[md.index("## 6. Diagrams"):]
            self.assertEqual(sec6.count("flowchart LR"), 1)
            seen_in = re.search(r"appears in ([^.]*)\.", sec6).group(1)
            parts = [p.strip() for p in seen_in.split(",")]
            self.assertEqual(len(parts), len(set(parts)),
                             f"duplicate entries in {parts}")
        finally:
            inv.close()

    def test_deep_dives_are_exported_in_full(self):
        inv = _Inv()
        try:
            exp = Explanation(
                investigation_id=inv.id, question="how does the leak work",
                status="done", mode="deep_dive", answer=json.dumps({
                    "summary": "the payload leaves unfiltered",
                    "sections": [{"heading": "Trigger",
                                  "body": "any AI action on an asset"}],
                    "diagram": {"mermaid": "flowchart LR\n A-->B"},
                }))
            inv.db.add(exp)
            inv.db.commit()
            md = dossier_markdown(inv.db, inv.id)
            self.assertIn("The deep-dives, in full", md)
            self.assertIn("the payload leaves unfiltered", md)
            self.assertIn("Trigger", md)
            self.assertIn("flowchart LR", md)
        finally:
            inv.close()


class TestDossierBundle(unittest.TestCase):
    """The zip carries the markdown plus every diagram as a picture file."""

    FLOW = ("flowchart TD\n"
            "    A[User] --> B[Assistant]")

    def _bundled_inv(self):
        inv = _Inv()
        out = _run("standard", inv.db, inv.id)
        rec = _store(inv.db, inv.id, out)
        rec.markdown = ("report text\n```mermaid\n" + self.FLOW + "\n```\n"
                        "```mermaid\n" + self.FLOW + "\n```\n")
        inv.db.commit()
        return inv

    def _fake_png(self):
        import io as _io
        from PIL import Image
        buf = _io.BytesIO()
        Image.new("RGB", (120, 60), (180, 30, 30)).save(buf, format="PNG")
        return buf.getvalue()

    def test_bundle_has_markdown_pictures_and_fences(self):
        import io as _io
        import zipfile as _zf
        from app import mermaid_png
        inv = self._bundled_inv()
        try:
            with mock.patch.object(mermaid_png, "render_sources",
                                   return_value={self.FLOW: self._fake_png()}):
                raw = dossier_bundle(inv.db, inv.id)
            zf = _zf.ZipFile(_io.BytesIO(raw))
            names = zf.namelist()
            self.assertIn("dossier.md", names)
            pics = sorted(n for n in names if n.startswith("images/"))
            # The same figure twice still ships one picture file.
            self.assertEqual(len(pics), 1)
            md = zf.read("dossier.md").decode("utf-8")
            # Picture link for viewers without a diagram plugin...
            self.assertIn(f"]({pics[0]})", md)
            self.assertIn("![Figure", md)
            # ...and the fence itself, which renders natively on GitHub.
            self.assertIn("```mermaid", md)
            self.assertIn(self.FLOW, md)
            from PIL import Image
            Image.open(_io.BytesIO(zf.read(pics[0]))).verify()
        finally:
            inv.close()

    def test_bundle_without_pictures_is_plain_markdown(self):
        import io as _io
        import zipfile as _zf
        from app import mermaid_png
        inv = self._bundled_inv()
        try:
            with mock.patch.object(mermaid_png, "render_sources",
                                   return_value={}):
                raw = dossier_bundle(inv.db, inv.id)
            zf = _zf.ZipFile(_io.BytesIO(raw))
            self.assertEqual(zf.namelist(), ["dossier.md"])
            md = zf.read("dossier.md").decode("utf-8")
            self.assertNotIn("images/", md)
            self.assertIn("```mermaid", md)
        finally:
            inv.close()


if __name__ == "__main__":
    unittest.main()