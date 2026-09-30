"""Tests for the separate model assessment A2A path.

When the subject is a MODEL, assessment runs model-profiler → internals →
collector → privacy → dimension scoring → reporter: no catalog threats, no
control catalogue math, no AI-standards mapping. Same result contract as the
standard path (pcts, threats-shaped findings, markdown, perspectives), so
storage, the report UI and the manager compile path work unchanged.
"""
import json
import os
import tempfile
import unittest
from unittest import mock

# Pin the database before app.database is imported: a module that omits
# this can inherit data/akm.db and write test rows into the live store.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-model-path-"), "test.db"))

from app import agents  # noqa: E402
from app import security as sec  # noqa: E402
from app import database  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.models import Investigation, SecurityAssessment  # noqa: E402

database.init_db()


TABULAR = ("Tabular Foundation Models",
           "capability advancements, batch scored over customer rows",
           ["tabular", "models", "capabilities"])
CHATBOT = ("Support chatbot",
           "answer billing questions in chat",
           ["chatbot"])


def _model_out():
    with mock.patch("app.llm.chat", side_effect=RuntimeError("down")):
        return sec.build_assessment(
            product_name=TABULAR[0], product_url="", exposure="public",
            use_case=TABULAR[1], focus=list(TABULAR[2]), db=None,
            investigation_id=None, declared_controls=[])


class TestModelRouting(unittest.TestCase):
    def test_model_query_takes_model_path(self):
        out = _model_out()
        self.assertEqual(out["scoring"].get("assessment_path"), "model")
        self.assertEqual(out["scoring"].get("method"), "model-internals-v1")
        self.assertTrue(out["threats"])
        self.assertTrue(all(t["id"].startswith(("M", "P")) for t in out["threats"]))
        self.assertEqual(out["perspectives"][0]["key"], "model")

    def test_chatbot_stays_on_standard_path(self):
        with mock.patch("app.llm.chat", side_effect=RuntimeError("down")):
            out = sec.build_assessment(
                product_name=CHATBOT[0], product_url="", exposure="public",
                use_case=CHATBOT[1], focus=list(CHATBOT[2]), db=None,
                investigation_id=None, declared_controls=[])
        self.assertNotEqual(out["scoring"].get("assessment_path"), "model")
        self.assertTrue(any(t["id"].startswith("T") for t in out["threats"]))

    def test_report_carries_profile_and_weightage(self):
        out = _model_out()
        md = out["markdown"]
        for section in ("## Subject profile", "## Weightage",
                        "## Privacy findings", "## Internals findings",
                        "(model)"):
            self.assertIn(section, md)
        self.assertIn("tabular", md.lower())


class TestModelScoring(unittest.TestCase):
    def test_weights_sum_to_one(self):
        total = sum(w for _, w, _ in sec.MODEL_DIMENSIONS)
        self.assertAlmostEqual(total, 1.0)
        self.assertEqual(
            [d for d, _, _ in sec.MODEL_DIMENSIONS],
            ["training_data_privacy", "model_integrity",
             "deployment_surface", "governance"])

    def test_full_marks_aggregate_to_100(self):
        out = sec.score_model_assessment(
            {d: 100.0 for d, _, _ in sec.MODEL_DIMENSIONS})
        self.assertEqual(out["overall_pct"], 100.0)
        self.assertEqual(out["residual_pct"], 100.0)
        self.assertEqual(out["assessment_path"], "model")

    def test_missing_dimensions_fall_back_not_to_zero(self):
        out = sec.score_model_assessment({})
        for row in out["dimensions"]:
            self.assertEqual(row["score"], 20.0)
        self.assertEqual(out["overall_pct"], 20.0)

    def test_weightage_favours_internals(self):
        out = sec.score_model_assessment(
            {"training_data_privacy": 80.0, "model_integrity": 60.0,
             "deployment_surface": 40.0, "governance": 20.0})
        # 80*.35 + 60*.25 + 40*.20 + 20*.20 = 28 + 15 + 8 + 4 = 55
        self.assertEqual(out["overall_pct"], 55.0)
        by_id = {r["id"]: r for r in out["dimensions"]}
        self.assertEqual(by_id["training_data_privacy"]["contribution"], 28.0)

    def test_findings_shape_fits_the_threats_ui(self):
        out = _model_out()
        for t in out["threats"]:
            for key in ("id", "title", "likelihood", "impact",
                        "inherent_score", "residual_score", "residual_severity",
                        "coverage", "controls", "applicable", "mitigations",
                        "dimension"):
                self.assertIn(key, t, key)


class TestModelAgents(unittest.TestCase):
    def _env(self, payload):
        return agents.new_envelope("model-orchestrator", "x", "y", payload)

    def test_profiler_is_deterministic(self):
        out = agents.model_profiler_handle(
            self._env({"product_name": TABULAR[0], "use_case": TABULAR[1],
                       "focus": TABULAR[2]}))
        prof = out["payload"]["profile"]
        self.assertTrue(prof["is_model_query"])
        self.assertIn("tabular records", prof["data"])

    def test_internals_fallback_is_profile_honest(self):
        with mock.patch("app.llm.chat", side_effect=RuntimeError("down")):
            out = agents.model_internals_handle(
                self._env({"product_name": TABULAR[0], "use_case": TABULAR[1],
                           "focus": TABULAR[2]}))
        findings = out["payload"]["findings"]
        self.assertTrue(findings)
        dims = {f["dimension"] for f in findings}
        self.assertIn("training_data_privacy", dims)
        self.assertIn("deterministic", out["payload"]["source"])

    def test_privacy_fallback_names_data_lifecycle(self):
        with mock.patch("app.llm.chat", side_effect=RuntimeError("down")):
            out = agents.model_privacy_handle(
                self._env({"product_name": TABULAR[0], "use_case": TABULAR[1],
                           "focus": TABULAR[2]}))
        self.assertTrue(out["payload"]["findings"])
        self.assertTrue(all(f["id"].startswith("P")
                            for f in out["payload"]["findings"]))

    def test_reporter_falls_back_without_invention(self):
        with mock.patch("app.llm.chat", side_effect=RuntimeError("down")):
            out = agents.model_reporter_handle(
                self._env({"product_name": TABULAR[0],
                           "exposure_label": "Public",
                           "profile": {"summary": "tabular foundation model"},
                           "dimensions": [],
                           "findings": [], "evidence": [],
                           "scoring": {"overall_pct": 20.0}}))
        self.assertIn("Tabular Foundation Models",
                      out["payload"]["model_sections"])
        self.assertIn("Deterministic brief", out["payload"]["exec_paragraph"])

    def test_registry_lists_model_agents(self):
        names = {c["name"] for c in agents.get_agent_cards()}
        for expected in ("model-profiler", "model-internals", "model-privacy",
                         "model-reporter"):
            self.assertIn(expected, names)


def _row(product, scoring_extra=None, focus=()):
    db = SessionLocal()
    try:
        inv = Investigation(title="model-path-target")
        db.add(inv)
        db.commit()
        db.refresh(inv)
        rec = SecurityAssessment(
            investigation_id=inv.id, product_name=product,
            exposure="public", overall_pct=40.0,
            scoring_json=json.dumps(scoring_extra or {}),
            threats_json=json.dumps([]),
            focus_json=json.dumps(list(focus)),
            markdown="# test")
        db.add(rec)
        db.commit()
        db.refresh(rec)
        return rec.id
    finally:
        db.close()


class TestModelStandardsSkip(unittest.TestCase):
    def test_marked_model_row_skips_matrix(self):
        from app import standards_matrix as sm
        aid = _row("Tabular Foundation Models",
                   {"assessment_path": "model", "method": "model-internals-v1"},
                   ["tabular"])
        db = SessionLocal()
        try:
            with mock.patch.object(sm, "fetch_dashboard",
                                   return_value={"frameworks": [],
                                                 "generated": "2026-01-01"}):
                payload = sm.build_matrix(db, aid)
        finally:
            db.close()
        self.assertTrue(payload.get("skipped"))
        self.assertEqual(payload["frameworks"], [])

    def test_unmarked_model_row_skips_by_derivation(self):
        from app import standards_matrix as sm
        aid = _row("Tabular Foundation Models", {},
                   ["tabular", "models"])
        db = SessionLocal()
        try:
            with mock.patch.object(sm, "fetch_dashboard",
                                   return_value={"frameworks": [],
                                                 "generated": "2026-01-01"}):
                payload = sm.build_matrix(db, aid)
        finally:
            db.close()
        self.assertTrue(payload.get("skipped"))

    def test_product_row_still_maps(self):
        from app import standards_matrix as sm
        aid = _row("Support chatbot", {}, ["chatbot"])
        db = SessionLocal()
        try:
            with mock.patch.object(sm, "fetch_dashboard",
                                   return_value={"frameworks": [],
                                                 "generated": "2026-01-01"}):
                payload = sm.build_matrix(db, aid)
        finally:
            db.close()
        self.assertFalse(payload.get("skipped", False))


class TestModelRescoreGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient  # noqa: E402
        from app import main as main_mod  # noqa: E402
        cls.client = TestClient(main_mod.app)

    def test_rescore_refuses_model_path(self):
        aid = _row("Tabular Foundation Models",
                   {"assessment_path": "model"}, ["tabular"])
        r = self.client.post(f"/api/security/assessments/{aid}/rescore", json={})
        self.assertEqual(r.status_code, 422, r.text)
        self.assertIn("Model-path", r.json()["detail"])

    def test_assessment_json_marks_path(self):
        aid = _row("Tabular Foundation Models",
                   {"assessment_path": "model"}, ["tabular"])
        r = self.client.get(f"/api/security/assessments/{aid}")
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["assessment_path"], "model")
        self.assertTrue(body["subject_profile"]["is_model_query"])


if __name__ == "__main__":
    unittest.main()
