"""The analysis bundle on the assessment API surface (WS3-WS7 exposure).

Run with:  python3 -m pytest tests/test_assessment_analysis_api.py -q

Pins the contract that a stored assessment exposes a credible band, the
external-reach budget its research spent, and a reproducibility manifest --
and that a row which cannot support one of those (a model-path assessment with
no catalog threats, a legacy row with no evidence) degrades to ``None`` rather
than failing the read.
"""
import json
import os
import tempfile
import unittest

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(
        tempfile.mkdtemp(prefix="akm-analysis-api-"), "test.db"))

from app import database as _db  # noqa: E402
from app import evalkit as E  # noqa: E402
from app import repro as R  # noqa: E402
from app import security as sec  # noqa: E402
from app import threatpack as tp  # noqa: E402
from app.database import Base, SessionLocal  # noqa: E402
from app.models import Investigation, SecurityAssessment  # noqa: E402

_db.init_db()


class AnalysisApiCase(unittest.TestCase):
    def setUp(self):
        Base.metadata.create_all(_db.engine)
        self.db = SessionLocal()
        from fastapi.testclient import TestClient

        from app.main import app
        self.client = TestClient(app)
        self.client.__enter__()
        self.inv = Investigation(title="Analysis API", keywords="k",
                                 description="d", sources="web")
        self.db.add(self.inv)
        self.db.commit()
        self.db.refresh(self.inv)

    def tearDown(self):
        try:
            self.client.__exit__(None, None, None)
        finally:
            try:
                self.db.query(SecurityAssessment).filter(
                    SecurityAssessment.investigation_id == self.inv.id).delete()
                self.db.query(Investigation).filter(
                    Investigation.id == self.inv.id).delete()
                self.db.commit()
            except Exception:
                self.db.rollback()
            self.db.close()

    def _catalog_assessment(self):
        inherent = E._inherent("confidential_data")
        result = sec.score_assessment("confidential_data", inherent,
                                      active_controls=["C02", "C04"])
        rec = SecurityAssessment(
            investigation_id=self.inv.id, run_id=1, product_name="copilot",
            exposure="confidential_data",
            inherent_pct=result["inherent_pct"],
            residual_pct=result["residual_pct"], markdown="# stub",
            scoring_json=json.dumps(result),
            threats_json=json.dumps(result["threats"]),
            evidence_json=json.dumps({
                "evidence": [{"url": "https://a.com/p", "snippet": "s1"},
                             {"url": "https://b.com/q", "snippet": "s2"}],
                "queries_run": ["q1", "q2", "q3"]}),
            controls_json=json.dumps({"active_controls": ["C02", "C04"]}),
            threat_pack_version=tp.PACK_VERSION,
            threat_pack_fingerprint=tp.pack_fingerprint())
        self.db.add(rec)
        self.db.commit()
        self.db.refresh(rec)
        return rec

    def _legacy_assessment(self):
        rec = SecurityAssessment(
            investigation_id=self.inv.id, product_name="legacy",
            exposure="confidential_data", overall_pct=50, markdown="m")
        self.db.add(rec)
        self.db.commit()
        self.db.refresh(rec)
        return rec

    def test_full_read_carries_the_analysis_bundle(self):
        rec = self._catalog_assessment()
        body = self.client.get(
            f"/api/security/assessments/{rec.id}").json()
        self.assertIsNotNone(body["uncertainty"])
        self.assertIsNotNone(body["privacy"])
        self.assertIsNotNone(body["repro"])

    def test_uncertainty_band_surrounds_the_headline(self):
        rec = self._catalog_assessment()
        band = self.client.get(
            f"/api/security/assessments/{rec.id}").json()["uncertainty"]
        self.assertTrue(band["headline_inside"])
        self.assertLessEqual(band["lower_pct"], band["headline_pct"])
        self.assertGreaterEqual(band["upper_pct"], band["headline_pct"])

    def test_privacy_budget_counts_external_reach(self):
        rec = self._catalog_assessment()
        priv = self.client.get(
            f"/api/security/assessments/{rec.id}").json()["privacy"]
        self.assertEqual(priv["queries"], 3)
        self.assertEqual(priv["external_pages"], 2)
        self.assertIn(priv["advice"], ("ok", "degrade", "refuse"))

    def test_repro_manifest_verifies(self):
        rec = self._catalog_assessment()
        manifest = self.client.get(
            f"/api/security/assessments/{rec.id}").json()["repro"]
        self.assertTrue(R.verify(manifest))
        self.assertEqual(manifest["label"], f"assessment-{rec.id}")

    def test_dedicated_analysis_endpoint_matches(self):
        rec = self._catalog_assessment()
        r = self.client.get(
            f"/api/security/assessments/{rec.id}/analysis")
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["assessment_id"], rec.id)
        self.assertEqual(body["residual_pct"], rec.residual_pct)
        self.assertTrue(body["uncertainty"]["headline_inside"])
        self.assertIsNotNone(body["privacy"])

    def test_analysis_endpoint_404s_for_unknown(self):
        r = self.client.get("/api/security/assessments/999999/analysis")
        self.assertEqual(r.status_code, 404)

    def test_legacy_row_degrades_to_none_not_error(self):
        rec = self._legacy_assessment()
        r = self.client.get(f"/api/security/assessments/{rec.id}")
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        # No catalog threats and no evidence -> band and budget honestly absent.
        self.assertIsNone(body["uncertainty"])
        self.assertIsNone(body["privacy"])
        # A manifest is still available: it just pins less.
        self.assertIsNotNone(body["repro"])

    def test_model_path_row_has_no_catalog_band(self):
        rec = self._legacy_assessment()
        rec.scoring_json = json.dumps({"assessment_path": "model",
                                       "residual_pct": 40.0,
                                       "dimensions": []})
        self.db.commit()
        body = self.client.get(
            f"/api/security/assessments/{rec.id}").json()
        self.assertIsNone(body["uncertainty"])


if __name__ == "__main__":
    unittest.main()
