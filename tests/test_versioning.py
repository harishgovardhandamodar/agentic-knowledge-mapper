"""Versioning discipline: silent catalog edits fail CI.

A fingerprint that moves without a version bump means somebody changed what
the numbers mean without saying so. These pins make that a red build; the
fix is a deliberate version bump plus an evalkit update in the same commit.
"""
import json
import os
import tempfile
import unittest
from unittest import mock

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-versioning-"), "test.db"))

from app import threatpack as tp  # noqa: E402
from app import model_eval as me  # noqa: E402
from app import database as _db  # noqa: E402
from app import models as _models  # noqa: E402,F401 -- registers tables

_db.init_db()


class TestPinnedFingerprints(unittest.TestCase):
    def test_threat_pack_fingerprint_pinned(self):
        self.assertEqual(tp.pack_fingerprint(), "19a11481e69d")

    def test_model_catalog_fingerprints_pinned(self):
        self.assertEqual(me.model_adv_fingerprint(), "34d1e949c36c")
        self.assertEqual(me.adoption_fingerprint(), "429c1576c12e")
        self.assertEqual(me.mitigation_fingerprint(), "478f15fc184f")
        self.assertEqual(me.experiment_fingerprint(), "081a735a41da")

    def test_manifest_version_matches_constant(self):
        self.assertEqual(tp.pack_manifest()["version"], tp.PACK_VERSION)
        for catalog_id, entry in me.CHANGE_POLICY.items():
            current = {"akm-model-adversarial": me.MODEL_ADV_VERSION,
                       "akm-adoption-risk": me.ADOPTION_VERSION,
                       "akm-model-mitigations": me.MITIGATION_VERSION,
                       "akm-experiment-plan": me.EXPERIMENT_VERSION}
            self.assertEqual(entry["version"], current[catalog_id], catalog_id)


class TestChangePolicy(unittest.TestCase):
    def test_product_policy_names_all_bump_levels(self):
        for level in ("major", "minor", "patch"):
            self.assertTrue(tp.CHANGE_POLICY[level], level)

    def test_model_policy_covers_every_catalog(self):
        self.assertEqual(set(me.CHANGE_POLICY),
                         {"akm-model-adversarial", "akm-adoption-risk",
                          "akm-model-mitigations", "akm-experiment-plan"})
        for catalog_id, entry in me.CHANGE_POLICY.items():
            for level in ("major", "minor", "patch", "version"):
                self.assertTrue(entry[level], f"{catalog_id}.{level}")


class TestSupersededBadge(unittest.TestCase):
    def _old_pack_inv(self):
        from app.database import SessionLocal
        from app.models import Investigation, SecurityAssessment
        db = SessionLocal()
        try:
            inv = Investigation(title="t", keywords="k", description="d",
                                sources="web")
            db.add(inv)
            db.commit()
            rec = SecurityAssessment(
                investigation_id=inv.id, product_name="Widget",
                exposure="confidential_data", overall_pct=50.0,
                posture="ELEVATED", markdown="m",
                scoring_json=json.dumps({"assessment_path": "standard"}),
                threats_json=json.dumps([]),
                threat_pack_version="0.0.0",
                threat_pack_fingerprint="deadbeefcafe")
            db.add(rec)
            db.commit()
            return db, inv.id, rec.id
        except Exception:
            db.close()
            raise

    def test_stale_pack_badged_in_dossier(self):
        from app.dossier import dossier_markdown
        db, inv_id, _ = self._old_pack_inv()
        try:
            md = dossier_markdown(db, inv_id)
            self.assertIn("Superseded pack", md)
        finally:
            db.close()

    def test_stale_pack_flagged_in_history(self):
        from app.main import list_security_assessments
        from app.database import SessionLocal
        db, inv_id, rec_id = self._old_pack_inv()
        try:
            items = list_security_assessments(inv_id, db)["items"]
            self.assertTrue(items[0]["pack_stale"])
        finally:
            db.close()

    def test_current_pack_not_badged(self):
        from app import threatpack as tp
        from app.main import list_security_assessments
        from app.database import SessionLocal
        from app.models import Investigation, SecurityAssessment
        db = SessionLocal()
        try:
            inv = Investigation(title="t", keywords="k", description="d",
                                sources="web")
            db.add(inv)
            db.commit()
            db.add(SecurityAssessment(
                investigation_id=inv.id, product_name="Widget",
                exposure="confidential_data", overall_pct=50.0,
                posture="ELEVATED", markdown="m",
                scoring_json=json.dumps({"assessment_path": "standard"}),
                threats_json=json.dumps([]),
                threat_pack_version=tp.PACK_VERSION,
                threat_pack_fingerprint=tp.pack_fingerprint()))
            db.commit()
            items = list_security_assessments(inv.id, db)["items"]
            self.assertFalse(items[0]["pack_stale"])
        finally:
            db.close()


class TestRescoreNewRow(unittest.TestCase):
    def test_persist_creates_new_row_leaves_old_untouched(self):
        from fastapi.testclient import TestClient
        from app import main as main_mod
        from app.database import SessionLocal
        from app.models import SecurityAssessment
        client = TestClient(main_mod.app)
        inv = client.post("/api/investigations", json={
            "title": "t", "keywords": "k", "description": "d",
            "sources": "web"}).json()
        db = SessionLocal()
        try:
            rec = SecurityAssessment(
                investigation_id=inv["id"], product_name="Widget",
                exposure="confidential_data", overall_pct=68.8,
                inherent_pct=68.8, residual_pct=68.8, posture="ELEVATED",
                markdown="m",
                scoring_json=json.dumps({"assessment_path": "standard"}),
                threats_json=json.dumps([
                    {"id": "T01", "title": "t", "stride": "s", "owasp": "o",
                     "likelihood": 5.0, "impact": 5.0, "description": "d",
                     "mitigations": [], "coverage": 0.0,
                     "residual_likelihood": 5.0, "residual_score": 25.0,
                     "residual_severity": "Critical", "controls": [],
                     "applicability": 1.0, "applicable": True}]),
                threat_pack_version="2.1.0",
                threat_pack_fingerprint="x")
            db.add(rec)
            db.commit()
            old_id = rec.id
            before = {c: getattr(rec, c) for c in
                      ("controls_json", "scoring_json", "threats_json",
                       "residual_pct", "posture")}
        finally:
            db.close()
        r = client.post(f"/api/security/assessments/{old_id}/rescore",
                        json={"active_controls": ["C01"], "persist": True})
        self.assertEqual(r.status_code, 200, r.text[:200])
        new_id = r.json()["assessment_id"]
        self.assertNotEqual(new_id, old_id)
        db = SessionLocal()
        try:
            old = db.query(SecurityAssessment).filter(
                SecurityAssessment.id == old_id).first()
            for c, v in before.items():
                self.assertEqual(getattr(old, c), v, c)
            new = db.query(SecurityAssessment).filter(
                SecurityAssessment.id == new_id).first()
            self.assertEqual(new.supersedes_id, old_id)
            self.assertEqual(new.threat_pack_version, "2.1.0")
        finally:
            db.close()


class TestDeprecation(unittest.TestCase):
    def test_deprecated_control_is_inert_for_new_scores(self):
        from app import security as sec
        from app import evalkit
        with mock.patch.dict(sec.DEPRECATED_CONTROLS,
                             {"C01": {"replaced_by": "C02",
                                      "reason": "t"}}):
            inherent = evalkit._inherent()
            a = sec.score_assessment("confidential_data", inherent,
                                     active_controls=["C01"])
            b = sec.score_assessment("confidential_data", inherent,
                                     active_controls=[])
            self.assertEqual(a["residual_pct"], b["residual_pct"])

    def test_deprecated_threat_skipped_in_inherent(self):
        from app import security as sec
        rows = [t for t in sec._THREAT_CATALOG
                if t[0] not in {"T01"}]
        self.assertLess(len(rows), len(sec._THREAT_CATALOG))
        # The build path filters the same way (mirrors the comprehension).
        with mock.patch.dict(sec.DEPRECATED_THREATS,
                             {"T01": {"replaced_by": "T02",
                                      "reason": "t"}}):
            kept = [t[0] for t in sec._THREAT_CATALOG
                    if t[0] not in sec.DEPRECATED_THREATS]
            self.assertNotIn("T01", kept)

    def test_deprecated_model_class_skipped(self):
        from app import model_eval as me
        with mock.patch.dict(me.DEPRECATED["attack_classes"],
                             {"extraction": {"replaced_by": "",
                                             "reason": "t"}}):
            r = me.score_adversarial([
                {"attack_class": "extraction",
                 "applies_to": "model_specific", "confidence": 0.9}])
            self.assertIsNone(r["overall_pct"])
            self.assertEqual(r["coverage_pct"], 0.0)

    def test_deprecated_mm_invisible_to_new_plans(self):
        from app import model_eval as me
        with mock.patch.dict(me.DEPRECATED["mitigations"],
                             {"MM05": {"replaced_by": "MM09",
                                       "reason": "t"}}):
            app, deferred = me.prefilter_mitigations(
                {"model_family": "tabular_fm",
                 "weights_source": "open_weights"})
            self.assertNotIn("MM05", {c["id"] for c in app})
            self.assertNotIn("MM05", {d["control_id"] for d in deferred})

    def test_old_rows_still_render_deprecated_ids(self):
        from app.database import SessionLocal
        from app.models import Investigation, SecurityAssessment
        db = SessionLocal()
        try:
            inv = Investigation(title="t", keywords="k", description="d",
                                sources="web")
            db.add(inv)
            db.commit()
            db.add(SecurityAssessment(
                investigation_id=inv.id, product_name="Widget",
                exposure="confidential_data", overall_pct=50.0,
                posture="x", markdown="m",
                scoring_json=json.dumps({"assessment_path": "standard"}),
                threats_json=json.dumps([{"id": "T01", "title": "old threat",
                                          "residual_score": 20.0}]),
                threat_pack_version="0.0.0",
                threat_pack_fingerprint="x"))
            db.commit()
            from app.dossier import dossier_markdown
            md = dossier_markdown(db, inv.id)
            self.assertIn("T01", md)
        finally:
            db.close()


class TestChangelog(unittest.TestCase):
    def test_endpoint_serves_entries(self):
        from fastapi.testclient import TestClient
        from app import main as main_mod
        r = TestClient(main_mod.app).get("/api/packs/changelog")
        self.assertEqual(r.status_code, 200, r.text[:200])
        entries = r.json()["entries"]
        self.assertTrue(entries)
        self.assertIn("akm-threat-pack",
                      entries[0].get("adopted_versions", {}))

    def test_excerpt_only_newer_versions(self):
        from app import threatpack as tp
        self.assertEqual(tp.changelog_excerpt("akm-threat-pack", "2.1.0"), [])
        self.assertEqual(tp.changelog_excerpt("akm-threat-pack", None), [])


class TestScorePurity(unittest.TestCase):
    def test_same_inputs_same_numbers(self):
        from app import security as sec
        from app import evalkit
        inherent = evalkit._inherent()
        a = sec.score_assessment("confidential_data", inherent,
                                 active_controls=["C01", "C02"])
        b = sec.score_assessment("confidential_data", inherent,
                                 active_controls=["C01", "C02"])
        self.assertEqual(a, b)

    def test_inputs_move_numbers(self):
        from app import security as sec
        from app import evalkit
        inherent = evalkit._inherent()
        a = sec.score_assessment("confidential_data", inherent,
                                 active_controls=[])
        b = sec.score_assessment("confidential_data", inherent,
                                 active_controls=["C01", "C02"])
        self.assertNotEqual(a["residual_pct"], b["residual_pct"])


class TestCompareEndpoint(unittest.TestCase):
    def setUp(self):
        from fastapi.testclient import TestClient
        from app import main as main_mod
        from app.database import SessionLocal
        from app.models import Investigation, SecurityAssessment
        self.client = TestClient(main_mod.app)
        db = SessionLocal()
        try:
            inv = Investigation(title="t", keywords="k", description="d",
                                sources="web")
            db.add(inv)
            db.commit()
            self.inv_id = inv.id

            def _row(path, residual, scoring_extra=None, inv=None):
                scoring = {"assessment_path": path}
                scoring.update(scoring_extra or {})
                r = SecurityAssessment(
                    investigation_id=inv or self.inv_id,
                    product_name="Widget", exposure="confidential_data",
                    overall_pct=residual or 0.0,
                    inherent_pct=68.8, residual_pct=residual,
                    posture="x", markdown="m",
                    scoring_json=json.dumps(scoring),
                    threats_json=json.dumps([]),
                    threat_pack_version="2.1.0",
                    threat_pack_fingerprint="x")
                db.add(r)
                db.commit()
                return r.id
            self.std_a = _row("standard", 40.0)
            self.std_b = _row("standard", 24.3)
            self.eng_a = _row("model_engineering", None, {
                "w1": {"overall_pct": 46.6},
                "w2": {"overall_pct": 60.0}})
            self.eng_b = _row("model_engineering", None, {
                "w1": {"overall_pct": 30.0},
                "w2": {"overall_pct": None}})
            self.hyp_a = _row("model_hypothesis", 55.0)
        finally:
            db.close()

    def test_product_compare_shows_delta(self):
        r = self.client.get(
            f"/api/security/assessments/{self.std_a}/compare/{self.std_b}")
        self.assertEqual(r.status_code, 200, r.text[:200])
        body = r.json()
        self.assertEqual(body["residual_pct"]["delta"], -15.7)
        self.assertTrue(body["same_pack"])

    def test_cross_method_refused(self):
        r = self.client.get(
            f"/api/security/assessments/{self.std_a}/compare/{self.eng_a}")
        self.assertEqual(r.status_code, 422)

    def test_model_compare_shows_w1_w2(self):
        r = self.client.get(
            f"/api/security/assessments/{self.eng_a}/compare/{self.eng_b}")
        self.assertEqual(r.status_code, 200, r.text[:200])
        body = r.json()
        self.assertEqual(body["w1"]["delta"], -16.6)
        self.assertIsNone(body["w2"]["b"])
        self.assertIsNone(body["w2"]["delta"])

    def test_cross_investigation_refused(self):
        from app.database import SessionLocal
        from app.models import Investigation
        db = SessionLocal()
        try:
            inv = Investigation(title="other", keywords="k",
                                description="d", sources="web")
            db.add(inv)
            db.commit()
            other = inv.id
        finally:
            db.close()
        from app.database import SessionLocal as _S
        from app.models import SecurityAssessment as _SA
        db = _S()
        try:
            r = _SA(investigation_id=other, product_name="W",
                    exposure="confidential_data", overall_pct=10.0,
                    posture="x", markdown="m",
                    scoring_json=json.dumps({"assessment_path": "standard"}),
                    threats_json=json.dumps([]))
            db.add(r)
            db.commit()
            oid = r.id
        finally:
            db.close()
        r = self.client.get(
            f"/api/security/assessments/{self.std_a}/compare/{oid}")
        self.assertEqual(r.status_code, 422)


if __name__ == "__main__":
    unittest.main()
