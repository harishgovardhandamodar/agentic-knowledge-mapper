"""Hypothesis builder: structured register over scored claims."""
import json
import os
import tempfile
import unittest
from unittest import mock

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-hypbuild-"), "test.db"))

from app import database  # noqa: E402
from app import models as _models  # noqa: E402,F401 -- registers tables
from app.database import SessionLocal  # noqa: E402

database.init_db()

CLAIMS = [
    {"id": "H01", "claim": "Outputs reveal training rows",
     "premise": "p", "mechanism": "m", "consequence": "c",
     "falsifier": "Canary rows never surface in outputs",
     "impact": 4, "testability": 4, "confidence": 62.0,
     "supporting": ["M01"], "counter_evidence": [],
     "contradicted_by": [], "cross_flow": True},
    {"id": "H02", "claim": "Vendor logs everything",
     "premise": "p", "mechanism": "m", "consequence": "c",
     "falsifier": "Data-processing addendum forbids retention",
     "impact": 3, "testability": 3, "confidence": 41.0,
     "supporting": [], "counter_evidence": ["vendor DPA"],
     "contradicted_by": [], "cross_flow": False},
]


def _hyp_rec(db, inv_id, threats=None, hypothesis_json=None):
    rec = _models.SecurityAssessment(
        investigation_id=inv_id, product_name="Widget",
        exposure="confidential_data", overall_pct=55.0,
        posture="confidence", markdown="m",
        scoring_json=json.dumps({"assessment_path": "model_hypothesis",
                                 "method": "hypothesis-synthesis-v1"}),
        threats_json=json.dumps(threats if threats is not None else CLAIMS),
        threat_pack_version="2.1.0", threat_pack_fingerprint="x")
    if hypothesis_json is not None:
        rec.hypothesis_json = json.dumps(hypothesis_json)
    db.add(rec)
    db.commit()
    return rec.id


def _inv(db, title="hyp"):
    inv = _models.Investigation(title=title, keywords="k", description="d",
                                sources="web")
    db.add(inv)
    db.commit()
    return inv.id


class TestClaimShape(unittest.TestCase):
    def test_verifier_sets_status_and_lists(self):
        from app import agents as am
        claim = dict(CLAIMS[0])
        claim["_target_ids"] = ["M01"]  # attached by the orchestrator
        env = am.new_envelope("t", "hypothesis-verifier", "verify_hypotheses", {
            "hypotheses": [claim],
            "evidence": [], "target_rows": [{"id": "M01"}],
            "adversarial_rows": []})
        out = am.hypothesis_verifier_handle(env, None)["payload"]
        v = out["verified"][0]
        self.assertEqual(v["hypothesis_id"], "H01")
        self.assertIn(v["status"], ("supported", "contested", "untested"))
        self.assertIn("Canary rows never surface in outputs", v["falsifiers"])
        self.assertIn("model", v["source_flows"])

    def test_contested_when_countered(self):
        from app import agents as am
        env = am.new_envelope("t", "hypothesis-verifier", "verify_hypotheses", {
            "hypotheses": [dict(CLAIMS[1])],
            "evidence": [], "target_rows": [], "adversarial_rows": []})
        out = am.hypothesis_verifier_handle(env, None)["payload"]
        self.assertEqual(out["verified"][0]["status"], "contested")


class TestRegisterMerge(unittest.TestCase):
    def test_builder_edits_overlay_without_moving_scores(self):
        from app import dossier as _dossier
        db = SessionLocal()
        try:
            inv_id = _inv(db)
            aid = _hyp_rec(db, inv_id, hypothesis_json={
                "claims": [{"hypothesis_id": "H01", "status": "supported",
                            "falsifiers": ["Canary rows never surface",
                                           "Red-team extraction fails"],
                            "add_evidence": [12]}]})
            rec = db.query(_models.SecurityAssessment).filter(
                _models.SecurityAssessment.id == aid).first()
            before = rec.scoring_json
            register = _dossier.hypothesis_register(rec)
            h01 = next(c for c in register
                       if c["hypothesis_id"] == "H01")
            self.assertEqual(h01["status"], "supported")
            self.assertIn("Red-team extraction fails", h01["falsifiers"])
            self.assertIn(12, h01["supporting_artifacts"])
            h02 = next(c for c in register
                       if c["hypothesis_id"] == "H02")
            self.assertEqual(h02["status"], "untested")
            self.assertEqual(rec.scoring_json, before)
            self.assertEqual(rec.threats_json, json.dumps(CLAIMS))
        finally:
            db.close()


class TestBuilderApi(unittest.TestCase):
    def setUp(self):
        from fastapi.testclient import TestClient
        from app import main as main_mod
        self.client = TestClient(main_mod.app)
        db = SessionLocal()
        try:
            self.inv_id = _inv(db)
            self.aid = _hyp_rec(db, self.inv_id)
        finally:
            db.close()

    def test_get_register(self):
        r = self.client.get(f"/api/security/assessments/{self.aid}/hypotheses")
        self.assertEqual(r.status_code, 200, r.text[:200])
        claims = r.json()["claims"]
        self.assertEqual({c["hypothesis_id"] for c in claims}, {"H01", "H02"})
        self.assertTrue(all(c["status"] == "untested" for c in claims))

    def test_patch_status_and_falsifiers(self):
        r = self.client.patch(
            f"/api/security/assessments/{self.aid}/hypotheses",
            json={"claims": [{"hypothesis_id": "H01", "status": "supported",
                              "falsifiers": ["Canary test passes"],
                              "add_evidence": [7]}]})
        self.assertEqual(r.status_code, 200, r.text[:200])
        h01 = next(c for c in r.json()["claims"]
                   if c["hypothesis_id"] == "H01")
        self.assertEqual(h01["status"], "supported")
        self.assertIn("Canary test passes", h01["falsifiers"])
        self.assertIn(7, h01["supporting_artifacts"])
        db = SessionLocal()
        try:
            rec = db.query(_models.SecurityAssessment).filter(
                _models.SecurityAssessment.id == self.aid).first()
            scoring = json.loads(rec.scoring_json)
            self.assertNotIn("H01", json.dumps(scoring.get("claims", []))
                             if scoring.get("claims") else "")
        finally:
            db.close()

    def test_patch_rejects_unknown_id_and_bad_status(self):
        r = self.client.patch(
            f"/api/security/assessments/{self.aid}/hypotheses",
            json={"claims": [{"hypothesis_id": "H99", "status": "supported"}]})
        self.assertEqual(r.status_code, 422)
        r = self.client.patch(
            f"/api/security/assessments/{self.aid}/hypotheses",
            json={"claims": [{"hypothesis_id": "H01", "status": "proven"}]})
        self.assertEqual(r.status_code, 422)

    def test_collect_evidence_starts_gap_run(self):
        from app import security_agent as sec_mod
        with mock.patch.object(sec_mod, "launch_security_assessment",
                               return_value=111):
            pass
        with mock.patch("app.main.launch_run_with_goal",
                         return_value=222) as launcher:
            r = self.client.post(
                f"/api/security/assessments/{self.aid}/hypotheses/H01/collect-evidence")
        self.assertEqual(r.status_code, 200, r.text[:200])
        self.assertEqual(r.json()["run_id"], 222)
        self.assertIn("H01", launcher.call_args[0][1])

    def test_non_hypothesis_assessment_rejected(self):
        from app.database import SessionLocal as _S
        db = _S()
        try:
            other = _hyp_rec(db, self.inv_id)
            rec = db.query(_models.SecurityAssessment).filter(
                _models.SecurityAssessment.id == other).first()
            rec.scoring_json = json.dumps({"assessment_path": "standard"})
            db.commit()
        finally:
            db.close()
        r = self.client.get(f"/api/security/assessments/{other}/hypotheses")
        self.assertEqual(r.status_code, 422)


class TestPartialGate(unittest.TestCase):
    def setUp(self):
        from fastapi.testclient import TestClient
        from app import main as main_mod
        self.client = TestClient(main_mod.app)

    def _inv(self):
        return self.client.post("/api/investigations", json={
            "title": "t", "keywords": "k", "description": "d",
            "sources": "web"}).json()["id"]

    def _assess(self, inv_id, **kw):
        body = {"assessment_mode": "hypothesis", "product_name": "Widget"}
        body.update(kw)
        return self.client.post(
            f"/api/investigations/{inv_id}/security/assess", json=body)

    def test_strict_gate_refuses_without_priors(self):
        from app import security_agent as sec_mod
        inv_id = self._inv()
        with mock.patch.object(sec_mod, "launch_security_assessment",
                               return_value=999) as launcher:
            r = self._assess(inv_id, allow_partial=False)
        self.assertEqual(r.status_code, 409, r.text[:200])
        launcher.assert_not_called()

    def test_strict_gate_passes_with_priors(self):
        from app import security_agent as sec_mod
        from app.database import SessionLocal
        inv_id = self._inv()
        db = SessionLocal()
        try:
            for path in ("model", "model_adversarial"):
                db.add(_models.SecurityAssessment(
                    investigation_id=inv_id, product_name="Widget",
                    exposure="confidential_data", overall_pct=50.0,
                    posture="x", markdown="m",
                    scoring_json=json.dumps({"assessment_path": path}),
                    threats_json=json.dumps([])))
            db.commit()
        finally:
            db.close()
        with mock.patch.object(sec_mod, "launch_security_assessment",
                               return_value=999):
            r = self._assess(inv_id, allow_partial=False)
        self.assertEqual(r.status_code, 200, r.text[:200])

    def test_default_allows_partial(self):
        from app import security_agent as sec_mod
        inv_id = self._inv()
        with mock.patch.object(sec_mod, "launch_security_assessment",
                               return_value=999):
            r = self._assess(inv_id)
        self.assertEqual(r.status_code, 200, r.text[:200])


class TestDossierRegisterTable(unittest.TestCase):
    def test_register_table_renders_status(self):
        from app.dossier import dossier_markdown
        db = SessionLocal()
        try:
            inv_id = _inv(db)
            _hyp_rec(db, inv_id, hypothesis_json={
                "claims": [{"hypothesis_id": "H02", "status": "contested"}]})
            md = dossier_markdown(db, inv_id)
            self.assertIn("Claim register", md)
            self.assertIn("contested", md)
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
