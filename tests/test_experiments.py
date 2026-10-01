"""Experiment builder: ranked probes, plan only, never execution."""
import json
import os
import tempfile
import unittest
from unittest import mock

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-exp-"), "test.db"))

from app import model_eval as me  # noqa: E402
from app import database  # noqa: E402
from app import models as _models  # noqa: E402,F401 -- registers tables
from app.database import SessionLocal  # noqa: E402

database.init_db()

TABULAR = {"model_name": "TabPFN", "model_family": "tabular_fm",
           "modality": "tabular", "weights_source": "open_weights"}


class TestPlanExperiments(unittest.TestCase):
    def test_unknown_memorization_plans_canary(self):
        plan = me.plan_experiments(
            dict(TABULAR), [], [{"dimension": "memorization",
                                 "rating": "unknown"}], [], [])
        methods = [e["method_type"] for e in plan["experiments"]]
        self.assertIn("canary", methods)
        self.assertEqual(plan["method"], "experiment_plan_v1")
        self.assertTrue(plan["method_fingerprint"])

    def test_api_only_never_bare_weight_access(self):
        plan = me.plan_experiments(
            {"model_family": "diffusion", "weights_source": "api_only"},
            [{"attack_class": "extraction", "applies_to": "family",
              "confidence": 0.6}], [], [], [])
        self.assertTrue(plan["experiments"])
        for e in plan["experiments"]:
            self.assertIn("query_api", e["prerequisites"])
            if not e.get("vendor_coop", True) and \
                    e["method_type"] in ("unlearning_check",
                                         "watermark_detect"):
                self.assertIn("vendor_coop", e["prerequisites"])

    def test_falsifier_maps_to_experiment(self):
        plan = me.plan_experiments(
            {"model_family": "llm", "weights_source": "api_only"},
            [], [],
            [{"hypothesis_id": "H01", "status": "untested",
              "falsifiers": ["vendor retains prompts for training"]}], [])
        targets = [t for e in plan["experiments"]
                   for t in e["targets"]["hypothesis_ids"]]
        self.assertIn("H01", targets)

    def test_untestable_falsifier_is_explicit(self):
        plan = me.plan_experiments(
            {"model_family": "llm", "weights_source": "api_only"},
            [], [],
            [{"hypothesis_id": "H09", "status": "untested",
              "falsifiers": []}], [])
        targets = [t for e in plan["experiments"]
                   for t in e["targets"]["hypothesis_ids"]]
        self.assertIn("H09", targets)

    def test_settled_hypotheses_get_no_probe(self):
        plan = me.plan_experiments(
            dict(TABULAR), [],
            [{"dimension": "memorization", "rating": "low"}],
            [{"hypothesis_id": "H01", "status": "supported",
              "falsifiers": ["x"]}], [])
        targets = [t for e in plan["experiments"]
                   for t in e["targets"]["hypothesis_ids"]]
        self.assertNotIn("H01", targets)

    def test_top_mm_links_validation(self):
        plan = me.plan_experiments(
            dict(TABULAR), [], [],
            [], [{"control_id": "MM05", "priority": 1},
                 {"control_id": "MM09", "priority": 2}])
        mm_targets = [t for e in plan["experiments"]
                      for t in e["targets"]["mitigation_ids"]]
        self.assertIn("MM05", mm_targets)


class TestExperimentAgent(unittest.TestCase):
    def setUp(self):
        import app.llm as _llm
        self._chat = _llm.chat
        _llm.chat = lambda *a, **k: (_ for _ in ()).throw(
            RuntimeError("down"))

    def tearDown(self):
        import app.llm as _llm
        _llm.chat = self._chat

    def test_offline_plan_is_deterministic(self):
        from app import agents as am
        env = am.new_envelope("t", "experiment-planner", "plan_experiments", {
            "model_meta": dict(TABULAR),
            "findings": [], "dimensions": [
                {"dimension": "memorization", "rating": "unknown"}],
            "hypotheses": [], "mitigation_plan": []})
        out = am.experiment_planner_handle(env, None)["payload"]
        self.assertTrue(out["experiments"])
        self.assertIn("deterministic", out["source"])
        self.assertEqual(out["method"], "experiment_plan_v1")


class TestExperimentEndpoint(unittest.TestCase):
    def setUp(self):
        from fastapi.testclient import TestClient
        from app import main as main_mod
        self.client = TestClient(main_mod.app)
        db = SessionLocal()
        try:
            inv = _models.Investigation(title="t", keywords="k",
                                        description="d", sources="web")
            db.add(inv)
            db.commit()
            self.inv_id = inv.id
            rec = _models.SecurityAssessment(
                investigation_id=inv.id, product_name="TabPFN",
                exposure="restricted_data", overall_pct=0.0,
                posture="UNKNOWN", markdown="m",
                scoring_json=json.dumps({
                    "assessment_path": "model_engineering",
                    "w1": {"overall_pct": None},
                    "w2": {"overall_pct": None, "uncertainty_pct": 100.0,
                           "rated": []}}),
                threats_json=json.dumps([]),
                model_json=json.dumps({
                    "meta": dict(TABULAR),
                    "dimensions": [{"dimension": "memorization",
                                    "rating": "unknown",
                                    "rationale": "no evidence",
                                    "adoption_implications": []}]}))
            db.add(rec)
            db.commit()
            self.aid = rec.id
        finally:
            db.close()

    def test_build_stores_plan_without_touching_scores(self):
        import app.llm as _llm
        old = _llm.chat
        _llm.chat = lambda *a, **k: (_ for _ in ()).throw(
            RuntimeError("down"))
        try:
            before = self.client.get(
                f"/api/security/assessments/{self.aid}").json()["scoring"]
            r = self.client.post(
                f"/api/security/assessments/{self.aid}/experiments/build",
                json={})
            self.assertEqual(r.status_code, 200, r.text[:200])
            self.assertTrue(r.json()["experiments"])
            after = self.client.get(
                f"/api/security/assessments/{self.aid}").json()
            self.assertEqual(after["scoring"], before)
            self.assertTrue(after["experiments"])
        finally:
            _llm.chat = old

    def test_non_model_assessment_rejected(self):
        db = SessionLocal()
        try:
            rec = _models.SecurityAssessment(
                investigation_id=self.inv_id, product_name="Widget",
                exposure="confidential_data", overall_pct=50.0,
                posture="x", markdown="m",
                scoring_json=json.dumps({"assessment_path": "standard"}),
                threats_json=json.dumps([]))
            db.add(rec)
            db.commit()
            other = rec.id
        finally:
            db.close()
        r = self.client.post(
            f"/api/security/assessments/{other}/experiments/build", json={})
        self.assertEqual(r.status_code, 422)

    def test_dossier_shows_experiments(self):
        import app.llm as _llm
        old = _llm.chat
        _llm.chat = lambda *a, **k: (_ for _ in ()).throw(
            RuntimeError("down"))
        try:
            self.client.post(
                f"/api/security/assessments/{self.aid}/experiments/build",
                json={})
            from app.dossier import dossier_markdown
            db = SessionLocal()
            try:
                md = dossier_markdown(db, self.inv_id)
            finally:
                db.close()
            self.assertIn("Experiments — plan only", md)
            self.assertIn("execution is out of band", md)
        finally:
            _llm.chat = old


if __name__ == "__main__":
    unittest.main()
