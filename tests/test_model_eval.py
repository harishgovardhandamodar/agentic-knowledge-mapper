"""Tests for Model Engineering Security Assessment (W1 + W2).

W1 maps published attacks onto a model/family; W2 rates adoption dimensions.
Scores may be None (no evidence) and must stay None through display: a dash,
never a zero that would read as "secure".
"""
import json
import os
import tempfile
import unittest
from unittest import mock

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-modeleval-"), "test.db"))

from app import model_eval as me  # noqa: E402
from app import database  # noqa: E402
from app import models as _models  # noqa: E402,F401 -- registers tables

database.init_db()

TABULAR = {"model_name": "TabPFN", "model_family": "tabular_fm",
           "modality": "tabular", "weights_source": "open_weights",
           "training_data_posture": "mixed", "deployment_pattern": "vpc"}


class TestNormalizeMeta(unittest.TestCase):
    def test_enums_validated(self):
        m = me.normalize_model_meta(dict(TABULAR, model_family="diffusion"))
        self.assertEqual(m["model_family"], "diffusion")

    def test_unknown_family_becomes_other_with_text_kept(self):
        m = me.normalize_model_meta(dict(TABULAR, model_family="quantum_fm"))
        self.assertEqual(m["model_family"], "other")
        self.assertEqual(m["model_family_text"], "quantum_fm")

    def test_unknown_weights_stays_unknown(self):
        m = me.normalize_model_meta({"model_name": "X"})
        self.assertEqual(m["weights_source"], "unknown")
        self.assertEqual(m["modality"], "other")

    def test_workflows_default_both_subset_kept(self):
        self.assertEqual(me.normalize_model_meta({"model_name": "X"})["workflows"],
                         ["adversarial_research", "adoption_risk",
                          "mitigation_controls"])
        m = me.normalize_model_meta({"model_name": "X",
                                      "workflows": ["adoption_risk", "nope"]})
        self.assertEqual(m["workflows"], ["adoption_risk"])


class TestW1Scoring(unittest.TestCase):
    def test_model_specific_outranks_family(self):
        same = {"attack_class": "extraction", "confidence": 0.8}
        fam = me.score_adversarial([{**same, "applies_to": "family"}])
        own = me.score_adversarial([{**same, "applies_to": "model_specific"}])
        self.assertGreater(own["overall_pct"], fam["overall_pct"])

    def test_empty_is_no_score_not_zero(self):
        r = me.score_adversarial([])
        self.assertIsNone(r["overall_pct"])
        self.assertEqual(r["coverage_pct"], 0.0)
        self.assertEqual(r["method"], "adversarial_coverage_v1")

    def test_pinned_diffusion_case(self):
        r = me.score_adversarial([
            {"attack_class": "extraction", "applies_to": "model_specific",
             "confidence": 0.8},
            {"attack_class": "membership_inference", "applies_to": "family",
             "confidence": 0.6}])
        self.assertAlmostEqual(r["overall_pct"], 46.6, places=1)
        self.assertAlmostEqual(r["coverage_pct"], 20.0, places=1)

    def test_fingerprint_is_stable(self):
        self.assertEqual(me.model_adv_fingerprint(), "2426c8c494d6")
        self.assertEqual(me.MODEL_ADV_VERSION, "2.0.0")


class TestW2Scoring(unittest.TestCase):
    def test_unknown_raises_uncertainty_not_low_risk(self):
        r = me.score_adoption([
            {"dimension": "memorization", "rating": "high"},
            {"dimension": "data_processing", "rating": "high"},
            {"dimension": "governance_documentation", "rating": "low"}])
        self.assertAlmostEqual(r["overall_pct"], 60.0, places=1)
        self.assertAlmostEqual(r["uncertainty_pct"], 50.0, places=1)

    def test_all_unknown_is_no_score(self):
        r = me.score_adoption([])
        self.assertIsNone(r["overall_pct"])
        self.assertEqual(r["uncertainty_pct"], 100.0)

    def test_fully_rated_low_is_low(self):
        r = me.score_adoption([{"dimension": d[0], "rating": "low"}
                               for d in me.ADOPTION_DIMENSIONS])
        self.assertAlmostEqual(r["overall_pct"], 25.0, places=1)
        self.assertEqual(r["uncertainty_pct"], 0.0)

    def test_posture_none_is_unknown_not_low(self):
        self.assertIn("UNKNOWN", me.posture_for(None))
        self.assertIn("LOW", me.posture_for(10.0))

    def test_fingerprint_is_stable(self):
        self.assertEqual(me.adoption_fingerprint(), "429c1576c12e")
        self.assertEqual(me.ADOPTION_VERSION, "1.0.0")


class TestMitigationCatalog(unittest.TestCase):
    def test_catalog_shape(self):
        self.assertEqual(len(me.MITIGATION_CATALOG), 16)
        ids = [c["id"] for c in me.MITIGATION_CATALOG]
        self.assertEqual(ids, [f"MM{i:02d}" for i in range(1, 17)])
        for c in me.MITIGATION_CATALOG:
            for key in ("title", "description",
                        "mitigates_attack_classes",
                        "mitigates_adoption_dimensions", "requires",
                        "efficacy_hint", "cost_burden",
                        "residual_limitations"):
                self.assertIn(key, c, c["id"])
            self.assertIn(c["cost_burden"], ("low", "medium", "high"))
        self.assertEqual(me.mitigation_fingerprint(), "394dbf5a8e8e")
        self.assertEqual(me.MITIGATION_VERSION, "2.0.0")

    def test_tabular_open_defers_watermarking(self):
        app, deferred = me.prefilter_mitigations(
            {"model_family": "tabular_fm", "weights_source": "open_weights"})
        ids = {c["id"] for c in app}
        self.assertIn("MM01", ids)
        self.assertNotIn("MM04", ids)
        self.assertIn("MM04", {d["control_id"] for d in deferred})

    def test_api_only_defers_training_and_weight_controls(self):
        app, deferred = me.prefilter_mitigations(
            {"model_family": "diffusion", "weights_source": "api_only"})
        ids = {c["id"] for c in app}
        for gone in ("MM01", "MM03", "MM10"):
            self.assertNotIn(gone, ids)
        for must in ("MM09", "MM12", "MM13", "MM15"):
            self.assertIn(must, ids)

    def test_rank_prioritizes_dp_and_canaries_for_memorization(self):
        plan = me.rank_mitigations(
            {"model_family": "tabular_fm", "weights_source": "open_weights"},
            [{"attack_class": "extraction", "applies_to": "model_specific",
              "confidence": 0.8}],
            [{"dimension": "memorization", "rating": "high"}])
        top = [p["control_id"] for p in plan[:5]]
        self.assertIn("MM05", top)
        proposed = {p["control_id"] for p in plan}
        self.assertIn("MM01", proposed)
        self.assertIn("MM03", proposed)
        self.assertEqual([p["priority"] for p in plan],
                         list(range(1, len(plan) + 1)))

    def test_residual_keeps_uncovered_visible(self):
        attacks = [{"attack_class": "extraction",
                    "applies_to": "model_specific", "confidence": 0.8}]
        plan = me.rank_mitigations(
            {"model_family": "tabular_fm", "weights_source": "open_weights"},
            attacks, [])
        res = me.score_mitigation_residual(attacks, [], plan)
        self.assertLess(res["per_class"]["extraction"], 85.0)
        self.assertIn("indicative", res["note"])
        bare = me.score_mitigation_residual(attacks, [], [])
        self.assertIn("extraction", bare["uncovered"])
        self.assertEqual(bare["per_class"]["extraction"], 68.0)


class TestEvalkitModelGate(unittest.TestCase):
    def test_model_cases_and_invariants_pass(self):
        from app import evalkit
        rep = evalkit.run_eval()
        self.assertEqual(rep["model_cases_failed"], 0)
        self.assertEqual(rep["model_invariants_failed"], 0)
        self.assertTrue(rep["ok"])


def _down(*a, **k):
    raise RuntimeError("gateway down for tests")


def _down_json(*a, **k):
    raise RuntimeError("gateway down for tests")


class TestOrchestratorOffline(unittest.TestCase):
    """No DB evidence, no LLM: fallbacks produce an honest empty report."""

    def setUp(self):
        # The test database file is shared across test modules and the
        # research-collector falls back to the whole app graph: without this,
        # other modules' leftover artifacts become our "evidence".
        from app.database import SessionLocal
        from app.models import Artifact
        db = SessionLocal()
        try:
            db.query(Artifact).delete()
            db.commit()
        finally:
            db.close()
        # Fallbacks must be deterministic: a reachable-but-slow gateway
        # would otherwise make "offline" assertions flaky.
        import app.llm as _llm_mod
        self._chat = _llm_mod.chat
        self._chat_json = _llm_mod.chat_json
        _llm_mod.chat = _down
        _llm_mod.chat_json = _down_json

    def tearDown(self):
        import app.llm as _llm_mod
        _llm_mod.chat = self._chat
        _llm_mod.chat_json = self._chat_json

    def test_empty_corpus_yields_no_evidence_scores(self):
        from app.agents import run_model_engineering_a2a_workflow
        from app.database import SessionLocal
        db = SessionLocal()
        try:
            out = run_model_engineering_a2a_workflow(dict(TABULAR), db=db)
        finally:
            db.close()
        self.assertTrue(out["task_id"].startswith("mev-"))
        self.assertGreater(len(out["a2a_trace"]), 3)
        self.assertIsNone(out["scoring"]["w1"]["overall_pct"])
        self.assertIsNone(out["scoring"]["w2"]["overall_pct"])
        self.assertIsNone(out["scoring"]["overall_pct"])
        self.assertIn("UNKNOWN", me.posture_for(None))
        self.assertIn("No adversarial evidence found", out["report_markdown"])
        self.assertEqual(len(out["model_attacks"]), 0)
        # W3 with zero risk context: explicit empty plan, never silent.
        self.assertEqual(out["mitigation"]["plan"], [])
        self.assertIn("insufficient evidence", out["report_markdown"].lower())

    def test_ledger_keeps_the_task_chain(self):
        from app.agents import run_model_engineering_a2a_workflow
        from app.database import SessionLocal
        from app import ledger_models as _lm
        db = SessionLocal()
        try:
            out = run_model_engineering_a2a_workflow(dict(TABULAR), db=db)
            task_id = out["task_id"]
            hops = db.query(_lm.LedgerEvent).filter(
                _lm.LedgerEvent.run_id == task_id).all()
            self.assertGreater(len(hops), 0)
        finally:
            db.close()

    def test_stop_after_analyst_parks_on_plan(self):
        # Approval preview: plan without reporter output.
        from app.agents import run_model_engineering_a2a_workflow
        from app.database import SessionLocal
        db = SessionLocal()
        try:
            meta = dict(TABULAR,
                        workflows=["adversarial_research", "adoption_risk",
                                   "mitigation_controls"])
            out = run_model_engineering_a2a_workflow(meta, db=db,
                                                     stop_after="analyst")
            self.assertIn("mitigation", out)
            self.assertIn("w3_scoring", out)
            self.assertNotIn("report_markdown", out)
            intents = [h.get("intent") for h in out["a2a_trace"]]
            self.assertIn("propose_model_mitigations", intents)
        finally:
            db.close()

    def test_workflow_subset_skips_cleanly(self):
        from app.agents import run_model_engineering_a2a_workflow
        from app.database import SessionLocal
        db = SessionLocal()
        try:
            meta = dict(TABULAR, workflows=["adoption_risk"])
            out = run_model_engineering_a2a_workflow(meta, db=db)
            self.assertEqual(out["scoring"]["w1"]["overall_pct"], None)
            self.assertEqual(out["model_attacks"], [])
            self.assertTrue(out["scoring"]["w2"]["uncertainty_pct"] >= 0)
        finally:
            db.close()


class TestModelApi(unittest.TestCase):
    def setUp(self):
        from fastapi.testclient import TestClient
        from app import main as main_mod
        self.client = TestClient(main_mod.app)
        inv = self.client.post("/api/investigations", json={
            "title": "TabPFN safety review", "keywords": "TabPFN, tabular",
            "description": "assess a tabular foundation model",
            "sources": "web"}).json()
        self.inv_id = inv["id"]

    def _assess(self, **kw):
        body = {"assessment_mode": "model_engineering",
                "model_name": "TabPFN", "model_family": "tabular_fm",
                "modality": "tabular", "weights_source": "open_weights",
                "training_data_posture": "mixed", "deployment_pattern": "vpc",
                "model_focus_terms": ["membership inference"],
                "workflows": ["adversarial_research", "adoption_risk"]}
        body.update(kw)
        return self.client.post(
            f"/api/investigations/{self.inv_id}/security/assess", json=body)

    def test_model_assessment_starts_with_path(self):
        from app import security_agent as sec_mod
        with mock.patch.object(sec_mod, "launch_security_assessment",
                               return_value=999) as launcher:
            r = self._assess()
        self.assertEqual(r.status_code, 200, r.text[:200])
        data = r.json()
        self.assertEqual(data["assessment_mode"], "model_engineering")
        self.assertEqual(data["assessment_path"], "model_engineering")
        params = launcher.call_args[0][1]
        self.assertEqual(params["model_meta"]["model_name"], "TabPFN")
        self.assertEqual(params["model_meta"]["model_family"], "tabular_fm")

    def test_missing_model_name_is_422(self):
        r = self._assess(model_name="")
        self.assertEqual(r.status_code, 422)

    def test_unknown_family_normalizes_to_other(self):
        from app import security_agent as sec_mod
        with mock.patch.object(sec_mod, "launch_security_assessment",
                               return_value=999) as launcher:
            r = self._assess(model_family="quantum_fm")
        self.assertEqual(r.status_code, 200, r.text[:200])
        meta = launcher.call_args[0][1]["model_meta"]
        self.assertEqual(meta["model_family"], "other")
        self.assertEqual(meta["model_family_text"], "quantum_fm")

    def test_bad_mode_still_rejected(self):
        r = self.client.post(
            f"/api/investigations/{self.inv_id}/security/assess",
            json={"assessment_mode": "nope"})
        self.assertEqual(r.status_code, 422)


class TestModelDossierW3(unittest.TestCase):
    """W3 plan, deferrals and approvals render in the dossier."""

    def _w3_inv(self):
        from app.database import SessionLocal
        from app.models import Investigation, SecurityAssessment
        db = SessionLocal()
        inv = Investigation(title="TabPFN safety", keywords="TabPFN",
                            description="d", sources="web")
        db.add(inv)
        db.commit()
        plan = me.rank_mitigations(
            {"model_family": "tabular_fm", "weights_source": "open_weights"},
            [{"attack_class": "extraction", "applies_to": "model_specific",
              "confidence": 0.8}], [])[:3]
        _, deferred = me.prefilter_mitigations(
            {"model_family": "tabular_fm", "weights_source": "open_weights"})
        scoring = {
            "overall_pct": None, "assessment_path": "model_engineering",
            "method": "model_engineering_v1",
            "posture": me.posture_for(None),
            "w1": {"method": "adversarial_coverage_v1",
                   "overall_pct": 68.0, "coverage_pct": 12.5},
            "w2": {"method": "adoption_risk_v1", "overall_pct": None,
                   "uncertainty_pct": 100.0, "rated": []},
            "w3": {"method": "mitigation_residual_v1",
                   "mitigation_version": me.MITIGATION_VERSION,
                   "mitigation_fingerprint": me.mitigation_fingerprint()},
            "model_adv_version": me.MODEL_ADV_VERSION,
            "model_adv_fingerprint": me.model_adv_fingerprint(),
            "adoption_version": me.ADOPTION_VERSION,
            "adoption_fingerprint": me.adoption_fingerprint()}
        rec = SecurityAssessment(
            investigation_id=inv.id, product_name="TabPFN",
            exposure="restricted_data", overall_pct=0.0,
            posture=me.posture_for(None), markdown="# Model report",
            scoring_json=json.dumps(scoring),
            threats_json=json.dumps([
                {"attack_id": "MA-01", "title": "Extraction",
                 "attack_class": "extraction", "applies_to": "model_specific",
                 "confidence": 0.8, "prerequisites": ["open weights"],
                 "mitigations": [], "residual_notes": ""},
                {"attack_id": "MA-09", "title": "Novel exfiltration",
                 "attack_class": "other", "applies_to": "family",
                 "confidence": 0.9, "prerequisites": ["query access"],
                 "mitigations": [], "residual_notes": ""}]),
            model_json=json.dumps({
                "meta": me.normalize_model_meta(dict(TABULAR)),
                "mitigation": {"plan": plan, "deferred": deferred,
                               "uncovered_risks": ["other"],
                               "roadmap": {"30d": ["plant canaries"],
                                           "60d": [], "90d": []}},
                "w1": scoring["w1"], "w2": scoring["w2"],
                "w3": scoring["w3"]}),
            threat_pack_version="2.1.0", threat_pack_fingerprint="x")
        db.add(rec)
        db.commit()
        return db, inv.id

    def test_w3_plan_deferred_and_exec(self):
        from app.dossier import dossier_markdown
        db, inv_id = self._w3_inv()
        try:
            md = dossier_markdown(db, inv_id)
            for s in ("**W3 — Mitigation plan", "MM05", "MM04 deferred",
                      "mitigation-residual 2.0.0",
                      "Top recommended controls:",
                      "Still uncovered", "Top residual risks after plan:"):
                self.assertIn(s, md)
        finally:
            db.close()


class TestModelDossierRow(unittest.TestCase):
    """A stored model assessment renders identity, W1/W2 and versions."""

    def test_full_model_sections(self):
        from app.database import SessionLocal
        from app.models import Investigation, SecurityAssessment
        db = SessionLocal()
        try:
            inv = Investigation(title="TabPFN safety", keywords="TabPFN",
                                description="d", sources="web")
            db.add(inv)
            db.commit()
            scoring = {
                "overall_pct": None, "inherent_pct": None,
                "residual_pct": None, "delta": 0.0,
                "assessment_path": "model_engineering",
                "method": "model_engineering_v1",
                "posture": me.posture_for(None),
                "w1": {"method": "adversarial_coverage_v1",
                       "overall_pct": None, "coverage_pct": 0.0},
                "w2": {"method": "adoption_risk_v1",
                       "overall_pct": None, "uncertainty_pct": 100.0,
                       "rated": [{"dimension": "memorization",
                                  "rating": "unknown"}]},
                "model_adv_version": me.MODEL_ADV_VERSION,
                "model_adv_fingerprint": me.model_adv_fingerprint(),
                "adoption_version": me.ADOPTION_VERSION,
                "adoption_fingerprint": me.adoption_fingerprint()}
            rec = SecurityAssessment(
                investigation_id=inv.id, product_name="TabPFN",
                exposure="restricted_data", overall_pct=0.0,
                posture=me.posture_for(None),
                markdown="# Model engineering assessment — TabPFN",
                scoring_json=json.dumps(scoring),
                threats_json=json.dumps([]),
                model_json=json.dumps({
                    "meta": me.normalize_model_meta(dict(TABULAR)),
                    "dimensions": [{
                        "dimension": "memorization", "rating": "unknown",
                        "rationale": "no evidence collected",
                        "adoption_implications": ["verify first"]}],
                    "w1": scoring["w1"], "w2": scoring["w2"],
                    "model_adv_version": me.MODEL_ADV_VERSION,
                    "model_adv_fingerprint": me.model_adv_fingerprint(),
                    "adoption_version": me.ADOPTION_VERSION,
                    "adoption_fingerprint": me.adoption_fingerprint()}),
                threat_pack_version="2.1.0", threat_pack_fingerprint="x")
            db.add(rec)
            db.commit()
            from app.dossier import dossier_markdown, investigation_dossier
            d = investigation_dossier(db, inv.id)
            row = [r for r in d["scores"]["rows"]
                   if r["path"] == "model_engineering"][0]
            self.assertIsNone(row["score"])
            self.assertEqual(row["detail"]["kind"], "model_engineering")
            md = dossier_markdown(db, inv.id, dossier=d)
            for s in ("**Model identity.**", "TabPFN", "tabular_fm",
                      "W1 — Adversarial research", "W2 — Adoption risk",
                      "model-adversarial 2.0.0", "adoption-risk 1.0.0",
                      "— (no evidence)", "Unknown dimensions"):
                self.assertIn(s, md)
            head = md[:md.index("## 1. The request")]
            self.assertIn("**Model TabPFN.**", head)
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
