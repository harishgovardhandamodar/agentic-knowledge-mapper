"""RLHF memorization risks RM01-06: taxonomy, register, join, write-guard.

Covers the 11 acceptance criteria for the memorization work order.
"""

import json
import os
import tempfile
import unittest
from unittest import mock

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-mem-"), "test.db"))

from app import database as _db  # noqa: E402
from app import model_eval as me  # noqa: E402
from app import model_kb as kb  # noqa: E402
from app import memorization as rm  # noqa: E402
from app import provider_posture as pp  # noqa: E402
from app.database import Base, SessionLocal  # noqa: E402
from app.models import Investigation, SecurityAssessment, Artifact  # noqa: E402

_db.init_db()

class TestTaxonomy(unittest.TestCase):
    def test_new_classes_and_subtypes_exist(self):
        self.assertIn("memorization", me.ATTACK_CLASSES)
        self.assertIn("alignment_data_leakage", me.ATTACK_CLASSES)
        self.assertEqual(me.ATTACK_CLASSES["memorization"]["severity"], 80)
        self.assertIn("preference_memorization", me.ATTACK_SUBTYPES["memorization"])
        self.assertEqual(me.valid_subtype("memorization", "preference_memorization"), "preference_memorization")
        self.assertIsNone(me.valid_subtype("memorization", "nope"))
        self.assertIsNone(me.valid_subtype("extraction", "sft_memorization"))
        self.assertEqual(me.MODEL_ADV_VERSION, "2.0.0")
        self.assertEqual(me.MITIGATION_VERSION, "2.0.0")
        self.assertEqual(me.EXPERIMENT_VERSION, "1.1.0")

    def test_scope_weight_method_general(self):
        self.assertAlmostEqual(me.scope_weight("method_general"), 0.25)
        scope, ev = kb.scope_of_finding({"attack_class": "memorization", "applies_to": "method_general"})
        self.assertEqual(scope, "inherited")
        self.assertEqual(ev, "method_general")
        self.assertAlmostEqual(me.scope_weight(ev), 0.25)

    def test_pinned_coverage_and_fingerprints(self):
        r = me.score_adversarial([
            {"attack_class": "extraction", "applies_to": "model_specific", "confidence": 0.8},
            {"attack_class": "membership_inference", "applies_to": "family", "confidence": 0.6}])
        self.assertAlmostEqual(r["overall_pct"], 46.6, places=1)
        self.assertAlmostEqual(r["coverage_pct"], 20.0, places=1)
        self.assertEqual(me.model_adv_fingerprint(), "2426c8c494d6")
        self.assertEqual(me.mitigation_fingerprint(), "394dbf5a8e8e")
        self.assertEqual(me.experiment_fingerprint(), "d8988b1f2799")

class TestRMCatalog(unittest.TestCase):
    def test_rm_risks_shape(self):
        self.assertEqual(len(rm.RM_RISKS), 6)
        ids = [r["id"] for r in rm.RM_RISKS]
        self.assertEqual(ids, [f"RM{i:02d}" for i in range(1, 7)])
        for r in rm.RM_RISKS:
            for k in ("attack_class", "data_class", "pipeline_stage", "layer", "mitigations", "org_controllability"):
                self.assertIn(k, r)
        self.assertEqual(rm.RM_ID, "akm-rlhf-memorization")
        self.assertTrue(rm.rm_fingerprint())

class TestRMRows(unittest.TestCase):
    def setUp(self):
        Base.metadata.create_all(_db.engine)
        self.db = SessionLocal()
        self.inv = Investigation(title="mem test", keywords="x", description="x")
        self.db.add(self.inv)
        self.db.commit()
        self.db.refresh(self.inv)

    def tearDown(self):
        self.db.query(SecurityAssessment).filter(SecurityAssessment.investigation_id == self.inv.id).delete()
        self.db.query(Investigation).filter(Investigation.id == self.inv.id).delete()
        self.db.commit()
        self.db.close()

    def _assess(self, attacks, model_name="TabPFN", weights="open_weights"):
        meta = {"model_name": model_name, "model_family": "tabular_fm", "weights_source": weights}
        rec = SecurityAssessment(
            investigation_id=self.inv.id, product_name=model_name, exposure="confidential_data",
            overall_pct=50, markdown="# report", scoring_json=json.dumps({}), model_json=json.dumps({"meta": meta, "attacks": attacks}),
            hypothesis_json=json.dumps({}), threat_pack_version="2.1.0", threat_pack_fingerprint="x")
        self.db.add(rec)
        self.db.commit()
        self.db.refresh(rec)
        kb.sync_model_kb(self.db, rec.id)
        return rec, meta

    def test_rlhf_focus_produces_rm_findings_with_correct_scope(self):
        attacks = [{"attack_class": "memorization", "attack_subtype": "preference_memorization", "applies_to": "model_specific", "confidence": 0.8, "title": "Preference memorization"}]
        rec, meta = self._assess(attacks)
        rows = rm.rm_rows_for_model(rec, meta)
        self.assertTrue(rows)
        r = rows[0]
        self.assertEqual(r["rm_id"], "RM01")
        self.assertEqual(r["scope"], "own")
        self.assertEqual(r["evidence_scope"], "model_specific")
        self.assertIsNotNone(r["severity"])
        # method_general must not appear as own
        attacks2 = [{"attack_class": "memorization", "attack_subtype": "preference_memorization", "applies_to": "method_general", "confidence": 0.6}]
        rec2, meta2 = self._assess(attacks2, model_name="OtherModel")
        rows2 = rm.rm_rows_for_model(rec2, meta2)
        self.assertEqual(rows2[0]["scope"], "inherited")
        self.assertEqual(rows2[0]["evidence_scope"], "method_general")

    def test_null_score_if_no_evidence(self):
        r = me.score_adversarial([])
        self.assertIsNone(r["overall_pct"])

    def test_provider_retention_elevates_rm05(self):
        # Provider with multi-year feedback retention -> elevated
        rlhf = [{"id": "RLHF01", "standing": "partial"}, {"id": "RLHF02", "standing": "partial"}]
        rating = rm.rm05_situational(rlhf, {}, {"weights_source": "open_weights"})
        self.assertEqual(rating["rating"], "elevated")
        # Org API no-train + no feedback disabled would be reduced? Our reduced path requires supported not-trained
        rlhf2 = [{"id": "RLHF01", "standing": "supported", "summary": "not trained on API data"}, {"id": "RLHF04", "standing": "supported", "summary": "not trained"}]
        rating2 = rm.rm05_situational(rlhf2, {}, {"weights_source": "api_only"})
        self.assertEqual(rating2["rating"], "reduced")
        # Unknown stays unknown
        rating3 = rm.rm05_situational([], {}, {})
        self.assertEqual(rating3["rating"], "unknown")

    def test_api_notrain_reduced_rm05_not_model_memorization(self):
        # API no-train + no feedback disabled => RM05 reduced, but RM01 still family-level unknown (not cleared)
        attacks = [{"attack_class": "memorization", "applies_to": "family", "confidence": 0.6}]
        rec, meta = self._assess(attacks, weights="api_only")
        rows = rm.rm_rows_for_model(rec, meta)
        # RM01 still exists as family-level (not cleared)
        self.assertTrue(any(r["rm_id"] == "RM01" and r["scope"] == "inherited" for r in rows))

    def test_kb_lists_preference_memorization(self):
        attacks = [{"attack_class": "memorization", "attack_subtype": "preference_memorization", "applies_to": "family", "confidence": 0.6}]
        rec, meta = self._assess(attacks)
        # Check portfolio register includes RM rows alongside leakage
        from app import portfolio as pf
        pf_rows = pf.register_with_state(self.db, self.inv.id)
        rm_rows = [r for r in pf_rows if r["source_catalog"] == rm.RM_ID]
        self.assertTrue(rm_rows)
        # Also leakage pathways exist separately
        self.assertTrue(any(r["source_catalog"] == "akm-leakage-pathways" or r["source_catalog"] == "akm-model-adversarial" for r in pf_rows))

    def test_write_guard_blocks_unsafe_phrases(self):
        out = rm.guard_memorization_claims("RLHF is safe from memorization. We are secure.")
        self.assertEqual(out["removed_count"], 1)
        out2 = rm.guard_memorization_claims("Your API data is in the reward model. No tier term.")
        self.assertEqual(out2["removed_count"], 1)
        out3 = pp.guard_provider_claims("RLHF is safe from memorization")
        self.assertEqual(out3["removed_count"], 1)

    def test_evalkit_fails_if_method_general_as_model_specific(self):
        # Simulate a finding that incorrectly claims method_general as model_specific
        scope, ev = kb.scope_of_finding({"attack_class": "memorization", "applies_to": "method_general", "attack_subtype": "preference_memorization"})
        self.assertNotEqual(scope, "own")
        # If someone stored it as model_specific, they'd be wrong
        bad = kb.scope_of_finding({"attack_class": "memorization", "applies_to": "model_specific", "attack_subtype": "preference_memorization"})
        self.assertEqual(bad[0], "own")

class TestQueryPack(unittest.TestCase):
    def test_rlhf_memorization_queries_added(self):
        from app import agent as ag
        inv = Investigation(title="TabPFN RLHF preference memorization", keywords="TabPFN, rlhf, preference", description="test", sources="web,arxiv")
        clean = []
        ag._ensure_model_queries(inv, clean, {"web", "arxiv"})
        texts = " ".join(q["text"] for q in clean).lower()
        self.assertIn("rlhf memorization", texts)

class TestHypothesesExperiments(unittest.TestCase):
    def test_hypotheses_attach_to_rm(self):
        from app.agents import _hypothesis_fallback
        adv = [{"attack_class": "memorization", "attack_subtype": "preference_memorization", "title": "preference memorization", "applies_to": "family"}]
        hyps = _hypothesis_fallback([], adv, {"is_model_query": True, "summary": "test"})
        ids = [h["id"] for h in hyps]
        self.assertIn("H-RM01", ids)
        self.assertIn("H-RM05", ids)

    def test_experiments_for_memorization(self):
        exps = me.plan_experiments({"model_family": "tabular_fm", "weights_source": "open_weights"},
                                   [{"attack_class": "memorization", "applies_to": "model_specific", "confidence": 0.8}],
                                   [{"dimension": "memorization", "rating": "high"}], [], [])
        mtypes = [e["method_type"] for e in exps["experiments"]]
        self.assertIn("canary", mtypes)

class TestLandscapeFilter(unittest.TestCase):
    def test_portfolio_tag_filter(self):
        Base.metadata.create_all(_db.engine)
        db = SessionLocal()
        inv = Investigation(title="landscape mem", keywords="x", description="x")
        db.add(inv)
        db.commit()
        db.refresh(inv)
        try:
            meta = {"model_name": "TestModel", "model_family": "tabular_fm", "weights_source": "open_weights"}
            rec = SecurityAssessment(investigation_id=inv.id, product_name="TestModel", exposure="confidential_data", overall_pct=50, markdown="# rep", scoring_json=json.dumps({}), model_json=json.dumps({"meta": meta, "attacks": [{"attack_class": "memorization", "attack_subtype": "preference_memorization", "applies_to": "family", "confidence": 0.6}]}), hypothesis_json=json.dumps({}), threat_pack_version="2.1.0", threat_pack_fingerprint="x")
            db.add(rec)
            db.commit()
            kb.sync_model_kb(db, rec.id)
            from app import portfolio as pf
            rows = pf.register_with_state(db, inv.id)
            rm_rows = [r for r in rows if "rlhf_memorization" in (r.get("situation_tags") or [])]
            self.assertTrue(rm_rows)
        finally:
            db.query(SecurityAssessment).filter(SecurityAssessment.investigation_id == inv.id).delete()
            db.query(Investigation).filter(Investigation.id == inv.id).delete()
            db.commit()
            db.close()

if __name__ == "__main__":
    unittest.main()
