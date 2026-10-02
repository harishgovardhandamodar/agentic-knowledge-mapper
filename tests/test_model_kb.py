"""Model-security knowledge base: scope partition, idempotent sync, landscape.

The KB's whole claim is that a second assessment of the same model makes the
knowledge base *better* rather than *longer*, and that a reader can always tell
whether a risk is the model's own, inherited from its family, or created by a
composition around it. These tests pin both, plus the rules that keep the KB
honest: no re-scoring, no second scoring engine, cascade never counted as own,
and pending evidence never dressed up as a finding.
"""
import contextlib
import json
import os
import tempfile
import unittest
from unittest import mock
from datetime import datetime, timezone

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-modelkb-"), "test.db"))

from app import database as _db  # noqa: E402
from app import model_eval as me  # noqa: E402
from app import model_kb as kb  # noqa: E402
from app import models as _models  # noqa: E402,F401 -- registers tables
from app.database import SessionLocal  # noqa: E402
from app.models import (Artifact, Investigation, Relationship,  # noqa: E402
                        SecurityAssessment)

_db.init_db()


def _scoring(w1_pct=46.6, **over):
    base = {
        "assessment_path": "model_engineering",
        "w1": {"overall_pct": w1_pct, "coverage_pct": 25.0,
               "model_adv_version": me.MODEL_ADV_VERSION,
               "model_adv_fingerprint": me.model_adv_fingerprint()},
        "w2": {"overall_pct": 60.0, "uncertainty_pct": 50.0,
               "adoption_version": me.ADOPTION_VERSION,
               "adoption_fingerprint": me.adoption_fingerprint()},
        "w3": {"residual_pct": 22.0, "mitigation_version": me.MITIGATION_VERSION,
               "mitigation_fingerprint": me.mitigation_fingerprint()},
    }
    base.update(over)
    return json.dumps(base)


def _loads(text):
    return json.loads(text)


def _model_json(attacks, **over):
    base = {
        "meta": {"model_name": "Acme TabPFN v2", "model_family": "tabular_fm",
                 "weights_source": "open_weights",
                 "training_data_posture": "proprietary",
                 "deployment_pattern": "on_prem",
                 "workflows": ["adversarial_research", "adoption_risk"]},
        "attacks": attacks,
        "dimensions": [{"dimension": "memorization", "rating": "high"},
                       {"dimension": "data_processing", "rating": "unknown"}],
        "mitigation": {"plan": [{"control_id": "MM05", "burden": "medium",
                                 "priority": 1,
                                 "addresses": {"attacks": ["extraction"]}}],
                       "deferred": [{"control_id": "MM04",
                                     "reason": "no output surface"}],
                       "roadmap": {"30d": ["MM05 canary"], "60d": [],
                                   "90d": []}},
        "experiments": [{"id": "EX-01", "title": "canary probe",
                         "method_type": "canary", "effort": "medium",
                         "status": "proposed",
                         "targets": {"attack_classes": ["extraction"],
                                     "hypothesis_ids": ["H-01"]}}],
    }
    base.update(over)
    return json.dumps(base)


class KBTestCase(unittest.TestCase):
    def setUp(self):
        self.db = SessionLocal()
        self.inv = Investigation(title="kb test inv")
        self.db.add(self.inv)
        self.db.commit()
        self.db.refresh(self.inv)
        # one accepted paper, one advisory still in review
        self.paper = Artifact(
            investigation_id=self.inv.id, title="Carlini extracting training data",
            artifact_type="adversarial_paper", review="accepted",
            date_published=datetime(2021, 4, 1, tzinfo=timezone.utc))
        self.advisory = Artifact(
            investigation_id=self.inv.id, title="Vendor advisory CVE-2024-1",
            artifact_type="cve_advisory", review="pending",
            date_published=datetime(2024, 3, 1, tzinfo=timezone.utc))
        self.db.add_all([self.paper, self.advisory])
        self.db.commit()
        self.db.refresh(self.paper)
        self.db.refresh(self.advisory)

    def tearDown(self):
        self.db.query(Relationship).filter(
            Relationship.investigation_id == self.inv.id).delete()
        self.db.query(Artifact).filter(
            Artifact.investigation_id == self.inv.id).delete()
        self.db.query(SecurityAssessment).filter(
            SecurityAssessment.investigation_id == self.inv.id).delete()
        self.db.query(Investigation).filter(
            Investigation.id == self.inv.id).delete()
        self.db.commit()
        self.db.close()

    def _assessment(self, attacks, product="acme-tabpfn-v2",
                    use_case="churn scoring, fine-tuned adapter on our PII",
                    model_json=None, hypothesis=None, w1_pct=46.6, **col):
        rec = SecurityAssessment(
            investigation_id=self.inv.id,
            product_name=product,
            exposure=col.pop("exposure", "restricted_data"),
            use_case=use_case,
            focus_json=json.dumps(col.pop("focus", ["fine-tune"])),
            overall_pct=46.6, inherent_pct=46.6, residual_pct=40.0,
            markdown="# report",
            threat_pack_version="2.1.0",
            threat_pack_fingerprint="19a11481e69d",
            scoring_json=_scoring(w1_pct=w1_pct),
            model_json=model_json if model_json is not None else _model_json(attacks),
            hypothesis_json=json.dumps({"claims": hypothesis if hypothesis is not None
                                        else [{"hypothesis_id": "H-01",
                                               "status": "untested",
                                               "falsifiers": ["canary finds nothing"]}]}),
            **col)
        self.db.add(rec)
        self.db.commit()
        self.db.refresh(rec)
        return rec


class TestScopePartition(KBTestCase):
    def test_scope_mapping_is_deterministic(self):
        self.assertEqual(kb.scope_of_finding(
            {"applies_to": "model_specific"}), ("own", "model_specific"))
        self.assertEqual(kb.scope_of_finding(
            {"applies_to": "family", "attack_class": "extraction"}),
            ("inherited", "family"))
        self.assertEqual(kb.scope_of_finding(
            {"applies_to": "modality"}), ("inherited", "modality"))
        self.assertEqual(kb.scope_of_finding(
            {"attack_class": "cascade"}), ("cascade", "composition"))

    def test_unlabelled_finding_is_not_own(self):
        # An unlabelled finding must not claim model-specific standing: W1's own
        # default weight for it is the modality tier.
        self.assertEqual(kb.scope_of_finding({"attack_class": "extraction"})[0],
                         "inherited")

    def test_register_partitions_own_inherited_cascade(self):
        rec = self._assessment([
            {"attack_id": "MA-01", "attack_class": "extraction",
             "applies_to": "model_specific", "confidence": 0.8,
             "evidence_artifact_ids": [self.paper.id]},
            {"attack_id": "MA-02", "attack_class": "membership_inference",
             "applies_to": "family", "confidence": 0.6,
             "evidence_artifact_ids": [self.advisory.id]},
        ])
        snap = kb.build_snapshot(self.db, rec)
        scopes = {r["attack_class"]: r["scope"] for r in snap["risk_register"]}
        self.assertEqual(scopes["extraction"], "own")
        self.assertEqual(scopes["membership_inference"], "inherited")
        self.assertEqual(scopes["cascade"], "cascade")
        self.assertEqual(snap["counts"]["own"], 1)
        self.assertEqual(snap["counts"]["inherited"], 1)
        self.assertEqual(snap["counts"]["cascade"], 1)

    def test_cascade_is_never_counted_as_own(self):
        """The acceptance criterion that matters most: a fine-tune of a leaky
        base is a different problem from the base being leaky."""
        rec = self._assessment([
            {"attack_id": "MA-01", "attack_class": "extraction",
             "applies_to": "family", "confidence": 0.9},
        ], use_case="adapter fine-tuned from a base model with extraction history")
        snap = kb.build_snapshot(self.db, rec)
        own = [r for r in snap["risk_register"] if r["scope"] == "own"]
        casc = [r for r in snap["risk_register"] if r["scope"] == "cascade"]
        self.assertEqual(own, [], "cascade risk leaked into the own bucket")
        self.assertTrue(casc)
        self.assertTrue(all(r["attack_class"] == "cascade" for r in casc))

    def test_scope_weight_matches_w1_arithmetic(self):
        rec = self._assessment([
            {"attack_id": "MA-01", "attack_class": "extraction",
             "applies_to": "family", "confidence": 0.6},
        ])
        snap = kb.build_snapshot(self.db, rec)
        row = [r for r in snap["risk_register"] if r["attack_class"] == "extraction"][0]
        self.assertEqual(row["scope_weight"], me.scope_weight("family"))
        self.assertLess(row["scope_weight"], me.scope_weight("model_specific"))

    def test_inheritance_override_recorded(self):
        rec = self._assessment([
            {"attack_id": "MA-01", "attack_class": "extraction",
             "applies_to": "family", "confidence": 0.5},
            {"attack_id": "MA-02", "attack_class": "extraction",
             "applies_to": "model_specific", "confidence": 0.9},
        ])
        snap = kb.build_snapshot(self.db, rec)
        inh = snap["inheritance"][0]
        self.assertIn("extraction", inh["inherited_attack_classes"])
        self.assertEqual([o["attack_class"] for o in inh["overrides"]],
                         ["extraction"])


class TestIdempotentSync(KBTestCase):
    def _attacks(self):
        return [
            {"attack_id": "MA-01", "attack_class": "extraction",
             "applies_to": "model_specific", "confidence": 0.8,
             "evidence_artifact_ids": [self.paper.id]},
            {"attack_id": "MA-02", "attack_class": "membership_inference",
             "applies_to": "family", "confidence": 0.6,
             "evidence_artifact_ids": [self.advisory.id]},
        ]

    def test_re_sync_creates_nothing_new(self):
        rec = self._assessment(self._attacks())
        first = kb.sync_model_kb(self.db, rec.id)
        self.assertGreater(first["nodes_created"], 0)
        second = kb.sync_model_kb(self.db, rec.id)
        self.assertEqual(second["nodes_created"], 0)
        self.assertEqual(second["edges_created"], 0)
        self.assertEqual(second["fingerprint"], first["fingerprint"])
        third = kb.sync_model_kb(self.db, rec.id)
        self.assertEqual(third["nodes_created"], 0)
        self.assertEqual(third["edges_created"], 0)

    def test_one_model_node_per_model(self):
        rec = self._assessment(self._attacks())
        kb.sync_model_kb(self.db, rec.id)
        kb.sync_model_kb(self.db, rec.id)
        rows = self.db.query(Artifact).filter(
            Artifact.investigation_id == self.inv.id,
            Artifact.artifact_type == "model").all()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].stable_key, "acme-tabpfn-v2")

    def test_kb_does_not_mint_wrappers_for_its_own_nodes(self):
        """The exploit view reads collected artifacts. If it also read its own
        ``known_issue:*`` nodes, each sync would wrap the previous sync's
        wrapper, forever."""
        rec = self._assessment(self._attacks())
        kb.sync_model_kb(self.db, rec.id)
        n1 = self.db.query(Artifact).filter(
            Artifact.artifact_type == "known_issue").count()
        kb.sync_model_kb(self.db, rec.id)
        kb.sync_model_kb(self.db, rec.id)
        n3 = self.db.query(Artifact).filter(
            Artifact.artifact_type == "known_issue").count()
        self.assertEqual(n1, n3)
        self.assertEqual(n1, 2)  # one per collected reference, not per run

    def test_second_assessment_enriches_same_node(self):
        rec1 = self._assessment(self._attacks())
        kb.sync_model_kb(self.db, rec1.id)
        rec2 = self._assessment(self._attacks(), hypothesis=[
            {"hypothesis_id": "H-02", "status": "contested",
             "falsifiers": ["probe contradicts claim"]}])
        kb.sync_model_kb(self.db, rec2.id)
        model_row = self.db.query(Artifact).filter(
            Artifact.artifact_type == "model").one()
        meta = json.loads(model_row.node_meta)
        self.assertIn(rec1.id, meta["assessment_ids"])
        self.assertIn(rec2.id, meta["assessment_ids"])
        self.assertEqual(model_row.assessment_id, rec2.id)

    def test_product_path_is_skipped(self):
        rec = SecurityAssessment(
            investigation_id=self.inv.id, product_name="Some SaaS assistant",
            exposure="internal", overall_pct=30.0, residual_pct=20.0,
            markdown="# product report",
            scoring_json=json.dumps({"assessment_path": "standard"}),
            controls_json="{}", scoring_json_=None) if False else SecurityAssessment(
            investigation_id=self.inv.id, product_name="Some SaaS assistant",
            exposure="internal", overall_pct=30.0, residual_pct=20.0,
            markdown="# product report",
            scoring_json=json.dumps({"assessment_path": "standard"}))
        self.db.add(rec)
        self.db.commit()
        self.db.refresh(rec)
        out = kb.sync_model_kb(self.db, rec.id)
        self.assertTrue(out["skipped"])
        self.assertEqual(out["nodes_created"], 0)
        self.assertIsNone(rec.kb_json)
        self.assertEqual(self.db.query(Artifact).filter(
            Artifact.artifact_type == "model").count(), 0)


class TestSnapshotHonesty(KBTestCase):
    def test_snapshot_reads_stored_numbers_and_nulls_survive(self):
        rec = self._assessment([
            {"attack_id": "MA-01", "attack_class": "extraction",
             "applies_to": "model_specific", "confidence": 0.8},
        ])
        snap = kb.build_snapshot(self.db, rec)
        self.assertEqual(snap["inventory"]["w1_pct"], 46.6)
        self.assertEqual(snap["inventory"]["w2_pct"], 60.0)
        self.assertIsNone(snap["counts"].get("nothing"))

    def test_no_evidence_keeps_null_score(self):
        rec = self._assessment([], w1_pct=None,
                               use_case="score churn rows in batch", focus=[])
        snap = kb.build_snapshot(self.db, rec)
        self.assertIsNone(snap["inventory"]["w1_pct"])
        self.assertEqual(snap["risk_register"], [])
        self.assertEqual(snap["counts"]["risk_rows"], 0)

    def test_catalog_versions_travel_with_every_row(self):
        rec = self._assessment([
            {"attack_id": "MA-01", "attack_class": "extraction",
             "applies_to": "model_specific", "confidence": 0.8},
        ])
        snap = kb.build_snapshot(self.db, rec)
        for name in ("model_adversarial", "adoption_risk", "model_mitigations",
                     "experiment_plan", "product_threat_pack"):
            self.assertIn(name, snap["catalogs"])
            self.assertIn("version", snap["catalogs"][name])
            self.assertIn("fingerprint", snap["catalogs"][name])
        own = [r for r in snap["risk_register"] if r["scope"] == "own"][0]
        self.assertEqual(own["catalog_version"], me.MODEL_ADV_VERSION)
        self.assertEqual(own["catalog_fingerprint"], me.model_adv_fingerprint())

    def test_fingerprint_changes_when_a_register_row_changes(self):
        rec = self._assessment([
            {"attack_id": "MA-01", "attack_class": "extraction",
             "applies_to": "model_specific", "confidence": 0.8}])
        a = kb.build_snapshot(self.db, rec)["fingerprint"]
        rec.model_json = _model_json([
            {"attack_id": "MA-01", "attack_class": "extraction",
             "applies_to": "model_specific", "confidence": 0.8},
            {"attack_id": "MA-02", "attack_class": "inversion",
             "applies_to": "model_specific", "confidence": 0.7}])
        self.db.commit()
        b = kb.build_snapshot(self.db, rec)["fingerprint"]
        self.assertNotEqual(a, b)

    def test_snapshot_is_stored_on_the_row(self):
        rec = self._assessment([
            {"attack_id": "MA-01", "attack_class": "extraction",
             "applies_to": "model_specific", "confidence": 0.8}])
        out = kb.sync_model_kb(self.db, rec.id)
        self.db.refresh(rec)
        self.assertEqual(rec.kb_fingerprint, out["fingerprint"])
        stored = json.loads(rec.kb_json)
        self.assertEqual(stored["method"], kb.KB_METHOD)
        self.assertGreaterEqual(len(stored["risk_register"]), 1)


class TestLandscape(KBTestCase):
    def _one_model(self):
        rec = self._assessment([
            {"attack_id": "MA-01", "attack_class": "extraction",
             "applies_to": "model_specific", "confidence": 0.8,
             "evidence_artifact_ids": [self.paper.id]},
            {"attack_id": "MA-02", "attack_class": "membership_inference",
             "applies_to": "family", "confidence": 0.6,
             "evidence_artifact_ids": [self.advisory.id]},
        ])
        kb.sync_model_kb(self.db, rec.id)
        return rec

    def test_landscape_counts_match_the_register(self):
        self._one_model()
        land = kb.landscape(self.db, self.inv.id)
        self.assertEqual(land["counts"]["risk_rows"], len(land["risk_register"]))
        for scope in ("own", "inherited", "cascade"):
            self.assertEqual(land["partition"][scope],
                             len(land[scope]), f"{scope} count disagrees")
        self.assertEqual(land["counts"]["own"], len(land["own"]))

    def test_landscape_reads_a_row_that_predates_the_kb(self):
        """An assessment written before the KB existed must still appear: the
        landscape derives its snapshot from stored columns rather than showing
        an empty tab."""
        rec = self._assessment([
            {"attack_id": "MA-01", "attack_class": "extraction",
             "applies_to": "model_specific", "confidence": 0.8}])
        self.assertIsNone(rec.kb_json)
        land = kb.landscape(self.db, self.inv.id)
        self.assertEqual(len(land["inventory"]), 1)
        self.assertGreaterEqual(land["counts"]["own"], 1)

    def test_pending_evidence_is_flagged_not_promoted(self):
        self._one_model()
        land = kb.landscape(self.db, self.inv.id)
        by_class = {r["attack_class"]: r for r in land["risk_register"]}
        self.assertEqual(by_class["extraction"]["evidence_review"], "accepted")
        self.assertEqual(by_class["membership_inference"]["evidence_review"],
                         "pending")
        gaps = [g["kind"] for g in land["gaps"]]
        self.assertIn("evidence_pending", gaps)

    def test_exploit_view_prefers_accepted_and_reports_recency(self):
        self._one_model()
        land = kb.landscape(self.db, self.inv.id)
        rows = {x["label"]: x for x in land["exploits"]}
        self.assertEqual(
            rows["Carlini extracting training data"]["confidence_band"],
            "strong")
        self.assertEqual(
            rows["Vendor advisory CVE-2024-1"]["confidence_band"], "unknown")
        self.assertEqual(
            rows["Carlini extracting training data"]["recency_year"], 2021)

    def test_insights_are_deterministic_and_cite_rows(self):
        self._one_model()
        land = kb.landscape(self.db, self.inv.id)
        again = kb.landscape(self.db, self.inv.id)
        self.assertEqual([c["id"] for c in land["insights"]],
                         [c["id"] for c in again["insights"]])
        ids = {c["id"] for c in land["insights"]}
        self.assertIn("weights-acme-tabpfn-v2", ids)
        self.assertIn("cascade-acme-tabpfn-v2", ids)
        for c in land["insights"]:
            self.assertEqual(c["basis"], "deterministic")

    def test_gap_for_an_unaddressed_own_attack(self):
        rec = self._assessment([
            {"attack_id": "MA-01", "attack_class": "inversion",
             "applies_to": "model_specific", "confidence": 0.9}])
        kb.sync_model_kb(self.db, rec.id)
        land = kb.landscape(self.db, self.inv.id)
        kinds = {g["kind"]: g for g in land["gaps"]}
        self.assertIn("attack_unaddressed", kinds)
        self.assertIn("inversion", kinds["attack_unaddressed"]["label"])
        self.assertEqual(kinds["attack_unaddressed"]["severity"], "high")

    def test_gap_for_a_dimension_left_unknown(self):
        self._one_model()
        land = kb.landscape(self.db, self.inv.id)
        gaps = [g for g in land["gaps"] if g["kind"] == "dimension_unknown"]
        self.assertTrue(gaps)
        self.assertIn("data_processing", gaps[0]["detail"])

    def _named(self, name, version_note=""):
        rec = self._assessment(
            [{"attack_id": "MA-01", "attack_class": "extraction",
              "applies_to": "model_specific", "confidence": 0.8}],
            product=name, use_case="tabular churn scoring" + version_note,
            model_json=_model_json(
                [{"attack_id": "MA-01", "attack_class": "extraction",
                  "applies_to": "model_specific", "confidence": 0.8}],
                meta={"model_name": name, "model_family": "tabular_fm",
                      "weights_source": "open_weights",
                      "deployment_pattern": "on_prem",
                      "training_data_posture": "proprietary",
                      "workflows": ["adversarial_research"]}))
        kb.sync_model_kb(self.db, rec.id)
        return rec

    def test_supersedes_links_versions_of_one_lineage(self):
        self._named("acme-tabpfn-v2")
        self._named("acme-tabpfn-v3")
        land = kb.landscape(self.db, self.inv.id)
        keys = {i["model_key"] for i in land["inventory"]}
        self.assertEqual(keys, {"acme-tabpfn-v2", "acme-tabpfn-v3"})
        edges = kb._supersedes_edges(kb._latest_per_model(
            [kb.build_snapshot(self.db, r) for r in
             self.db.query(SecurityAssessment).all()]))
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0]["source"], "acme-tabpfn-v3")
        self.assertEqual(edges[0]["target"], "acme-tabpfn-v2")
        # and it is persisted, so the Graph tab can show it without re-deriving
        graph = kb.landscape_graph(self.db, self.inv.id)
        sup = [e for e in graph["edges"] if e["type"] == "supersedes"]
        self.assertEqual(len(sup), 1)
        self.assertEqual(sup[0]["payload"]["to_version"], "2")
        self.assertEqual(sup[0]["payload"]["from_version"], "3")
        by_id = {n["stable_key"]: n["id"] for n in graph["nodes"]}
        self.assertEqual(sup[0]["from"], by_id["acme-tabpfn-v3"])
        self.assertEqual(sup[0]["to"], by_id["acme-tabpfn-v2"])

    def test_supersedes_survives_a_resync_without_duplicating(self):
        self._named("acme-tabpfn-v2")
        self._named("acme-tabpfn-v3")
        again = kb.sync_investigation_kb(self.db, self.inv.id)
        self.assertEqual(again["superseded_by_id"] if "superseded_by_id" in again
                         else 0, 0)
        graph = kb.landscape_graph(self.db, self.inv.id)
        sup = [e for e in graph["edges"] if e["type"] == "supersedes"]
        self.assertEqual(len(sup), 1)

    def test_no_supersedes_without_a_version_to_compare(self):
        self._named("acme-tabpfn")
        self._named("acme-tabular")
        edges = kb._supersedes_edges(kb._latest_per_model(
            [kb.build_snapshot(self.db, r) for r in
             self.db.query(SecurityAssessment).all()]))
        self.assertEqual(edges, [])

    def test_latest_assessment_wins_a_repeated_model(self):
        first = self._assessment([
            {"attack_id": "MA-01", "attack_class": "extraction",
             "applies_to": "model_specific", "confidence": 0.8}])
        kb.sync_model_kb(self.db, first.id)
        second = self._assessment([
            {"attack_id": "MA-01", "attack_class": "extraction",
             "applies_to": "model_specific", "confidence": 0.8},
            {"attack_id": "MA-02", "attack_class": "inversion",
             "applies_to": "model_specific", "confidence": 0.7}])
        kb.sync_model_kb(self.db, second.id)
        land = kb.landscape(self.db, self.inv.id)
        self.assertEqual(len(land["inventory"]), 1)
        own = [r for r in land["risk_register"]
               if r["model_key"] == "acme-tabpfn-v2" and r["scope"] == "own"]
        self.assertEqual({r["attack_class"] for r in own},
                         {"extraction", "inversion"})
        self.assertTrue(all(r["assessment_id"] == second.id for r in own))


class TestSelectionGuidance(KBTestCase):
    def _model(self, product, weights, attacks):
        rec = self._assessment(
            attacks, product=product, use_case="churn scoring",
            model_json=_model_json(attacks, meta={
                "model_name": product, "model_family": "tabular_fm",
                "weights_source": weights, "deployment_pattern": "on_prem",
                "training_data_posture": "proprietary",
                "workflows": ["adversarial_research"]}))
        kb.sync_model_kb(self.db, rec.id)
        return rec

    def test_scorecard_is_multi_axis_and_picks_no_winner(self):
        self._model("acme-a", "open_weights", [
            {"attack_id": "MA-01", "attack_class": "extraction",
             "applies_to": "model_specific", "confidence": 0.9}])
        out = kb.compare(self.db, self.inv.id)
        self.assertIsNone(out["ranked"])
        self.assertIn("no single winner", out["note"])
        row = out["models"][0]
        for axis in ("own_high_confidence", "inherited_classes", "cascade_count",
                     "w2_unknown_dimensions", "mm_burden", "experiment_count"):
            self.assertIn(axis, row)

    def test_exclude_open_weights_is_a_hard_gate(self):
        self._model("acme-a", "open_weights", [
            {"attack_id": "MA-01", "attack_class": "extraction",
             "applies_to": "model_specific", "confidence": 0.9}])
        out = kb.compare(self.db, self.inv.id,
                         filters={"exclude_open_weights": True})
        self.assertEqual(out["models"], [])
        self.assertEqual(len(out["excluded"]), 1)
        self.assertIn("open weights excluded",
                      out["excluded"][0]["exclusion_reasons"][0])

    def test_weights_are_optional_and_opt_in(self):
        self._model("acme-a", "api_only", [
            {"attack_id": "MA-01", "attack_class": "extraction",
             "applies_to": "model_specific", "confidence": 0.9}])
        out = kb.compare(self.db, self.inv.id, weights={"own_risk": -2.0})
        self.assertEqual(out["case"], "scorecard")
        self.assertEqual(out["axes_used"], ["own_risk"])
        self.assertEqual(len(out["ranked"]), 1)
        # the contribution is shown, so the number can be re-derived by hand
        self.assertEqual(out["ranked"][0]["contributions"], {"own_risk": -2.0})
        self.assertIn("ranked by the weights", out["note"])

    def test_weighting_shows_contributions_not_just_an_order(self):
        self._model("acme-a", "api_only", [
            {"attack_id": "MA-01", "attack_class": "extraction",
             "applies_to": "model_specific", "confidence": 0.9}])
        self._model("acme-b", "open_weights", [
            {"attack_id": "MA-02", "attack_class": "inversion",
             "applies_to": "model_specific", "confidence": 0.9}])
        out = kb.compare(self.db, self.inv.id,
                         weights={"own_risk": -1.0, "cascade": -3.0})
        self.assertEqual(len(out["ranked"]), 2)
        self.assertEqual([r["rank"] for r in out["ranked"]], [1, 2])
        for r in out["ranked"]:
            self.assertEqual(set(r["contributions"]), {"own_risk", "cascade"})

    def test_an_unknown_axis_or_filter_is_an_error_not_a_silent_no_op(self):
        self._model("acme-a", "api_only", [
            {"attack_id": "MA-01", "attack_class": "extraction",
             "applies_to": "model_specific", "confidence": 0.9}])
        with self.assertRaises(ValueError) as cm:
            kb.compare(self.db, self.inv.id, weights={"vibes": 1.0})
        self.assertIn("vibes", str(cm.exception))
        with self.assertRaises(ValueError) as cm2:
            kb.compare(self.db, self.inv.id, filters={"data_residency": ["eu"]})
        self.assertIn("data_residency", str(cm2.exception))

    def test_decision_is_an_edge_and_keeps_history(self):
        self._model("acme-a", "api_only", [
            {"attack_id": "MA-01", "attack_class": "extraction",
             "applies_to": "model_specific", "confidence": 0.9}])
        out = kb.record_decision(self.db, self.inv.id, "acme-a",
                                 "churn-initiative", "selected", "fox",
                                 "fits the tabular task")
        self.assertEqual(out["relation"], "selected_for")
        again = kb.record_decision(self.db, self.inv.id, "acme-a",
                                   "churn-initiative", "rejected", "fox",
                                   "privacy posture")
        self.assertEqual(again["relation"], "rejected_for")
        # selecting and then rejecting are two facts, not one overwritten fact
        rels = self.db.query(Relationship).filter(
            Relationship.relationship_type.in_(("selected_for",
                                                 "rejected_for"))).all()
        self.assertEqual(len(rels), 2)
        rejected = self.db.query(Relationship).filter(
            Relationship.relationship_type == "rejected_for").one()
        self.assertEqual(json.loads(rejected.payload_json)["decision"],
                         "rejected")
        self.assertEqual(rejected.origin, "manual")

    def test_redeciding_the_same_relation_keeps_the_earlier_record(self):
        self._model("acme-a", "api_only", [
            {"attack_id": "MA-01", "attack_class": "extraction",
             "applies_to": "model_specific", "confidence": 0.9}])
        kb.record_decision(self.db, self.inv.id, "acme-a", "churn",
                           "selected", "fox", "first, on cost")
        kb.record_decision(self.db, self.inv.id, "acme-a", "churn",
                           "selected", "ravi", "again, after the audit")
        rows = self.db.query(Relationship).filter(
            Relationship.relationship_type == "selected_for").all()
        self.assertEqual(len(rows), 1)
        payload = json.loads(rows[0].payload_json)
        self.assertEqual(payload["actor"], "ravi")
        self.assertEqual(payload["history"][0]["actor"], "fox")
        self.assertEqual(payload["history"][0]["rationale"], "first, on cost")

    def test_decision_requires_actor_and_a_real_verdict(self):
        with self.assertRaises(ValueError):
            kb.record_decision(self.db, self.inv.id, "acme-a", "init",
                               "selected", "")
        with self.assertRaises(ValueError):
            kb.record_decision(self.db, self.inv.id, "acme-a", "init",
                               "maybe", "fox")


class TestGraphProjection(KBTestCase):
    def test_graph_is_filtered_to_kb_nodes_and_relations(self):
        self._assessment([
            {"attack_id": "MA-01", "attack_class": "extraction",
             "applies_to": "model_specific", "confidence": 0.8,
             "evidence_artifact_ids": [self.paper.id]},
            {"attack_id": "MA-02", "attack_class": "membership_inference",
             "applies_to": "family", "confidence": 0.6},
        ])
        kb.sync_model_kb(self.db, self.db.query(SecurityAssessment).filter(
            SecurityAssessment.investigation_id == self.inv.id).one().id)
        g = kb.landscape_graph(self.db, self.inv.id)
        kinds = {n["kind"] for n in g["nodes"]}
        self.assertIn("model", kinds)
        self.assertIn("model_family", kinds)
        self.assertIn("attack", kinds)
        # the collected paper itself is not a KB node
        self.assertNotIn(self.paper.id, {n["id"] for n in g["nodes"]})
        node_ids = {n["id"] for n in g["nodes"]}
        for e in g["edges"]:
            self.assertIn(e["from"], node_ids)
            self.assertIn(e["to"], node_ids)
            self.assertIn(e["type"], kb.REL_TYPES)

    def test_risk_edges_carry_scope_payload(self):
        self._assessment([
            {"attack_id": "MA-01", "attack_class": "extraction",
             "applies_to": "model_specific", "confidence": 0.8},
            {"attack_id": "MA-02", "attack_class": "membership_inference",
             "applies_to": "family", "confidence": 0.6},
        ])
        kb.sync_model_kb(self.db, self.db.query(SecurityAssessment).filter(
            SecurityAssessment.investigation_id == self.inv.id).one().id)
        g = kb.landscape_graph(self.db, self.inv.id)
        own = [e for e in g["edges"] if e["type"] == "own_risk"]
        self.assertEqual(len(own), 1)
        self.assertEqual(own[0]["payload"]["scope"], "own")
        self.assertEqual(own[0]["payload"]["evidence_scope"], "model_specific")
        inh = [e for e in g["edges"] if e["type"] == "inherits_risk_from"]
        self.assertTrue(inh)
        self.assertEqual(inh[0]["payload"]["scope"], "inherited")

    def test_cascade_edge_is_not_own_risk(self):
        self._assessment([
            {"attack_id": "MA-01", "attack_class": "extraction",
             "applies_to": "family", "confidence": 0.9}],
            use_case="adapter fine-tuned from a leaky base model")
        kb.sync_model_kb(self.db, self.db.query(SecurityAssessment).filter(
            SecurityAssessment.investigation_id == self.inv.id).one().id)
        g = kb.landscape_graph(self.db, self.inv.id)
        scopes = {e["type"]: e["payload"].get("scope")
                  for e in g["edges"] if e["payload"].get("scope")}
        self.assertIn("cascade", scopes.values())
        cascade_edges = [e for e in g["edges"]
                         if e["payload"].get("scope") == "cascade"]
        self.assertTrue(cascade_edges)
        self.assertFalse([e for e in cascade_edges if e["type"] == "own_risk"])

    def test_relation_vocabulary_rejects_unknown_names(self):
        self.assertEqual(kb.canon_relation("inherits-from"),
                         "inherits_risk_from")
        self.assertEqual(kb.canon_relation("vulnerable_to"), "vulnerable_to")
        self.assertEqual(kb.canon_relation("exploits_everything"), "")


class TestFieldHonesty(KBTestCase):
    def test_field_basis_distinguishes_explicit_from_unknown(self):
        self.assertEqual(kb.field_basis("open_weights"), "explicit")
        self.assertEqual(kb.field_basis("unknown"), "unknown")
        self.assertEqual(kb.field_basis(""), "unknown")
        self.assertEqual(kb.field_basis("other"), "unknown")

    def test_inventory_marks_unknown_fields(self):
        rec = self._assessment([
            {"attack_id": "MA-01", "attack_class": "extraction",
             "applies_to": "model_specific", "confidence": 0.8}])
        inv = kb.build_snapshot(self.db, rec)["inventory"]
        self.assertEqual(inv["field_basis"]["weights_source"], "explicit")
        self.assertEqual(inv["field_basis"]["modality"], "unknown")

    def test_cascade_signal_records_the_text_it_inferred_from(self):
        sigs = kb.cascade_signals({}, use_case="we plan an adapter fine-tune")
        self.assertEqual([s["mechanism"] for s in sigs], ["fine_tune"])
        self.assertTrue(sigs[0]["term"])
        self.assertIn(sigs[0]["basis"], ("explicit", "inferred"))

    def test_no_cascade_signal_when_the_brief_says_none(self):
        self.assertEqual(kb.cascade_signals({}, use_case="score churn rows"),
                         [])


class TestLandscapeEndpoints(KBTestCase):
    """The API surface the Landscape tab talks to.

    Pinned at the endpoint because these are the reads that must never start
    scoring: the tests assert stored-row provenance (kb_synced flips only when
    a sync happened) and that the decision endpoint needs a real actor.
    """

    def setUp(self):
        super().setUp()
        from fastapi.testclient import TestClient
        from app.main import app as fastapi_app
        self.client = TestClient(fastapi_app)
        self.client.__enter__()

    def tearDown(self):
        try:
            self.client.__exit__(None, None, None)
        finally:
            super().tearDown()

    def _synced(self):
        rec = self._assessment([
            {"attack_id": "MA-01", "attack_class": "extraction",
             "applies_to": "model_specific", "confidence": 0.8}])
        kb.sync_model_kb(self.db, rec.id)
        return rec

    def test_landscape_returns_the_partition_and_gaps(self):
        self._synced()
        r = self.client.get("/api/security/landscape",
                            params={"investigation_id": self.inv.id})
        self.assertEqual(r.status_code, 200)
        p = r.json()
        self.assertEqual(p["method"], kb.KB_METHOD)
        self.assertEqual(p["version"], kb.KB_VERSION)
        self.assertEqual(len(p["inventory"]), 1)
        self.assertGreaterEqual(p["partition"]["own"], 1)
        self.assertIn("coverage_gaps", p)
        self.assertTrue(all(a["kb_synced"] for a in p["assessments"]))

    def test_landscape_is_empty_not_broken_for_a_fresh_investigation(self):
        r = self.client.get("/api/security/landscape",
                            params={"investigation_id": self.inv.id})
        self.assertEqual(r.status_code, 200)
        p = r.json()
        self.assertEqual(p["inventory"], [])
        self.assertEqual(p["risk_register"], [])
        self.assertEqual(p["counts"]["models"], 0)

    def test_landscape_404s_on_an_unknown_investigation(self):
        r = self.client.get("/api/security/landscape",
                            params={"investigation_id": 999999})
        self.assertEqual(r.status_code, 404)

    def test_landscape_graph_returns_kb_shapes_and_payloads(self):
        self._synced()
        r = self.client.get("/api/security/landscape/graph",
                            params={"investigation_id": self.inv.id})
        self.assertEqual(r.status_code, 200)
        g = r.json()
        self.assertIn("model", g["kinds"])
        self.assertIn("own_risk", g["relations"])
        self.assertIn("cascades_from", g["relations"])
        self.assertTrue(any(e["payload"].get("scope") for e in g["edges"]))
        # the same edges under the generic graph's key, so a client can read
        # either shape without translating
        self.assertEqual(len(g["edges"]), len(g["relationships"]))

    def test_compare_returns_a_comparison_and_ranks_nothing_by_default(self):
        self._synced()
        r = self.client.post("/api/security/landscape/compare",
                             json={"investigation_id": self.inv.id,
                                   "model_keys": [], "filters": {},
                                   "weights": {}})
        self.assertEqual(r.status_code, 200)
        p = r.json()
        self.assertEqual(p["case"], "comparison")
        self.assertIsNone(p["ranked"])
        self.assertTrue(p["models"])

    def test_compare_ranks_only_when_weights_are_supplied(self):
        self._synced()
        r = self.client.post("/api/security/landscape/compare",
                             json={"investigation_id": self.inv.id,
                                   "model_keys": [], "filters": {},
                                   "weights": {"own_risk": -1.0, "experiments": 0.5}})
        self.assertEqual(r.status_code, 200)
        p = r.json()
        self.assertEqual(p["case"], "scorecard")
        self.assertTrue(p["ranked"])
        self.assertEqual(p["axes_used"], ["experiments", "own_risk"])
        self.assertTrue(p["ranked"][0]["contributions"])
        self.assertIn(p["ranked"][0]["model_key"],
                      [m["model_key"] for m in p["models"]])

    def test_compare_reports_an_excluded_model_with_its_reason(self):
        self._synced()
        r = self.client.post("/api/security/landscape/compare",
                             json={"investigation_id": self.inv.id,
                                   "model_keys": [],
                                   "filters": {"exposure": ["public_data"]},
                                   "weights": {}})
        self.assertEqual(r.status_code, 200)
        p = r.json()
        self.assertEqual(p["models"], [])
        self.assertTrue(p["excluded"])
        reasons = " ".join(p["excluded"][0]["exclusion_reasons"])
        self.assertIn("exposure", reasons)

    def test_decision_requires_an_actor(self):
        self._synced()
        r = self.client.post("/api/security/landscape/decision",
                             json={"investigation_id": self.inv.id,
                                   "model_key": "acme-tabpfn-v2",
                                   "initiative_key": "churn-initiative",
                                   "decision": "selected", "actor": "",
                                   "rationale": "no reason"})
        self.assertEqual(r.status_code, 422)
        self.assertIn("actor", r.json()["detail"].lower())

    def test_decision_writes_an_edge_and_shows_up_in_the_landscape(self):
        self._synced()
        r = self.client.post("/api/security/landscape/decision",
                             json={"investigation_id": self.inv.id,
                                   "model_key": "acme-tabpfn-v2",
                                   "initiative_key": "churn-initiative",
                                   "decision": "selected", "actor": "fox",
                                   "rationale": "cost and auditability"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["relation"], "selected_for")
        again = self.client.get("/api/security/landscape",
                                params={"investigation_id": self.inv.id}).json()
        self.assertEqual(len(again["decisions"]), 1)
        self.assertEqual(again["decisions"][0]["actor"], "fox")

    def test_decision_rejects_an_unknown_decision(self):
        self._synced()
        r = self.client.post("/api/security/landscape/decision",
                             json={"investigation_id": self.inv.id,
                                   "model_key": "acme-tabpfn-v2",
                                   "initiative_key": "x",
                                   "decision": "deferred", "actor": "fox"})
        self.assertEqual(r.status_code, 422)

    def test_assessment_sync_endpoint_is_idempotent(self):
        rec = self._assessment([
            {"attack_id": "MA-01", "attack_class": "extraction",
             "applies_to": "model_specific", "confidence": 0.8}])
        url = f"/api/security/assessments/{rec.id}/kb/sync"
        first = self.client.post(url).json()
        second = self.client.post(url).json()
        self.assertEqual(first["fingerprint"], second["fingerprint"])
        self.assertEqual(second["nodes_created"], 0)
        self.assertEqual(second["edges_created"], 0)

    def test_assessment_sync_404s_when_the_row_is_gone(self):
        self.assertEqual(
            self.client.post("/api/security/assessments/999999/kb/sync").status_code,
            404)

    def test_landscape_sync_skips_a_product_assessment(self):
        product = SecurityAssessment(
            investigation_id=self.inv.id, product_name="our fraud classifier",
            use_case="score card transactions",
            focus_json=json.dumps([]),
            scoring_json=json.dumps({"assessment_path": "standard"}),
            overall_pct=40.0, inherent_pct=40.0, residual_pct=30.0,
            markdown="# product report")
        self.db.add(product)
        self.db.commit()
        self._synced()
        r = self.client.post("/api/security/landscape/sync",
                             params={"investigation_id": self.inv.id})
        self.assertEqual(r.status_code, 200)
        results = r.json()["results"]
        self.assertTrue(any(x.get("skipped") for x in results),
                        "a product assessment must be skipped, not mapped")
        self.assertTrue(any(not x.get("skipped") for x in results))

    def test_compare_422s_on_an_unknown_filter_or_axis(self):
        self._synced()
        r = self.client.post("/api/security/landscape/compare",
                             json={"investigation_id": self.inv.id,
                                   "model_keys": [], "weights": {"vibes": 1.0},
                                   "filters": {}})
        self.assertEqual(r.status_code, 422)
        self.assertIn("vibes", r.json()["detail"])
        r2 = self.client.post("/api/security/landscape/compare",
                              json={"investigation_id": self.inv.id,
                                    "model_keys": [], "weights": {},
                                    "filters": {"data_residency": ["eu"]}})
        self.assertEqual(r2.status_code, 422)
        self.assertIn("data_residency", r2.json()["detail"])

    def test_decision_lands_in_the_ledger_with_the_requests_session(self):
        from app import ledger as L
        from app.ledger_api import ACTOR_HEADER, SESSION_HEADER
        self._synced()
        key = "kb-decision-sitting"
        r = self.client.post("/api/security/landscape/decision",
                             headers={SESSION_HEADER: key,
                                      ACTOR_HEADER: "fox"},
                             json={"investigation_id": self.inv.id,
                                   "model_key": "acme-tabpfn-v2",
                                   "initiative_key": "churn-initiative",
                                   "decision": "selected", "actor": "fox",
                                   "rationale": "cost and auditability"})
        self.assertEqual(r.status_code, 200)
        sid = L.resolve_session(key)
        self.assertTrue(sid, "the request must open a ledger session")
        acts = L.session_insights(sid)["human_actions"]
        mine = [a for a in acts if a.get("intent") == "model_selected"]
        self.assertEqual(len(mine), 1,
                         f"one decision, one ledger action: {acts}")
        self.assertEqual(mine[0]["actor"], "fox")

    def test_a_decision_cannot_be_signed_as_somebody_else(self):
        """The payload may name an actor; the ledger signs the request."""
        from app import ledger as L
        from app.ledger_api import ACTOR_HEADER, SESSION_HEADER
        self._synced()
        key = "kb-impersonation-sitting"
        r = self.client.post("/api/security/landscape/decision",
                             headers={SESSION_HEADER: key,
                                      ACTOR_HEADER: "fox"},
                             json={"investigation_id": self.inv.id,
                                   "model_key": "acme-tabpfn-v2",
                                   "initiative_key": "churn-initiative",
                                   "decision": "selected", "actor": "ravi",
                                   "rationale": "signed as somebody else"})
        self.assertEqual(r.status_code, 200)
        sid = L.resolve_session(key)
        acts = L.session_insights(sid)["human_actions"]
        self.assertEqual(len(acts), 1)
        # signed by fox: the edge keeps the declared name, the trail does not
        self.assertEqual(acts[0]["actor"], "fox")


class TestDerivedExperimentPlan(KBTestCase):
    """A row with no stored experiment plan still shows what is planned.

    Derived with the same deterministic planner the engineering path uses, from
    the row's own stored columns -- no agent run, no re-score.
    """

    def test_planned_experiments_appear_without_a_stored_plan(self):
        # the fixture stores a plan; drop it to model a row that never had one
        rec = self._assessment([
            {"attack_id": "MA-01", "attack_class": "extraction",
             "applies_to": "model_specific", "confidence": 0.8}],
            model_json=_model_json([
                {"attack_id": "MA-01", "attack_class": "extraction",
                 "applies_to": "model_specific", "confidence": 0.8}],
                experiments=[]))
        self.assertEqual(json.loads(rec.model_json)["experiments"], [])
        snap = kb.build_snapshot(self.db, rec)
        self.assertTrue(snap["experiments"],
                        "attacks plus claims are enough to plan a probe")
        self.assertTrue(snap["counts"]["experiments"])

    def test_a_stored_plan_wins_over_the_derived_one(self):
        stored = [{"id": "EX-99", "title": "ours", "method_type": "probe",
                   "status": "planned",
                   "targets": {"risk_ids": ["r-1"], "hypothesis_ids": ["H-01"],
                               "dimension_ids": []}}]
        rec = self._assessment(
            [{"attack_id": "MA-01", "attack_class": "extraction",
              "applies_to": "model_specific", "confidence": 0.8}],
            model_json=_model_json([
                {"attack_id": "MA-01", "attack_class": "extraction",
                 "applies_to": "model_specific", "confidence": 0.8}],
                experiments=stored))
        snap = kb.build_snapshot(self.db, rec)
        self.assertEqual([e["id"] for e in snap["experiments"]], ["EX-99"])

    def test_planned_experiments_reach_the_graph_and_the_scorecard(self):
        rec = self._assessment(
            [{"attack_id": "MA-01", "attack_class": "extraction",
              "applies_to": "model_specific", "confidence": 0.8}],
            model_json=_model_json([
                {"attack_id": "MA-01", "attack_class": "extraction",
                 "applies_to": "model_specific", "confidence": 0.8}],
                experiments=[]))
        kb.sync_model_kb(self.db, rec.id)
        g = kb.landscape_graph(self.db, self.inv.id)
        self.assertTrue([e for e in g["edges"] if e["type"] == "tested_by"])
        out = kb.compare(self.db, self.inv.id,
                         weights={"experiments": 1.0})
        self.assertGreater(out["ranked"][0]["contributions"]["experiments"], 0)

    def test_a_plan_that_could_not_be_planned_is_reported_not_hidden(self):
        rec = self._assessment([
            {"attack_id": "MA-01", "attack_class": "extraction",
             "applies_to": "model_specific", "confidence": 0.8}],
            model_json=_model_json([
                {"attack_id": "MA-01", "attack_class": "extraction",
                 "applies_to": "model_specific", "confidence": 0.8}],
                experiments=[]))
        snap = kb.build_snapshot(self.db, rec)
        self.assertEqual(snap["experiment_plan_error"], "")
        real = me.plan_experiments

        def broken(*a, **kw):
            raise RuntimeError("planner unavailable")

        me.plan_experiments = broken
        try:
            snap2 = kb.build_snapshot(self.db, rec)
        finally:
            me.plan_experiments = real
        self.assertEqual(snap2["experiments"], [])
        self.assertIn("planner unavailable", snap2["experiment_plan_error"])


class TestPipelineSyncHook(KBTestCase):
    """The assessment pipeline syncs the KB; a KB failure costs nothing.

    Drives the real ``run_security_assessment`` with only the agent's model call
    stubbed, because the claim under test is "an assessment that completes
    leaves the KB up to date" -- and the hook inside that function is the only
    thing that makes it true.
    """

    def _run(self, sync_side_effect=None, product="acme-tabpfn-v2",
             model=True):
        from app import security_agent as sa
        from app.models import AgentRun, AgentEvent
        params = {"product_name": product,
                  "use_case": "churn scoring, fine-tuned adapter on our PII",
                  "focus": ["fine-tune"], "exposure": "restricted_data"}
        run = AgentRun(investigation_id=self.inv.id, trigger="security",
                       status="running", plan=json.dumps(params))
        self.db.add(run)
        self.db.commit()
        self.db.refresh(run)
        attacks = [{"attack_id": "MA-01", "attack_class": "extraction",
                    "applies_to": "model_specific", "confidence": 0.8}]
        # the engine's own result shape: the pipeline reads these keys, so a
        # stub with different names would test nothing about the real path
        fake = {
            "product_name": product,
            "product_url": "",
            "exposure": "restricted_data",
            "overall_pct": 46.6,
            "inherent_pct": 46.6,
            "residual_pct": 40.0,
            "posture": "exposed",
            "markdown": "# model report",
            "diagrams": [],
            "threats": [],
            "perspectives": [],
            "evidence": [],
            "queries_run": [],
            "known_exploits": [],
            "scope": "",
            "exec_paragraph": "",
            "a2a_task_id": "",
            "a2a_trace": [],
            "scoring": (_loads(_scoring()) if model
                        else {"assessment_path": "standard"}),
            "model_meta": ({"model_name": product,
                            "model_family": "tabular_fm",
                            "weights_source": "open_weights",
                            "deployment_pattern": "on_prem",
                            "training_data_posture": "proprietary",
                            "workflows": ["adversarial_research"]}
                           if model else {}),
            "model_attacks": attacks if model else [],
            "adoption_dimensions": ([{"dimension": "memorization",
                                      "rating": "high"}] if model else []),
            "mitigation": {"plan": []},
            "experiments": [],
            "hypotheses": ([{"hypothesis_id": "H-01", "status": "untested",
                             "falsifiers": ["canary finds nothing"]}]
                           if model else []),
        }
        # no polling worker: this test calls the persist path directly, and a
        # live worker would race this run and leave threads behind the suite
        ctxs = [mock.patch.object(sa.sec_engine, "build_assessment",
                                  return_value=fake),
                mock.patch.object(sa, "_ensure_worker", lambda: None)]
        if sync_side_effect is not None:
            ctxs.append(mock.patch("app.model_kb.sync_model_kb",
                                   sync_side_effect))
        with contextlib.ExitStack() as stack:
            for c in ctxs:
                stack.enter_context(c)
            sa.run_security_assessment(run.id, params)
        self.db.expire_all()
        return (self.db.query(SecurityAssessment).filter(
                    SecurityAssessment.investigation_id == self.inv.id).first(),
                self.db.query(AgentEvent).filter(
                    AgentEvent.run_id == run.id).all())

    def test_a_completed_assessment_leaves_the_kb_up_to_date(self):
        rec, events = self._run()
        self.assertIsNotNone(rec, "the assessment row must survive")
        self.assertIsNotNone(rec.kb_json, "the hook must sync the KB")
        self.assertTrue(rec.kb_fingerprint)
        self.assertTrue([e for e in events
                         if "Knowledge base synced" in (e.message or "")],
                        "the sync must be visible in the run's events")
        land = kb.landscape(self.db, self.inv.id)
        self.assertEqual(len(land["inventory"]), 1)
        self.assertGreaterEqual(land["partition"]["own"], 1)

    def test_a_kb_failure_keeps_the_assessment_and_says_so(self):
        rec, events = self._run(
            sync_side_effect=RuntimeError("kb offline"))
        self.assertIsNotNone(rec, "a KB failure must not cost the assessment")
        self.assertEqual(rec.markdown, "# model report")
        self.assertIsNone(rec.kb_json)
        self.assertTrue([e for e in events
                         if "Knowledge base sync failed" in (e.message or "")],
                        "a silent failure would leave the operator guessing")
        # and it is repairable from stored columns, not a lost row
        healed = kb.sync_model_kb(self.db, rec.id)
        self.assertFalse(healed.get("skipped"))
        self.assertGreater(healed["nodes_created"], 0)

    def test_a_product_assessment_is_not_mapped_into_the_model_kb(self):
        # what the engine returns for a non-model subject: no model_meta, and
        # the standard path recorded on the row
        rec, events = self._run(product="our checkout page", model=False)
        self.assertIsNotNone(rec)
        self.assertIsNone(rec.kb_json,
                          "a product assessment must not create model nodes")
        self.assertEqual(kb.landscape(self.db, self.inv.id)["inventory"], [])
class TestPipelineSyncHook(KBTestCase):
    """The assessment pipeline syncs the KB; a KB failure costs nothing.

    Drives the real ``run_security_assessment`` with only the agent's model call
    stubbed, because the claim under test is "an assessment that completes
    leaves the KB up to date" -- and the hook inside that function is the only
    thing that makes it true.
    """

    def _run(self, sync_side_effect=None, product="acme-tabpfn-v2",
             model=True):
        from app import security_agent as sa
        from app.models import AgentRun, AgentEvent
        params = {"product_name": product,
                  "use_case": "churn scoring, fine-tuned adapter on our PII",
                  "focus": ["fine-tune"], "exposure": "restricted_data"}
        run = AgentRun(investigation_id=self.inv.id, trigger="security",
                       status="running", plan=json.dumps(params))
        self.db.add(run)
        self.db.commit()
        self.db.refresh(run)
        attacks = [{"attack_id": "MA-01", "attack_class": "extraction",
                    "applies_to": "model_specific", "confidence": 0.8}]
        # the engine's own result shape: the pipeline reads these keys, so a
        # stub with different names would test nothing about the real path
        fake = {
            "product_name": product,
            "product_url": "",
            "exposure": "restricted_data",
            "overall_pct": 46.6,
            "inherent_pct": 46.6,
            "residual_pct": 40.0,
            "posture": "exposed",
            "markdown": "# model report",
            "diagrams": [],
            "threats": [],
            "perspectives": [],
            "evidence": [],
            "queries_run": [],
            "known_exploits": [],
            "scope": "",
            "exec_paragraph": "",
            "a2a_task_id": "",
            "a2a_trace": [],
            "scoring": (_loads(_scoring()) if model
                        else {"assessment_path": "standard"}),
            "model_meta": ({"model_name": product,
                            "model_family": "tabular_fm",
                            "weights_source": "open_weights",
                            "deployment_pattern": "on_prem",
                            "training_data_posture": "proprietary",
                            "workflows": ["adversarial_research"]}
                           if model else {}),
            "model_attacks": attacks if model else [],
            "adoption_dimensions": ([{"dimension": "memorization",
                                      "rating": "high"}] if model else []),
            "mitigation": {"plan": []},
            "experiments": [],
            "hypotheses": ([{"hypothesis_id": "H-01", "status": "untested",
                             "falsifiers": ["canary finds nothing"]}]
                           if model else []),
        }
        # no polling worker: this test calls the persist path directly, and a
        # live worker would race this run and leave threads behind the suite
        ctxs = [mock.patch.object(sa.sec_engine, "build_assessment",
                                  return_value=fake),
                mock.patch.object(sa, "_ensure_worker", lambda: None)]
        if sync_side_effect is not None:
            ctxs.append(mock.patch("app.model_kb.sync_model_kb",
                                   sync_side_effect))
        with contextlib.ExitStack() as stack:
            for c in ctxs:
                stack.enter_context(c)
            sa.run_security_assessment(run.id, params)
        self.db.expire_all()
        return (self.db.query(SecurityAssessment).filter(
                    SecurityAssessment.investigation_id == self.inv.id).first(),
                self.db.query(AgentEvent).filter(
                    AgentEvent.run_id == run.id).all())

    def test_a_completed_assessment_leaves_the_kb_up_to_date(self):
        rec, events = self._run()
        self.assertIsNotNone(rec, "the assessment row must survive")
        self.assertIsNotNone(rec.kb_json, "the hook must sync the KB")
        self.assertTrue(rec.kb_fingerprint)
        self.assertTrue([e for e in events
                         if "Knowledge base synced" in (e.message or "")],
                        "the sync must be visible in the run's events")
        land = kb.landscape(self.db, self.inv.id)
        self.assertEqual(len(land["inventory"]), 1)
        self.assertGreaterEqual(land["partition"]["own"], 1)

    def test_a_kb_failure_keeps_the_assessment_and_says_so(self):
        rec, events = self._run(
            sync_side_effect=RuntimeError("kb offline"))
        self.assertIsNotNone(rec, "a KB failure must not cost the assessment")
        self.assertEqual(rec.markdown, "# model report")
        self.assertIsNone(rec.kb_json)
        self.assertTrue([e for e in events
                         if "Knowledge base sync failed" in (e.message or "")],
                        "a silent failure would leave the operator guessing")
        # and it is repairable from stored columns, not a lost row
        healed = kb.sync_model_kb(self.db, rec.id)
        self.assertFalse(healed.get("skipped"))
        self.assertGreater(healed["nodes_created"], 0)

    def test_a_product_assessment_is_not_mapped_into_the_model_kb(self):
        # what the engine returns for a non-model subject: no model_meta, and
        # the standard path recorded on the row
        rec, events = self._run(product="our checkout page", model=False)
        self.assertIsNotNone(rec)
        self.assertIsNone(rec.kb_json,
                          "a product assessment must not create model nodes")
        self.assertEqual(kb.landscape(self.db, self.inv.id)["inventory"], [])
