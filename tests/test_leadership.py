"""Leadership dashboard views and the acceptance workflow.

Run with:  python3 -m pytest tests/test_leadership.py -q

The views are tested against a seeded database rather than a fixture blob,
because the behaviour under test is mostly *joining* correctly: a residual is
only meaningful next to its evidence confidence and gate status, and two
products in one investigation must not collapse into a single headline row.
"""
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

# Pinned before the app import: app.database reads the URL at import time, and
# a test run must never touch the developer's working database.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.gettempdir(), "akm_test_leadership.db"))

from app import assurance as A
from app import leadership as LD
from app.database import SessionLocal, init_db
from app.models import (AgentRun, Artifact, Explanation, Investigation,
                        SecurityAssessment)

NOW = datetime.now(timezone.utc)


def _assurance(**over) -> dict:
    base = {
        "assessed": True,
        "evidence_confidence": 0.31,
        "verified": {"residual_pct": 62.7, "headline": "verified"},
        "headline_layer": "verified",
        "control_attestation": {
            "MDR-AI-001": {"status": "evidenced", "evidence_ids": [1]},
            "MDR-AI-014": {"status": "declared", "evidence_ids": []},
            "MDR-AI-022": {"status": "unknown", "evidence_ids": []},
        },
        "architecture_gate": {"gate_blocked_applied": True,
                              "banner": "Scoring returned to inherent for 3 threats",
                              "open_items": ["no-logging", "no-retention"]},
        "forensics": {"reconstructable": False, "score": 21.0, "band": "partial",
                      "not_found": ["prompt_hash"]},
        "blast_radius": {"quantified": True, "records_at_risk": 250_000,
                         "residual_pct": 62.7,
                         "inventory": {"restricted_assets": 4,
                                       "confidential_assets": 9,
                                       "privileged_users": 180},
                         "summary": "4 restricted / 9 confidential / 180 privileged"},
        "gates_open": ["evidence_threshold", "architecture_completeness"],
        "decision": {"decision": A.DECISION_REJECT,
                     "headline": "Reject until architecture gate closed"},
        "pending_evidence": {"share_of_credit_pct": 100},
    }
    base.update(over)
    return base


def _row(db, inv_id, *, name, tier, run_id, verified, confidence,
         exposure_assurance=None, days_ago=5, markdown="# stub"):
    """One assessment row with a stored assurance pass."""
    ens = exposure_assurance or _assurance()
    rec = SecurityAssessment(
        investigation_id=inv_id, run_id=run_id, product_name=name,
        product_family=name.lower(), exposure=tier, inherent_pct=100.0,
        residual_pct=35.4, overall_pct=35.4, evidence_confidence=confidence,
        assurance_json=json.dumps(ens),
        scoring_json=json.dumps({"assessment_path": "standard"}),
        markdown=markdown, threat_pack_version="2024.1",
        created_at=NOW - timedelta(days=days_ago))
    db.add(rec)
    # Committed here because the session is built with autoflush=False: the
    # views read through queries, so uncommitted rows are invisible to them.
    db.commit()
    return rec


class LeadershipTestBase(unittest.TestCase):
    def setUp(self):
        init_db()
        self.db = SessionLocal()
        for m in (SecurityAssessment, Artifact, AgentRun, Explanation, Investigation):
            self.db.query(m).delete()
        self.db.commit()
        self.inv = Investigation(title="ACME Support Copilot")
        self.db.add(self.inv)
        self.db.commit()

    def tearDown(self):
        self.db.close()


class TestRiskPosition(LeadershipTestBase):
    def test_residual_is_reported_with_confidence_and_gate_status(self):
        _row(self.db, self.inv.id, name="restricted copilot",
             tier="restricted_data", run_id=1, verified=62.7, confidence=0.31)
        rp = LD.risk_position(self.db)
        self.assertTrue(rp["tiers"])
        self.assertEqual(rp["tiers"][0]["mean_verified_residual"], 62.7)
        # The confidence figure travels with the number, never separately.
        self.assertIsNotNone(rp["evidence_confidence"]["mean_pct"])
        self.assertEqual(rp["evidence_confidence"]["distribution"]["20-40%"], 1)

    def test_tiers_are_separated_not_averaged(self):
        _row(self.db, self.inv.id, name="restricted copilot", tier="restricted_data",
             run_id=1, verified=62.7, confidence=0.31)
        _row(self.db, self.inv.id, name="public faq", tier="public", run_id=2,
             verified=12.0, confidence=0.86,
             exposure_assurance=_assurance(
                 evidence_confidence=0.86,
                 verified={"residual_pct": 12.0},
                 architecture_gate={"gate_blocked_applied": False, "open_items": []},
                 decision={"decision": A.DECISION_ACCEPT}))
        rp = LD.risk_position(self.db)
        tiers = {t["tier"]: t for t in rp["tiers"]}
        self.assertEqual(set(tiers), {"restricted_data", "public"})
        self.assertEqual(tiers["public"]["mean_verified_residual"], 12.0)
        self.assertEqual(tiers["restricted_data"]["mean_verified_residual"], 62.7)

    def test_two_products_in_one_investigation_do_not_collapse(self):
        _row(self.db, self.inv.id, name="copilot a", tier="restricted_data",
             run_id=1, verified=62.7, confidence=0.31)
        _row(self.db, self.inv.id, name="copilot b", tier="restricted_data",
             run_id=2, verified=40.0, confidence=0.5)
        rp = LD.risk_position(self.db)
        self.assertEqual(rp["assessments"], 2)

    def test_rerun_supersedes_the_previous_row_for_one_product(self):
        _row(self.db, self.inv.id, name="copilot", tier="restricted_data",
             run_id=1, verified=62.7, confidence=0.31, days_ago=200)
        _row(self.db, self.inv.id, name="copilot", tier="restricted_data",
             run_id=2, verified=20.0, confidence=0.8, days_ago=3,
             exposure_assurance=_assurance(verified={"residual_pct": 20.0},
                                           evidence_confidence=0.8,
                                           architecture_gate={
                                               "gate_blocked_applied": False,
                                               "open_items": []}))
        rp = LD.risk_position(self.db)
        self.assertEqual(rp["assessments"], 1)
        self.assertEqual(rp["tiers"][0]["mean_verified_residual"], 20.0)

    def test_explicit_supersedes_id_drops_the_parent(self):
        parent = _row(self.db, self.inv.id, name="copilot", tier="public",
                      run_id=1, verified=50.0, confidence=0.5, days_ago=100)
        self.db.commit()
        _row(self.db, self.inv.id, name="copilot", tier="public", run_id=2,
             verified=10.0, confidence=0.9, days_ago=2,
             exposure_assurance=_assurance(verified={"residual_pct": 10.0}))
        child = self.db.query(SecurityAssessment).filter(
            SecurityAssessment.run_id == 2).one()
        child.supersedes_id = parent.id
        self.db.commit()
        rp = LD.risk_position(self.db)
        self.assertEqual(rp["tiers"][0]["mean_verified_residual"], 10.0)

    def test_architecture_gaps_are_ranked(self):
        _row(self.db, self.inv.id, name="a", tier="restricted_data", run_id=1,
             verified=62.7, confidence=0.3)
        rp = LD.risk_position(self.db)
        self.assertEqual(rp["architecture_gaps"][0]["item"], "no-logging")
        self.assertEqual(rp["architecture_gaps"][0]["assessments"], 1)

    def test_top_threats_carry_verified_and_declared_side_by_side(self):
        rec = _row(self.db, self.inv.id, name="a", tier="restricted_data",
                   run_id=1, verified=62.7, confidence=0.31)
        rec.threats_json = json.dumps([{
            "id": "T02", "title": "Model extraction", "verified_residual": 62.7,
            "declared_residual": 30.0, "coverage_confidence_pct": 21,
            "forced_to_inherent": True}])
        self.db.commit()
        top = LD.risk_position(self.db)["top_residual_threats"][0]
        self.assertEqual(top["verified_residual"], 62.7)
        self.assertEqual(top["declared_residual"], 30.0)
        self.assertTrue(top["forced_to_inherent"])


class TestDecisionQueue(LeadershipTestBase):
    def test_queue_shows_the_four_things_a_signoff_accepts(self):
        _row(self.db, self.inv.id, name="restricted copilot",
             tier="restricted_data", run_id=1, verified=62.7, confidence=0.31)
        item = LD.decision_queue(self.db)["items"][0]
        self.assertEqual(item["state"], LD.STATE_BLOCKED)
        self.assertEqual(item["verified_residual_pct"], 62.7)
        self.assertEqual(item["evidence_confidence_pct"], 31)
        self.assertTrue(item["architecture_gate"])
        self.assertEqual(item["architecture_open_items"], ["no-logging", "no-retention"])
        self.assertEqual(item["blast_radius"],
                         "4 restricted / 9 confidential / 180 privileged")
        self.assertEqual(item["recommended_decision"], A.DECISION_REJECT)

    def test_accepted_rows_leave_the_queue(self):
        _row(self.db, self.inv.id, name="public faq", tier="public", run_id=1,
             verified=10.0, confidence=0.9,
             exposure_assurance=_assurance(
                 verified={"residual_pct": 10.0},
                 architecture_gate={"gate_blocked_applied": False, "open_items": []},
                 decision={"decision": A.DECISION_ACCEPT}))
        self.assertEqual(LD.decision_queue(self.db)["count"], 0)

    def test_blocked_rows_sort_above_open_ones(self):
        _row(self.db, self.inv.id, name="blocked", tier="restricted_data",
             run_id=1, verified=62.7, confidence=0.31)
        _row(self.db, self.inv.id, name="open", tier="internal", run_id=2,
             verified=30.0, confidence=0.5,
             exposure_assurance=_assurance(
                 verified={"residual_pct": 30.0},
                 architecture_gate={"gate_blocked_applied": False, "open_items": []},
                 decision={"decision": None}))
        items = LD.decision_queue(self.db)["items"]
        self.assertEqual(items[0]["product"], "blocked")


class TestAssuranceHealth(LeadershipTestBase):
    def test_controls_split_into_verified_declared_unknown(self):
        _row(self.db, self.inv.id, name="a", tier="restricted_data", run_id=1,
             verified=62.7, confidence=0.31)
        c = LD.assurance_health(self.db)["controls"]
        # One assessment carrying three control attestations: one evidenced,
        # one declared, one unknown -- 1 of 3 evidenced.
        self.assertEqual(c["verified"], 1)
        self.assertEqual(c["declared"], 1)
        self.assertEqual(c["unknown"], 1)
        self.assertEqual(round(c["verified_pct"]), 33)
        self.assertEqual(c["least_evidenced"][0]["evidenced"], 0)

    def test_forensics_is_reported_across_the_portfolio(self):
        _row(self.db, self.inv.id, name="a", tier="restricted_data", run_id=1,
             verified=62.7, confidence=0.31)
        f = LD.assurance_health(self.db)["forensics"]
        self.assertEqual(f["mean_score"], 21.0)
        self.assertEqual(f["reconstructable"], 0)

    def test_failed_explainer_gap_counts_as_open_work(self):
        self.db.add(AgentRun(investigation_id=self.inv.id, trigger="explainer_gap",
                             status="error", error="worker killed",
                             started_at=NOW - timedelta(days=2)))
        self.db.add(AgentRun(investigation_id=self.inv.id, trigger="explainer_gap",
                             status="done", started_at=NOW - timedelta(days=2),
                             finished_at=NOW - timedelta(days=1)))
        self.db.commit()
        s = LD.assurance_health(self.db)["stalled_runs"]
        self.assertEqual(s["explainer_gap_open"], 1)
        self.assertEqual(s["explainer_gap_failed"], 1)

    def test_overdue_evidence_uses_an_ageing_threshold(self):
        self.db.add(Artifact(investigation_id=self.inv.id, title="old",
                             source="vendor", review="pending", relevance=0.5,
                             created_at=NOW - timedelta(days=40)))
        self.db.add(Artifact(investigation_id=self.inv.id, title="fresh",
                             source="vendor", review="pending", relevance=0.9,
                             created_at=NOW - timedelta(days=1)))
        self.db.commit()
        o = LD.assurance_health(self.db)["overdue_evidence"]
        self.assertEqual(o["pending"], 2)
        self.assertEqual(o["overdue"], 1)
        self.assertEqual(o["oldest_days"], 40)


class TestExposureAndSystem(LeadershipTestBase):
    def test_unquantified_assessment_is_not_reported_as_zero_exposure(self):
        _row(self.db, self.inv.id, name="a", tier="restricted_data", run_id=1,
             verified=62.7, confidence=0.31)
        _row(self.db, self.inv.id, name="b", tier="restricted_data", run_id=2,
             verified=50.0, confidence=0.4,
             exposure_assurance=_assurance(
                 verified={"residual_pct": 50.0},
                 blast_radius={"quantified": False}))
        ex = LD.exposure_lens(self.db)
        self.assertEqual(ex["quantified_assessments"], 1)
        self.assertEqual(ex["unquantified_assessments"], 1)

    def test_materiality_needs_a_score_and_a_population(self):
        _row(self.db, self.inv.id, name="big", tier="restricted_data", run_id=1,
             verified=62.7, confidence=0.31)
        self.assertEqual(len(LD.exposure_lens(self.db)["material_items"]), 1)
        # Same score, four records: not material.
        _row(self.db, self.inv.id, name="small", tier="restricted_data", run_id=2,
             verified=62.7, confidence=0.31,
             exposure_assurance=_assurance(
                 verified={"residual_pct": 62.7},
                 blast_radius={"quantified": True, "records_at_risk": 4,
                               "residual_pct": 62.7,
                               "inventory": {"restricted_assets": 1}}))
        items = LD.exposure_lens(self.db)["material_items"]
        self.assertEqual([i["product"] for i in items], ["big"])

    def test_stale_pack_is_reported_and_never_auto_rescored(self):
        _row(self.db, self.inv.id, name="a", tier="restricted_data", run_id=1,
             verified=62.7, confidence=0.31)
        si = LD.system_integrity(self.db)
        self.assertEqual(si["threat_pack"]["stale"], 1)
        self.assertEqual(si["threat_pack"]["currency_pct"], 0)

    def test_time_to_close_uses_finish_time(self):
        self.db.add(Explanation(investigation_id=self.inv.id, question="q?",
                                status="done", created_at=NOW - timedelta(days=5),
                                finished_at=NOW - timedelta(days=1)))
        self.db.commit()
        self.assertEqual(LD.system_integrity(self.db)["time_to_close"][
            "median_days_to_answer"], 4)


class TestAcceptanceWorkflow(LeadershipTestBase):
    def _one(self):
        return _row(self.db, self.inv.id, name="restricted copilot",
                    tier="restricted_data", run_id=7, verified=62.7,
                    confidence=0.31)

    def test_decision_is_written_with_actor_and_rationale(self):
        rec = self._one()
        self.db.commit()
        out = LD.record_decision(self.db, rec.id, A.DECISION_ACCEPT,
                                 actor="ciso@example.com", rationale="capped")
        self.assertTrue(out["recorded_in_ledger"])
        self.assertEqual(out["actor"], "ciso@example.com")
        self.db.expire_all()
        self.assertEqual(LD._decision_state(LD._assessment_dict(rec)),
                         LD.STATE_ACCEPTED)

    def test_override_of_the_derivation_stays_visible_as_an_override(self):
        rec = self._one()
        self.db.commit()
        out = LD.record_decision(self.db, rec.id, A.DECISION_ACCEPT,
                                 actor="ciso@example.com", rationale="risk accepted")
        self.assertEqual(out["decision_derived"], A.DECISION_REJECT)
        self.assertTrue(out["overrode_derivation"])

    def test_exception_is_time_bounded_and_expires_back_to_open(self):
        rec = self._one()
        self.db.commit()
        out = LD.record_decision(self.db, rec.id, "exception",
                                 actor="ciso@example.com", rationale="SIEM pending",
                                 expires_days=30)
        self.assertTrue(out["expires_at"])
        reg = LD.exception_register(self.db)
        self.assertEqual(reg["count"], 1)
        self.assertFalse(reg["expired"])
        self.assertLessEqual(reg["exceptions"][0]["days_remaining"], 30)
        # Age it out: the exception stops protecting the score.
        stored = self.db.get(SecurityAssessment, rec.id)
        stored.assurance_decision_expires_at = NOW - timedelta(days=1)
        self.db.commit()
        self.assertTrue(LD.exception_register(self.db)["expired"])
        self.assertEqual(LD._decision_state(LD._assessment_dict(stored)),
                         LD.STATE_OPEN)

    def test_exception_without_rationale_is_refused(self):
        rec = self._one()
        self.db.commit()
        with self.assertRaises(ValueError):
            LD.record_decision(self.db, rec.id, "exception", actor="ciso",
                               rationale="")

    def test_decision_without_an_actor_is_refused(self):
        rec = self._one()
        self.db.commit()
        with self.assertRaises(ValueError):
            LD.record_decision(self.db, rec.id, A.DECISION_ACCEPT, actor="  ")

    def test_unknown_decision_is_refused(self):
        rec = self._one()
        self.db.commit()
        with self.assertRaises(ValueError):
            LD.record_decision(self.db, rec.id, "maybe", actor="ciso")


class TestAlertsAndBoard(LeadershipTestBase):
    def test_alerts_escalate_the_right_severity(self):
        _row(self.db, self.inv.id, name="restricted copilot", tier="restricted_data",
             run_id=1, verified=62.7, confidence=0.31)
        _row(self.db, self.inv.id, name="unquantified", tier="restricted_data",
             run_id=2, verified=55.0, confidence=0.5,
             exposure_assurance=_assurance(
                 verified={"residual_pct": 55.0},
                 blast_radius={"quantified": False},
                 architecture_gate={"gate_blocked_applied": False, "open_items": []},
                 decision={"decision": None}))
        alerts = LD.alerts(self.db)["alerts"]
        severities = {a["id"].split("-")[0]: a["severity"] for a in alerts}
        self.assertEqual(severities.get("gate"), "block")
        self.assertEqual(severities.get("unquantified"), "warn")
        self.assertEqual(severities.get("low"), "warn")

    def test_board_is_one_payload_with_persona_emphasis(self):
        _row(self.db, self.inv.id, name="a", tier="restricted_data", run_id=1,
             verified=62.7, confidence=0.31)
        b = LD.board(self.db, self.inv.id, persona="ciso")
        for view in ("risk_position", "decision_queue", "assurance_health",
                     "exposure_lens", "system_integrity", "alerts"):
            self.assertIn(view, b)
        self.assertIn("assurance_health", b["emphasis"])
        self.assertTrue(b["contract"]["residual_always_with_confidence"])

    def test_change_log_keeps_history_and_names_the_current_row(self):
        _row(self.db, self.inv.id, name="copilot", tier="restricted_data",
             run_id=1, verified=62.7, confidence=0.31, days_ago=90)
        _row(self.db, self.inv.id, name="copilot", tier="restricted_data",
             run_id=2, verified=20.0, confidence=0.8, days_ago=2,
             exposure_assurance=_assurance(verified={"residual_pct": 20.0},
                                           evidence_confidence=0.8,
                                           architecture_gate={
                                               "gate_blocked_applied": False,
                                               "open_items": []}))
        log = LD.change_log(self.db, self.inv.id)
        self.assertEqual(len(log["current"]), 1)
        self.assertEqual(log["current"][0]["verified_residual_pct"], 20.0)
        self.assertEqual(log["superseded_count"], 1)
        self.assertEqual(log["superseded"][0]["verified_residual_pct"], 62.7)


class TestDashboardMetrics(LeadershipTestBase):
    """§9.3 A verified-vs-declared split and §9.3 E time-to-close."""

    def test_verified_share_is_the_reduction_backed_by_evidence(self):
        # inherent=100, declared=35.4, verified=62.7
        _row(self.db, self.inv.id, name="copilot", tier="restricted_data",
             run_id=1, verified=62.7, confidence=0.31)
        rp = LD.risk_position(self.db)
        vd = rp["verified_vs_declared"]
        self.assertAlmostEqual(vd["claimed_reduction_pct_points"], 64.6, places=1)
        self.assertAlmostEqual(vd["verified_reduction_pct_points"], 37.3, places=1)
        self.assertAlmostEqual(vd["verified_share_pct"], 57.7, places=0)

    def test_fully_verified_reduction_reports_a_hundred_percent_share(self):
        _row(self.db, self.inv.id, name="copilot", tier="restricted_data",
             run_id=1, verified=10.0, confidence=0.9,
             exposure_assurance=_assurance(verified={"residual_pct": 10.0}))
        vd = LD.risk_position(self.db)["verified_vs_declared"]
        self.assertEqual(vd["verified_share_pct"], 100)

    def test_architecture_gap_close_time_uses_the_next_unblocked_row(self):
        blocked = _assurance(architecture_gate={"gate_blocked_applied": True,
                                               "open_items": ["retention"]},
                             verified={"residual_pct": 62.7})
        unblocked = _assurance(architecture_gate={"gate_blocked_applied": False,
                                                  "open_items": []},
                               verified={"residual_pct": 62.7})
        _row(self.db, self.inv.id, name="copilot", tier="restricted_data",
             run_id=1, verified=62.7, confidence=0.31,
             exposure_assurance=blocked, days_ago=10)
        _row(self.db, self.inv.id, name="copilot", tier="restricted_data",
             run_id=2, verified=62.7, confidence=0.31,
             exposure_assurance=unblocked, days_ago=2)
        ttc = LD.assurance_health(self.db)["time_to_close"]["architecture_gaps"]
        self.assertEqual(ttc["closed_count"], 1)
        self.assertAlmostEqual(ttc["mean_close_days"], 8.0, places=0)
        self.assertEqual(ttc["open_count"], 0)

    def test_an_open_gap_reports_its_age_not_a_close_time(self):
        blocked = _assurance(architecture_gate={"gate_blocked_applied": True,
                                               "open_items": ["retention"]})
        _row(self.db, self.inv.id, name="copilot", tier="restricted_data",
             run_id=1, verified=62.7, confidence=0.31,
             exposure_assurance=blocked, days_ago=6)
        ttc = LD.assurance_health(self.db)["time_to_close"]["architecture_gaps"]
        self.assertEqual(ttc["closed_count"], 0)
        self.assertEqual(ttc["open_count"], 1)
        self.assertGreaterEqual(ttc["open"][0]["open_days"], 5.0)

    def test_pending_evidence_reports_review_latency(self):
        from app.models import Artifact
        art = Artifact(investigation_id=self.inv.id, title="vendor doc",
                       artifact_type="research", source="vendor",
                       review="pending",
                       created_at=NOW - timedelta(days=4))
        self.db.add(art)
        self.db.commit()
        ttc = LD.assurance_health(self.db)["time_to_close"]["evidence_reviews"]
        self.assertEqual(ttc["pending_count"], 1)
        self.assertAlmostEqual(ttc["mean_pending_days"], 4.0, places=0)


if __name__ == "__main__":
    unittest.main()