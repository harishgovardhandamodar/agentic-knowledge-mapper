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
from app import assurance_ledger as AL
from app import leadership as LD
from app.database import SessionLocal, init_db
from app.ledger_models import LeadershipAlertState, LedgerEvent, LedgerRun
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
         exposure_assurance=None, days_ago=5, markdown="# stub",
         threats=None, initiative_id=None, layer=None):
    """One assessment row with a stored assurance pass.

    ``verified`` is the number the views actually read, so it is pushed into the
    stored assurance blob as well as the column. Without that the row would look
    like 62.7 to every view while the test asserted on, say, 30.
    """
    ens = exposure_assurance or _assurance(verified={"residual_pct": verified},
                                           evidence_confidence=confidence)
    rec = SecurityAssessment(
        investigation_id=inv_id, run_id=run_id, product_name=name,
        product_family=name.lower(), exposure=tier, inherent_pct=100.0,
        residual_pct=35.4, overall_pct=35.4, evidence_confidence=confidence,
        assurance_json=json.dumps(ens),
        scoring_json=json.dumps({"assessment_path": "standard"}),
        markdown=markdown, threat_pack_version="2024.1",
        created_at=NOW - timedelta(days=days_ago),
        threats_json=json.dumps(threats) if threats else None,
        initiative_id=initiative_id,
        model_json=json.dumps({"model_key": name}) if layer == "model" else None)
    db.add(rec)
    # Committed here because the session is built with autoflush=False: the
    # views read through queries, so uncommitted rows are invisible to them.
    db.commit()
    return rec


class LeadershipTestBase(unittest.TestCase):
    def setUp(self):
        init_db()
        self.db = SessionLocal()
        # Alert acknowledgements are their own table. Leaving them behind makes
        # the next test's alerts look already-answered, which reads as a
        # regression in the alerting logic rather than as dirty test state.
        #
        # Ledger events are cleared too: run ids are reused across tests once
        # the runs are deleted, so the same `akm-run-1` chain would otherwise
        # accumulate another test's swarm failures onto this one's totals.
        for m in (SecurityAssessment, Artifact, AgentRun, Explanation, Investigation,
                  LeadershipAlertState):
            self.db.query(m).delete()
        for m in (LedgerEvent, LedgerRun):
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

# ---------------------------------------------------------------------------
# The improvements: scope filters, queue age/SLA, alert acknowledgement, export.
# ---------------------------------------------------------------------------

class TestScopeFilters(LeadershipTestBase):
    """A filter that silently drops rows is worse than one that refuses."""

    def test_unknown_layer_is_refused_rather_than_widened(self):
        with self.assertRaises(ValueError) as ctx:
            LD.resolve_scope(1, layer="supply_chain")
        self.assertIn("unknown layer", str(ctx.exception))

    def test_unknown_tier_is_refused(self):
        with self.assertRaises(ValueError):
            LD.resolve_scope(1, exposure="top_secret")

    def test_non_numeric_window_is_refused(self):
        with self.assertRaises(ValueError):
            LD.resolve_scope(1, window_days="ninety")

    def test_scope_normalises_and_pins_window_minimum(self):
        s = LD.resolve_scope(3, window_days=0)
        self.assertEqual(s["investigation_id"], 3)
        self.assertEqual(s["window_days"], 1)
        self.assertIsNone(s["layer"])

    def test_layer_filter_splits_model_rows_from_product_rows(self):
        _row(self.db, self.inv.id, name="chat", tier="internal", run_id=1,
             verified=40.0, confidence=0.5)
        _row(self.db, self.inv.id, name="claims", tier="internal", run_id=2,
             verified=30.0, confidence=0.5, layer="model")
        self.assertEqual(LD.risk_position(self.db, layer="model")["assessments"], 1)
        self.assertEqual(LD.risk_position(self.db, layer="product")["assessments"], 1)
        self.assertEqual(LD.risk_position(self.db)["assessments"], 2)
        self.assertEqual(LD.risk_position(self.db, layer="model")
                         ["tiers"][0]["count"], 1)

    def test_tier_filter_narrows_the_views_that_read_assessments(self):
        _row(self.db, self.inv.id, name="restricted copilot", tier="restricted_data",
             run_id=1, verified=62.7, confidence=0.31)
        _row(self.db, self.inv.id, name="public faq", tier="public", run_id=2,
             verified=12.0, confidence=0.86)
        self.assertEqual(LD.risk_position(self.db, exposure="public")["assessments"], 1)
        self.assertEqual(
            LD.assurance_health(self.db, exposure="public")["forensics"]["scored"], 1)
        self.assertEqual(
            LD.exposure_lens(self.db, exposure="public")["quantified_assessments"], 1)
        self.assertEqual(
            LD.system_integrity(self.db, exposure="public")
            ["threat_pack"]["assessments"], 1)
        self.assertEqual(len(LD.decision_queue(self.db, exposure="public")["items"]), 1)

    def test_exposure_and_tier_are_interchangeable_names_for_one_filter(self):
        _row(self.db, self.inv.id, name="restricted copilot", tier="restricted_data",
             run_id=1, verified=62.7, confidence=0.31)
        _row(self.db, self.inv.id, name="public faq", tier="public", run_id=2,
             verified=12.0, confidence=0.86)
        self.assertEqual(len(LD.decision_queue(self.db, exposure="public")["items"]),
                         len(LD.decision_queue(self.db, tier="public")["items"]))

    def test_asking_for_two_different_tiers_at_once_is_refused(self):
        with self.assertRaises(ValueError):
            LD.decision_queue(self.db, tier="public", exposure="internal")

    def test_initiative_filter_selects_only_that_initiative(self):
        from app.models import Initiative
        ini = Initiative(investigation_id=self.inv.id, title="Modernise claims")
        self.db.add(ini)
        self.db.commit()
        _row(self.db, self.inv.id, name="unscoped", tier="internal", run_id=1,
             verified=40.0, confidence=0.5)
        rec = _row(self.db, self.inv.id, name="claims", tier="internal", run_id=2,
                   verified=30.0, confidence=0.5)
        rec.initiative_id = ini.id
        self.db.commit()
        rp = LD.risk_position(self.db, initiative_id=ini.id)
        self.assertEqual(rp["assessments"], 1)
        self.assertEqual(rp["tiers"][0]["count"], 1)
        self.assertEqual(LD.risk_position(self.db)["scope"]["initiative_id"], None)


class TestQueueAgeAndSla(LeadershipTestBase):
    def test_row_reports_its_age_and_the_sla_it_is_measured_against(self):
        _row(self.db, self.inv.id, name="old copilot", tier="restricted_data",
             run_id=1, verified=62.7, confidence=0.31, days_ago=40)
        row = LD.decision_queue(self.db, sla_days=14)["items"][0]
        self.assertEqual(row["age_days"], 40)
        self.assertEqual(row["sla_days"], 14)
        self.assertTrue(row["over_sla"])

    def test_age_within_the_sla_is_not_flagged(self):
        _row(self.db, self.inv.id, name="fresh", tier="internal", run_id=1,
             verified=20.0, confidence=0.9, days_ago=3)
        row = LD.decision_queue(self.db, sla_days=14)["items"][0]
        self.assertFalse(row["over_sla"])

    def test_an_accepted_row_is_aged_from_the_signature_not_the_scoring(self):
        rec = _row(self.db, self.inv.id, name="signed", tier="internal", run_id=1,
                   verified=20.0, confidence=0.9, days_ago=60)
        LD.record_decision(self.db, rec.id, A.DECISION_ACCEPT, actor="Dana",
                           rationale="evidenced")
        self.db.expire_all()
        row = LD.decision_queue(self.db, states=[LD.STATE_ACCEPTED])["items"][0]
        # A decision taken today does not sit in the queue for 60 days.
        self.assertEqual(row["age_days"], 0)
        self.assertFalse(row["over_sla"])

    def test_over_sla_items_are_surfaced_as_alerts(self):
        _row(self.db, self.inv.id, name="stale copilot", tier="restricted_data",
             run_id=1, verified=62.7, confidence=0.31, days_ago=40)
        body = LD.alerts(self.db, sla_days=14)
        slas = [a for a in body["alerts"] if a["category"] == "decision_sla"]
        self.assertEqual(len(slas), 1)
        self.assertIn("40d", slas[0]["title"])
        self.assertIn("SLA 14d", slas[0]["title"])
        # An SLA alert has to name the assessment, or nobody can action it.
        self.assertTrue(slas[0]["assessment_id"])
        self.assertTrue(slas[0]["action"])

    def test_over_sla_is_configurable(self):
        _row(self.db, self.inv.id, name="aged", tier="internal", run_id=1,
             verified=20.0, confidence=0.9, days_ago=20)
        self.assertEqual(
            len([a for a in LD.alerts(self.db, sla_days=30)["alerts"]
                 if a["category"] == "decision_sla"]), 0)
        self.assertEqual(
            len([a for a in LD.alerts(self.db, sla_days=7)["alerts"]
                 if a["category"] == "decision_sla"]), 1)


class TestQueueFiltersAndPaging(LeadershipTestBase):
    def _three(self):
        _row(self.db, self.inv.id, name="alpha", tier="restricted_data", run_id=1,
             verified=62.7, confidence=0.31, days_ago=5)
        _row(self.db, self.inv.id, name="bravo", tier="public", run_id=2,
             verified=12.0, confidence=0.86, days_ago=30,
             exposure_assurance=_assurance(
                 verified={"residual_pct": 12.0}, evidence_confidence=0.86,
                 architecture_gate={"gate_blocked_applied": False, "open_items": []},
                 decision={"decision": A.DECISION_ACCEPT}))
        _row(self.db, self.inv.id, name="charlie", tier="internal", run_id=3,
             verified=25.0, confidence=0.55, days_ago=15)

    def test_every_state_is_counted_including_the_signed_ones(self):
        self._three()
        st = LD.decision_queue(self.db, states=list(LD.ALL_STATES))["states"]
        self.assertEqual(sum(st.values()), 3)
        self.assertIn(LD.STATE_ACCEPTED, st)

    def test_default_queue_shows_only_what_is_waiting(self):
        self._three()
        names = [r["product"] for r in LD.decision_queue(self.db)["items"]]
        self.assertNotIn("bravo", names)

    def test_tier_filter_narrows_the_queue(self):
        self._three()
        body = LD.decision_queue(self.db, tier="restricted_data")
        self.assertEqual([r["product"] for r in body["items"]], ["alpha"])
        self.assertEqual(body["tier"], "restricted_data")

    def test_pagination_reports_position_and_whether_more_remain(self):
        self._three()
        every = list(LD.ALL_STATES)
        page1 = LD.decision_queue(self.db, states=every, limit=2, offset=0)
        self.assertEqual(page1["returned"], 2)
        self.assertEqual(page1["count"], 3)
        self.assertTrue(page1["has_more"])
        page2 = LD.decision_queue(self.db, states=every, limit=2, offset=2)
        self.assertEqual(page2["returned"], 1)
        self.assertFalse(page2["has_more"])
        self.assertEqual(page2["offset"], 2)

    def test_paging_walks_the_queue_without_repeating_or_dropping_a_row(self):
        self._three()
        seen = []
        for offset in (0, 1, 2):
            seen += [r["assessment_id"] for r in
                     LD.decision_queue(self.db, states=list(LD.ALL_STATES),
                                       limit=1, offset=offset)["items"]]
        self.assertEqual(len(seen), 3)
        self.assertEqual(len(set(seen)), 3)

    def test_sort_by_residual_puts_the_biggest_exposure_first(self):
        self._three()
        items = LD.decision_queue(self.db)["items"]
        self.assertEqual(items[0]["product"], "alpha")

    def test_sort_by_age_puts_the_longest_waiting_first(self):
        self._three()
        items = LD.decision_queue(self.db, states=list(LD.ALL_STATES),
                                  sort="age")["items"]
        self.assertEqual(items[0]["product"], "bravo")
        self.assertEqual(items[-1]["product"], "alpha")

    def test_sort_by_confidence_puts_the_least_trustworthy_first(self):
        self._three()
        items = LD.decision_queue(self.db, sort="confidence")["items"]
        self.assertEqual(items[0]["evidence_confidence_pct"], 31)

    def test_by_tier_counts_every_tier_present_in_the_scope(self):
        self._three()
        by_tier = LD.decision_queue(self.db, states=list(LD.ALL_STATES))["by_tier"]
        self.assertEqual(by_tier["public"], 1)
        self.assertEqual(by_tier["restricted_data"], 1)
        self.assertEqual(by_tier["internal"], 1)

    def test_unknown_sort_tier_or_state_is_refused(self):
        for kwargs in ({"sort": "sideways"}, {"tier": "nope"},
                       {"states": ["not_a_state"]}):
            with self.assertRaises(ValueError):
                LD.decision_queue(self.db, **kwargs)


class TestDecisionAliases(LeadershipTestBase):
    """The API docstring said ``reject`` while the stored constant was the long
    form, so a caller using the documented spelling got a 422."""

    def test_short_reject_maps_onto_the_stored_constant(self):
        rec = _row(self.db, self.inv.id, name="a", tier="internal", run_id=1,
                   verified=40.0, confidence=0.5)
        out = LD.record_decision(self.db, rec.id, "reject", actor="Dana",
                                 rationale="retiring")
        self.assertEqual(out["decision"], A.DECISION_REJECT)
        self.assertEqual(out["decision_requested"], "reject")
        self.db.expire_all()
        self.assertEqual(rec.assurance_decision, A.DECISION_REJECT)

    def test_guardrails_short_form_maps_too(self):
        rec = _row(self.db, self.inv.id, name="a", tier="internal", run_id=1,
                   verified=40.0, confidence=0.5)
        out = LD.record_decision(self.db, rec.id, "guardrails", actor="Dana",
                                 rationale="mitigate first")
        self.assertEqual(out["decision"], A.DECISION_GUARDRAILS)

    def test_an_override_is_reported_as_an_override(self):
        rec = _row(self.db, self.inv.id, name="a", tier="internal", run_id=1,
                   verified=40.0, confidence=0.5)
        out = LD.record_decision(self.db, rec.id, "accept", actor="Dana",
                                 rationale="we accept it")
        self.assertTrue(out["overrode_derivation"])

    def test_an_unknown_decision_lists_what_is_accepted(self):
        rec = _row(self.db, self.inv.id, name="a", tier="internal", run_id=1,
                   verified=40.0, confidence=0.5)
        with self.assertRaises(ValueError) as ctx:
            LD.record_decision(self.db, rec.id, "maybe", actor="Dana")
        self.assertIn("accept", str(ctx.exception))

    def test_every_alias_is_canonicalised(self):
        for alias, expected in LD.DECISION_ALIASES.items():
            self.assertEqual(LD.canonical_decision(alias), expected)
            self.assertEqual(LD.canonical_decision(alias.upper()), expected)
        self.assertIsNone(LD.canonical_decision("sideways"))


class TestAlertAcknowledgement(LeadershipTestBase):
    def _blocked(self):
        _row(self.db, self.inv.id, name="blocked copilot", tier="restricted_data",
             run_id=1, verified=62.7, confidence=0.31, days_ago=2)

    def test_an_acknowledged_alert_leaves_the_open_list(self):
        self._blocked()
        alert = [a for a in LD.alerts(self.db)["alerts"]
                 if a["category"] == "architecture_gate"][0]
        LD.acknowledge_alert(self.db, alert["id"], actor="Dana", note="agreed")
        ids = [a["id"] for a in LD.alerts(self.db)["alerts"]]
        self.assertNotIn(alert["id"], ids)

    def test_it_is_still_reported_when_acknowledged_alerts_are_asked_for(self):
        self._blocked()
        alert = LD.alerts(self.db)["alerts"][0]
        LD.acknowledge_alert(self.db, alert["id"], actor="Dana")
        body = LD.alerts(self.db, include_acknowledged=True)
        mine = [a for a in body["alerts"] if a["id"] == alert["id"]][0]
        self.assertTrue(mine["acknowledged"])
        self.assertEqual(mine["acknowledged_by"], "Dana")
        self.assertEqual(body["acknowledged"], 1)

    def test_a_snooze_suppresses_the_alert_until_it_expires(self):
        self._blocked()
        alert = LD.alerts(self.db)["alerts"][0]
        LD.acknowledge_alert(self.db, alert["id"], actor="Dana", status="snoozed",
                             snooze_days=7)
        self.assertNotIn(alert["id"], [a["id"] for a in LD.alerts(self.db)["alerts"]])

    def test_an_expired_snooze_lets_the_alert_back_in(self):
        self._blocked()
        alert = LD.alerts(self.db)["alerts"][0]
        LD.acknowledge_alert(self.db, alert["id"], actor="Dana", status="snoozed",
                             snooze_days=1)
        from app.ledger_models import LeadershipAlertState, LedgerEvent, LedgerRun
        row = self.db.query(LeadershipAlertState).filter(
            LeadershipAlertState.alert_id == alert["id"]).one()
        row.snoozed_until = NOW - timedelta(days=1)
        self.db.commit()
        self.assertIn(alert["id"], [a["id"] for a in LD.alerts(self.db)["alerts"]])

    def test_acknowledging_requires_a_named_actor(self):
        self._blocked()
        alert = LD.alerts(self.db)["alerts"][0]
        with self.assertRaises(ValueError):
            LD.acknowledge_alert(self.db, alert["id"], actor="  ")

    def test_an_acknowledgement_does_not_hide_a_changed_finding(self):
        """Someone who looked at a different finding has not looked at this one."""
        self._blocked()
        alert = LD.alerts(self.db, include_acknowledged=True)["alerts"][0]
        LD.acknowledge_alert(self.db, alert["id"], actor="Dana")
        from app.ledger_models import LeadershipAlertState, LedgerEvent, LedgerRun
        row = self.db.query(LeadershipAlertState).filter(
            LeadershipAlertState.alert_id == alert["id"]).one()
        row.finding_hash = "a-different-finding"
        self.db.commit()
        ids = [a["id"] for a in LD.alerts(self.db)["alerts"]]
        self.assertIn(alert["id"], ids)

    def test_the_acknowledgement_is_bound_to_the_finding_it_saw(self):
        self._blocked()
        alert = LD.alerts(self.db, include_acknowledged=True)["alerts"][0]
        LD.acknowledge_alert(self.db, alert["id"], actor="Dana",
                             finding_hash=alert["finding_hash"])
        self.assertNotIn(alert["id"],
                         [a["id"] for a in LD.alerts(self.db)["alerts"]])

    def test_an_unknown_status_is_refused(self):
        self._blocked()
        alert = LD.alerts(self.db)["alerts"][0]
        with self.assertRaises(ValueError):
            LD.acknowledge_alert(self.db, alert["id"], actor="D", status="ignored")

    def test_unacknowledging_brings_the_alert_back(self):
        self._blocked()
        alert = LD.alerts(self.db)["alerts"][0]
        LD.acknowledge_alert(self.db, alert["id"], actor="Dana")
        LD.acknowledge_alert(self.db, alert["id"], actor="Dana",
                             status="unacknowledged")
        self.assertIn(alert["id"], [a["id"] for a in LD.alerts(self.db)["alerts"]])

    def test_open_blocking_drops_once_the_blocker_is_acknowledged(self):
        self._blocked()
        self.assertEqual(LD.alerts(self.db)["open_blocking"], 1)
        alert = LD.alerts(self.db)["alerts"][0]
        LD.acknowledge_alert(self.db, alert["id"], actor="Dana")
        self.assertEqual(LD.alerts(self.db)["open_blocking"], 0)


class TestPortfolioSeries(LeadershipTestBase):
    """The charted series must be dated, not a fold of undated values."""

    def _one(self, days_ago, residual=40.0, confidence=0.5, run_id=1):
        return _row(self.db, self.inv.id, name=f"p{days_ago}",
                    tier="restricted_data", run_id=run_id,
                    verified=residual, confidence=confidence,
                    days_ago=days_ago)

    def test_every_point_carries_the_window_it_covers(self):
        self._one(5)
        self._one(40)
        rows = LD.risk_position(self.db, self.inv.id, window_days=90)
        series = rows["portfolio_series"]
        self.assertTrue(series)
        for pt in series:
            self.assertIn("bucket_start", pt)
            self.assertRegex(str(pt["bucket_start"]), r"^\d{4}-\d{2}-\d{2}$")

    def test_a_quiet_period_is_omitted_rather_than_drawn_as_zero(self):
        # One row now, one a year ago, and a 30-day window: the middle of the
        # chart has no assessments at all.
        self._one(1)
        self._one(360)
        rows = LD.risk_position(self.db, self.inv.id, window_days=30)
        series = rows["portfolio_series"]
        self.assertEqual(len(series), 1)
        # A zero here would read as "risk fell to nothing".
        self.assertNotEqual(series[0]["mean_verified_residual_pct"], 0)

    def test_the_series_respects_the_window_it_was_asked_for(self):
        self._one(200)
        short = LD.risk_position(self.db, self.inv.id, window_days=30)
        long = LD.risk_position(self.db, self.inv.id, window_days=365)
        self.assertEqual(short["portfolio_series"], [])
        self.assertEqual(len(long["portfolio_series"]), 1)

    def test_the_series_reports_the_worst_row_not_only_the_mean(self):
        # Same bucket (30d window / 24 buckets is ~1.25d wide), so the mean and
        # the worst genuinely describe the same set of rows.
        self._one(5, residual=10.0, run_id=1)
        self._one(6, residual=80.0, run_id=2)
        rows = LD.risk_position(self.db, self.inv.id, window_days=30)
        pt = rows["portfolio_series"][0]
        self.assertEqual(pt["worst_residual_pct"], 80.0)
        self.assertLess(pt["mean_verified_residual_pct"], 80.0)

    def test_confidence_travels_with_the_residual_on_the_same_point(self):
        self._one(1, residual=40.0, confidence=0.75)
        rows = LD.risk_position(self.db, self.inv.id, window_days=30)
        pt = rows["portfolio_series"][0]
        self.assertEqual(pt["mean_confidence_pct"], 75.0)


class TestTrendWindows(LeadershipTestBase):
    def test_three_horizons_are_reported_with_their_sample_counts(self):
        for d, v in ((5, 60.0), (100, 40.0), (300, 20.0)):
            _row(self.db, self.inv.id, name=f"p{d}", tier="internal", run_id=d,
                 verified=v, confidence=0.5, days_ago=d)
        rp = LD.risk_position(self.db, window_days=365)
        wins = {w["window_days"]: w for w in rp["trend_windows"]}
        self.assertEqual(set(wins), {30, 90, 365})
        self.assertEqual(wins[30]["samples"], 1)
        self.assertEqual(wins[90]["samples"], 1)
        self.assertEqual(wins[365]["samples"], 3)
        # The two older rows are the "prior" for the short horizons, which is
        # what makes a 30d delta possible at all.
        self.assertEqual(wins[30]["prior_samples"], 2)
        self.assertEqual(wins[365]["prior_samples"], 0)
        # Shorter windows see fewer assessments, so their mean differs.
        self.assertGreater(wins[30]["mean_residual_pct"], wins[365]["mean_residual_pct"])

    def test_a_horizon_with_no_prior_is_reported_as_insufficient_history(self):
        _row(self.db, self.inv.id, name="fresh", tier="internal", run_id=1,
             verified=20.0, confidence=0.5, days_ago=1)
        w = {x["window_days"]: x for x in LD.risk_position(self.db)["trend_windows"]}[30]
        self.assertEqual(w["direction"], "insufficient_history")

    def test_per_tier_trends_do_not_average_into_one_line(self):
        _row(self.db, self.inv.id, name="r1", tier="restricted_data", run_id=1,
             verified=70.0, confidence=0.5, days_ago=120)
        _row(self.db, self.inv.id, name="r2", tier="restricted_data", run_id=2,
             verified=30.0, confidence=0.5, days_ago=2)
        _row(self.db, self.inv.id, name="p1", tier="public", run_id=3,
             verified=10.0, confidence=0.5, days_ago=120)
        _row(self.db, self.inv.id, name="p2", tier="public", run_id=4,
             verified=10.0, confidence=0.5, days_ago=2)
        trends = {t["tier"]: t
                  for t in LD.risk_position(self.db, window_days=90)["tier_trends"]}
        # Restricted improved sharply across the window; public is flat. One
        # portfolio line would have shown neither.
        self.assertEqual(trends["restricted_data"]["window_mean_residual_pct"], 30.0)
        self.assertEqual(trends["restricted_data"]["prior_mean_residual_pct"], 70.0)
        self.assertLess(trends["restricted_data"]["delta_pct_points"], 0)
        self.assertEqual(trends["public"]["delta_pct_points"], 0)
        self.assertTrue(trends["restricted_data"]["series"])

    def test_a_tier_with_no_in_window_sample_reports_no_delta(self):
        _row(self.db, self.inv.id, name="old", tier="public", run_id=1,
             verified=10.0, confidence=0.5, days_ago=120)
        trends = {t["tier"]: t
                  for t in LD.risk_position(self.db, window_days=90)["tier_trends"]}
        # Only prior data exists for public, so there is no movement to claim.
        self.assertEqual(trends["public"]["window_samples"], 0)
        self.assertIsNone(trends["public"]["delta_pct_points"])

    def test_per_tier_trends_follow_the_window_the_board_was_asked_for(self):
        _row(self.db, self.inv.id, name="r1", tier="internal", run_id=1,
             verified=70.0, confidence=0.5, days_ago=120)
        _row(self.db, self.inv.id, name="r2", tier="internal", run_id=2,
             verified=30.0, confidence=0.5, days_ago=2)
        wide = LD.risk_position(self.db, window_days=365)["tier_trends"][0]
        narrow = LD.risk_position(self.db, window_days=30)["tier_trends"][0]
        # Over 365d both rows sit inside the window, so there is no prior to
        # compare against. Over 30d the older row is prior and the delta exists.
        self.assertIsNone(wide["delta_pct_points"])
        self.assertIsNotNone(narrow["delta_pct_points"])

    def test_a_tier_with_no_prior_window_reports_no_delta(self):
        _row(self.db, self.inv.id, name="one", tier="internal", run_id=1,
             verified=20.0, confidence=0.5, days_ago=1)
        t = LD.risk_position(self.db)["tier_trends"][0]
        self.assertIsNone(t["delta_pct_points"])
        self.assertEqual(t["window_samples"], 1)


class TestThreatsByTier(LeadershipTestBase):
    def test_dominant_threats_are_ranked_within_each_tier(self):
        _row(self.db, self.inv.id, name="restricted", tier="restricted_data",
             run_id=1, verified=62.7, confidence=0.31, threats=[
                 {"id": "T01", "title": "Model extraction", "verified_residual": 62.7}])
        _row(self.db, self.inv.id, name="public", tier="public", run_id=2,
             verified=12.0, confidence=0.86, threats=[
                 {"id": "T99", "title": "low", "verified_residual": 5}])
        by_tier = {t["tier"]: t for t in LD.risk_position(self.db)["top_threats_by_tier"]}
        self.assertEqual(set(by_tier), {"restricted_data", "public"})
        self.assertEqual(by_tier["public"]["threats"][0]["threat_id"], "T99")
        self.assertEqual(by_tier["restricted_data"]["threats"][0]["threat_id"], "T01")

    def test_a_tier_with_no_scored_threats_is_absent_not_empty(self):
        _row(self.db, self.inv.id, name="restricted", tier="restricted_data",
             run_id=1, verified=62.7, confidence=0.31, threats=[
                 {"id": "T01", "title": "a", "verified_residual": 62.7}])
        _row(self.db, self.inv.id, name="public", tier="public", run_id=2,
             verified=12.0, confidence=0.86)
        by_tier = {t["tier"]: t for t in LD.risk_position(self.db)["top_threats_by_tier"]}
        # Public is in the portfolio and in the risk table, but has no scored
        # threat, so it must not appear with an empty list a reader could
        # mistake for "we checked and found nothing".
        self.assertEqual(set(by_tier), {"restricted_data"})

    def test_threats_forced_to_inherent_are_counted(self):
        _row(self.db, self.inv.id, name="restricted", tier="restricted_data",
             run_id=1, verified=62.7, confidence=0.31, threats=[
                 {"id": "T01", "title": "a", "verified_residual": 62.7,
                  "forced_to_inherent": True}])
        tb = LD.risk_position(self.db)["top_threats_by_tier"][0]
        self.assertEqual(tb["forced_to_inherent"], 1)
        self.assertIn("inherent", tb["note"])

    def test_the_same_threat_id_is_not_counted_twice_in_a_tier(self):
        _row(self.db, self.inv.id, name="dup", tier="internal", run_id=1,
             verified=40.0, confidence=0.5, threats=[
                 {"id": "T01", "title": "a", "verified_residual": 10},
                 {"id": "T01", "title": "b", "verified_residual": 40}])
        tb = LD.risk_position(self.db)["top_threats_by_tier"][0]
        self.assertEqual(len(tb["threats"]), 1)
        self.assertEqual(tb["threats"][0]["verified_residual"], 40)

    def test_a_threat_repeated_across_products_keeps_the_worst_instance(self):
        _row(self.db, self.inv.id, name="one", tier="internal", run_id=1,
             verified=10.0, confidence=0.5, threats=[
                 {"id": "T05", "title": "a", "verified_residual": 10}])
        _row(self.db, self.inv.id, name="two", tier="internal", run_id=2,
             verified=80.0, confidence=0.5, threats=[
                 {"id": "T05", "title": "a", "verified_residual": 80}])
        tb = LD.risk_position(self.db)["top_threats_by_tier"][0]
        self.assertEqual(len(tb["threats"]), 1)
        self.assertEqual(tb["threats"][0]["verified_residual"], 80)
        self.assertEqual(tb["distinct_threats"], 1)
        self.assertEqual(tb["threats"][0]["products"], 2)


class TestBoardCompleteness(LeadershipTestBase):
    def test_board_carries_the_exception_register_and_the_change_log(self):
        _row(self.db, self.inv.id, name="a", tier="internal", run_id=1,
             verified=40.0, confidence=0.5)
        b = LD.board(self.db, self.inv.id)
        self.assertIn("exceptions", b)
        self.assertIn("change_log", b)
        self.assertIn("exceptions", b["emphasis"] if False else b)
        # Both are present for every persona that emphasises them.
        audit = LD.board(self.db, self.inv.id, persona="audit")
        self.assertIn("change_log", audit["emphasis"])
        self.assertIn("exceptions", audit)

    def test_an_unknown_persona_is_refused_rather_than_defaulted(self):
        with self.assertRaises(ValueError) as ctx:
            LD.board(self.db, self.inv.id, persona="ceo")
        self.assertIn("unknown persona", str(ctx.exception))

    def test_every_catalogued_persona_resolves_to_its_own_emphasis(self):
        for name in LD.PERSONAS:
            b = LD.board(self.db, self.inv.id, persona=name)
            self.assertEqual(b["persona"], name)
            self.assertEqual(b["emphasis"], LD.PERSONAS[name]["emphasis"])

    def test_the_board_ships_its_own_decision_contract_for_the_ui(self):
        b = LD.board(self.db, self.inv.id)
        opts = {o["value"] for o in b["decisions_available"]["options"]}
        self.assertEqual(opts, {A.DECISION_ACCEPT, A.DECISION_GUARDRAILS,
                                A.DECISION_REJECT, "exception"})
        self.assertIn("reject", b["decisions_available"]["aliases"])
        self.assertTrue(b["decisions_available"]["requires_actor"])
        self.assertTrue(b["decisions_available"]["exception_requires_rationale"])

    def test_the_board_publishes_its_own_filter_vocabulary(self):
        f = LD.board(self.db, self.inv.id)["queue_filters"]
        self.assertEqual(set(f["sorts"]), set(LD.QUEUE_SORTS))
        self.assertEqual(set(f["states"]), set(LD.ALL_STATES))
        self.assertEqual(f["default_states"],
                         [LD.STATE_OPEN, LD.STATE_GUARDRAILS, LD.STATE_BLOCKED])

    def test_scope_is_echoed_so_a_reader_knows_what_they_are_looking_at(self):
        b = LD.board(self.db, self.inv.id, window_days=30, tier=None)
        self.assertEqual(b["scope"]["window_days"], 30)
        self.assertEqual(b["scope"]["investigation_id"], self.inv.id)


class TestSystemIntegrityRates(LeadershipTestBase):
    """gate_failure_rate was reported as failures/hops, which made a working
    architecture gate look like fabric flakiness."""

    def _swarm_run(self, gate_failures: int, plain_failures: int,
                   completions: int = 0):
        run = AgentRun(investigation_id=self.inv.id, trigger="manual",
                       status="done")
        self.db.add(run)
        self.db.commit()
        rid = f"akm-run-{run.id}"
        AL.record_swarm_event(rid, role="security_engineer", phase="spawn")
        for _ in range(completions):
            AL.record_swarm_event(rid, role="security_engineer", phase="complete")
        for _ in range(gate_failures):
            AL.record_swarm_event(
                rid, role="security_engineer", phase="failure",
                policy={"decision": "scorer_blocked", "blocked_by": "architecture"})
        for _ in range(plain_failures):
            AL.record_swarm_event(rid, role="security_engineer", phase="failure",
                                  error="llm timeout")
        _row(self.db, self.inv.id, name="a", tier="internal", run_id=run.id,
             verified=40.0, confidence=0.5)
        return run

    def test_failure_rate_and_gate_failure_rate_are_separate_figures(self):
        self._swarm_run(gate_failures=2, plain_failures=1, completions=2)
        sw = LD.system_integrity(self.db)["swarm"]
        self.assertEqual(sw["failures"], 3)
        self.assertEqual(sw["gate_failures"], 2)
        # Two thirds of the failures were the gate working as designed.
        self.assertEqual(sw["gate_failure_rate"], 0.67)
        # 3 failures over 5 role attempts (2 completions + 3 failures).
        self.assertEqual(sw["failure_rate"], 0.6)
        # The two rates describe the same three failures from different angles.
        # Reporting one as the other is what made a working gate look broken.
        self.assertNotEqual(sw["gate_failure_rate"], sw["failure_rate"])
        self.assertIn("gate_failure_rate", sw["rate_note"])

    def test_the_fabric_rate_ignores_gate_failures_it_should_not_blame_on_it(self):
        # Same gate block, more successful work: the gate share holds while the
        # fabric rate falls, because the block never counted against reliability.
        self._swarm_run(gate_failures=2, plain_failures=0, completions=8)
        sw = LD.system_integrity(self.db)["swarm"]
        self.assertEqual(sw["gate_failure_rate"], 1.0)
        self.assertEqual(sw["failure_rate"], 0.2)
        self.assertEqual(sw["overall_success_rate"], 0.8)

    def test_a_clean_run_reports_no_failures_rather_than_a_zero_rate(self):
        self._swarm_run(gate_failures=0, plain_failures=0, completions=3)
        sw = LD.system_integrity(self.db)["swarm"]
        self.assertEqual(sw["failures"], 0)
        # No failures at all means the gate share is undefined, not zero --
        # 0.0 would read as "the gate never fires" on a run it never had to.
        self.assertIsNone(sw["gate_failure_rate"])
        self.assertEqual(sw["overall_success_rate"], 1.0)
        self.assertEqual(sw["failure_rate"], 0.0)

    def test_a_gate_that_blocks_everything_is_not_reported_as_flakiness(self):
        self._swarm_run(gate_failures=2, plain_failures=0, completions=0)
        sw = LD.system_integrity(self.db)["swarm"]
        self.assertEqual(sw["gate_failure_rate"], 1.0)
        self.assertEqual(sw["failure_rate"], 1.0)

    def test_an_investigation_with_swarm_activity_does_not_raise(self):
        # Regression: the per-role merge indexed a key SW.health only reports
        # in its portfolio total, so this raised KeyError.
        self._swarm_run(gate_failures=1, plain_failures=1, completions=1)
        self.assertIn("roles", LD.system_integrity(self.db)["swarm"])

    def test_swarm_stats_survive_a_role_whose_rows_have_no_gate_figure(self):
        self._swarm_run(gate_failures=0, plain_failures=2, completions=0)
        roles = LD.system_integrity(self.db)["swarm"]["roles"]
        self.assertEqual([r["gate_failures"] for r in roles], [0])


class TestBoardExport(LeadershipTestBase):
    def test_the_export_states_scope_persona_and_generation_time(self):
        _row(self.db, self.inv.id, name="a", tier="internal", run_id=1,
             verified=40.0, confidence=0.5)
        md = LD.export_markdown(self.db, self.inv.id, persona="ciso")
        self.assertIn("# Leadership board snapshot", md)
        self.assertIn("CISO", md)
        self.assertIn(f"investigation={self.inv.id}", md)
        self.assertIn("Generated:", md)

    def test_an_empty_portfolio_exports_without_inventing_numbers(self):
        md = LD.export_markdown(self.db)
        self.assertIn("Nothing is waiting on a leadership decision", md)
        self.assertIn("No time-bounded exceptions are in force", md)
        self.assertIn("No open alerts", md)

    def test_every_exported_residual_carries_its_confidence_column(self):
        _row(self.db, self.inv.id, name="a", tier="internal", run_id=1,
             verified=62.7, confidence=0.31)
        md = LD.export_markdown(self.db, self.inv.id)
        # Both figures, side by side, in the same table row: a reader who copies
        # one line out of this document must not be able to drop the caveat.
        self.assertIn("| Verified residual | Confidence |", md)
        self.assertIn("62.7%", md)
        self.assertIn("31%", md)
        row = [l for l in md.splitlines() if l.startswith("| a |")][0]
        self.assertIn("62.7%", row)
        self.assertIn("31%", row)

    def test_an_over_sla_item_is_visible_in_the_export(self):
        _row(self.db, self.inv.id, name="aged", tier="internal", run_id=1,
             verified=40.0, confidence=0.5, days_ago=60)
        md = LD.export_markdown(self.db, self.inv.id)
        self.assertIn("OVER", md)


class TestExceptionRegisterDetail(LeadershipTestBase):
    def test_an_exception_carries_its_grant_and_expiry_detail(self):
        rec = _row(self.db, self.inv.id, name="a", tier="restricted_data",
                   run_id=1, verified=40.0, confidence=0.5)
        LD.record_decision(self.db, rec.id, "exception", actor="Dana",
                           rationale="vendor contract", expires_days=30)
        self.db.expire_all()
        ex = LD.exception_register(self.db)["exceptions"][0]
        self.assertEqual(ex["actor"], "Dana")
        self.assertEqual(ex["rationale"], "vendor contract")
        self.assertFalse(ex["expired"])
        self.assertEqual(ex["days_remaining"], 29)
        self.assertTrue(ex["granted_at"])
        # The link has to be the action that ends the exception, not a
        # human-readable label.
        self.assertEqual(ex["re_evaluate_link"],
                         f"/api/security/assessments/{rec.id}/rescore")

    def test_an_expired_exception_is_flagged_for_re_evaluation(self):
        rec = _row(self.db, self.inv.id, name="a", tier="restricted_data",
                   run_id=1, verified=40.0, confidence=0.5)
        LD.record_decision(self.db, rec.id, "exception", actor="Dana",
                           rationale="vendor", expires_days=1)
        rec.assurance_decision_expires_at = NOW - timedelta(days=1)
        self.db.commit()
        body = LD.exception_register(self.db)
        self.assertEqual(body["expired"], 1)
        self.assertEqual(body["active"], 0)
        self.assertTrue(body["exceptions"][0]["reevaluation_due"])
        # And the expired exception stops protecting the row.
        self.assertEqual(LD.exception_register(self.db)["active"], 0)
        self.assertEqual(_state_of(self.db, rec.id), LD.STATE_OPEN)


def _state_of(db, assessment_id):
    """The effective decision state the queue would show for one row."""
    a = [LD._assessment_dict(r) for r in LD._assessments(db)]
    row = [x for x in a if x["assessment_id"] == assessment_id][0]
    return LD._decision_state(row)


class TestChangeLogPortfolio(LeadershipTestBase):
    def test_an_unscoped_change_log_groups_by_investigation(self):
        other = Investigation(title="Second")
        self.db.add(other)
        self.db.commit()
        _row(self.db, self.inv.id, name="a", tier="internal", run_id=1,
             verified=40.0, confidence=0.5)
        _row(self.db, other.id, name="b", tier="internal", run_id=2,
             verified=30.0, confidence=0.5)
        body = LD.change_log(self.db)
        self.assertEqual(len(body["current"]), 2)
        self.assertIn("by_investigation", body)
        self.assertEqual({r["investigation_id"] for r in body["by_investigation"]},
                         {self.inv.id, other.id})

    def test_the_scoped_change_log_names_the_current_row(self):
        _row(self.db, self.inv.id, name="a", tier="internal", run_id=1,
             verified=40.0, confidence=0.5, days_ago=20)
        newer = _row(self.db, self.inv.id, name="a", tier="internal", run_id=2,
                     verified=30.0, confidence=0.5, days_ago=1)
        newer.supersedes_id = 1
        self.db.commit()
        body = LD.change_log(self.db, self.inv.id)
        self.assertEqual(len(body["current"]), 1)
        self.assertEqual(body["superseded_count"], 1)
        self.assertEqual(body["superseded"][0]["superseded_by_id"], newer.id)


class TestExportCarriesTheChartSeries(LeadershipTestBase):
    """The PDF/Markdown snapshot must be checkable against the screen."""

    def _rows(self):
        _row(self.db, self.inv.id, name="restricted copilot",
             tier="restricted_data", run_id=1, verified=62.7, confidence=0.31,
             days_ago=4)
        _row(self.db, self.inv.id, name="public faq", tier="public", run_id=2,
             verified=9.0, confidence=0.9, days_ago=30)

    def test_the_export_prints_the_same_dated_series_the_chart_draws(self):
        self._rows()
        md = LD.export_markdown(self.db, window_days=90)
        self.assertIn("Dated residual and confidence", md)
        # Every charted bucket has to be readable as a row: an executive who
        # disputes the line needs the numbers behind it in the export.
        series = LD.risk_position(self.db, window_days=90)["portfolio_series"]
        self.assertTrue(series)
        for pt in series:
            self.assertIn(str(pt["bucket_start"]), md)

    def test_the_export_omits_the_series_table_when_there_is_no_history(self):
        md = LD.export_markdown(self.db, window_days=90)
        self.assertNotIn("Dated residual and confidence", md)


def _model_row(db, inv_id, *, name, experiments, hypotheses,
               tier="confidential_data", run_id=1, days_ago=5,
               plan_error=None):
    """A model-layer assessment row carrying an experiment plan."""
    mj = {"model_key": name, "model_name": name, "meta": {"model_name": name},
          "experiments": experiments}
    if plan_error:
        mj["experiment_plan_error"] = plan_error
    rec = _row(db, inv_id, name=name, tier=tier, run_id=run_id,
               verified=55.0, confidence=0.4, layer="model",
               days_ago=days_ago)
    # _row writes only a stub model_json; replace it with the plan-bearing one.
    rec.model_json = json.dumps(mj)
    rec.hypothesis_json = json.dumps({"hypotheses": hypotheses})
    db.commit()
    return rec


class TestCoverage(LeadershipTestBase):
    """Coverage of the scope: investigations assessed vs total, and the
    experiment plans over the open-falsifier space."""

    def test_investigation_coverage_counts_assessed_versus_total(self):
        _row(self.db, self.inv.id, name="a", tier="internal", run_id=1,
             verified=40.0, confidence=0.5)
        other = Investigation(title="Never assessed")
        self.db.add(other)
        self.db.commit()
        c = LD.coverage(self.db)
        self.assertEqual(c["investigations"]["total"], 2)
        self.assertEqual(c["investigations"]["assessed"], 1)
        self.assertEqual(c["investigations"]["unassessed"], 1)
        self.assertEqual(c["investigations"]["coverage_pct"], 50)

    def test_coverage_respects_the_resolved_scope(self):
        # A tier filter narrows the coverage claim the same way it narrows
        # every other board section: an assessment in another tier does not
        # make this scope "assessed".
        _row(self.db, self.inv.id, name="a", tier="public", run_id=1,
             verified=40.0, confidence=0.5)
        c = LD.coverage(self.db, exposure="restricted_data")
        self.assertEqual(c["investigations"]["assessed"], 0)

    def test_single_investigation_scope_reports_one(self):
        _row(self.db, self.inv.id, name="a", tier="internal", run_id=1,
             verified=40.0, confidence=0.5)
        c = LD.coverage(self.db, self.inv.id)
        self.assertEqual(c["investigations"]["total"], 1)
        self.assertEqual(c["investigations"]["assessed"], 1)

    def test_experiment_coverage_counts_plans_and_falsifier_targets(self):
        covered = {"hypothesis_id": "H01", "status": "untested"}
        bare = {"hypothesis_id": "H02", "status": "contested"}
        _model_row(self.db, self.inv.id, name="m", run_id=1,
                   experiments=[{"id": "EX-01", "title": "canary probe",
                                 "method_type": "canary_probe",
                                 "targets": {"hypothesis_ids": ["H01"]}}],
                   hypotheses=[covered, bare])
        c = LD.coverage(self.db, self.inv.id)
        e = c["experiments"]
        self.assertEqual(e["model_assessments"], 1)
        self.assertEqual(e["with_plan"], 1)
        self.assertEqual(e["planned"], 1)
        self.assertEqual(e["plan_coverage_pct"], 100)
        self.assertEqual(e["open_falsifiers"], 2)
        self.assertEqual(e["covered_falsifiers"], 1)
        self.assertEqual(e["falsifier_coverage_pct"], 50)
        self.assertEqual(e["planner_unavailable"], 0)

    def test_a_product_row_is_not_counted_as_a_model_assessment(self):
        _row(self.db, self.inv.id, name="p", tier="internal", run_id=1,
             verified=40.0, confidence=0.5, layer="product")
        c = LD.coverage(self.db, self.inv.id)
        self.assertEqual(c["experiments"]["model_assessments"], 0)
        self.assertIsNone(c["experiments"]["plan_coverage_pct"])

    def test_an_unbuildable_plan_is_reported_not_hidden(self):
        _model_row(self.db, self.inv.id, name="m", run_id=1,
                   experiments=[],
                   hypotheses=[{"hypothesis_id": "H01", "status": "untested"}],
                   plan_error="planner unavailable: timeout")
        c = LD.coverage(self.db, self.inv.id)
        self.assertEqual(c["experiments"]["planner_unavailable"], 1)
        self.assertEqual(c["experiments"]["with_plan"], 0)

    def test_board_payload_and_export_carry_the_coverage_section(self):
        _model_row(self.db, self.inv.id, name="m", run_id=1,
                   experiments=[{"id": "EX-01", "title": "x",
                                 "method_type": "canary_probe",
                                 "targets": {"hypothesis_ids": ["H01"]}}],
                   hypotheses=[{"hypothesis_id": "H01", "status": "untested"}])
        b = LD.board(self.db, self.inv.id)
        self.assertEqual(b["coverage"]["investigations"]["total"], 1)
        md = LD.export_markdown(self.db, self.inv.id)
        self.assertIn("## Coverage", md)
        self.assertIn("1/1", md)
