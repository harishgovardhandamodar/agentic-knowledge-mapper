"""Assurance + leadership API surface.

Run with:  python3 -m pytest tests/test_assurance_api.py -q

These tests exist to pin the contract the endpoints promise rather than the
arithmetic inside the assurance engine (covered in test_assurance.py):

- a residual is never returned without its evidence confidence and gate status
- an unassessed row says so explicitly instead of looking like a passing one
- a decision is refused without an actor, and an exception without a rationale
- reviewing evidence reports what it would change, not that the score moved
"""
import json
import os
import tempfile
import unittest

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(
        tempfile.mkdtemp(prefix="akm-assurance-api-"), "test.db"))

from app import database as _db  # noqa: E402
from app import leadership as LD  # noqa: E402
from app.database import Base, SessionLocal  # noqa: E402
from app.models import (AgentRun, Artifact, Investigation,  # noqa: E402
                        SecurityAssessment)

_db.init_db()

ASSURANCE = {
    "assessed": True,
    "evidence_confidence": 0.31,
    "verified": {"residual_pct": 62.7, "headline": "verified"},
    "declared": {"residual_pct": 35.4},
    "headline_layer": "verified",
    "control_attestation": {"MDR-AI-001": {"status": "declared", "evidence_ids": []}},
    "architecture_gate": {"gate_blocked_applied": True,
                          "banner": "Scoring returned to inherent for 3 threats",
                          "open_items": ["no-logging"],
                          "items": [{"key": "logging", "status": "unknown",
                                     "value": ""}]},
    "forensics": {"reconstructable": False, "score": 21.0, "band": "partial",
                  "not_found": ["prompt_hash"]},
    "blast_radius": {"quantified": False},
    "chains": [{"chain_id": "KE-01->KE-06", "complete": False, "break": "KE-04"}],
    "gates_open": ["evidence_threshold"],
    "threats": [{"id": "T02", "title": "Model extraction",
                 "coverage_confidence_pct": 21,
                 "verified_residual": 62.7}],
    "decision": {"decision": "reject_until_architecture_gate_closed",
                 "headline": "Reject until architecture gate closed"},
}


class AssuranceApiCase(unittest.TestCase):
    def setUp(self):
        Base.metadata.create_all(_db.engine)
        self.db = SessionLocal()
        from fastapi.testclient import TestClient
        from app.main import app
        self.client = TestClient(app)
        self.client.__enter__()
        self.inv = Investigation(title="Assurance API", keywords="k",
                                 description="d", sources="web")
        self.db.add(self.inv)
        self.db.commit()
        self.db.refresh(self.inv)

    def tearDown(self):
        try:
            self.client.__exit__(None, None, None)
        finally:
            try:
                # Leave the shared database as we found it: every module in one
                # pytest process shares one SQLite file, and an investigation
                # left behind becomes an orphaned row the next time that rowid
                # is reused.
                for m in (SecurityAssessment, Artifact, AgentRun):
                    self.db.query(m).filter(
                        m.investigation_id == self.inv.id).delete()
                self.db.query(Investigation).filter(
                    Investigation.id == self.inv.id).delete()
                self.db.commit()
            except Exception:
                self.db.rollback()
            self.db.close()

    def _assessment(self, *, assurance=ASSURANCE, name="restricted copilot",
                    exposure="restricted_data"):
        rec = SecurityAssessment(
            investigation_id=self.inv.id, run_id=1, product_name=name,
            product_family=name, exposure=exposure, inherent_pct=100.0,
            residual_pct=35.4, evidence_confidence=0.31, markdown="# stub",
            assurance_json=(json.dumps(assurance) if assurance is not None else None),
            scoring_json=json.dumps({"assessment_path": "standard"}),
            threats_json=json.dumps(assurance.get("threats") if assurance else []))
        self.db.add(rec)
        self.db.commit()
        self.db.refresh(rec)
        return rec

    # ---- the assessment endpoints -------------------------------------

    def test_assurance_returns_confidence_and_gates_with_the_number(self):
        rec = self._assessment()
        r = self.client.get(f"/api/security/assessments/{rec.id}/assurance")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["assurance"]["verified"]["residual_pct"], 62.7)
        self.assertEqual(body["evidence_confidence"], 0.31)
        self.assertTrue(body["assurance"]["architecture_gate"]["gate_blocked_applied"])
        self.assertEqual(body["decision_state"], LD.STATE_BLOCKED)
        self.assertEqual(body["decision_derived"],
                         "reject_until_architecture_gate_closed")

    def test_unassessed_row_reports_that_it_is_unassessed(self):
        rec = self._assessment(assurance=None)
        r = self.client.get(f"/api/security/assessments/{rec.id}/assurance")
        # 422 rather than an empty object that reads like "no findings".
        self.assertEqual(r.status_code, 422)
        # The assessment payload itself says so explicitly.
        body = self.client.get(f"/api/security/assessments/{rec.id}").json()
        self.assertIs(body["assurance"]["assessed"], False)
        self.assertIn("predates", body["assurance"]["reason"])

    def test_vendor_questionnaire_names_the_threats_each_answer_unblocks(self):
        rec = self._assessment()
        body = self.client.get(
            f"/api/security/assessments/{rec.id}/vendor-questionnaire").json()
        self.assertTrue(body["items"])
        self.assertTrue(all(i["blocks"] for i in body["items"]))

    def test_review_queue_surfaces_pending_evidence(self):
        rec = self._assessment()
        self.db.add(Artifact(investigation_id=self.inv.id, title="vendor doc",
                             source="acme", origin="vendor_docs",
                             artifact_type="vendor_docs", review="pending",
                             relevance=0.9, assessment_id=rec.id))
        self.db.commit()
        body = self.client.get(
            f"/api/security/assessments/{rec.id}/review-queue").json()
        self.assertEqual(body["pending"], 1)

    def test_canonical_register_keys_are_stable_per_product_family(self):
        rec = self._assessment()
        body = self.client.get(
            f"/api/security/assessments/{rec.id}/assurance/register").json()
        self.assertTrue(body["canonical_keys"])
        self.assertEqual(body["count"], len(body["canonical_keys"]))
        # Every key is namespaced by product family, so two runs of one family
        # address the same rows.
        for key in body["canonical_keys"]:
            self.assertTrue(key.startswith("restricted"), key)

    # ---- the decision endpoint ----------------------------------------

    def test_decision_is_recorded_with_actor_and_ledger_event(self):
        rec = self._assessment()
        r = self.client.post(f"/api/security/assessments/{rec.id}/decision",
                             json={"decision": "exception",
                                   "actor": "ciso@example.com",
                                   "rationale": "SIEM pending", "expires_days": 30})
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertTrue(body["recorded_in_ledger"])
        self.assertTrue(body["expires_at"])
        # An exception defers the derived recommendation rather than
        # replacing it, so it is recorded as a deferral, not an override.
        self.assertFalse(body["overrode_derivation"])

    def test_unnamed_caller_with_no_session_is_refused(self):
        # The shared default actor cannot tell two people apart, so a
        # decision that has to be attributable is refused instead.
        rec = self._assessment()
        r = self.client.post(f"/api/security/assessments/{rec.id}/decision",
                             json={"decision": "accept", "actor": "  "})
        self.assertEqual(r.status_code, 422)

    def test_named_actor_header_is_accepted_as_the_signatory(self):
        rec = self._assessment()
        r = self.client.post(f"/api/security/assessments/{rec.id}/decision",
                             json={"decision": "accept"},
                             headers={"X-AKM-Actor": "ciso@example.com"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["actor"], "ciso@example.com")

    def test_exception_without_rationale_is_refused(self):
        rec = self._assessment()
        r = self.client.post(f"/api/security/assessments/{rec.id}/decision",
                             json={"decision": "exception", "actor": "ciso",
                                   "rationale": ""})
        self.assertEqual(r.status_code, 422)

    def test_unknown_decision_is_refused(self):
        rec = self._assessment()
        r = self.client.post(f"/api/security/assessments/{rec.id}/decision",
                             json={"decision": "maybe", "actor": "ciso"})
        self.assertEqual(r.status_code, 422)

    # ---- evidence review ------------------------------------------------

    def test_review_reports_impact_and_does_not_claim_the_score_moved(self):
        rec = self._assessment()
        self.db.add(Artifact(investigation_id=self.inv.id, title="dpa",
                             source="acme", origin="contract",
                             artifact_type="contract", review="pending",
                             relevance=0.92, assessment_id=rec.id))
        self.db.commit()
        art = self.db.query(Artifact).filter(Artifact.assessment_id == rec.id).one()
        r = self.client.post(
            f"/api/security/assessments/{rec.id}/evidence/{art.id}/review",
            json={"review": "accepted", "reviewer": "reviewer@example.com"})
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["review"], "accepted")
        self.assertTrue(body["impact"]["qualifies_for_verified_credit"])
        self.assertTrue(body["impact"]["would_raise_coverage_for"])
        self.assertIn("unchanged", body["note"])

    def test_irrelevant_or_drifted_evidence_releases_no_credit(self):
        rec = self._assessment()
        self.db.add(Artifact(investigation_id=self.inv.id, title="blog post",
                             source="blog", origin="blog", artifact_type="blog",
                             review="pending", relevance=0.2, drift=1,
                             assessment_id=rec.id))
        self.db.commit()
        art = self.db.query(Artifact).filter(Artifact.assessment_id == rec.id).one()
        body = self.client.post(
            f"/api/security/assessments/{rec.id}/evidence/{art.id}/review",
            json={"review": "accepted"}).json()
        self.assertFalse(body["impact"]["qualifies_for_verified_credit"])

    def test_review_of_an_unknown_review_state_is_refused(self):
        rec = self._assessment()
        self.db.add(Artifact(investigation_id=self.inv.id, title="d",
                             source="s", origin="contract",
                             artifact_type="contract", review="pending",
                             relevance=0.9, assessment_id=rec.id))
        self.db.commit()
        art = self.db.query(Artifact).filter(Artifact.assessment_id == rec.id).one()
        r = self.client.post(
            f"/api/security/assessments/{rec.id}/evidence/{art.id}/review",
            json={"review": "maybe"})
        self.assertEqual(r.status_code, 422)

    # ---- ledger ---------------------------------------------------------

    def test_ledger_integrity_and_pack_endpoints_respond(self):
        rec = self._assessment()
        for path in (f"/api/security/assessments/{rec.id}/ledger/integrity",
                     f"/api/security/assessments/{rec.id}/evidence-pack"):
            r = self.client.get(path)
            self.assertEqual(r.status_code, 200, path)
            self.assertIn("run_id", r.json())

    # ---- leadership -----------------------------------------------------

    def test_board_carries_every_view(self):
        self._assessment()
        r = self.client.get(f"/api/leadership/board?investigation_id={self.inv.id}")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        for view in ("risk_position", "decision_queue", "assurance_health",
                     "exposure_lens", "system_integrity", "alerts"):
            self.assertIn(view, body)
        self.assertTrue(body["contract"]["residual_always_with_confidence"])

    def test_decision_queue_rows_carry_confidence_and_gate_status(self):
        self._assessment()
        item = self.client.get(
            f"/api/leadership/decision-queue?investigation_id={self.inv.id}"
        ).json()["items"][0]
        self.assertEqual(item["verified_residual_pct"], 62.7)
        self.assertEqual(item["evidence_confidence_pct"], 31)
        self.assertTrue(item["architecture_gate"])

    def test_individual_leadership_views_respond(self):
        for path in ("risk-position", "decision-queue", "assurance-health",
                     "exposure", "system-integrity", "alerts", "exceptions"):
            r = self.client.get(f"/api/leadership/{path}")
            self.assertEqual(r.status_code, 200, path)

    def test_change_log_names_the_current_row(self):
        self._assessment()
        body = self.client.get(
            f"/api/leadership/change-log/{self.inv.id}").json()
        self.assertEqual(len(body["current"]), 1)

    def test_board_supports_the_security_engineering_persona(self):
        r = self.client.get("/api/leadership/board?persona=security_engineering")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["persona"], "security_engineering")
        self.assertIn("system_integrity", body["emphasis"])

    def test_integrity_monitor_endpoint_verifies_recent_runs(self):
        self._assessment()
        r = self.client.get("/api/assurance/ledger/integrity-monitor")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertGreaterEqual(body["runs_checked"], 0)
        self.assertIn("verified", body)
        self.assertIn("broken", body)

    def test_siem_export_endpoint_streams_json_lines(self):
        self._assessment()
        r = self.client.get("/api/assurance/ledger/siem-export")
        self.assertEqual(r.status_code, 200)
        self.assertIn("application/x-ndjson", r.headers["content-type"])
        lines = [ln for ln in r.text.splitlines() if ln.strip()]
        self.assertGreater(len(lines), 0)
        import json as _json
        first = _json.loads(lines[0])
        self.assertIn("@timestamp", first)
        self.assertIn("run_id", first)

    def test_alerts_escalate_an_unquantified_restricted_tier(self):
        self._assessment()
        body = self.client.get(
            f"/api/leadership/alerts?investigation_id={self.inv.id}").json()
        ids = {a["id"].split("-")[0] for a in body["alerts"]}
        self.assertIn("gate", ids)
        self.assertIn("unquantified", ids)

    def test_assess_request_carries_the_assurance_inputs(self):
        from app.main import SecurityAssessRequest
        req = SecurityAssessRequest(product_name="copilot",
                                    architecture_checklist={"logging": True},
                                    exposure_inventory={"records": 10})
        self.assertEqual(req.architecture_checklist, {"logging": True})
        self.assertEqual(req.exposure_inventory, {"records": 10})
        # Absent inputs stay empty rather than defaulting to a pass.
        self.assertIsNone(SecurityAssessRequest().architecture_checklist)


if __name__ == "__main__":
    unittest.main()