"""Tests for the approval gate: the bypass, and the distinct approver.

Two findings are closed here.

The bypass: a request could carry ``approved_control_plan``, and the runner
honoured it without ever asking anyone -- so the gate was a field the requester
set for themselves. A plan is now only honoured when it names its approver.

The missing approver: the decision recorded nobody, so an approval could not be
attributed and the requester could approve their own run. Both are refused now,
and the decision goes to the ledger naming the approver and the requester.

The tests that matter most are the ones that would have passed before the fix:
an approved plan with no approver, and a requester approving their own run.
"""
import contextlib
import os
import tempfile
import json
import os
import unittest
from unittest import mock


from fastapi.testclient import TestClient  # noqa: E402

# Pin the database before app.database is imported: a module that omits
# this can inherit data/akm.db and write test rows into the live store.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-approvals-"), "test.db"))

from app import database  # noqa: E402
from app import approvals  # noqa: E402
from app import security_agent  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.models import AgentEvent, AgentRun, Investigation, Job  # noqa: E402

database.init_db()


@contextlib.contextmanager
def no_worker():
    """Stop ``launch`` from starting the polling thread.

    The test drains the queue itself. Left running, the worker races the drain
    for the same job, and the two of them writing one run looks exactly like a
    duplicate-execution bug in the queue.
    """
    with mock.patch.object(security_agent, "_ensure_worker", lambda: None):
        yield


def _investigation(title="gate-target") -> int:
    db = SessionLocal()
    try:
        inv = Investigation(title=title)
        db.add(inv)
        db.commit()
        db.refresh(inv)
        return inv.id
    finally:
        db.close()


def _parked_run(inv_id, plan=None, requested_by="alice", run_status="awaiting_approval"):
    """A run sitting at the control-plan gate, as the runner leaves it."""
    plan = plan if plan is not None else {
        "declared_controls": ["C01"], "proposed_controls": ["C09"], "confidence": 0.7,
    }
    db = SessionLocal()
    try:
        run = AgentRun(
            investigation_id=inv_id, trigger="security", status=run_status,
            plan=json.dumps({"product": "Widget", "exposure": "confidential_data"}),
            stats=json.dumps({"pending_gate": "control_plan", "control_plan": plan,
                              "params": {"product_name": "Widget", "requested_by": requested_by}}))
        db.add(run)
        db.commit()
        db.refresh(run)
        return run.id
    finally:
        db.close()


class TestCheckApprover(unittest.TestCase):
    def test_a_different_person_may_approve(self):
        self.assertEqual(
            approvals.check_approver(approver="bob", requester="alice"), "bob")

    def test_the_requester_cannot_approve_their_own_run(self):
        with self.assertRaises(approvals.ApprovalError) as ctx:
            approvals.check_approver(approver="alice", requester="alice")
        self.assertEqual(ctx.exception.status, 403)
        self.assertIn("cannot approve", ctx.exception.reason)

    def test_case_and_whitespace_do_not_launder_a_self_approval(self):
        """``"Alice "`` and ``"alice"`` are one person.

        A gate that compares raw strings is one case-flip away from being off.
        """
        for variant in ("Alice", "ALICE", " alice ", "Alice\t"):
            with self.assertRaises(approvals.ApprovalError, msg=variant):
                approvals.check_approver(approver=variant, requester="alice")

    def test_an_unnamed_approver_is_refused(self):
        for who in ("", "   ", None):
            with self.assertRaises(approvals.ApprovalError):
                approvals.check_approver(approver=who, requester="alice")

    def test_the_refusal_reports_both_names(self):
        with self.assertRaises(approvals.ApprovalError) as ctx:
            approvals.check_approver(approver="alice", requester="alice", run_id=7)
        self.assertEqual(ctx.exception.detail["approver"], "alice")
        self.assertEqual(ctx.exception.detail["run_id"], 7)

    def test_the_approver_name_is_bounded(self):
        long = "z" * 500
        self.assertLessEqual(len(approvals.check_approver(approver=long,
                                                           requester="alice")), 64)


class TestDecisionRecord(unittest.TestCase):
    def test_the_record_carries_the_approved_control_set(self):
        """"Approved" is only meaningful next to *what* was approved."""
        rec = approvals.decision_record(
            run_id=3, decision="approve", approver="bob", requester="alice",
            plan={"declared_controls": ["C01", "C02"], "proposed_controls": ["C09"]},
            edited=True, note="ok")
        self.assertEqual(rec["approver"], "bob")
        self.assertEqual(rec["requester"], "alice")
        self.assertEqual(rec["active_controls"], ["C01", "C02"])
        self.assertTrue(rec["edited"])
        self.assertEqual(rec["decision"], "approve")

    def test_a_long_note_is_bounded(self):
        rec = approvals.decision_record(run_id=1, decision="approve", approver="b",
                                        requester="a", note="n" * 900)
        self.assertLessEqual(len(rec["note"]), 500)

    def test_requester_of_reads_the_gate_state(self):
        stats = json.dumps({"params": {"requested_by": "carol"}})
        self.assertEqual(approvals.requester_of(stats), "carol")

    def test_requester_of_survives_unreadable_state(self):
        for stats in ("not json", "[]", None, ""):
            self.assertEqual(approvals.requester_of(stats), approvals.UNKNOWN_ACTOR)


class _QueueCase(unittest.TestCase):
    """Truncates the job queue between tests.

    ``drain`` claims whatever is oldest, so one test's leftover job would be run
    against another test's run -- and the resulting assertion failure looks like
    a bug in the approval gate rather than in the test.
    """

    def setUp(self):
        db = SessionLocal()
        try:
            db.query(Job).delete()
            db.commit()
        finally:
            db.close()


class TestApprovedPlanNeedsAnApprover(_QueueCase):
    """The bypass: a plan on the request used to skip the gate entirely."""

    def _drain_once(self, params):
        """Launch a run, run the queue's handler for it, return the run row."""
        inv_id = _investigation("bypass-check")
        with no_worker():
            run_id = security_agent.launch_security_assessment(
                inv_id, params, requested_by="alice")
        db = SessionLocal()
        try:
            security_agent.jobqueue.drain(db, security_agent._handle_security_job,
                                          kinds=[security_agent.KIND_SECURITY])
            # The handler committed through its own session; this one is holding
            # a copy from before, so let it go before reading.
            db.expire_all()
            return db.query(AgentRun).filter(AgentRun.id == run_id).first()
        finally:
            db.close()

    def test_a_plan_with_no_approver_does_not_skip_the_gate(self):
        run = self._drain_once({
            "product_name": "Widget", "exposure": "confidential_data",
            "require_approval": True,
            "approved_control_plan": {"declared_controls": ["C01"]}})
        self.assertEqual(run.status, "awaiting_approval",
                         "an unattributed plan skipped the approval gate")
        self.assertEqual(json.loads(run.stats)["pending_gate"], "control_plan")

    def test_the_refused_bypass_is_recorded_as_an_event(self):
        run = self._drain_once({"product_name": "Widget", "require_approval": True,
                                "approved_control_plan": {"declared_controls": ["C01"]}})
        db = SessionLocal()
        try:
            msgs = [e.message for e in db.query(AgentEvent)
                    .filter(AgentEvent.run_id == run.id).all()]
            self.assertTrue(any("no recorded approver" in m for m in msgs), msgs)
        finally:
            db.close()

    def test_a_plan_that_names_its_approver_is_honoured(self):
        """The gate opens when -- and only when -- a second person signed it.

        ``build_assessment`` is stubbed: reaching it *is* the proof the gate
        opened, and letting it run would call the model for nothing.
        """
        from app.models import AgentEvent
        inv_id = _investigation("honoured")
        with no_worker():
            run_id = security_agent.launch_security_assessment(inv_id, {
                "product_name": "Widget", "require_approval": True,
                "approved_control_plan": {"declared_controls": ["C01"]},
                "approved_by": "bob", "approved_at": "2026-01-01T00:00:00+00:00",
            }, requested_by="alice")
        params = {"product_name": "Widget", "require_approval": True,
                  "approved_control_plan": {"declared_controls": ["C01"]},
                  "approved_by": "bob",
                  "approved_at": "2026-01-01T00:00:00+00:00"}
        db = SessionLocal()
        try:
            with mock.patch.object(security_agent.sec_engine, "build_assessment",
                                   side_effect=RuntimeError("stop-after-gate")) as m:
                security_agent.run_security_assessment(run_id, params)
            self.assertTrue(m.called, "an attributed plan did not open the gate")
            msgs = [e.message for e in db.query(AgentEvent)
                    .filter(AgentEvent.run_id == run_id).all()]
            self.assertFalse([m for m in msgs if "no recorded approver" in m],
                             "an attributed plan was refused")
        finally:
            db.close()

    def test_the_requester_is_stamped_on_the_run(self):
        inv_id = _investigation("stamped")
        with no_worker():
            run_id = security_agent.launch_security_assessment(
                inv_id, {"product_name": "Widget", "require_approval": True},
                requested_by="alice")
        db = SessionLocal()
        try:
            job = db.query(Job).filter(Job.run_id == run_id).first()
            self.assertIsNotNone(job, "the work was not persisted as a job")
            self.assertEqual(job.kind, security_agent.KIND_SECURITY)
            self.assertEqual(job.status, "pending")
            self.assertEqual(
                json.loads(job.payload_json)["params"]["requested_by"], "alice")
        finally:
            db.close()


class TestStartupRecovery(_QueueCase):
    """What a restart finds, and what it must not destroy.

    The old sweep marked *every* run left at "running" as interrupted. Once
    there is a queue, that is wrong for a run whose job is about to be picked up
    again -- the crash is being repaired, and recording it as a failure is a
    lie the operator then has to read.
    """

    def test_a_recovered_job_keeps_its_run_alive(self):
        inv_id = _investigation("recovered")
        with no_worker():
            run_id = security_agent.launch_security_assessment(
                inv_id, {"product_name": "Widget"}, requested_by="alice")
        db = SessionLocal()
        try:
            job = db.query(Job).filter(Job.run_id == run_id).first()
            job.status = "running"          # as a crashed worker left it
            job.attempts = 1
            job.lease_expires_at = None     # died before stamping a lease
            db.commit()

            from app import main as main_mod
            with mock.patch.object(security_agent, "start_worker", lambda: None):
                main_mod.on_start()
            db.expire_all()
            self.assertEqual(db.query(AgentRun).filter(
                AgentRun.id == run_id).first().status, "running",
                "the sweep killed a run whose job had just been re-queued")
            self.assertEqual(db.query(Job).filter(Job.run_id == run_id)
                             .first().status, "pending",
                             "the job was not re-queued")
        finally:
            db.close()

    def test_a_job_with_no_run_does_not_break_recovery(self):
        """A job need not belong to a run; recovery must not choke on one."""
        db = SessionLocal()
        try:
            db.add(Job(kind="orphan", status="running", payload_json="{}",
                       lease_expires_at=None))
            db.commit()
            self.assertEqual(security_agent.recover_jobs(), [])
        finally:
            db.close()

    def test_a_run_with_no_job_is_still_marked_interrupted(self):
        """The sweep keeps doing its job for work that really is lost."""
        inv_id = _investigation("truly-lost")
        run_id = security_agent.launch_security_assessment(
            inv_id, {"product_name": "Widget"}, requested_by="alice")
        db = SessionLocal()
        try:
            db.query(Job).delete()
            db.commit()
            from app import main as main_mod
            with mock.patch.object(security_agent, "start_worker", lambda: None):
                main_mod.on_start()
            db.expire_all()
            run = db.query(AgentRun).filter(AgentRun.id == run_id).first()
            self.assertEqual(run.status, "error")
            self.assertIn("restart", run.error)
        finally:
            db.close()


class TestLaunchIdempotency(_QueueCase):
    def test_a_double_submit_does_not_queue_the_work_twice(self):
        inv_id = _investigation("double-submit")
        params = {"product_name": "Widget", "require_approval": True}
        with no_worker():
            first = security_agent.launch_security_assessment(inv_id, params,
                                                              requested_by="alice")
            second = security_agent.launch_security_assessment(inv_id, params,
                                                               requested_by="alice")
        db = SessionLocal()
        try:
            live = (db.query(Job)
                    .filter(Job.status.in_(["pending", "retry", "running"]))
                    .all())
            keys = [j.key for j in live]
            self.assertEqual(len(keys), len(set(keys)),
                             f"two live jobs share a key: {keys}")
        finally:
            db.close()
        self.assertNotEqual(first, second, "each launch should make its own run")


class TestApprovalEndpoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from app import main as main_mod
        cls.client = TestClient(main_mod.app)

    def _approve(self, run_id, actor, **body):
        headers = {"X-AKM-Actor": actor} if actor is not None else {}
        return self.client.post(f"/api/security/runs/{run_id}/approval",
                                json={"decision": "approve", **body}, headers=headers)

    def test_the_requester_cannot_approve_their_own_run(self):
        run_id = _parked_run(_investigation("self-approve"), requested_by="alice")
        r = self._approve(run_id, "alice")
        self.assertEqual(r.status_code, 403, r.text)
        self.assertIn("cannot approve", r.json()["detail"])

    def test_a_refused_self_approval_does_not_resume_the_run(self):
        run_id = _parked_run(_investigation("self-approve-2"), requested_by="alice")
        self._approve(run_id, "alice")
        db = SessionLocal()
        try:
            self.assertEqual(db.query(AgentRun).filter(
                AgentRun.id == run_id).first().status, "awaiting_approval")
        finally:
            db.close()

    def test_a_different_person_can_approve(self):
        run_id = _parked_run(_investigation("other-approves"), requested_by="alice")
        r = self._approve(run_id, "bob")
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["status"], "resumed")
        self.assertEqual(body["approver"], "bob")
        self.assertEqual(body["requester"], "alice")

    def test_approval_queues_the_resume_with_the_approver_stamped(self):
        run_id = _parked_run(_investigation("stamped-resume"), requested_by="alice")
        self._approve(run_id, "bob")
        db = SessionLocal()
        try:
            job = db.query(Job).filter(Job.run_id == run_id).order_by(
                Job.id.desc()).first()
            params = json.loads(job.payload_json)["params"]
            self.assertEqual(params["approved_by"], "bob")
            self.assertTrue(params["approved_at"], "the approval has no timestamp")
            self.assertFalse(params["require_approval"])
        finally:
            db.close()

    def test_the_approver_may_edit_the_control_set(self):
        run_id = _parked_run(_investigation("edited"), requested_by="alice")
        r = self._approve(run_id, "bob", active_controls=["C01", "C04"])
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["edited"])
        self.assertEqual(r.json()["approved_controls"], ["C01", "C04"])

    def test_a_different_person_may_reject(self):
        run_id = _parked_run(_investigation("rejected"), requested_by="alice")
        r = self.client.post(f"/api/security/runs/{run_id}/approval",
                             json={"decision": "reject"},
                             headers={"X-AKM-Actor": "bob"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["status"], "rejected")
        db = SessionLocal()
        try:
            self.assertEqual(db.query(AgentRun).filter(
                AgentRun.id == run_id).first().status, "error")
        finally:
            db.close()

    def test_the_requester_cannot_reject_their_own_run_either(self):
        """Rejection is a decision too, and it is recorded the same way."""
        run_id = _parked_run(_investigation("self-reject"), requested_by="alice")
        r = self.client.post(f"/api/security/runs/{run_id}/approval",
                             json={"decision": "reject"},
                             headers={"X-AKM-Actor": "alice"})
        self.assertEqual(r.status_code, 403, r.text)

    def test_an_unnamed_approver_is_refused(self):
        """No ``X-AKM-Actor`` and no session means nobody to attribute it to."""
        run_id = _parked_run(_investigation("anon"), requested_by="alice")
        r = self._approve(run_id, None)
        self.assertEqual(r.status_code, 403, r.text)

    def test_approving_a_run_that_is_not_waiting_is_a_conflict(self):
        run_id = _parked_run(_investigation("not-waiting"), requested_by="alice",
                             run_status="running")
        r = self._approve(run_id, "bob")
        self.assertEqual(r.status_code, 409, r.text)

    def test_approving_an_unknown_run_is_a_404(self):
        self.assertEqual(self._approve(999999, "bob").status_code, 404)


class TestApprovalIsAudited(unittest.TestCase):
    """An approval nobody can be named against is not a control."""

    @classmethod
    def setUpClass(cls):
        from app import main as main_mod
        cls.client = TestClient(main_mod.app)

    def _actions(self):
        from app.ledger_models import LedgerEvent
        db = SessionLocal()
        try:
            rows = db.query(LedgerEvent).filter(
                LedgerEvent.kind == "human.action").all()
            return [(e.actor, json.loads(e.data_json or "{}")) for e in rows]
        finally:
            db.close()

    def test_the_approver_and_the_requester_are_both_on_the_ledger(self):
        run_id = _parked_run(_investigation("audited"), requested_by="alice")
        r = self.client.post(f"/api/security/runs/{run_id}/approval",
                             json={"decision": "approve", "note": "checked"},
                             headers={"X-AKM-Actor": "bob", "X-AKM-Session": "s-audited"})
        self.assertEqual(r.status_code, 200, r.text)
        found = [d for _, d in self._actions()
                 if d.get("action") == "approved_control_plan"
                 and d.get("detail", {}).get("run_id") == run_id]
        self.assertEqual(len(found), 1, self._actions())
        detail = found[0]["detail"]
        self.assertEqual(detail["approver"], "bob")
        self.assertEqual(detail["requester"], "alice")
        self.assertEqual(detail["note"], "checked")
        self.assertIn("active_controls", detail)

    def test_a_refused_approval_is_recorded_too(self):
        """Somebody trying to pass their own gate is worth a record."""
        run_id = _parked_run(_investigation("audited-refusal"), requested_by="alice")
        r = self.client.post(f"/api/security/runs/{run_id}/approval",
                             json={"decision": "approve"},
                             headers={"X-AKM-Actor": "alice", "X-AKM-Session": "s-refused"})
        self.assertEqual(r.status_code, 403, r.text)
        found = [d for _, d in self._actions()
                 if d.get("action") == "approval_refused"
                 and d.get("detail", {}).get("run_id") == run_id]
        self.assertEqual(len(found), 1, self._actions())
        self.assertEqual(found[0]["detail"]["approver"], "alice")

    def test_the_approval_carries_a_trace(self):
        run_id = _parked_run(_investigation("audited-trace"), requested_by="alice")
        r = self.client.post(f"/api/security/runs/{run_id}/approval",
                             json={"decision": "approve"},
                             headers={"X-AKM-Actor": "bob",
                                      "X-AKM-Session": "s-traced",
                                      "X-AKM-Trace-Id": "t-mine"})
        self.assertEqual(r.status_code, 200, r.text)
        from app.ledger_models import LedgerEvent
        db = SessionLocal()
        try:
            traces = {e.trace for e in db.query(LedgerEvent).filter(
                LedgerEvent.kind == "human.action").all()}
            self.assertIn("t-mine", traces, traces)
        finally:
            db.close()


class TestActorIdentity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from app import main as main_mod
        cls.client = TestClient(main_mod.app)

    def test_a_named_actor_is_used(self):
        r = self.client.get("/api/runs/1",
                            headers={"X-AKM-Actor": "dana", "X-AKM-Session": "s1"})
        self.assertIn(r.status_code, (200, 404))

    def test_an_endpoint_404_stays_a_404_with_a_session_header(self):
        """A fail-open audit dependency must not swallow the endpoint's own error.

        The browser always sends a session header, so this path is every
        request. When the guard wrapped the yield, the endpoint's 404 was caught
        as if the *ledger* had failed and re-raised as
        "generator didn't stop after athrow()" -- a 500 where the honest answer
        was 404, and a refusal that could not be read.
        """
        r = self.client.get("/api/runs/987654", headers={"X-AKM-Session": "s-404"})
        self.assertEqual(r.status_code, 404, r.text)

    def test_an_endpoint_403_stays_a_403_with_a_session_header(self):
        """The refusal path has to survive the browser's own headers."""
        run_id = _parked_run(_investigation("self-approve-session"),
                             requested_by="alice")
        r = self.client.post(f"/api/security/runs/{run_id}/approval",
                             json={"decision": "approve"},
                             headers={"X-AKM-Actor": "alice", "X-AKM-Session": "s-403"})
        self.assertEqual(r.status_code, 403, r.text)
        self.assertIn("cannot approve", r.json()["detail"])

    def test_request_actor_falls_back_to_the_session(self):
        """Two browsers must be distinguishable.

        A shared default of "user" cannot tell two people apart, and telling
        two people apart is the whole job of this check.
        """
        from starlette.requests import Request
        from app import ledger_api

        def actor_for(headers):
            scope = {"type": "http", "method": "GET", "path": "/", "headers": [
                (k.lower().encode(), v.encode()) for k, v in headers.items()]}
            return ledger_api.request_actor(Request(scope))

        self.assertEqual(actor_for({"X-AKM-Session": "s-1"}), "s-1")
        self.assertNotEqual(actor_for({"X-AKM-Session": "s-1"}),
                            actor_for({"X-AKM-Session": "s-2"}))
        self.assertEqual(actor_for({"X-AKM-Actor": "dana", "X-AKM-Session": "s-1"}),
                         "dana")
        self.assertNotEqual(ledger_api.DEFAULT_ACTOR, actor_for({"X-AKM-Session": "s-1"}))


if __name__ == "__main__":
    unittest.main()
