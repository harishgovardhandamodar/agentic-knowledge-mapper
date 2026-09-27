"""Tests for the persisted job queue.

The point of the queue is that a job survives the process that would have
carried it in a thread, so the tests that matter are about what a restart or a
crash leaves behind: a job that was mid-flight is recovered, a job that was
merely slow is not duplicated, and a dead worker leaves a record rather than a
run stuck at "running" forever.

The most important test here is ``test_a_live_lease_is_not_recovered``: recovery
that re-claimed a healthy job would run every slow assessment twice and bill the
model calls twice, which is worse than losing one.
"""
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

os.environ.setdefault("AKM_DATABASE_URL", "sqlite:///" + os.path.join(
    tempfile.mkdtemp(prefix="akm-jobqueue-test-"), "test.db"))

from sqlalchemy.exc import IntegrityError  # noqa: E402

from app import database  # noqa: E402
from app import jobqueue  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.models import Job  # noqa: E402

database.init_db()


def _naive(dt):
    """SQLite hands datetimes back without a tzinfo; the queue compares in SQL,
    so only the test's own Python comparisons need them aligned."""
    return None if dt is None else dt.replace(tzinfo=None)


def _fresh(key, kind="test", **kw):
    """Enqueue one job, due now, on a key the caller chose. Returns its id.

    Only the id, not the object: the row is read back through the test's own
    session, because ``enqueue`` closes its session and a detached object would
    silently swallow the edits a test makes to it.
    """
    db = SessionLocal()
    try:
        return jobqueue.enqueue(db, kind, {"n": 1}, key=key, **kw).id
    finally:
        db.close()


def _row(db, job_id):
    return db.query(Job).filter(Job.id == job_id).first()


class _JobTestCase(unittest.TestCase):
    """Truncates the queue between tests.

    Every test here claims from the same queue, so a leftover job from an
    earlier test would be claimed instead of the one under test -- which looks
    exactly like the queue being wrong.
    """

    def setUp(self):
        db = SessionLocal()
        try:
            db.query(Job).delete()
            db.commit()
        finally:
            db.close()


class TestIdempotency(_JobTestCase):
    def test_duplicate_key_reuses_the_live_job(self):
        db = SessionLocal()
        try:
            first = jobqueue.enqueue(db, "test", {"a": 1}, key="dup")
            second = jobqueue.enqueue(db, "test", {"a": 2}, key="dup")
            self.assertEqual(first.id, second.id)
            self.assertEqual(db.query(Job).filter(Job.key == "dup").count(), 1)
        finally:
            db.close()

    def test_strict_mode_raises_on_a_duplicate(self):
        db = SessionLocal()
        try:
            jobqueue.enqueue(db, "test", {}, key="strict-dup")
            with self.assertRaises(jobqueue.JobExists):
                jobqueue.enqueue(db, "test", {}, key="strict-dup", strict=True)
        finally:
            db.close()

    def test_a_finished_job_frees_its_key_for_the_next_unit_of_work(self):
        """A run parked at a gate is re-queued under its original key.

        A plain UNIQUE(key) would refuse that forever, which would break every
        approval resume -- so uniqueness is over *live* jobs only.
        """
        db = SessionLocal()
        try:
            first = jobqueue.enqueue(db, "test", {}, key="resume-me")
            jobqueue.complete(db, first)
            second = jobqueue.enqueue(db, "test", {}, key="resume-me")
            self.assertNotEqual(first.id, second.id)
            self.assertEqual(second.status, "pending")
            self.assertEqual(db.query(Job).filter(Job.key == "resume-me").count(), 2)
        finally:
            db.close()

    def test_the_database_refuses_two_live_jobs_on_one_key(self):
        """Application-level check plus an index, so a concurrent submit loses."""
        db = SessionLocal()
        try:
            jobqueue.enqueue(db, "test", {}, key="race")
            db.add(Job(kind="test", key="race", status="pending",
                       payload_json="{}"))
            with self.assertRaises(IntegrityError):
                db.commit()
            db.rollback()
        finally:
            db.close()

    def test_null_keys_do_not_collide(self):
        db = SessionLocal()
        try:
            a = jobqueue.enqueue(db, "test", {})
            b = jobqueue.enqueue(db, "test", {})
            self.assertNotEqual(a.id, b.id)
        finally:
            db.close()


class TestClaiming(_JobTestCase):
    def test_claim_marks_running_with_a_lease_and_counts_the_attempt(self):
        jid = _fresh(key="claim-me")
        db = SessionLocal()
        try:
            got = jobqueue.claim(db)
            self.assertEqual(got.id, jid)
            self.assertEqual(got.status, "running")
            self.assertEqual(got.attempts, 1)
            self.assertIsNotNone(got.lease_expires_at)
        finally:
            db.close()

    def test_a_running_job_is_not_claimed_again(self):
        _fresh(key="only-once")
        db = SessionLocal()
        try:
            first = jobqueue.claim(db)
            second = jobqueue.claim(db)
            self.assertIsNotNone(first)
            self.assertIsNone(second, "a claimed job was handed out twice")
        finally:
            db.close()

    def test_claim_filters_by_kind(self):
        _fresh(kind="alpha", key="k-alpha")
        _fresh(kind="beta", key="k-beta")
        db = SessionLocal()
        try:
            got = jobqueue.claim(db, kinds=["beta"])
            self.assertEqual(got.kind, "beta")
        finally:
            db.close()

    def test_a_backoff_is_not_due_yet(self):
        jid = _fresh(key="backing-off")
        db = SessionLocal()
        try:
            row = _row(db, jid)
            row.status = "retry"
            row.next_attempt_at = jobqueue._now() + timedelta(seconds=30)
            db.commit()
            self.assertIsNone(jobqueue.claim(db), "claimed a job inside its backoff")
        finally:
            db.close()

    def test_nothing_to_do_reports_idle(self):
        db = SessionLocal()
        try:
            self.assertEqual(jobqueue.run_one(db, lambda j, p: True), "idle")
        finally:
            db.close()


class TestFailureAndRetry(_JobTestCase):
    def test_a_failure_reschedules_rather_than_being_lost(self):
        jid = _fresh(key="flaky", max_attempts=3)
        db = SessionLocal()
        try:
            claimed = jobqueue.claim(db)
            status = jobqueue.fail(db, claimed, "gateway timeout")
            self.assertEqual(status, "retry")
            self.assertIn("gateway timeout", claimed.last_error)
            self.assertGreater(_naive(claimed.next_attempt_at),
                               _naive(jobqueue._now()), "no backoff applied")
        finally:
            db.close()

    def test_attempts_are_exhausted_into_a_parked_failure(self):
        """A job that never recovers stops consuming attempts and parks.

        ``fail`` reschedules with a backoff, so each round has to make the job
        due again -- that is what a real retry does when the backoff elapses.
        """
        jid = _fresh(key="doomed", max_attempts=2)
        db = SessionLocal()
        try:
            for _ in range(2):
                claimed = jobqueue.claim(db)
                self.assertIsNotNone(claimed, "attempt budget not reached")
                status = jobqueue.fail(db, _row(db, jid), "still broken")
                row = _row(db, jid)
                row.next_attempt_at = jobqueue._now()   # pretend the backoff passed
                db.commit()
            self.assertEqual(status, "failed")
            self.assertEqual(_row(db, jid).attempts, 2)
            self.assertIsNotNone(_row(db, jid).finished_at)
            self.assertIsNone(jobqueue.claim(db), "a parked job was claimed again")
        finally:
            db.close()

    def test_backoff_grows_between_attempts(self):
        jid = _fresh(key="growing", max_attempts=4)
        db = SessionLocal()
        try:
            jobqueue.fail(db, jobqueue.claim(db), "x")
            first_delay = (_naive(_row(db, jid).next_attempt_at)
                           - _naive(jobqueue._now())).total_seconds()
            row = _row(db, jid)
            row.next_attempt_at = jobqueue._now()
            db.commit()
            jobqueue.fail(db, jobqueue.claim(db), "x")
            second_delay = (_naive(_row(db, jid).next_attempt_at)
                            - _naive(jobqueue._now())).total_seconds()
            self.assertGreater(second_delay, first_delay)
        finally:
            db.close()

    def test_a_raising_handler_is_retried_and_the_error_is_kept(self):
        _fresh(key="raiser", max_attempts=3)
        db = SessionLocal()
        try:
            def boom(job, payload):
                raise ValueError("handler exploded")
            status = jobqueue.run_one(db, boom)
            self.assertEqual(status, "retry")
            row = db.query(Job).filter(Job.key == "raiser").first()
            self.assertIn("handler exploded", row.last_error)
            self.assertIn("ValueError", row.last_error)
        finally:
            db.close()

    def test_no_retry_budget_parks_immediately(self):
        _fresh(key="one-shot", max_attempts=1)
        db = SessionLocal()
        try:
            status = jobqueue.run_one(db, lambda j, p: (_ for _ in ()).throw(
                RuntimeError("nope")))
            self.assertEqual(status, "failed")
        finally:
            db.close()

    def test_a_long_error_is_truncated(self):
        _fresh(key="verbose", max_attempts=1)
        db = SessionLocal()
        try:
            jobqueue.run_one(db, lambda j, p: (_ for _ in ()).throw(
                RuntimeError("x" * 9000)))
            row = db.query(Job).filter(Job.key == "verbose").first()
            self.assertLessEqual(len(row.last_error), jobqueue.ERROR_CHARS)
        finally:
            db.close()


class TestRecovery(_JobTestCase):
    def test_an_expired_lease_is_recovered(self):
        """The crash case: the worker died and nothing else will finish the job."""
        jid = _fresh(key="orphan")
        db = SessionLocal()
        try:
            jobqueue.claim(db)
            row = _row(db, jid)
            row.lease_expires_at = jobqueue._now() - timedelta(seconds=1)
            db.commit()
            recovered = jobqueue.recover_orphans(db)
            self.assertEqual([j.id for j in recovered], [jid])
            row = _row(db, jid)
            self.assertEqual(row.status, "pending")
            self.assertIsNone(row.lease_expires_at)
        finally:
            db.close()

    def test_a_live_lease_is_not_recovered(self):
        """A slow job is not a dead one.

        Recovery that re-claimed a healthy job would run every long assessment a
        second time -- duplicating the work and double-billing the model calls,
        which is worse than the failure it was meant to prevent.
        """
        jid = _fresh(key="slow-but-alive")
        db = SessionLocal()
        try:
            jobqueue.claim(db, lease_s=1800)
            self.assertEqual(jobqueue.recover_orphans(db), [])
            row = _row(db, jid)
            self.assertEqual(row.status, "running")
        finally:
            db.close()

    def test_a_lease_with_no_deadline_is_recovered(self):
        """A worker that died before stamping a lease must not hold the job."""
        jid = _fresh(key="no-lease")
        db = SessionLocal()
        try:
            jobqueue.claim(db)
            row = _row(db, jid)
            row.lease_expires_at = None
            db.commit()
            self.assertEqual(len(jobqueue.recover_orphans(db)), 1)
        finally:
            db.close()

    def test_a_heartbeat_pushes_the_deadline_out(self):
        jid = _fresh(key="beating")
        db = SessionLocal()
        try:
            jobqueue.claim(db, lease_s=60)
            before = _row(db, jid).lease_expires_at
            jobqueue.heartbeat(db, _row(db, jid), lease_s=1800)
            after = _row(db, jid).lease_expires_at
            self.assertGreater(_naive(after), _naive(before))
        finally:
            db.close()

    def test_finished_jobs_are_never_recovered(self):
        jid = _fresh(key="already-done")
        db = SessionLocal()
        try:
            jobqueue.claim(db)
            jobqueue.complete(db, _row(db, jid))
            self.assertEqual(jobqueue.recover_orphans(db), [])
        finally:
            db.close()


class TestRunOne(_JobTestCase):
    def test_a_handled_job_completes(self):
        _fresh(key="handled")
        db = SessionLocal()
        try:
            seen = []
            status = jobqueue.run_one(db, lambda j, p: seen.append(p) or True)
            self.assertEqual(status, "done")
            self.assertEqual(seen, [{"n": 1}])
        finally:
            db.close()

    def test_a_deferred_job_does_not_burn_an_attempt(self):
        """A job parked at an approval gate is not a failure.

        Without this, a gate that takes an hour to be approved would exhaust the
        retry budget and land in "failed" while a human was still reading it.
        """
        _fresh(key="waiting", max_attempts=2)
        db = SessionLocal()
        try:
            for _ in range(3):
                status = jobqueue.run_one(db, lambda j, p: False)
                self.assertEqual(status, "deferred")
                row = db.query(Job).filter(Job.key == "waiting").first()
                row.next_attempt_at = jobqueue._now()
                db.commit()
            row = db.query(Job).filter(Job.key == "waiting").first()
            self.assertEqual(row.status, "pending")
            self.assertLess(row.attempts, row.max_attempts + 3)
        finally:
            db.close()

    def test_drain_runs_everything_due_then_stops(self):
        for i in range(3):
            _fresh(key=f"batch-{i}")
        db = SessionLocal()
        try:
            counts = jobqueue.drain(db, lambda j, p: True)
            self.assertEqual(counts["done"], 3)
            self.assertEqual(db.query(Job).filter(
                Job.status.in_(["pending", "retry"])).count(), 0)
        finally:
            db.close()

    def test_drain_respects_its_limit(self):
        for i in range(5):
            _fresh(key=f"limited-{i}")
        db = SessionLocal()
        try:
            counts = jobqueue.drain(db, lambda j, p: True, limit=2)
            self.assertEqual(counts["done"], 2)
        finally:
            db.close()

    def test_a_null_payload_reads_as_empty(self):
        db = SessionLocal()
        try:
            job = Job(kind="test", status="pending", payload_json="not json")
            db.add(job)
            db.commit()
            self.assertEqual(jobqueue.payload_of(job), {})
        finally:
            db.close()


class TestPendingCount(_JobTestCase):
    def test_counts_live_jobs_only(self):
        jid = _fresh("counted", kind="counted")
        db = SessionLocal()
        try:
            self.assertEqual(jobqueue.pending_count(db, "counted"), 1)
            jobqueue.claim(db)
            jobqueue.complete(db, _row(db, jid))
            self.assertEqual(jobqueue.pending_count(db, "counted"), 0)
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
