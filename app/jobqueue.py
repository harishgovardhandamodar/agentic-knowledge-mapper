"""A persisted, idempotent, retrying job queue.

Background work used to be a bare ``threading.Thread(daemon=True)``. The run row
was written first, so from the outside a job looked like it existed -- but the
only record of the work itself was the thread's memory. Restart the process and
the job is gone while its ``AgentRun`` sits at "running" forever: no error, no
retry, nothing to recover. The same applies to a double-clicked button, which
runs the assessment twice and pays for the model calls twice.

This is a small queue that fixes exactly those three things, over SQLite, with
no new dependency:

* **Persistence** -- the job is a row before the thread starts.
* **Idempotency** -- a unique ``key``; a duplicate submit re-attaches to the
  existing job instead of duplicating the work.
* **Retry with backoff** -- a failure reschedules with growing delay until
  ``max_attempts``, then parks as ``failed`` for a human.

And one thing a naive queue gets wrong, which is why ``lease_expires_at``
exists: a job whose worker dies must be recoverable, but a job that is merely
*slow* must not be duplicated. A lease is claimed with a deadline, and recovery
only re-claims a job whose lease has actually expired. A security assessment
takes minutes; a 5-minute lease would have re-run it while the first copy was
still going.

Deliberately not a distributed queue. One process, one SQLite file, one worker
per kind is the shape this app has; claiming that needs more would be
architecture for a problem it does not have.
"""
import json
import threading
import time
import traceback
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_

from .models import Job

#: How long a claimed job may run before recovery will consider it orphaned.
#: Long enough that no legitimate assessment is re-claimed while still running.
DEFAULT_LEASE_S = 1800

#: First retry delay. Doubles per attempt, because the failures worth retrying
#: (a gateway timeout, a locked database) clear in seconds, and a dead gateway
#: should not be hammered.
BASE_BACKOFF_S = 2.0

#: A failed job's error is truncated to this. A full traceback belongs in the
#: job's own log or the run's error field, not in a column read in a list view.
ERROR_CHARS = 2000


class JobExists(Exception):
    """Raised by :func:`enqueue` in ``strict`` mode when the key is taken."""

    def __init__(self, job):
        super().__init__(f"job key already queued: {job.key}")
        self.job = job


def _now():
    return datetime.now(timezone.utc)


#: Statuses in which a job is still owed work. A key is unique across exactly
#: these, so a double-submit re-attaches to a live job while a *finished* job
#: leaves the key free for the next unit of work under it.
LIVE = ("pending", "retry", "running")


def enqueue(db, kind: str, payload: dict, *, key: str = None,
            run_id: int = None, max_attempts: int = 3,
            strict: bool = False) -> Job:
    """Add a job, or return the live job that already holds the key.

    With ``strict`` the duplicate raises instead, for callers that need to tell
    the difference between "I queued this" and "this was already queued".
    Without it, returning the live job is the idempotent behaviour: the caller
    gets a run id back and a second submit does no work.

    A ``done`` or ``failed`` job under the same key is not returned -- the work
    is genuinely over, and asking for the same key again means the next unit of
    work, which is how an approved run resumes.
    """
    if key:
        existing = (db.query(Job)
                    .filter(Job.key == key, Job.status.in_(LIVE)).first())
        if existing is not None:
            if strict:
                raise JobExists(existing)
            return existing
    job = Job(kind=kind, payload_json=json.dumps(payload or {}), key=key,
              run_id=run_id, max_attempts=max_attempts, status="pending",
              attempts=0, next_attempt_at=_now())
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def claim(db, kinds=None, lease_s: int = DEFAULT_LEASE_S) -> Job:
    """Take the next due job, marking it running with a lease.

    Returns ``None`` when there is nothing due -- including a job that failed
    and is waiting out its backoff, which is the point of ``next_attempt_at``.
    """
    q = db.query(Job).filter(Job.status.in_(["pending", "retry"]))
    if kinds:
        q = q.filter(Job.kind.in_(list(kinds)))
    job = (q.filter(Job.next_attempt_at <= _now())
           .order_by(Job.next_attempt_at, Job.id).first())
    if job is None:
        return None
    job.status = "running"
    job.attempts = (job.attempts or 0) + 1
    job.started_at = _now()
    job.lease_expires_at = _now() + timedelta(seconds=lease_s)
    db.commit()
    db.refresh(job)
    return job


def complete(db, job: Job) -> None:
    job.status = "done"
    job.finished_at = _now()
    job.lease_expires_at = None
    job.last_error = None
    db.commit()


def fail(db, job: Job, error, *, retry: bool = True) -> str:
    """Record a failure. Reschedules, or parks as ``failed``.

    Returns the new status so a caller can log it without re-reading the row.
    """
    text = (str(error) or "")[:ERROR_CHARS]
    if retry and (job.attempts or 0) < (job.max_attempts or 1):
        job.status = "retry"
        delay = BASE_BACKOFF_S * (2 ** ((job.attempts or 1) - 1))
        job.next_attempt_at = _now() + timedelta(seconds=delay)
        job.lease_expires_at = None
        job.last_error = text
    else:
        job.status = "failed"
        job.finished_at = _now()
        job.lease_expires_at = None
        job.last_error = text
    db.commit()
    return job.status


def recover_orphans(db, *, now=None) -> list:
    """Re-queue jobs whose worker died. Call at startup.

    Only jobs whose lease has *expired* are touched. A job that is merely slow
    still holds a valid lease, so a five-minute assessment is never duplicated
    by a restart that happened while it was running.
    """
    now = now or _now()
    stale = (db.query(Job)
             .filter(Job.status == "running",
                     or_(Job.lease_expires_at.is_(None),
                         Job.lease_expires_at <= now))
             .all())
    for job in stale:
        job.status = "pending"
        job.next_attempt_at = now
        job.lease_expires_at = None
    if stale:
        db.commit()
    return stale


def heartbeat(db, job: Job, lease_s: int = DEFAULT_LEASE_S) -> None:
    """Extend a lease from inside a long-running job.

    Optional, and only needed by work whose duration is not bounded. Without it
    a job longer than the lease is a candidate for recovery even though it is
    healthy -- which is a duplicate assessment and a doubled bill.
    """
    job.lease_expires_at = _now() + timedelta(seconds=lease_s)
    db.commit()


def payload_of(job: Job) -> dict:
    try:
        out = json.loads(job.payload_json or "{}")
    except Exception:
        return {}
    return out if isinstance(out, dict) else {}


def pending_count(db, kind: str = None) -> int:
    q = db.query(Job).filter(Job.status.in_(LIVE))
    if kind:
        q = q.filter(Job.kind == kind)
    return q.count()


def run_one(db, handler, kinds=None, lease_s: int = DEFAULT_LEASE_S) -> str:
    """Claim one job and run it. Returns the job status, or ``"idle"``.

    The handler is called as ``handler(job, payload)``. A handler that returns
    ``False`` means "not done, come back later" and is rescheduled without
    counting against the attempt budget -- that is how a job parks at an
    approval gate without burning a retry.
    """
    job = claim(db, kinds=kinds, lease_s=lease_s)
    if job is None:
        return "idle"
    payload = payload_of(job)
    try:
        result = handler(job, payload)
    except Exception as exc:  # noqa: BLE001 - the queue is the failure boundary
        status = fail(db, job, f"{type(exc).__name__}: {exc}\n"
                              f"{traceback.format_exc()[-ERROR_CHARS:]}")
        return status
    if result is False:
        job.status = "pending"
        job.next_attempt_at = _now() + timedelta(seconds=BASE_BACKOFF_S)
        job.lease_expires_at = None
        db.commit()
        return "deferred"
    complete(db, job)
    return "done"


def drain(db, handler, kinds=None, limit: int = 50,
          lease_s: int = DEFAULT_LEASE_S) -> dict:
    """Run due jobs until none remain or the limit is hit.

    For tests, and for the startup sweep that catches up on anything the queue
    already held. Not the production path: a live worker is
    :func:`start_worker`.
    """
    counts = {"done": 0, "failed": 0, "retry": 0, "deferred": 0, "idle": 0}
    for _ in range(limit):
        status = run_one(db, handler, kinds=kinds, lease_s=lease_s)
        counts[status] = counts.get(status, 0) + 1
        if status == "idle":
            break
    return counts


def start_worker(handler, kinds=None, *, interval_s: float = 1.0,
                 lease_s: int = DEFAULT_LEASE_S, name: str = "akm-jobs"):
    """Start a polling worker thread. Returns it, so a caller can join it.

    A daemon thread, deliberately: the process must be able to exit, and a job
    mid-flight is a lease with a deadline, so a clean stop loses nothing that
    recovery will not pick up.
    """
    stop = threading.Event()

    def loop():
        from .database import SessionLocal
        while not stop.is_set():
            db = SessionLocal()
            try:
                run_one(db, handler, kinds=kinds, lease_s=lease_s)
            except Exception:
                # A worker that dies on a transient DB error stops the whole
                # queue; keep going and let the lease sort it out.
                pass
            finally:
                db.close()
            stop.wait(interval_s)

    t = threading.Thread(target=loop, name=name, daemon=True)
    t.stop = stop  # type: ignore[attr-defined]
    t.start()
    return t
