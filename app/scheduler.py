"""Per-investigation timetables: run the agent on a cron schedule.

A BackgroundScheduler ticks every minute; due investigations (enabled +
next_run_at passed) get a run launched with their scheduled caps, unless a
run is already in progress. Missed windows are skipped, never backfilled.
"""
import atexit
import logging
import threading
from datetime import datetime, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from croniter import croniter

from .database import SessionLocal
from .models import Investigation, AgentRun, Explanation

log = logging.getLogger("akm.scheduler")
_lock = threading.Lock()


def valid_cron(expr: str) -> bool:
    try:
        return croniter.is_valid((expr or "").strip())
    except Exception:
        return False


def next_time(expr: str, now: datetime | None = None) -> datetime:
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    nxt = croniter((expr or "").strip(), now).get_next(datetime)
    if nxt.tzinfo is None:
        nxt = nxt.replace(tzinfo=timezone.utc)
    return nxt


def compute_next(inv: Investigation, now: datetime | None = None):
    if not inv.schedule_enabled or not valid_cron(inv.schedule_cron or ""):
        return None
    return next_time(inv.schedule_cron, now)


def _tick():
    if not _lock.acquire(blocking=False):
        return
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        due = (db.query(Investigation)
               .filter(Investigation.schedule_enabled == 1,
                       Investigation.next_run_at.isnot(None),
                       Investigation.next_run_at <= now).all())
        for inv in due:
            busy = (db.query(AgentRun)
                    .filter(AgentRun.investigation_id == inv.id,
                            AgentRun.status == "running").first())
            if busy:
                inv.next_run_at = compute_next(inv, now)  # slip, don't pile up
                continue
            from .agent import launch_run
            launch_run(inv.id,
                       max_items=inv.schedule_max_items or 25,
                       max_rounds=inv.schedule_rounds or 2,
                       trigger="schedule")
            inv.last_scheduled_at = now
            inv.next_run_at = compute_next(inv, now)
            log.info("scheduled run launched for investigation %s", inv.id)
        db.commit()
    except Exception:
        log.exception("scheduler tick failed")
        db.rollback()
    finally:
        db.close()
        _lock.release()


def _tick_watched():
    """Re-answer watched explanations on a slow cadence; store drift verdict."""
    if not _lock.acquire(blocking=False):
        return
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        cutoff = now.replace(hour=0, minute=0, second=0, microsecond=0)
        for exp in (db.query(Explanation)
                    .filter(Explanation.watched == 1,
                            Explanation.status == "done").all()):
            busy = (db.query(Explanation)
                    .filter(Explanation.investigation_id == exp.investigation_id,
                            Explanation.status == "running").first())
            if busy:
                continue
            # Dedupe: one watch re-answer per day per watched explanation.
            recent = (db.query(Explanation)
                      .filter(Explanation.investigation_id == exp.investigation_id,
                              Explanation.created_at >= cutoff).all())
            already = any(f'"watch_of": {exp.id}' in (c.meta or "")
                          for c in recent)
            if already:
                continue
            child = Explanation(
                investigation_id=exp.investigation_id,
                question=exp.question,
                mode=exp.mode or "explain", depth=exp.depth or "balanced",
                audience=exp.audience or "intermediate",
                max_pages=exp.max_pages or 6,
                meta='{"watch_of": %d}' % exp.id)
            db.add(child)
            db.commit()
            db.refresh(child)
            from .explainer import launch_explanation
            launch_explanation(child.id, max_pages=child.max_pages or 6)
            log.info("watch re-answer launched for explanation %s", exp.id)
    except Exception:
        log.exception("watch tick failed")
        db.rollback()
    finally:
        db.close()
        _lock.release()


def _tick_dashboard():
    """One leadership snapshot per investigation per day.

    Skips investigations with no assessments (an empty register snapshots to
    nothing worth trending) and skips days already recorded, so restarts never
    backfill. Fail-open: a metrics failure must not disturb the other ticks.
    """
    if not _lock.acquire(blocking=False):
        return
    db = SessionLocal()
    try:
        from .models import Investigation, SecurityAssessment
        from . import executive as _ex
        for inv in db.query(Investigation).all():
            try:
                has_work = (db.query(SecurityAssessment)
                            .filter(SecurityAssessment.investigation_id
                                    == inv.id).first())
                if not has_work:
                    continue
                _ex.write_snapshot(db, inv.id)
            except Exception:
                log.exception("dashboard snapshot failed for %s", inv.id)
                db.rollback()
    except Exception:
        log.exception("dashboard tick failed")
        db.rollback()
    finally:
        db.close()
        _lock.release()


_scheduler: BackgroundScheduler | None = None


def start():
    global _scheduler
    if _scheduler:
        return
    _scheduler = BackgroundScheduler()
    _scheduler.add_job(_tick, "interval", minutes=1, id="akm-timetables")
    _scheduler.add_job(_tick_watched, "interval", minutes=10,
                       id="akm-watch", max_instances=1, coalesce=True)
    _scheduler.add_job(_tick_dashboard, "interval", hours=1,
                       id="akm-dashboard", max_instances=1, coalesce=True)
    _scheduler.start()
    atexit.register(lambda: _scheduler.shutdown(wait=False) if _scheduler else None)
