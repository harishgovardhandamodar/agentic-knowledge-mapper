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
from .models import Investigation, AgentRun

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


_scheduler: BackgroundScheduler | None = None


def start():
    global _scheduler
    if _scheduler:
        return
    _scheduler = BackgroundScheduler()
    _scheduler.add_job(_tick, "interval", minutes=1, id="akm-timetables")
    _scheduler.start()
    atexit.register(lambda: _scheduler.shutdown(wait=False) if _scheduler else None)
