"""One trace id, propagated, and logs that carry it.

The audit chain answers "what happened, in what order, and did it verify". It
does not answer "which of the three subsystems was slow while it happened", and
neither does stderr: every module prints its own ad-hoc line with its own
prefix, so a single user action arrives as a dozen unrelated messages with
nothing tying them together.

Two things live here:

* **A trace id** in a :class:`~contextvars.ContextVar`, so it follows the work
  across an HTTP request, the background thread it starts, and every A2A hop
  inside that thread -- without threading a parameter through every signature.
  A peer agent arriving over the bus brings its own trace in the envelope,
  because contextvars do not cross a process boundary.
* **A log line** that always carries it. Default format stays human-readable
  (``key=value`` pairs, greppable); ``AKM_LOG_FORMAT=json`` switches to one JSON
  object per line for a log shipper.

The trace is deliberately *not* written into the hashed core of a ledger event.
It is an observation about when a record was produced, not part of what the
record says, and folding it into ``data_json`` would change every event hash
and break verification of every run already on disk. It rides in its own
column instead -- see ``LedgerEvent.trace``.
"""
import contextlib
import contextvars
import json
import os
import sys
import time
import uuid
from typing import Optional

#: Set to "json" for one JSON object per line. Anything else keeps the
#: human-readable default, which is what you want when reading `docker logs`.
LOG_FORMAT = os.environ.get("AKM_LOG_FORMAT", "text").strip().lower()

#: Request header a client may set to stitch its own trace onto ours. Honoured
#: so a browser, a proxy, or an upstream agent can supply the id it already has
#: instead of forcing a second, unrelated identifier onto the same work.
TRACE_HEADER = "x-akm-trace-id"

_TRACE: contextvars.ContextVar = contextvars.ContextVar("akm_trace", default=None)
_LEVELS = ("debug", "info", "warn", "error")
_MIN_LEVEL = os.environ.get("AKM_LOG_LEVEL", "info").strip().lower()
if _MIN_LEVEL not in _LEVELS:
    _MIN_LEVEL = "info"


def new_trace(seed: Optional[str] = None) -> str:
    """A trace id. ``seed`` makes it deterministic when the caller already has a
    natural identity for the work (a session id, an A2A task id)."""
    if seed:
        # Short and stable: readable in a log line, and a namespace rather than
        # a secret. The real identity still lives on the run and the task.
        return f"t-{_slug(seed)}"
    return f"t-{uuid.uuid4().hex[:12]}"


def _slug(value: str) -> str:
    out = "".join(c if c.isalnum() or c in "-_" else "-" for c in str(value))
    return out.strip("-")[:40] or "root"


def current_trace() -> Optional[str]:
    return _TRACE.get()


def set_trace(trace_id: Optional[str]) -> contextvars.Token:
    return _TRACE.set(trace_id)


def reset_trace(token: contextvars.Token) -> None:
    try:
        _TRACE.reset(token)
    except ValueError:  # pragma: no cover - token from another context
        _TRACE.set(None)


@contextlib.contextmanager
def trace_scope(trace_id: Optional[str]):
    """Bind a trace for the duration of a block, restoring the previous one.

    Restores rather than clears, so nesting a session scope inside a task scope
    does not lose the task's id on the way out.
    """
    token = _TRACE.set(trace_id)
    try:
        yield trace_id
    finally:
        reset_trace(token)


def log(event: str, level: str = "info", **fields) -> None:
    """Emit one log line, always stamped with the current trace.

    Never raises. A logger that can fail the operation it is describing is a
    logger nobody turns on.
    """
    try:
        if _LEVELS.index(level) < _LEVELS.index(_MIN_LEVEL):
            return
        record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
                  + f".{int(time.time() * 1000) % 1000:03d}Z",
                  "level": level, "event": event,
                  "trace": current_trace() or ""}
        record.update({k: v for k, v in fields.items() if v is not None})
        if LOG_FORMAT == "json":
            line = json.dumps(record, default=str, sort_keys=True)
        else:
            tail = " ".join(
                f"{k}={_fmt(v)}" for k, v in record.items()
                if k not in ("ts", "level", "event", "trace"))
            trace = record["trace"]
            line = (f"[akm] {record['level']:<5} {event}"
                    + (f" trace={trace}" if trace else "")
                    + (f" {tail}" if tail else ""))
        print(line, file=sys.stderr, flush=True)
    except Exception:  # noqa: BLE001 - logging must never raise
        return


def _fmt(value) -> str:
    """Compact rendering for the text format: quoted if it has spaces."""
    s = str(value)
    if s == "":
        return '""'
    if any(c.isspace() for c in s) or '"' in s:
        return json.dumps(s, default=str)
    return s
