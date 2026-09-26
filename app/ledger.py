"""Append-only, hash-chained audit ledger for multi-actor agent work.

Why this exists
---------------
Agent work is a *chain of claims*: an orchestrator asks a collector to find
evidence, an LLM turns that evidence into prose, a writer emits conclusions a
human then acts on. When a conclusion is wrong there is no way to answer the
only question that matters -- "what did the agent actually do, on what basis,
and who checked it?" -- because the usual logs are mutable per-subsystem JSON
blobs with no cross-actor correlation.

This module makes that answerable. Every step by every actor (agents, LLM
calls, MCP tools, A2A hops in and out, humans) becomes one row in a single
hash-chained stream per run. Each row commits to its predecessor, so an edit,
a deletion or an insertion after the fact all break verification.

Three properties fall out of the chain, rather than being bolted on:

* **Proof-of-Work** -- an event that did something carries a *proof*: the input
  refs it consumed, the method (model + prompt hash, or tool + args hash), a
  hash of its output, and any verification verdict. ``verify_proof``
  re-derives all of it from the ledger instead of trusting the stored copy.
* **Grounding** -- claims are content-addressed, so a conclusion cites the exact
  hash it rests on. ``contamination`` walks those edges backwards to give the
  blast radius of a bad claim, and a reviewer can see whether a downstream
  agent re-verified it or just trusted it.
* **Alignment** -- a run is opened under a ``Mandate``. Every action is checked
  against it, and the verdict lands *on the action event*, so "was this in
  bounds?" is answerable per step rather than reconstructed after the fact.

Design notes
------------
* Zero new dependencies: SHA-256 from stdlib, SQLAlchemy as the repo already
  uses it. SQLite gives durability, not trust -- the chain is what detects
  tampering, and it is verifiable offline with ``verify_export``.
* ``proof_json`` is deliberately excluded from the hashed core. It is derived
  state, so verification recomputes it and reports drift instead of merely
  re-hashing a stored value.
* Payloads are redacted before they are written. An immutable log is the worst
  possible place to durably record a credential that leaked into a prompt.
* The active run lives in a ``ContextVar``, so instrumentation at choke points
  like ``llm.chat`` needs no signature changes and no-ops when no run is open.

Status codes used on events
---------------------------
``verdict``:  pass | allow | deny | flag | hold | block | grant
``severity``: info | warn | block
"""

import json
import os
import re
import sys
import threading
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Iterable, Optional

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError

from .database import SessionLocal
from .ledger_models import (LedgerApproval, LedgerClaim, LedgerEvent,
                            LedgerRun)

GENESIS = "0" * 64

#: Fields that make up a row's immutable core, and therefore its hash.
CORE_FIELDS = ("run_id", "seq", "ts", "actor_type", "actor", "kind", "intent",
               "verdict", "severity", "data", "prev_hash")

ACTOR_TYPES = frozenset({"agent", "llm", "mcp", "a2a", "human", "system"})

#: Kinds the mandate never gates: recording the audit trail is not an act the
#: audit trail can refuse to record.
INTERNAL_KINDS = frozenset({
    "run.start", "run.end", "mandate.set", "mandate.check", "gate.check",
    "approval.request", "approval.grant", "approval.deny", "claim.emit",
    "claim.verify", "drift.detect",
})

VALID_VERDICTS = frozenset({"pass", "allow", "deny", "flag", "hold", "block", "grant"})
VALID_SEVERITIES = frozenset({"info", "warn", "block"})
CLAIM_VERDICTS = frozenset({"supported", "unsupported", "uncertain", "unverified"})

#: Store full prompts/args in the log. Off by default: the ledger is immutable,
#: so anything written here is effectively permanent.
CAPTURE_PAYLOADS = os.environ.get("LEDGER_CAPTURE_PAYLOADS", "").lower() in ("1", "true", "yes")

# Credential names that are never a metric. Redacted whatever the value is.
_SECRET_KEY = re.compile(
    r"(pass(word|wd)?|secret|api[_-]?key|apikey|authorization|credential|"
    r"private[_-]?key|session[_-]?id|cookie|passphrase)", re.I)
# Names that are a credential *or* a metric depending on the value: "token" is
# an access token in `access_token` but a count in `tokens_in`. Only redact when
# the value could actually be a secret.
_SECRET_IF_STRING = re.compile(r"(^|[_-])(token|tokens|auth|bearer)([_-]|$)", re.I)
_SECRET_VALUE = re.compile(
    r"\b(?:sk|pk|ghp|gho|xox[baprs])-[A-Za-z0-9_-]{8,}"
    # A long opaque token -- unless it is a hex digest. A 40+ character run of
    # [0-9a-f] is a hash, and hashes are evidence: they appear in payload hashes,
    # genesis values and claim content addresses. Redacting those would silently
    # gut the payloads this function exists to preserve, so the hex case is
    # excluded and the named-key rules above still cover real credentials.
    r"|\b(?![A-Fa-f0-9]{40,}\b)[A-Za-z0-9+/]{40,}={0,2}\b")

# Serialises chain appends inside one process. Across processes the
# ``(run_id, seq)`` unique constraint is the real guard and ``append`` retries.
_LOCK = threading.RLock()

_current_run: ContextVar[Optional[str]] = ContextVar("ledger_run", default=None)
_current_mandate: ContextVar[Optional["Mandate"]] = ContextVar("ledger_mandate", default=None)
# The sitting this run belongs to. Independent of _current_run so a human action
# with no run of its own can still land on the session spine.
_current_session: ContextVar[Optional[str]] = ContextVar("ledger_session", default=None)


# ------------------------------------------------------------------ hashing --

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canon(obj: Any) -> str:
    """Canonical JSON. Sorting keys and pinning separators is what makes a hash
    reproducible across processes, dict orderings and Python versions."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)


def digest(obj: Any) -> str:
    return sha256(canon(obj).encode("utf-8")).hexdigest()


def text_digest(text: Optional[str]) -> str:
    return sha256((text or "").encode("utf-8")).hexdigest()


def is_hash(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _redact(value: Any) -> Any:
    """Strip credentials before anything reaches immutable storage.

    Numbers survive: an audit record is full of counts (tokens, latency,
    relevance scores) and redacting those would destroy the evidence while
    protecting nothing. Credentials are strings, so key-based redaction keys off
    the value as well as the name.
    """
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if isinstance(k, str) and _SECRET_KEY.search(k):
                out[k] = "[redacted]"
            elif (isinstance(k, str) and _SECRET_IF_STRING.search(k)
                  and isinstance(v, (str, list, dict))):
                out[k] = "[redacted]"
            else:
                out[k] = _redact(v)
        return out
    if isinstance(value, (list, tuple)):
        return [_redact(v) for v in value]
    if isinstance(value, str):
        return _SECRET_VALUE.sub("[redacted]", value)
    return value


def _payload(value: Any) -> Any:
    return value if CAPTURE_PAYLOADS else _redact(value)


def _dumps(value: Any) -> Optional[str]:
    return None if value is None else canon(value)


def _loads(value: Optional[str], default: Any = None) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def event_core(*, run_id: str, seq: int, ts: str, actor_type: str, actor: str,
               kind: str, intent: Optional[str], verdict: Optional[str],
               severity: Optional[str], data: Any, prev_hash: str) -> dict:
    """The exact structure a row's hash is taken over."""
    return {
        "run_id": run_id, "seq": seq, "ts": ts, "actor_type": actor_type,
        "actor": actor, "kind": kind, "intent": intent, "verdict": verdict,
        "severity": severity, "data": data, "prev_hash": prev_hash,
    }


def chain_hash(core: dict) -> str:
    missing = [f for f in CORE_FIELDS if f not in core]
    if missing:
        raise ValueError(f"event core missing fields: {missing}")
    return digest(core)


# ------------------------------------------------------------------ mandate --

@dataclass
class Verdict:
    decision: str = "pass"     # pass|allow|deny|flag|hold
    rule: str = "unconstrained"
    reason: str = ""
    severity: str = "info"
    detail: dict = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        return self.decision == "deny"

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class Mandate:
    """The policy a run is bound to.

    Two flavours of intent restriction, because they are not the same promise:
    ``allowed_intents`` is a hard boundary (an action outside it is denied), and
    ``planned_intents`` is the expected shape of the work (an action outside it
    is allowed but recorded as drift).
    """

    objective: str = ""
    allowed_actors: list = field(default_factory=list)     # empty = any
    allowed_intents: list = field(default_factory=list)    # hard boundary
    planned_intents: list = field(default_factory=list)    # soft: drift if outside
    allowed_tools: list = field(default_factory=list)      # mcp tool names
    allowed_domains: list = field(default_factory=list)    # source scopes
    human_gates: list = field(default_factory=list)        # kinds needing sign-off
    max_events: int = 0            # 0 = unbounded
    max_llm_calls: int = 0
    loop_threshold: int = 5        # repeats of one (actor, intent) before flagging
    require_grounding: bool = False  # ungrounded claims become violations

    @classmethod
    def from_dict(cls, raw: Optional[dict]) -> "Mandate":
        raw = raw or {}
        fields = {f for f in cls.__dataclass_fields__}  # noqa: F821
        return cls(**{k: v for k, v in raw.items() if k in fields})

    def as_dict(self) -> dict:
        return asdict(self)

    @property
    def hash(self) -> str:
        return digest(self.as_dict())

    def domain_allowed(self, domain: str) -> bool:
        if not self.allowed_domains or not domain:
            return True
        d = (domain or "").lower().lstrip(".")
        for allowed in self.allowed_domains:
            a = allowed.lower().lstrip(".")
            if d == a or d.endswith("." + a):
                return True
        return False

    def check(self, *, kind: str, actor: str, actor_type: str = "system",
              intent: Optional[str] = None, tool: Optional[str] = None,
              domain: Optional[str] = None,
              counts: Optional[dict] = None) -> Verdict:
        """Evaluate one action. First hard failure wins; soft signals are
        reported as ``flag`` so the work continues but the deviation is on the
        record."""
        if kind in INTERNAL_KINDS:
            return Verdict("pass", "internal", "audit-trail event; not gated")

        if self.allowed_actors and actor not in self.allowed_actors:
            return Verdict("deny", "actor_not_in_mandate",
                           f"actor {actor!r} is not in the mandate", "block",
                           {"actor": actor, "allowed": self.allowed_actors})

        if intent and self.allowed_intents and intent not in self.allowed_intents:
            return Verdict("deny", "intent_not_in_mandate",
                           f"intent {intent!r} is outside the mandate", "block",
                           {"intent": intent, "allowed": self.allowed_intents})

        if tool and self.allowed_tools and not any(
                tool == t or tool.startswith(t + ".") for t in self.allowed_tools):
            return Verdict("deny", "tool_not_in_mandate",
                           f"tool {tool!r} is outside the mandate", "block",
                           {"tool": tool, "allowed": self.allowed_tools})

        if kind == "run.end" and self.max_events and (counts or {}).get("total", 0) > self.max_events:
            return Verdict("deny", "budget_exceeded",
                           f"run exceeded max_events={self.max_events}", "block",
                           {"max_events": self.max_events, "observed": counts.get("total")})

        if self.max_llm_calls and (counts or {}).get("llm.call", 0) > self.max_llm_calls:
            return Verdict("deny", "budget_exceeded",
                           f"run exceeded max_llm_calls={self.max_llm_calls}", "block",
                           {"max_llm_calls": self.max_llm_calls,
                            "observed": counts.get("llm.call")})

        # Soft signals: allowed, but the deviation is recorded. Checked after the
        # human gate, because "waiting on a person" is the more urgent signal and
        # must not be masked by "that wasn't in the plan".
        if kind in self.human_gates:
            return Verdict("hold", "awaiting_approval",
                           f"{kind} requires human sign-off", "warn",
                           {"kind": kind})

        if intent and self.planned_intents and intent not in self.planned_intents:
            return Verdict("flag", "unplanned_intent",
                           f"intent {intent!r} was not in the plan", "warn",
                           {"intent": intent, "planned": self.planned_intents})

        if domain and not self.domain_allowed(domain):
            return Verdict("flag", "scope_creep",
                           f"source domain {domain!r} is outside the mandate", "warn",
                           {"domain": domain, "allowed": self.allowed_domains})

        return Verdict("allow", "within_mandate", "action is within mandate")


# ------------------------------------------------------------------ claims --

def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").lower()).strip()


def quote_is_verbatim(text: str, quote: str) -> bool:
    """Does ``quote`` actually appear in ``text``?

    Mirrors ``explainer._quote_valid`` deliberately rather than importing it:
    ``llm`` is an instrumentation point for this module, and pulling the
    explainer's dependency tree (bs4, feedparser) in through that edge would be
    a nasty import cycle. A quote under 12 normalised chars is rejected -- a
    two-word "quote" matches almost any source and proves nothing.
    """
    nq, nt = _norm(quote), _norm(text)
    if not nq or len(nq) < 12:
        return False
    if nq in nt:
        return True
    head, tail = nq[:25], nq[-10:]
    return bool(head and tail and head in nt and tail in nt)


def verify_grounding(claim_text: str, citations: Iterable[dict],
                     sources: Any) -> dict:
    """The hallucination gate: keep only citations a source actually contains.

    ``sources`` may be a list of page dicts (with ``text``) or a mapping of
    source key -> text. Returns the surviving citations plus a corroboration
    score based on how many *distinct* sources back the claim -- one source
    agreeing with itself is not corroboration.
    """
    texts: dict[Any, str] = {}
    if isinstance(sources, dict):
        texts = {k: (v.get("text") if isinstance(v, dict) else str(v))
                 for k, v in sources.items()}
    else:
        for idx, page in enumerate(sources or []):
            key = page.get("id", page.get("url", idx)) if isinstance(page, dict) else idx
            texts[key] = page.get("text", "") if isinstance(page, dict) else str(page)

    kept, dropped = [], []
    for cit in citations or []:
        key = cit.get("source", cit.get("sourceIndex"))
        quote = cit.get("quote") or ""
        body = texts.get(key)
        if body is not None and quote_is_verbatim(body, quote):
            kept.append({"source": key, "quote": quote[:180], "verified": True})
        else:
            dropped.append({"source": key, "quote": quote[:180], "reason": "not_found_in_source"})

    n_sources = len({k["source"] for k in kept})
    confidence = "none" if n_sources == 0 else "high" if n_sources >= 3 else "medium" if n_sources == 2 else "low"
    verdict = "unverified" if n_sources == 0 else "supported"
    return {
        "kept": kept, "dropped": dropped, "n_sources": n_sources,
        "confidence": confidence, "verdict": verdict,
        "violation": n_sources == 0, "claim": (claim_text or "")[:200],
    }


def claim_hash(text: str, citations: Optional[list] = None) -> str:
    """Content address for a claim. Two agents asserting the same thing with the
    same citations collide on purpose: that is how 'B just parroted A' becomes
    visible instead of invisible."""
    return digest({"text": (text or "").strip(), "citations": citations or []})


# ------------------------------------------------------------------ context --

def current_run() -> Optional[str]:
    return _current_run.get()


def current_mandate() -> Optional[Mandate]:
    return _current_mandate.get()


def current_session() -> Optional[str]:
    return _current_session.get()


# ---------------------------------------------------------------- sessions --

# A session is "one sitting", not one request. The browser holds a stable key and
# the server rolls a new session id once that key has been idle past this, so a
# long working session accumulates one continuous record while a tab left open
# overnight does not grow a single chain forever.
SESSION_IDLE_SECONDS = int(os.environ.get("AKM_SESSION_IDLE_S", "1800"))


def ensure_session(session_id: str, *, client_key: Optional[str] = None,
                   label: Optional[str] = None, db=None) -> str:
    """Fetch or create a session row. A session is a run row of ``kind='session'``
    so it reuses the same chain machinery -- its timeline is the spine.

    Returns the session id, not the ORM row: this owns its own DB session, so a
    returned row would already be detached and unusable.
    """
    own = db is None
    db = db or SessionLocal()
    try:
        row = db.get(LedgerRun, session_id)
        if row is None:
            row = LedgerRun(id=session_id, kind="session", status="open",
                            label=label or "session",
                            genesis_hash=GENESIS, head_hash=GENESIS, head_seq=-1,
                            client_key=client_key, last_seen_at=datetime.now(timezone.utc))
            db.add(row)
            db.flush()
            _touch_session(session_id, db=db)
        if label and not row.label:
            row.label = label
        db.commit()
        return session_id
    finally:
        if own:
            db.close()


def _touch_session(session_id: str, db) -> None:
    row = db.get(LedgerRun, session_id)
    if row is not None and row.kind == "session":
        row.last_seen_at = datetime.now(timezone.utc)
        db.commit()


def resolve_session(client_key: Optional[str], *, label: Optional[str] = None,
                    idle_seconds: Optional[int] = None,
                    db=None) -> Optional[str]:
    """Map a browser key to the session id it should keep appending to.

    Returns ``None`` for a missing key so callers with no session context behave
    exactly as they did before sessions existed. A key that has gone idle gets a
    fresh session rather than resuming an arbitrarily old one.
    """
    if not client_key:
        return None
    client_key = str(client_key).strip()[:64]
    if not client_key:
        return None
    idle = SESSION_IDLE_SECONDS if idle_seconds is None else idle_seconds
    own = db is None
    db = db or SessionLocal()
    try:
        row = (db.query(LedgerRun)
               .filter(LedgerRun.client_key == client_key,
                       LedgerRun.kind == "session")
               .order_by(LedgerRun.last_seen_at.desc().nullslast())
               .first())
        now = datetime.now(timezone.utc)
        if row is not None:
            last = row.last_seen_at
            if last is not None and last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)  # SQLite hands back naive
            if last is None or (now - last).total_seconds() <= idle:
                row.last_seen_at = now
                db.commit()
                return row.id
        session_id = f"ses-{uuid.uuid4().hex[:12]}"
        ensure_session(session_id, client_key=client_key,
                       label=label or f"session {now.strftime('%Y-%m-%d %H:%M')}", db=db)
        return session_id
    finally:
        if own:
            db.close()


def anchor_run(run_id: str, *, session_id: Optional[str] = None,
               label: Optional[str] = None, kind: str = "task",
               db=None) -> Optional[str]:
    """Record a run on its session's spine, in adoption order.

    This is the whole of the session guarantee: the anchor's position in the
    session chain fixes *when* the run joined, and the run's genesis hash binds
    the anchor to that specific run. Sessions therefore prove task ordering
    without each task's chain having to know about any other.
    """
    session_id = session_id or current_session()
    if not session_id or run_id == session_id:
        return None
    own = db is None
    db = db or SessionLocal()
    try:
        task = db.get(LedgerRun, run_id)
        if task is None or task.session_id:
            return None            # already anchored; never double-anchor a run
        task.session_id = session_id
        db.flush()
        _touch_session(session_id, db=db)
        h = append(session_id, "run.anchor", "ledger", actor_type="system",
                   intent="anchor_run", verdict="allow", severity="info",
                   data={"run_id": run_id, "kind": kind, "label": label or task.label,
                         "task_genesis": task.genesis_hash or GENESIS},
                   checked=False)
        return h
    finally:
        if own:
            db.close()


def _set_session(session_id: Optional[str]):
    return _current_session.set(session_id)


def list_sessions(limit: int = 50, db=None) -> list:
    own = db is None
    db = db or SessionLocal()
    try:
        rows = (db.query(LedgerRun)
                .filter(LedgerRun.kind == "session")
                .order_by(LedgerRun.created_at.desc()).limit(limit).all())
        return [{"session_id": r.id, "label": r.label, "status": r.status,
                 "client_key": r.client_key,
                 "created_at": str(r.created_at), "last_seen_at": str(r.last_seen_at),
                 "runs": db.query(func.count(LedgerEvent.id))
                            .filter(LedgerEvent.run_id == r.id).scalar() or 0,
                 "tasks": db.query(func.count(LedgerRun.id))
                            .filter(LedgerRun.session_id == r.id).scalar() or 0,
                 "head_hash": r.head_hash}
                for r in rows]
    finally:
        if own:
            db.close()


def session_tasks(session_id: str, db=None) -> list:
    """The runs anchored to a session, in the order the spine recorded them."""
    own = db is None
    db = db or SessionLocal()
    try:
        anchors = (db.query(LedgerEvent)
                   .filter(LedgerEvent.run_id == session_id,
                           LedgerEvent.kind == "run.anchor")
                   .order_by(LedgerEvent.seq).all())
        out = []
        for a in anchors:
            data = _loads(a.data_json, {})
            task = db.get(LedgerRun, data.get("run_id") or "")
            if task is None:
                continue
            out.append({"run_id": task.id, "label": task.label, "kind": data.get("kind") or task.kind,
                        "anchor_seq": a.seq, "anchor_hash": a.hash,
                        "task_genesis": data.get("task_genesis"),
                        "genesis_ok": (task.genesis_hash or GENESIS) == (data.get("task_genesis") or GENESIS),
                        "status": task.status, "events": _counts(db, task.id)["total"],
                        "created_at": str(task.created_at)})
        return out
    finally:
        if own:
            db.close()


def session_timeline(session_id: str, limit: int = 2000, db=None) -> dict:
    """One ordered view across every run in a session.

    Interleaves the session's own spine events with each task's events, sorted by
    timestamp, so the session reads as a single story while every event still
    names the run it belongs to.
    """
    own = db is None
    db = db or SessionLocal()
    try:
        if db.get(LedgerRun, session_id) is None:
            return {"session_id": session_id, "total": 0, "runs": [], "events": []}
        run_ids = [session_id] + [t["run_id"] for t in session_tasks(session_id, db=db)]
        rows = (db.query(LedgerEvent)
                .filter(LedgerEvent.run_id.in_(run_ids))
                .order_by(LedgerEvent.ts, LedgerEvent.run_id, LedgerEvent.seq)
                .limit(limit).all())
        events = [{
            "run_id": e.run_id, "seq": e.seq, "ts": e.ts, "kind": e.kind,
            "actor_type": e.actor_type, "actor": e.actor, "intent": e.intent,
            "verdict": e.verdict, "severity": e.severity, "hash": e.hash,
            "prev_hash": e.prev_hash, "input_refs": _loads(e.input_refs, []),
            "data": _loads(e.data_json, {}),
        } for e in rows]
        return {"session_id": session_id, "total": len(events), "runs": run_ids,
                "events": events}
    finally:
        if own:
            db.close()


def verify_session(session_id: str, db=None) -> dict:
    """Verify a session: its spine chain, plus every task it anchors.

    Reports each task separately so one broken task does not read as "the whole
    session is untrustworthy" -- which is exactly the failure mode a flat
    session chain would have.
    """
    own = db is None
    db = db or SessionLocal()
    try:
        row = db.get(LedgerRun, session_id)
        if row is None or row.kind != "session":
            return {"session_id": session_id, "ok": False, "findings": [
                {"issue": "unknown_session", "detail": f"no session {session_id}"}]}

        spine = verify_chain(session_id, db=db)
        findings = list(spine.get("findings") or [])

        tasks = []
        for t in session_tasks(session_id, db=db):
            rep = verify_chain(t["run_id"], db=db)
            drift = detect_drift(t["run_id"])
            if not t["genesis_ok"]:
                findings.append({"issue": "anchor_genesis_mismatch",
                                 "detail": f"spine anchors a different genesis for {t['run_id']}",
                                 "run_id": t["run_id"]})
            if not rep.get("ok"):
                findings.append({"issue": "task_broken", "run_id": t["run_id"],
                                 "detail": f"{len(rep.get('findings') or [])} finding(s) in {t['run_id']}"})
            tasks.append({"run_id": t["run_id"], "label": t["label"], "kind": t["kind"],
                          "ok": bool(rep.get("ok")), "events": rep.get("events", 0),
                          "proofs_checked": rep.get("proofs_checked", 0),
                          "drift_signals": len(drift.get("findings") or []),
                          "findings": rep.get("findings") or [],
                          "genesis_ok": t["genesis_ok"]})

        return {"session_id": session_id, "ok": not findings, "kind": "session",
                "spine_events": spine.get("events", 0), "spine_head": spine.get("head_hash"),
                "spine_findings": spine.get("findings") or [],
                "tasks": tasks, "findings": findings}
    finally:
        if own:
            db.close()


def _violation_class(event: dict, gate: dict) -> str:
    """Sort a non-pass verdict into the thing an auditor would call it.

    Three different problems share one verdict column, and collapsing them makes
    the list useless: a blocked action, a claim with no source behind it, and an
    action that merely departed from the plan.
    """
    if event["kind"] == "claim.emit" and event["verdict"] == "block":
        return "grounding"
    if event["kind"] == "gate.check" or event["verdict"] in ("deny", "hold", "block"):
        return "gate"
    return "drift"


def _violation_reason(event: dict, data: dict, gate: dict, action: dict) -> str:
    """One human-readable line per non-pass event.

    Returns "" for events that are not worth listing, so the caller can filter
    on a truthy reason instead of repeating the classification logic.
    """
    if event["kind"] == "claim.emit" and event["verdict"] == "block":
        verdict = data.get("grounding_verdict") or "unverified"
        dropped = data.get("dropped") or []
        if dropped:
            first = dropped[0]
            return (f"ungrounded claim ({verdict}): quote {first.get('quote', '')[:60]!r} "
                    f"not found in {first.get('source')}")
        return f"ungrounded claim ({verdict}): no source supports it"
    if gate.get("reason"):
        return str(gate["reason"])
    if event["kind"] == "gate.check":
        acted = action.get("kind") or "an action"
        return f"{acted} was {event['verdict']}ed"
    if event["verdict"] in ("warn", "flag"):
        # Drift: allowed, but off the plan the mandate declared.
        return f"{event['actor']} did {event['intent'] or event['kind']}, outside the planned intents"
    if data.get("reason"):
        return str(data["reason"])
    return event["intent"] or event["kind"]


def _as_dt(value):
    """Timestamps arrive as datetimes from the ORM and as strings from exports;
    normalise both so duration maths does not have to care which."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def session_insights(session_id: str, db=None) -> dict:
    """What actually happened in this sitting, aggregated across its runs.

    The point of a session view is the questions a single run cannot answer:
    what did this person work on, in what order, what did it cost, what was
    blocked, what was never grounded, which runs died, and how the sitting ended.

    Everything here is derived from the chains, so it inherits their
    verifiability -- an insight that cannot be recomputed from the events is not
    an insight, it is a second source of truth.
    """
    own = db is None
    db = db or SessionLocal()
    try:
        tl = session_timeline(session_id, limit=100000, db=db)
        events = tl["events"]
        tasks = session_tasks(session_id, db=db)

        by_actor, by_kind, by_intent = {}, {}, {}
        llm_models, llm_calls, latencies = {}, 0, []
        human_actions, investigations, findings_by_sev = [], set(), {}
        violations, activity = [], {}
        n_human = n_auto = 0
        per_run = {t["run_id"]: {"run_id": t["run_id"], "label": t["label"],
                                 "kind": t["kind"], "status": t["status"],
                                 "anchor_seq": t["anchor_seq"], "events": t["events"],
                                 "verdicts": {}, "human_actions": 0, "llm_calls": 0,
                                 "tokens_in": 0, "tokens_out": 0}
                   for t in tasks}

        # When the mandate refuses an action the ledger emits a second,
        # ``gate.check`` event pointing back at the original via input_refs. That
        # annotation carries the reason, so fold it into the action it describes:
        # counting both would double every violation in the session.
        gate_notes = {}
        for e in events:
            if e["kind"] == "gate.check":
                note = e.get("data") or {}
                for ref in (e.get("input_refs") or []):
                    gate_notes.setdefault(ref, (e, note.get("gate") or {},
                                                note.get("action") or {}))

        for e in events:
            d = e["data"] or {}
            r = per_run.get(e["run_id"])
            by_actor[e["actor"]] = by_actor.get(e["actor"], 0) + 1
            by_kind[e["kind"]] = by_kind.get(e["kind"], 0) + 1
            if e["intent"]:
                by_intent[e["intent"]] = by_intent.get(e["intent"], 0) + 1

            # Activity histogram, bucketed per minute: a session view should
            # show its own shape, including the long quiet gaps.
            ts = _as_dt(e["ts"])
            if ts:
                bucket = ts.strftime("%H:%M")
                activity[bucket] = activity.get(bucket, 0) + 1

            if e["kind"] == "llm.call":
                llm_calls += 1
                m = d.get("model") or "unknown"
                slot = llm_models.setdefault(m, {"calls": 0, "tokens_in": 0,
                                                  "tokens_out": 0})
                slot["calls"] += 1
                tin = d.get("tokens_in") if isinstance(d.get("tokens_in"), int) else 0
                tout = d.get("tokens_out") if isinstance(d.get("tokens_out"), int) else 0
                slot["tokens_in"] += tin
                slot["tokens_out"] += tout
                if r is not None:
                    r["llm_calls"] += 1
                    r["tokens_in"] += tin
                    r["tokens_out"] += tout
                if isinstance(d.get("latency_ms"), (int, float)):
                    latencies.append(d["latency_ms"])

            if e["actor_type"] == "human":
                n_human += 1
                if r is not None:
                    r["human_actions"] += 1
                human_actions.append({"ts": e["ts"], "actor": e["actor"],
                                      "kind": e["kind"], "intent": e["intent"],
                                      "run_id": e["run_id"]})
            else:
                n_auto += 1

            # A human action nests its payload under "detail"; a gate check puts
            # it at the top level. Look in both so either shape yields the id.
            for scope in (d, d.get("detail") if isinstance(d.get("detail"), dict) else {}):
                for key in ("investigation", "investigation_id", "inv_id"):
                    if scope.get(key) is not None:
                        investigations.add(str(scope[key]))

            if e["verdict"] in ("warn", "flag", "hold", "deny", "block"):
                # A gate.check that annotates another event is not its own
                # violation; it is that event's explanation. Skip it here too, so
                # the histogram and the notice list agree on the same number.
                if e["kind"] == "gate.check" and (e.get("input_refs") or []):
                    continue
                findings_by_sev[e["verdict"]] = findings_by_sev.get(e["verdict"], 0) + 1
                if r is not None:
                    r["verdicts"][e["verdict"]] = r["verdicts"].get(e["verdict"], 0) + 1
                gate, action = {}, {}
                note = gate_notes.get(e["hash"])
                if note:
                    _, gate, action = note
                reason = _violation_reason(e, d, gate, action)
                if reason:
                    violations.append({
                        "ts": e["ts"], "run_id": e["run_id"], "verdict": e["verdict"],
                        "severity": e["severity"], "kind": e["kind"],
                        "class": _violation_class(e, gate),
                        "actor": e["actor"], "intent": e["intent"],
                        "action": action.get("kind") or e["kind"],
                        "reason": reason,
                        "hash": e["hash"], "seq": e["seq"],
                    })

        claims = (db.query(LedgerClaim)
                  .filter(LedgerClaim.run_id.in_(tl["runs"])).all())
        ungrounded = [c for c in claims if c.n_sources == 0]
        pending = (db.query(LedgerApproval)
                   .filter(LedgerApproval.run_id.in_(tl["runs"]),
                           LedgerApproval.decision.is_(None)).all())
        decided = (db.query(LedgerApproval)
                   .filter(LedgerApproval.run_id.in_(tl["runs"]),
                           LedgerApproval.decision.isnot(None)).all())
        ungrounded_by_run = {}
        for c in ungrounded:
            ungrounded_by_run[c.run_id] = ungrounded_by_run.get(c.run_id, 0) + 1
        for run_id, r in per_run.items():
            r["ungrounded_claims"] = ungrounded_by_run.get(run_id, 0)

        stamp = [_as_dt(e["ts"]) for e in events]
        stamp = [t for t in stamp if t]
        span = None
        if stamp:
            span = {"first": events[0]["ts"], "last": events[-1]["ts"],
                    "duration_s": int((max(stamp) - min(stamp)).total_seconds())}

        failed = [{"run_id": r["run_id"], "label": r["label"]}
                  for r in per_run.values() if r["status"] == "error"]
        tot_in = sum(v["tokens_in"] for v in llm_models.values())
        tot_out = sum(v["tokens_out"] for v in llm_models.values())
        return {
            "session_id": session_id,
            "span": span,
            "tasks": [per_run[t["run_id"]] for t in tasks if t["run_id"] in per_run],
            "total_events": len(events),
            "by_actor": by_actor, "by_kind": by_kind, "by_intent": by_intent,
            "activity": [{"minute": k, "events": v}
                         for k, v in sorted(activity.items())],
            "split": {"human": n_human, "automated": n_auto},
            "llm": {"calls": llm_calls, "models": llm_models,
                    "tokens_in": tot_in, "tokens_out": tot_out,
                    "tokens": tot_in + tot_out,
                    "mean_latency_ms": (sum(latencies) // len(latencies)) if latencies else None},
            "human_actions": human_actions,
            "investigations": sorted(investigations),
            "claims": {"total": len(claims), "ungrounded": len(ungrounded),
                       "ungrounded_texts": [c.text[:120] for c in ungrounded[:5]]},
            "verdicts": findings_by_sev,
            "violations": violations[:25],
            "violation_count": len(violations),
            "failed_runs": failed,
            "approvals_pending": len(pending),
            "approvals_decided": len(decided),
        }
    finally:
        if own:
            db.close()


# ------------------------------------------------------------------- store --

def _counts(db, run_id: str) -> dict:
    rows = (db.query(LedgerEvent.kind, func.count(LedgerEvent.id))
            .filter(LedgerEvent.run_id == run_id)
            .group_by(LedgerEvent.kind).all())
    counts = {k: c for k, c in rows}
    counts["total"] = sum(counts.values())
    return counts


def get_run(run_id: str, db=None) -> Optional[LedgerRun]:
    own = db is None
    db = db or SessionLocal()
    try:
        return db.get(LedgerRun, run_id)
    finally:
        if own:
            db.close()


def ensure_run(run_id: str, mandate: Optional[Mandate] = None,
               label: Optional[str] = None, db=None,
               session_id: Optional[str] = None,
               kind: str = "task") -> LedgerRun:
    """Fetch or create a run row, backfilling the mandate if one was passed.

    A newly created run is anchored onto the current session's spine, so runs
    adopted during a sitting appear in the session in the order they started.
    Re-opening an existing run never re-anchors it.
    """
    own = db is None
    db = db or SessionLocal()
    try:
        row = db.get(LedgerRun, run_id)
        created = row is None
        if created:
            adopt = session_id or current_session()
            # session_id is left null here on purpose: anchor_run is the single
            # place that links a run to a session, so "is it anchored?" stays a
            # question with one answer.
            row = LedgerRun(id=run_id, label=label, status="open", kind=kind,
                            genesis_hash=GENESIS, head_hash=GENESIS, head_seq=-1,
                            last_seen_at=datetime.now(timezone.utc))
            db.add(row)
            db.flush()
        if mandate is not None and not row.mandate_hash:
            row.mandate_json = canon(mandate.as_dict())
            row.mandate_hash = mandate.hash
        if label and not row.label:
            row.label = label
        db.commit()
        if created:
            anchor_run(run_id, session_id=session_id or current_session(),
                       label=row.label, kind=kind, db=db)
        return row
    finally:
        if own:
            db.close()


def _resolve_mandate(run_id: str, db) -> Mandate:
    row = db.get(LedgerRun, run_id)
    return Mandate.from_dict(_loads(row.mandate_json, {}) if row else {})


def append(run_id: str, kind: str, actor: str, *, actor_type: str = "system",
           intent: Optional[str] = None, data: Optional[dict] = None,
           input_refs: Optional[list] = None,
           verdict: Optional[str] = None, severity: Optional[str] = None,
           proof: Optional[dict] = None, ts: Optional[str] = None,
           mandate: Optional[Mandate] = None, checked: bool = True,
           _db=None) -> str:
    """Append one event to a run's chain and return its hash.

    ``checked=False`` is for the machinery that records the audit trail's own
    decisions (gate checks, approvals) -- those are not themselves gated.
    Multi-process safety comes from the ``(run_id, seq)`` unique constraint: a
    losing writer retries against the new head.
    """
    if actor_type not in ACTOR_TYPES:
        raise ValueError(f"unknown actor_type {actor_type!r}")
    if verdict is not None and verdict not in VALID_VERDICTS:
        raise ValueError(f"unknown verdict {verdict!r}")
    if severity is not None and severity not in VALID_SEVERITIES:
        raise ValueError(f"unknown severity {severity!r}")

    data = _payload(data or {})
    refs = [r for r in (input_refs or []) if is_hash(r)]
    ts = ts or _now()

    own = _db is None
    db = _db or SessionLocal()
    try:
        with _LOCK:  # serialise read-head-then-append within this process
            for attempt in range(4):
                try:
                    ensure_run(run_id, db=db)
                    row = db.get(LedgerRun, run_id)
                    last = (db.query(LedgerEvent)
                            .filter(LedgerEvent.run_id == run_id)
                            .order_by(LedgerEvent.seq.desc()).first())
                    seq = (last.seq + 1) if last else 0
                    prev = last.hash if last else GENESIS

                    if checked:
                        pol = (mandate or _resolve_mandate(run_id, db))
                        v = pol.check(kind=kind, actor=actor, actor_type=actor_type,
                                      intent=intent, tool=data.get("tool"),
                                      domain=data.get("domain"),
                                      counts=_counts(db, run_id))
                        if verdict is None:
                            verdict = v.decision if v.decision != "pass" else "allow"
                        if severity is None:
                            severity = v.severity
                        data = dict(data, gate=v.as_dict())

                    core = event_core(
                        run_id=run_id, seq=seq, ts=ts, actor_type=actor_type,
                        actor=actor, kind=kind, intent=intent, verdict=verdict,
                        severity=severity, data=data, prev_hash=prev)
                    h = chain_hash(core)

                    db.add(LedgerEvent(
                        run_id=run_id, seq=seq, ts=ts, actor_type=actor_type,
                        actor=actor, kind=kind, intent=intent, verdict=verdict,
                        severity=severity, data_json=canon(data),
                        input_refs=canon(refs) if refs else None,
                        prev_hash=prev, hash=h,
                        proof_json=canon(proof) if proof else None))
                    row.head_hash, row.head_seq = h, seq
                    db.commit()
                    return h
                except IntegrityError:
                    # Another process took this seq between our read and our
                    # write. Re-read the head and try again against it.
                    db.rollback()
                    if attempt == 3:
                        raise
        raise RuntimeError("unreachable")
    finally:
        if own:
            db.close()


# ------------------------------------------------------------------- proof --

def build_proof(*, run_id: str, seq: int, event_hash: str, prev_hash: str,
                claim: Optional[str] = None, inputs: Optional[list] = None,
                method: Optional[dict] = None, output: Any = None,
                verification: Optional[dict] = None) -> dict:
    """Assemble the Proof-of-Work artifact for one event.

    Kept separate from ``append`` so a caller can build it once the event hash
    is known and attach it to a follow-up event or store it via
    ``attach_proof``.
    """
    v = dict(verification or {})
    if v.get("verdict") and v["verdict"] not in CLAIM_VERDICTS:
        raise ValueError(f"unknown claim verdict {v['verdict']!r}")
    return {
        "claim_hash": claim,
        "inputs": inputs or [],
        "method": method or {},
        "output_hash": text_digest(canon(output)) if output is not None else None,
        "verification": v,
        "chain": {"run_id": run_id, "seq": seq, "hash": event_hash,
                  "prev_hash": prev_hash},
    }


def attach_proof(run_id: str, seq: int, proof: dict) -> None:
    db = SessionLocal()
    try:
        ev = (db.query(LedgerEvent)
              .filter(LedgerEvent.run_id == run_id, LedgerEvent.seq == seq)
              .first())
        if ev is None:
            raise KeyError(f"no event {run_id}#{seq}")
        ev.proof_json = canon(proof)
        db.commit()
    finally:
        db.close()


def attach_event_proof(run_id: str, event_hash: str, *, claim: Optional[str] = None,
                       inputs: Optional[list] = None, method: Optional[dict] = None,
                       verification: Optional[dict] = None) -> dict:
    """Build and attach a proof *from the persisted event*.

    Deliberately re-reads the row instead of hashing the caller's in-memory
    values: ``append`` redacts payloads on the way in, so hashing a caller's
    original output would produce a digest that can never be re-derived, and
    every later verification would report a false failure. Deriving from
    storage makes the round-trip exact by construction.
    """
    db = SessionLocal()
    try:
        ev = (db.query(LedgerEvent)
              .filter(LedgerEvent.run_id == run_id,
                      LedgerEvent.hash == event_hash).first())
        if ev is None:
            raise KeyError(f"no event with hash {event_hash}")
        data = _loads(ev.data_json, {})
        proof = build_proof(
            run_id=run_id, seq=ev.seq, event_hash=ev.hash, prev_hash=ev.prev_hash,
            claim=claim if claim is not None else _claim_of(data),
            inputs=inputs if inputs is not None else _inputs_of(data, ev),
            method=method if method is not None else _method_of(data),
            output=data.get("output"), verification=verification)
        ev.proof_json = canon(proof)
        db.commit()
        return proof
    finally:
        db.close()


def _claim_of(data: dict) -> Optional[str]:
    """Content address of the claim an event asserts, if it asserts one."""
    text = data.get("text") or data.get("claim")
    if not text:
        return None
    return claim_hash(text, data.get("citations") or [])


def _method_of(data: dict) -> dict:
    """How the work was done, recovered from the fields recorders already set."""
    for kind, keys in (("llm", ("model", "prompt_hash")),
                       ("tool", ("tool", "args_hash"))):
        if all(k in data for k in keys):
            return {"type": kind, **{k: data[k] for k in keys}}
    if "protocol" in data and "to" in data:
        return {"type": "a2a", "protocol": data["protocol"], "to": data["to"]}
    return {}


def _inputs_of(data: dict, ev: "LedgerEvent") -> list:
    return [{"ref": r, "kind": "event"} for r in (_loads(ev.input_refs, []) or [])]


def proof_checks(proof: dict, *, data: dict, event_hash: str,
                 resolves: Optional[callable] = None) -> list:
    """Re-derive one event's proof from that event's own fields.

    Pure, so a live run and an offline export verify identically. ``resolves``
    answers "does this referenced input still exist"; the export passes None
    because it carries a ``known_refs`` index instead of a database, and reports
    those refs as unverifiable rather than silently passing them.
    """
    checks: list = []

    def check(name: str, ok: bool, detail: Any = None) -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    if not proof:
        return checks

    check("chain_position", (proof.get("chain") or {}).get("hash") == event_hash,
          {"proof_hash": (proof.get("chain") or {}).get("hash")})

    if proof.get("output_hash") is not None:
        check("output_hash",
              proof["output_hash"] == text_digest(canon(data.get("output"))),
              {"stored": proof["output_hash"]})

    if proof.get("claim_hash"):
        recomputed_claim = claim_hash(data.get("text") or data.get("claim") or "",
                                      data.get("citations"))
        check("claim_hash", recomputed_claim == proof["claim_hash"],
              {"stored": proof["claim_hash"], "recomputed": recomputed_claim})

    # Every ledger-referenced input must still resolve to the same hash.
    for ref in proof.get("inputs") or []:
        digest_ref = ref.get("ref") if isinstance(ref, dict) else ref
        if not is_hash(digest_ref):
            continue
        if resolves is None:
            check(f"input:{digest_ref[:12]}", False,
                  {"resolves_to": "unverifiable offline (no ledger attached)"})
            continue
        what = resolves(digest_ref)
        check(f"input:{digest_ref[:12]}", what is not None,
              {"resolves_to": what or "missing"})

    verdict_p = (proof.get("verification") or {}).get("verdict")
    if verdict_p is not None:
        check("verdict_vocabulary", verdict_p in CLAIM_VERDICTS,
              {"verdict": verdict_p})
    return checks


def verify_proof(run_id: str, seq: int, db=None) -> dict:
    """Re-derive an event's proof from the ledger. Reports each check
    separately so a failure says *what* stopped verifying."""
    own = db is None
    db = db or SessionLocal()
    try:
        ev = (db.query(LedgerEvent)
              .filter(LedgerEvent.run_id == run_id, LedgerEvent.seq == seq)
              .first())
        if ev is None:
            return {"ok": False, "run_id": run_id, "seq": seq,
                    "checks": [{"name": "event_exists", "ok": False}]}

        data = _loads(ev.data_json, {})
        proof = _loads(ev.proof_json, {})
        checks: list = []

        def check(name: str, ok: bool, detail: Any = None) -> None:
            checks.append({"name": name, "ok": bool(ok), "detail": detail})

        core = event_core(
            run_id=ev.run_id, seq=ev.seq, ts=ev.ts, actor_type=ev.actor_type,
            actor=ev.actor, kind=ev.kind, intent=ev.intent,
            verdict=ev.verdict, severity=ev.severity, data=data,
            prev_hash=ev.prev_hash)
        recomputed = chain_hash(core)
        check("event_hash", recomputed == ev.hash,
              {"stored": ev.hash, "recomputed": recomputed})

        def resolves(digest_ref: str) -> Optional[str]:
            src = (db.query(LedgerEvent)
                   .filter(LedgerEvent.hash == digest_ref).first())
            if src is not None:
                return "event"
            claim = db.query(LedgerClaim).filter(
                LedgerClaim.claim_hash == digest_ref).first()
            return "claim" if claim is not None else None

        checks.extend(proof_checks(proof, data=data, event_hash=ev.hash,
                                   resolves=resolves))

        return {
            "ok": all(c["ok"] for c in checks), "run_id": run_id, "seq": seq,
            "hash": ev.hash, "kind": ev.kind, "actor": ev.actor,
            "checks": checks, "proof": proof or None,
        }
    finally:
        if own:
            db.close()


# ---------------------------------------------------------- chain verify --

def verify_events(events: list, *, extra_refs: Optional[Iterable[str]] = None) -> dict:
    """Walk a chain of plain dicts. Pure, so it verifies a live run and an
    offline export with the same code.

    Also re-derives every proof and resolves each proof's input references
    against the bundle itself: a ref pointing at something the bundle does not
    contain is a finding, not a pass. Claim hashes live outside the event list,
    so callers pass them in ``extra_refs`` (a live run queries them, an export
    reads them out of the bundle).
    """
    findings: list = []
    prev = GENESIS
    expected_seq = 0
    proofs_checked = 0
    event_hashes = {e.get("hash") for e in events if is_hash(e.get("hash") or "")}
    known = set(extra_refs or ())

    def resolves(digest_ref: str) -> Optional[str]:
        if digest_ref in event_hashes:
            return "event"
        return "known_ref" if digest_ref in known else None

    for i, ev in enumerate(events):
        core = {k: ev.get(k) for k in CORE_FIELDS}
        recomputed = chain_hash(core)

        if ev.get("seq") != expected_seq:
            findings.append({"at_seq": ev.get("seq"), "issue": "sequence_gap",
                             "detail": f"expected seq {expected_seq}"})
            expected_seq = (ev.get("seq") or 0) + 1
        else:
            expected_seq += 1

        if ev.get("prev_hash") != prev:
            findings.append({"at_seq": ev.get("seq"), "issue": "broken_link",
                             "detail": "prev_hash does not match predecessor"})
        if recomputed != ev.get("hash"):
            findings.append({"at_seq": ev.get("seq"), "issue": "content_tampered",
                             "detail": "event hash does not match its contents",
                             "stored": ev.get("hash"), "recomputed": recomputed})
        prev = ev.get("hash")

        proof = ev.get("proof")
        if proof:
            proofs_checked += 1
            failing = [c for c in proof_checks(proof, data=ev.get("data") or {},
                                               event_hash=ev.get("hash"),
                                               resolves=resolves)
                       if not c["ok"]]
            if failing:
                findings.append({
                    "at_seq": ev.get("seq"), "issue": "proof_drift",
                    "detail": "stored proof no longer re-derives",
                    "failed": [c["name"] for c in failing],
                    "checks": failing})

    return {
        "ok": not findings, "events": len(events), "head_hash": prev,
        "proofs_checked": proofs_checked, "findings": findings,
    }


def verify_chain(run_id: str, db=None) -> dict:
    """Full audit of one run: chain integrity, head anchoring, proof drift and
    claim content-addresses."""
    own = db is None
    db = db or SessionLocal()
    try:
        rows = (db.query(LedgerEvent)
                .filter(LedgerEvent.run_id == run_id)
                .order_by(LedgerEvent.seq).all())
        run = db.get(LedgerRun, run_id)
        if run is None:
            return {"ok": False, "run_id": run_id, "events": 0,
                    "findings": [{"issue": "unknown_run", "detail": "no such run"}]}

        events = [{
            "run_id": r.run_id, "seq": r.seq, "ts": r.ts,
            "actor_type": r.actor_type, "actor": r.actor, "kind": r.kind,
            "intent": r.intent, "verdict": r.verdict, "severity": r.severity,
            "data": _loads(r.data_json, {}), "prev_hash": r.prev_hash,
            "hash": r.hash, "proof": _loads(r.proof_json, None),
            "input_refs": _loads(r.input_refs, []),
        } for r in rows]

        run_claims = db.query(LedgerClaim).filter(LedgerClaim.run_id == run_id).all()
        report = verify_events(events,
                               extra_refs=[c.claim_hash for c in run_claims])
        findings = list(report["findings"])

        if run.head_hash != report["head_hash"] or run.head_seq != (len(events) - 1):
            findings.append({
                "issue": "head_mismatch",
                "detail": "run head does not match the last event",
                "stored": [run.head_hash, run.head_seq],
                "recomputed": [report["head_hash"], len(events) - 1]})

        # Stored proofs are derived, so recompute rather than re-hash. verify_events
        # already re-derived them (and failed the run if any disagreed); this pass
        # only counts how many drifted and keeps the per-check detail.
        proof_drift = 0
        for ev in events:
            if not ev.get("proof"):
                continue
            res = verify_proof(run_id, ev["seq"], db=db)
            if not res["ok"]:
                proof_drift += 1

        for claim in run_claims:
            recomputed = claim_hash(claim.text, _loads(claim.citations_json, []))
            if recomputed != claim.claim_hash:
                findings.append({"at_seq": claim.seq, "issue": "claim_tampered",
                                 "detail": "claim hash does not match its text",
                                 "stored": claim.claim_hash, "recomputed": recomputed})

        return {
            "run_id": run_id, "ok": not findings, "events": len(events),
            "head_hash": report["head_hash"], "mandate_hash": run.mandate_hash,
            "status": run.status, "proofs_checked": sum(1 for e in events if e.get("proof")),
            "proof_drift": proof_drift, "findings": findings,
        }
    finally:
        if own:
            db.close()


# ------------------------------------------------------------------ claims --

def emit_claim(run_id: str, text: str, citations: Optional[list] = None,
               *, actor: str = "unknown", actor_type: str = "agent",
               verifier: Optional[str] = None,
               grounding: Optional[dict] = None,
               input_refs: Optional[list] = None) -> dict:
    """Record a claim and its grounding state as a first-class, content-addressed
    row -- the anchor for both verification and contamination tracing."""
    g = grounding or verify_grounding(text, citations or [], [])
    kept = g.get("kept") or citations or []
    ch = claim_hash(text, kept)
    violation = bool(g.get("violation"))

    h = append(run_id, "claim.emit", actor, actor_type=actor_type,
               intent="emit_claim", severity="block" if violation else "info",
               verdict="block" if violation else "pass",
               data={"text": (text or "")[:2000], "citations": kept,
                     "dropped": g.get("dropped") or [],
                     "n_sources": g.get("n_sources", 0),
                     "confidence": g.get("confidence", "none"),
                     "grounding_verdict": g.get("verdict", "unverified")},
               input_refs=input_refs)

    seq = _seq_of_db(run_id, h)
    db = SessionLocal()
    try:
        db.add(LedgerClaim(
            run_id=run_id, claim_hash=ch, seq=seq,
            actor=actor, text=(text or "")[:2000],
            citations_json=canon(kept), n_sources=g.get("n_sources", 0),
            confidence=g.get("confidence", "none"),
            verdict=g.get("verdict", "unverified"), verifier=verifier))
        db.commit()
    finally:
        db.close()

    # The proof is the interesting artefact here: which evidence this claim
    # rests on, how it was produced, and its grounding verdict -- re-derivable
    # later without trusting this row.
    attach_event_proof(run_id, h,
                       verification={"verdict": g.get("verdict", "unverified"),
                                     "method": verifier or "verbatim",
                                     "n_sources": g.get("n_sources", 0),
                                     "at": _now()})
    return {"claim_hash": ch, "event": h, **g}


def verify_claim(run_id: str, claim_hash_value: str, verdict: str, *,
                 method: str = "reviewer", note: str = "",
                 actor: str = "verifier", actor_type: str = "agent",
                 citations: Optional[list] = None) -> str:
    """Attach a verification verdict to a claim. ``unsupported`` is a
    ``block``-severity event, so it is impossible to miss on the timeline."""
    if verdict not in CLAIM_VERDICTS:
        raise ValueError(f"unknown claim verdict {verdict!r}")
    db = SessionLocal()
    try:
        claim = (db.query(LedgerClaim)
                 .filter(LedgerClaim.run_id == run_id,
                         LedgerClaim.claim_hash == claim_hash_value).first())
        if claim is not None:
            claim.verdict, claim.verifier = verdict, method
            db.commit()
    finally:
        db.close()
    return append(run_id, "claim.verify", actor, actor_type=actor_type,
                  intent="verify_claim",
                  verdict="block" if verdict == "unsupported" else "pass",
                  severity="block" if verdict == "unsupported" else
                           ("warn" if verdict == "uncertain" else "info"),
                  data={"text": (claim_text(run_id, claim_hash_value) or "")[:500],
                        "verdict": verdict, "method": method, "note": note,
                        "citations": citations or []},
                  input_refs=[claim_hash_value])


def _seq_of(db, run_id: str, event_hash: str) -> Optional[int]:
    row = db.query(LedgerEvent).filter(
        LedgerEvent.run_id == run_id, LedgerEvent.hash == event_hash).first()
    return row.seq if row else None


def claim_text(run_id: str, claim_hash_value: str) -> Optional[str]:
    db = SessionLocal()
    try:
        row = (db.query(LedgerClaim)
               .filter(LedgerClaim.run_id == run_id,
                       LedgerClaim.claim_hash == claim_hash_value).first())
        return row.text if row else None
    finally:
        db.close()


def contamination(run_id: str, ref: str, *, max_depth: int = 12) -> dict:
    """Blast radius of one piece of content: everything downstream that consumed
    it, transitively.

    This is the anti-hallucination tool that matters most in a pipeline. When a
    collector's research turns out to be fabricated, this answers "which
    conclusions are now suspect?" without re-reading any output.
    """
    db = SessionLocal()
    try:
        events = (db.query(LedgerEvent)
                  .filter(LedgerEvent.run_id == run_id)
                  .order_by(LedgerEvent.seq).all())
        claims = (db.query(LedgerClaim)
                  .filter(LedgerClaim.run_id == run_id).all())
        by_hash = {c.claim_hash: c for c in claims}

        # A claim is addressed by its content hash, but the thing that produced
        # it is an event. Alias the two directions so a query can start from
        # either "this claim" or "this act of asserting" and still walk the
        # whole lineage.
        alias: dict = {ref: [ref]}
        for c in claims:
            if c.seq is None:
                continue
            ev = next((e for e in events if e.seq == c.seq), None)
            if ev is None:
                continue
            alias.setdefault(c.claim_hash, []).append(ev.hash)
            alias.setdefault(ev.hash, []).append(c.claim_hash)

        consumers: dict = {}
        for ev in events:
            for r in (_loads(ev.input_refs, []) or []):
                consumers.setdefault(r, []).append(ev)

        frontier = list(dict.fromkeys(alias.get(ref, [ref])))
        reached: dict = {}
        depth = 0
        while frontier and depth < max_depth:
            nxt = []
            for cur in frontier:
                for ev in consumers.get(cur, []):
                    key = (ev.seq, ev.hash)
                    if key in reached:
                        continue
                    reached[key] = {
                        "seq": ev.seq, "hash": ev.hash, "kind": ev.kind,
                        "actor": ev.actor, "intent": ev.intent,
                        "severity": ev.severity, "verdict": ev.verdict,
                        "depth": depth + 1, "via": cur,
                    }
                    nxt.extend(alias.get(ev.hash, [ev.hash]))
            frontier = list(dict.fromkeys(nxt))
            depth += 1

        # A claim is implicated when it sits *between* the origin and the
        # conclusions: it consumed the target (or a descendant of it), so its
        # content address now appears as an input to something further along.
        implicated = {v["via"] for v in reached.values()} & set(by_hash)
        derived = [{
            "claim_hash": c.claim_hash, "actor": c.actor, "verdict": c.verdict,
            "confidence": c.confidence, "seq": c.seq, "text": (c.text or "")[:200],
        } for ch, c in by_hash.items() if ch in implicated]

        suspect = [{
            "claim_hash": c["claim_hash"], "actor": c["actor"],
            "verdict": c["verdict"], "seq": c["seq"], "text": c["text"],
            "consumed_by": [v["seq"] for v in reached.values()
                            if v["via"] == c["claim_hash"]],
        } for c in derived if c["verdict"] in ("unsupported", "uncertain", "unverified")]

        return {
            "run_id": run_id, "ref": ref, "blast_radius": len(reached),
            "is_event": is_hash(ref) and any(e.hash == ref for e in events),
            "direct_consumers": sorted(
                (v for v in reached.values() if v["depth"] == 1),
                key=lambda v: v["seq"]),
            "transitive": sorted((v for v in reached.values() if v["depth"] > 1),
                                 key=lambda v: (v["depth"], v["seq"])),
            "derived_claims": derived,
            "suspect_downstream": suspect,
        }
    finally:
        db.close()


# --------------------------------------------------------------- approvals --

def request_approval(run_id: str, kind: str, subject_hash: str, *,
                     summary: str = "", requested_by: str = "system",
                     input_refs: Optional[list] = None) -> int:
    h = append(run_id, "approval.request", requested_by, actor_type="system",
               intent="approval_request", verdict="hold", severity="warn",
               data={"kind": kind, "subject": subject_hash, "summary": summary},
               input_refs=input_refs, checked=False)
    db = SessionLocal()
    try:
        row = LedgerApproval(run_id=run_id, seq=_seq_of(db, run_id, h), kind=kind,
                             subject_hash=subject_hash, summary=summary,
                             requested_by=requested_by)
        db.add(row)
        db.commit()
        return row.id
    finally:
        db.close()


def decide_approval(approval_id: int, decision: str, *, decided_by: str,
                    note: str = "") -> str:
    if decision not in ("grant", "deny"):
        raise ValueError("decision must be 'grant' or 'deny'")
    db = SessionLocal()
    try:
        row = db.get(LedgerApproval, approval_id)
        if row is None:
            raise KeyError(f"no approval {approval_id}")
        row.decision, row.decided_by, row.decided_at = decision, decided_by, datetime.now(timezone.utc)
        row.note = note
        h = append(row.run_id, f"approval.{decision}", decided_by,
                   actor_type="human", intent=f"approval_{decision}",
                   verdict="grant" if decision == "grant" else "deny",
                   severity="info" if decision == "grant" else "warn",
                   data={"approval_id": approval_id, "kind": row.kind,
                         "subject": row.subject_hash, "note": note},
                   input_refs=[row.subject_hash] if row.subject_hash else None,
                   checked=False)
        row.event_hash = h
        db.commit()
        return h
    finally:
        db.close()


def pending_approval(run_id: str, subject_hash: str) -> Optional[LedgerApproval]:
    db = SessionLocal()
    try:
        return (db.query(LedgerApproval)
                .filter(LedgerApproval.run_id == run_id,
                        LedgerApproval.subject_hash == subject_hash,
                        LedgerApproval.decision.is_(None))
                .order_by(LedgerApproval.id.desc()).first())
    finally:
        db.close()


# ------------------------------------------------------------------- drift --

def detect_drift(run_id: str) -> dict:
    """Compare what happened against what was supposed to happen.

    Six signals, each pointing at the specific events involved, because a
    drift report that only says "something drifted" is not actionable.
    """
    db = SessionLocal()
    try:
        run = db.get(LedgerRun, run_id)
        if run is None:
            return {"run_id": run_id, "findings": [], "clean": True}
        mandate = Mandate.from_dict(_loads(run.mandate_json, {}))
        events = (db.query(LedgerEvent)
                  .filter(LedgerEvent.run_id == run_id)
                  .order_by(LedgerEvent.seq).all())
        claims = (db.query(LedgerClaim)
                  .filter(LedgerClaim.run_id == run_id).all())
        findings: list = []

        counts = _counts(db, run_id)
        if mandate.max_events and counts["total"] > mandate.max_events:
            findings.append({"signal": "budget_exceeded", "severity": "warn",
                             "detail": f"{counts['total']} events exceeds max_events={mandate.max_events}",
                             "seqs": None})
        if mandate.max_llm_calls and counts.get("llm.call", 0) > mandate.max_llm_calls:
            findings.append({"signal": "budget_exceeded", "severity": "warn",
                             "detail": f"{counts.get('llm.call')} llm calls exceeds max_llm_calls={mandate.max_llm_calls}",
                             "seqs": [e.seq for e in events if e.kind == "llm.call"]})

        # Unplanned intents, and work that happened outside a hard boundary.
        # The ledger's own bookkeeping is not agent behaviour, so internal kinds
        # and system actors are excluded -- otherwise every run self-reports drift.
        for ev in events:
            if ev.kind in INTERNAL_KINDS or ev.actor_type == "system":
                continue
            if ev.intent and mandate.planned_intents and ev.intent not in mandate.planned_intents:
                findings.append({"signal": "unplanned_intent", "severity": "warn",
                                 "detail": f"{ev.actor} performed unplanned intent {ev.intent!r}",
                                 "seqs": [ev.seq]})
            domain = _loads(ev.data_json, {}).get("domain")
            if domain and not mandate.domain_allowed(domain):
                findings.append({"signal": "scope_creep", "severity": "warn",
                                 "detail": f"{ev.actor} read outside mandate: {domain}",
                                 "seqs": [ev.seq]})

        # Repeated identical work: usually a retry loop burning budget.
        if mandate.loop_threshold:
            tally: dict = {}
            for ev in events:
                if ev.kind in INTERNAL_KINDS or ev.intent is None:
                    continue
                tally.setdefault((ev.actor, ev.kind, ev.intent), []).append(ev.seq)
            for (actor, kind, intent), seqs in tally.items():
                if len(seqs) >= mandate.loop_threshold:
                    findings.append({"signal": "loop", "severity": "warn",
                                     "detail": f"{actor} repeated {kind}/{intent} {len(seqs)}x",
                                     "seqs": seqs})

        # A blocked action followed by more work from the same actor: the gate
        # recorded a violation but nothing stopped.
        for ev in events:
            if ev.actor_type == "system" or ev.kind in INTERNAL_KINDS:
                continue
            if ev.verdict in ("deny", "block") and ev.severity == "block":
                later = [e.seq for e in events
                         if e.seq > ev.seq and e.actor == ev.actor
                         and e.actor_type != "system"
                         and e.kind not in INTERNAL_KINDS]
                if later:
                    findings.append({"signal": "violation_not_halted", "severity": "block",
                                     "detail": f"{ev.actor} continued after a blocked action at seq {ev.seq}",
                                     "seqs": [ev.seq] + later[:20]})

        # Ungrounded claims, and unverified claims that kept propagating.
        unverified = {c.claim_hash for c in claims
                      if c.verdict in ("unsupported", "uncertain", "unverified")}
        ungrounded = {c.claim_hash for c in claims if not c.n_sources}
        for ch in sorted(ungrounded):
            claim = next(c for c in claims if c.claim_hash == ch)
            findings.append({"signal": "ungrounded_claim",
                             "severity": "block" if mandate.require_grounding else "warn",
                             "detail": f"claim with no verified citation: {(claim.text or '')[:120]}",
                             "seqs": [claim.seq] if claim.seq is not None else None})
        for ev in events:
            if ev.kind == "claim.verify":
                continue  # consuming a claim to check it is the opposite of blind
            refs = _loads(ev.input_refs, []) or []
            bad = sorted(set(refs) & unverified)
            if bad:
                findings.append({"signal": "unverified_claim_propagated",
                                 "severity": "warn",
                                 "detail": f"{ev.actor} consumed {len(bad)} unverified claim(s) without re-checking",
                                 "seqs": [ev.seq]})

        return {
            "run_id": run_id, "mandate_hash": mandate.hash,
            "clean": not findings, "events": len(events),
            "findings": sorted(findings, key=lambda f: (f["severity"] != "block", f["signal"])),
        }
    finally:
        db.close()


# ---------------------------------------------------------------- timeline --

def timeline(run_id: str, *, kinds: Optional[list] = None,
             actor_types: Optional[list] = None, actors: Optional[list] = None,
             verdict: Optional[str] = None, min_severity: Optional[str] = None,
             since_seq: int = 0, limit: int = 500, offset: int = 0,
             include_data: bool = True, db=None) -> dict:
    """Ordered, filterable view of a run. ``min_severity`` is what a
    transparency UI wants by default: everything that went wrong, in order."""
    own = db is None
    db = db or SessionLocal()
    try:
        q = db.query(LedgerEvent).filter(LedgerEvent.run_id == run_id,
                                         LedgerEvent.seq >= since_seq)
        if kinds:
            q = q.filter(LedgerEvent.kind.in_(kinds))
        if actor_types:
            q = q.filter(LedgerEvent.actor_type.in_(actor_types))
        if actors:
            q = q.filter(LedgerEvent.actor.in_(actors))
        if verdict:
            q = q.filter(LedgerEvent.verdict == verdict)
        if min_severity:
            order = ["info", "warn", "block"]
            allowed = order[order.index(min_severity):] if min_severity in order else order
            q = q.filter(LedgerEvent.severity.in_(allowed))
        total = q.count()
        rows = q.order_by(LedgerEvent.seq).offset(offset).limit(limit).all()
        return {
            "run_id": run_id, "total": total, "offset": offset, "limit": limit,
            "events": [{
                "seq": r.seq, "ts": r.ts, "kind": r.kind,
                "actor_type": r.actor_type, "actor": r.actor, "intent": r.intent,
                "verdict": r.verdict, "severity": r.severity, "hash": r.hash,
                "prev_hash": r.prev_hash, "input_refs": _loads(r.input_refs, []),
                "proof": _loads(r.proof_json, None),
                "data": _loads(r.data_json, {}) if include_data else None,
            } for r in rows],
        }
    finally:
        if own:
            db.close()


def summary(run_id: str) -> dict:
    """Headline numbers for a run -- the dashboard's single call."""
    db = SessionLocal()
    try:
        run = db.get(LedgerRun, run_id)
        if run is None:
            raise KeyError(f"no ledger run {run_id}")
        counts = _counts(db, run_id)
        severities = dict(db.query(LedgerEvent.severity, func.count(LedgerEvent.id))
                          .filter(LedgerEvent.run_id == run_id)
                          .group_by(LedgerEvent.severity).all())
        actors = dict(db.query(LedgerEvent.actor, func.count(LedgerEvent.id))
                      .filter(LedgerEvent.run_id == run_id)
                      .group_by(LedgerEvent.actor).all())
        claims = db.query(LedgerClaim).filter(LedgerClaim.run_id == run_id).all()
        approvals = db.query(LedgerApproval).filter(LedgerApproval.run_id == run_id).all()
        return {
            "run_id": run_id, "label": run.label, "status": run.status,
            "mandate_hash": run.mandate_hash,
            "mandate": _loads(run.mandate_json, {}),
            "head_hash": run.head_hash, "head_seq": run.head_seq,
            "events": counts.get("total", 0), "by_kind": counts,
            "by_actor": actors, "by_severity": severities,
            "claims": {
                "total": len(claims),
                "ungrounded": sum(1 for c in claims if not c.n_sources),
                "unsupported": sum(1 for c in claims if c.verdict == "unsupported"),
                "uncertain": sum(1 for c in claims if c.verdict == "uncertain"),
            },
            "approvals": {
                "total": len(approvals),
                "pending": sum(1 for a in approvals if not a.decision),
                "denied": sum(1 for a in approvals if a.decision == "deny"),
            },
        }
    finally:
        db.close()


def export_run(run_id: str) -> dict:
    """Self-contained audit bundle: verify it offline with no database, no app
    and no network. This is the artefact an auditor or a regulator receives."""
    db = SessionLocal()
    try:
        run = db.get(LedgerRun, run_id)
        if run is None:
            raise KeyError(f"no ledger run {run_id}")
        events = (db.query(LedgerEvent)
                  .filter(LedgerEvent.run_id == run_id)
                  .order_by(LedgerEvent.seq).all())
        claims = (db.query(LedgerClaim)
                  .filter(LedgerClaim.run_id == run_id).all())
        approvals = db.query(LedgerApproval).filter(LedgerApproval.run_id == run_id).all()
        doc = {
            "format": "akm.ledger/1",
            "run": {"id": run.id, "label": run.label, "status": run.status,
                    "mandate": _loads(run.mandate_json, {}),
                    "mandate_hash": run.mandate_hash,
                    "genesis_hash": run.genesis_hash,
                    "head_hash": run.head_hash, "created_at": str(run.created_at)},
            "events": [{
                "run_id": e.run_id, "seq": e.seq, "ts": e.ts,
                "actor_type": e.actor_type, "actor": e.actor, "kind": e.kind,
                "intent": e.intent, "verdict": e.verdict, "severity": e.severity,
                "data": _loads(e.data_json, {}), "prev_hash": e.prev_hash,
                "hash": e.hash, "proof": _loads(e.proof_json, None),
                "input_refs": _loads(e.input_refs, []),
            } for e in events],
            "claims": [{
                "claim_hash": c.claim_hash, "seq": c.seq, "actor": c.actor,
                "text": c.text, "citations": _loads(c.citations_json, []),
                "n_sources": c.n_sources, "confidence": c.confidence,
                "verdict": c.verdict, "verifier": c.verifier,
            } for c in claims],
            "approvals": [{
                "id": a.id, "seq": a.seq, "kind": a.kind,
                "subject_hash": a.subject_hash, "decision": a.decision,
                "decided_by": a.decided_by, "event_hash": a.event_hash,
            } for a in approvals],
        }
        doc["verification"] = verify_events(
            doc["events"], extra_refs=[c["claim_hash"] for c in doc["claims"]])
        return doc
    finally:
        db.close()


def verify_export(doc: dict) -> dict:
    """Verify a bundle produced by ``export_run`` without touching the app."""
    if not isinstance(doc, dict) or "events" not in doc:
        raise ValueError("not a ledger export")
    return verify_events(doc.get("events") or [],
                         extra_refs=[(c or {}).get("claim_hash")
                                     for c in (doc.get("claims") or [])])


# ---------------------------------------------------------------- run scope --

class RunCtx:
    """Handle for an open run. Every recorder checks the mandate, writes the
    verdict onto the event, and -- when something was wrong -- also emits a
    ``gate.check`` so violations are impossible to scroll past."""

    def __init__(self, run_id: str, mandate: Optional[Mandate] = None,
                 label: Optional[str] = None):
        self.run_id = run_id
        self.mandate = mandate or Mandate()
        self.label = label
        self.started = _now()

    # -- plumbing ---------------------------------------------------------
    def _event(self, kind: str, actor: str, *, actor_type: str = "system",
               intent: Optional[str] = None, data: Optional[dict] = None,
               input_refs: Optional[list] = None,
               tool: Optional[str] = None, domain: Optional[str] = None,
               verdict: Optional[str] = None, severity: Optional[str] = None,
               proof: Optional[dict] = None) -> str:
        """Append one event under this run's mandate.

        ``verdict``/``severity`` are only supplied by callers that *are* the
        gate (``RunCtx.gate``, grounding failures); for ordinary actions they
        come from the mandate check and land on the event.
        """
        data = dict(data or {})
        if tool:
            data.setdefault("tool", tool)
        if domain:
            data.setdefault("domain", domain)
        if verdict is None:
            v = self.mandate.check(kind=kind, actor=actor, actor_type=actor_type,
                                   intent=intent, tool=tool, domain=domain)
            data["gate"] = v.as_dict()
            verdict = v.decision if v.decision != "pass" else "allow"
            severity = severity or v.severity
        h = append(self.run_id, kind, actor, actor_type=actor_type, intent=intent,
                   data=data, input_refs=input_refs, verdict=verdict,
                   severity=severity, proof=proof, checked=False)
        if verdict in ("deny", "hold", "block"):
            append(self.run_id, "gate.check", "ledger", actor_type="system",
                   intent=intent or kind, verdict=verdict,
                   severity=severity or "warn",
                   data={"action": {"kind": kind, "actor": actor, "intent": intent},
                         "gate": data.get("gate", {"reason": "explicit gate decision"})},
                   input_refs=[h], checked=False)
        return h

    # -- recorders --------------------------------------------------------
    def llm(self, model: str, prompt: str, output: str, *,
            intent: Optional[str] = None, latency_ms: int = 0,
            tokens_in: int = 0, tokens_out: int = 0, actor: Optional[str] = None,
            input_refs: Optional[list] = None, error: str = "",
            gateway: Optional[dict] = None) -> str:
        """An LLM call is the single most important thing to record: it is where
        text is invented. Prompt and output are stored hashed by default so the
        record proves *what ran* without durably copying the prompt."""
        data = {
            "model": model, "prompt_hash": text_digest(prompt),
            "prompt_chars": len(prompt or ""), "output": output,
            "latency_ms": latency_ms, "tokens_in": tokens_in,
            "tokens_out": tokens_out, "error": error,
        }
        gateway = {k: v for k, v in (gateway or {}).items() if v}
        if gateway:
            # Gateway request/proof IDs are content addresses and routing IDs,
            # safe to keep alongside the local hashes they corroborate.
            data["gateway"] = gateway
        if CAPTURE_PAYLOADS:
            data["prompt"] = prompt
        h = self._event("llm.call", actor or model, actor_type="llm",
                        intent=intent, data=data, input_refs=input_refs)
        method = {"type": "llm", "model": model, "prompt_hash": data["prompt_hash"]}
        if gateway.get("proof"):
            method["gateway_proof"] = gateway["proof"]
        if gateway.get("request_id"):
            method["gateway_request_id"] = gateway["request_id"]
        attach_event_proof(self.run_id, h, method=method)
        return h

    def step(self, stage: str, message: str, detail: Any = None, *,
             intent: Optional[str] = None, actor: Optional[str] = None) -> str:
        """A named phase of work ("planning round 2", "kept 6 artifacts").

        This is the spine of *how* a run unfolded, as opposed to ``llm.call``
        which is the spine of *what was said*. Both are needed: a run that kept
        nothing and made no model calls still has a story worth keeping.
        """
        return self._event("agent.step", actor or "agent", actor_type="agent",
                           intent=intent or stage,
                           data={"stage": stage, "message": message,
                                 "detail": detail})

    def mcp(self, server: str, tool: str, args: dict, output: Any, *,
            ok: bool = True, latency_ms: int = 0, intent: Optional[str] = None,
            input_refs: Optional[list] = None, error: str = "") -> str:
        full = f"{server}.{tool}" if server else tool
        data = {"server": server, "tool": full, "args_hash": digest(args),
                "args": args if CAPTURE_PAYLOADS else None, "output": output,
                "ok": ok, "latency_ms": latency_ms, "error": error}
        return self._event("mcp.call", full, actor_type="mcp", intent=intent,
                           data=data, input_refs=input_refs, tool=full)

    def hop(self, sender: str, recipient: str, intent: str, payload: Any,
            output: Any = None, *, task_id: Optional[str] = None,
            protocol: str = "a2a/1.0", latency_ms: int = 0,
            input_refs: Optional[list] = None) -> str:
        """One A2A envelope crossing the bus, in both directions, as a single
        chained event so the handoff is the unit of audit rather than two
        disconnected messages."""
        return self._event("agent.hop", sender, actor_type="a2a", intent=intent,
                           data={"from": sender, "to": recipient, "protocol": protocol,
                                 "task_id": task_id, "input": payload, "output": output,
                                 "latency_ms": latency_ms},
                           input_refs=input_refs)

    def human(self, actor: str, action: str, detail: Any = None, *,
              input_refs: Optional[list] = None) -> str:
        return self._event("human.action", actor, actor_type="human",
                           intent=action, data={"action": action, "detail": detail},
                           input_refs=input_refs)

    def source(self, url: str, *, title: str = "", kept: bool = True,
               reason: str = "", actor: str = "researcher",
               latency_ms: int = 0) -> str:
        """A source an agent read. ``kept=False`` records sources that were
        fetched and *rejected* -- discarding those silently is exactly how a
        reader ends up unable to explain why a claim was dropped."""
        from urllib.parse import urlparse
        domain = urlparse(url or "").netloc
        return self._event("source.fetch", actor, actor_type="agent",
                           intent="fetch_source",
                           data={"url": url, "title": title, "kept": kept,
                                 "reason": reason, "latency_ms": latency_ms},
                           domain=domain or None)

    def _emit_gate(self, intent: str, subject: dict, *,
                   verdict: str = "block", severity: str = "block",
                   input_refs: Optional[list] = None) -> str:
        """Append a ``gate.check`` without ``_event``'s auto-emit, so a
        deliberate gate decision yields exactly one event rather than two."""
        return append(self.run_id, "gate.check", "ledger", actor_type="system",
                      intent=intent, verdict=verdict, severity=severity,
                      data=subject, input_refs=input_refs, checked=False)

    def claim(self, text: str, citations: Optional[list] = None,
              sources: Any = None, *, actor: str = "unknown",
              actor_type: str = "agent",
              input_refs: Optional[list] = None) -> dict:
        grounding = verify_grounding(text, citations or [], sources or {})
        res = emit_claim(self.run_id, text, citations, actor=actor,
                         actor_type=actor_type, grounding=grounding,
                         input_refs=input_refs)
        if self.mandate.require_grounding and grounding["violation"]:
            self._emit_gate("ungrounded_claim",
                            {"claim_hash": res["claim_hash"],
                             "text": (text or "")[:300]},
                            input_refs=[res["event"]])
        return res

    def gate(self, subject: str, decision: str, reason: str, *,
             actor: str = "ledger", severity: str = "warn") -> str:
        if decision not in VALID_VERDICTS:
            raise ValueError(f"unknown verdict {decision!r}")
        return self._emit_gate("gate", {"subject": subject, "reason": reason},
                               verdict=decision, severity=severity)

    def ask(self, kind: str, subject_hash: str, summary: str, *,
            requested_by: str = "system") -> int:
        return request_approval(self.run_id, kind, subject_hash, summary=summary,
                                requested_by=requested_by)

    def decide(self, approval_id: int, decision: str, *, decided_by: str,
               note: str = "") -> str:
        return decide_approval(approval_id, decision, decided_by=decided_by, note=note)

    def close(self, status: str = "closed") -> str:
        h = self._event("run.end", "ledger", actor_type="system", intent="run_end",
                        data={"status": status, "started": self.started})
        db = SessionLocal()
        try:
            run = db.get(LedgerRun, self.run_id)
            if run is not None:
                run.status, run.closed_at = status, datetime.now(timezone.utc)
                db.commit()
        finally:
            db.close()
        return h


def _seq_of_db(run_id: str, event_hash: str) -> int:
    db = SessionLocal()
    try:
        seq = _seq_of(db, run_id, event_hash)
        return seq if seq is not None else 0
    finally:
        db.close()


@contextmanager
def session(session_id: str, *, label: Optional[str] = None,
            client_key: Optional[str] = None):
    """Make a session current for everything downstream.

    The session outlives any single run, so this is the context a request
    handler wants: run-level work anchors itself automatically, and human
    actions recorded with no run still land on the session.
    """
    ensure_session(session_id, client_key=client_key, label=label)
    token = _current_session.set(session_id)
    try:
        yield session_id
    finally:
        _current_session.reset(token)


@contextmanager
def run(run_id: str, mandate: Optional[Mandate] = None, *,
        label: Optional[str] = None):
    """Open a run and make it current for everything downstream in this
    context -- including background threads that copy the context.

    Instrumented call sites check ``current_run()`` and no-op when nothing is
    open, so wiring them in is safe even on code paths the ledger doesn't cover.

    A run id is one chain, for its lifetime: reopening one that already has a
    ``run.start`` continues the existing chain rather than forking a second one,
    so a run id cannot be reused to present two divergent histories. The mandate
    already on the run is adopted unless a new one is passed explicitly.
    """
    mandate = mandate or _stored_mandate(run_id) or Mandate()
    ensure_run(run_id, mandate, label)
    ctx = RunCtx(run_id, mandate, label)
    if not _has_event(run_id, "run.start"):
        append(run_id, "run.start", "ledger", actor_type="system",
               intent="run_start", verdict="allow", severity="info",
               data={"label": label, "mandate": mandate.as_dict(),
                     "mandate_hash": mandate.hash}, checked=False)
    t_run = _current_run.set(run_id)
    t_pol = _current_mandate.set(mandate)
    try:
        yield ctx
    except Exception as exc:
        append(run_id, "run.error", "ledger", actor_type="system", intent="run_error",
               verdict="deny", severity="block",
               data={"error": f"{exc}"[:500], "type": type(exc).__name__},
               checked=False)
        try:
            ctx.close("aborted")
        except Exception:
            pass
        raise
    finally:
        _current_run.reset(t_run)
        _current_mandate.reset(t_pol)


# ------------------------------------------------- instrumented checkpoints --

def _has_event(run_id: str, kind: str) -> bool:
    db = SessionLocal()
    try:
        return (db.query(LedgerEvent.id)
                .filter(LedgerEvent.run_id == run_id,
                        LedgerEvent.kind == kind).first()) is not None
    finally:
        db.close()


def _stored_mandate(run_id: str) -> Optional[Mandate]:
    """The mandate already on the run, if any.

    Adopting it matters for auditability: reopening a run must evaluate actions
    against the policy that was in force, not a blank default. Otherwise the
    same task could be judged under two different mandates and the recorded
    ``mandate_hash`` would stop describing the checks that actually ran.
    """
    db = SessionLocal()
    try:
        row = db.get(LedgerRun, run_id)
        if row is None or not row.mandate_json:
            return None
        return Mandate.from_dict(_loads(row.mandate_json, {}))
    finally:
        db.close()


@contextmanager
def scope(run_id: str, mandate: Optional[Mandate] = None, *,
          label: Optional[str] = None, close: bool = False):
    """Adopt an existing run id as the current audit context.

    Differs from ``run`` in the two ways instrumentation on a shared choke point
    needs: it does not fail if the run already exists, and it does not close the
    run on exit unless asked. Several calls that belong to one logical run (four
    hops of one A2A task, say) should share a chain, not open four.
    """
    mandate = mandate or _stored_mandate(run_id) or Mandate()
    ensure_run(run_id, mandate, label)
    t_run = _current_run.set(run_id)
    t_pol = _current_mandate.set(mandate)
    try:
        if not _has_event(run_id, "run.start"):
            append(run_id, "run.start", "ledger", actor_type="system",
                   intent="run_start", verdict="allow", severity="info",
                   data={"label": label, "mandate_hash": mandate.hash},
                   checked=False)
        yield RunCtx(run_id, mandate, label)
    finally:
        if close:
            append(run_id, "run.end", "ledger", actor_type="system",
                   intent="run_end", verdict="allow", severity="info",
                   data={"status": "closed"}, checked=False)
        _current_run.reset(t_run)
        _current_mandate.reset(t_pol)


def record_claim(text: str, citations: Optional[list] = None,
                 sources: Any = None, *, actor: str = "unknown",
                 actor_type: str = "agent",
                 input_refs: Optional[list] = None) -> Optional[dict]:
    """Register a claim on the open run, grounded against ``sources``.

    No-ops without an open run, so domain code can call this unconditionally
    and stay audit-free in tests and one-off scripts.
    """
    run_id = current_run()
    if not run_id:
        return None
    mandate = current_mandate() or Mandate()
    return _safe(RunCtx(run_id, mandate).claim, text, citations,
                 sources=sources, actor=actor, actor_type=actor_type,
                 input_refs=input_refs)


def _safe(fn, *args, **kwargs):
    """Run an audit recorder, swallowing its own failures.

    The ledger observes work; it must never be the reason that work fails. A
    dropped record is itself a gap in the audit trail, so it is reported loudly
    on stderr rather than swallowed.
    """
    try:
        return fn(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 - deliberately broad, see docstring
        print(f"[ledger] dropped audit record: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return None


def record_llm_call(model: str, prompt: str, output: str, **kwargs) -> Optional[str]:
    """No-op unless a run is open. Called from ``llm.chat`` so every model call
    anywhere in the app lands on the timeline without threading a context
    object through call sites."""
    run_id = current_run()
    if not run_id:
        return None
    mandate = current_mandate() or Mandate()
    return _safe(RunCtx(run_id, mandate).llm, model, prompt, output, **kwargs)


def record_agent_step(stage: str, message: str, detail: Any = None,
                      **kwargs) -> Optional[str]:
    """No-op unless a run is open. Mirrors an agent's own progress feed onto the
    chain, so the audit trail shows the shape of the work and not only the model
    calls that happened along the way."""
    run_id = current_run()
    if not run_id:
        return None
    mandate = current_mandate() or Mandate()
    return _safe(RunCtx(run_id, mandate).step, stage, message, detail, **kwargs)


def record_mcp_call(server: str, tool: str, args: dict, output: Any, **kwargs) -> Optional[str]:
    run_id = current_run()
    if not run_id:
        return None
    mandate = current_mandate() or Mandate()
    return _safe(RunCtx(run_id, mandate).mcp, server, tool, args, output, **kwargs)


def record_human_action(actor: str, action: str, detail: Any = None) -> Optional[str]:
    """Record a human action. Needs a *run* to append to; with only a session
    open the action is dropped, because a session row is a spine, not a
    timeline. ``session_action`` is the call site for those."""
    run_id = current_run()
    if not run_id:
        return None
    mandate = current_mandate() or Mandate()
    return _safe(RunCtx(run_id, mandate).human, actor, action, detail)


def record_human(actor: str, action: str, detail: Any = None) -> Optional[str]:
    """Record a human action wherever it belongs, and never raise.

    Dispatch order matters: an open *run* is the more specific place for the
    record, so it wins; a session with no run still gets one, on a run of its
    own; with neither, the action is dropped rather than guessed at.

    The whole dispatch is wrapped because callers are product request handlers
    -- an audit write must never be the reason a user's click returns a 500.
    """
    def _do():
        if current_run():
            return record_human_action(actor, action, detail)
        return record_session_action(actor, action, detail)
    return _safe(_do)


def record_session_action(actor: str, action: str, detail: Any = None) -> Optional[str]:
    """A human action that belongs to the sitting rather than to one run --
    switching investigation, starting an assessment, changing a preference.

    These get a run of their own so the session view can hold them: one
    ``ses-*``-scoped chain would mix spine events with work and make the spine's
    ordering argument ambiguous.
    """
    session_id = current_session()
    if not session_id:
        return None
    def _do():
        rid = f"{session_id}-ui"
        ensure_run(rid, Mandate(), label="human actions",
                   session_id=session_id, kind="actions")
        return RunCtx(rid, Mandate()).human(actor, action, detail)
    return _safe(_do)
