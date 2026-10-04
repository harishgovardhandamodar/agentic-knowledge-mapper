"""Tamper-evident audit ledger tables.

One append-only, hash-chained stream per run spans *every* actor: agents, LLM
calls, MCP tool invocations, A2A hops in and out, and human actions. The chain
is what makes the log auditable: each row commits to its predecessor, so an
edit, a deletion or an insertion after the fact all break verification.

Kept out of ``app/models.py`` because the ledger has a different shape from the
domain models (no investigation FK, string-keyed run ids, hash columns). It is
still registered on the same ``Base`` metadata, so ``init_db`` creates it.
"""
from datetime import datetime, timezone

from sqlalchemy import (Column, DateTime, ForeignKey, Integer, String, Text,
                        UniqueConstraint)
from sqlalchemy.orm import relationship

from .database import Base


def _now():
    return datetime.now(timezone.utc)


class LedgerRun(Base):
    """One audited unit of work: a mandate plus its chained event stream.

    The run id is caller-supplied (not an autoincrement) so an external
    orchestrator can key the ledger by its own correlation id.

    Two kinds of row live here, which is what makes a *session* verifiable
    without inventing a second chain implementation:

    - ``kind='task'`` (the default) is one piece of work -- an A2A task, an
      agent run. Its chain holds the actual events.
    - ``kind='session'`` is the spine for a sitting. Its chain does not hold
      the work; it holds one ``run.anchor`` event per task, in the order the
      tasks were adopted. So each task still verifies on its own, and the
      session chain independently proves the *order* the tasks happened in.
    """

    __tablename__ = "ledger_runs"

    id = Column(String(64), primary_key=True)
    label = Column(String(200), nullable=True)
    kind = Column(String(20), nullable=False, default="task")  # task|session
    session_id = Column(String(64), ForeignKey("ledger_runs.id", ondelete="SET NULL"),
                        nullable=True, index=True)   # session this task belongs to
    # Browser-supplied key plus last activity: a session is "the same sitting",
    # so the same key resumes its session until it goes idle.
    client_key = Column(String(64), nullable=True, index=True)
    last_seen_at = Column(DateTime, nullable=True, index=True)
    status = Column(String(20), nullable=False, default="open")  # open|closed|aborted
    mandate_json = Column(Text, nullable=True)   # JSON: policy in force for this run
    mandate_hash = Column(String(64), nullable=True)
    genesis_hash = Column(String(64), nullable=True)
    head_hash = Column(String(64), nullable=True)  # last event hash, for cheap anchoring
    head_seq = Column(Integer, nullable=False, default=-1)
    created_at = Column(DateTime, default=_now)
    closed_at = Column(DateTime, nullable=True)

    events = relationship("LedgerEvent", back_populates="run",
                          cascade="all, delete-orphan")


class LedgerEvent(Base):
    """One hash-chained step in a run's timeline.

    ``hash`` covers the full immutable core below, so any mutation to
    ``data_json`` invalidates the chain. ``proof_json`` is deliberately *not*
    hashed: it is derived state, and verification recomputes it and reports
    drift rather than trusting the stored copy.
    """

    __tablename__ = "ledger_events"
    __table_args__ = (
        UniqueConstraint("run_id", "seq", name="uq_ledger_event_seq"),
    )

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(String(64), ForeignKey("ledger_runs.id", ondelete="CASCADE"),
                    nullable=False, index=True)
    seq = Column(Integer, nullable=False)          # 0-based position in the chain
    # ISO-8601 string, not DateTime: audit needs the exact authored timestamp
    # with offset preserved, and lexicographic order equals chronological order.
    ts = Column(String(40), nullable=False, index=True)
    actor_type = Column(String(20), nullable=False)  # agent|llm|mcp|a2a|human|system
    actor = Column(String(120), nullable=False, index=True)
    kind = Column(String(40), nullable=False, index=True)  # llm.call|mcp.call|agent.hop|...
    intent = Column(String(80), nullable=True, index=True)
    verdict = Column(String(20), nullable=True, index=True)  # pass|allow|deny|flag|hold|block
    severity = Column(String(10), nullable=True, index=True)  # info|warn|block
    data_json = Column(Text, nullable=False)        # canonical JSON core (hashed)
    input_refs = Column(Text, nullable=True)        # JSON list of sha256 — lineage edges
    prev_hash = Column(String(64), nullable=False)
    hash = Column(String(64), nullable=False, index=True)
    proof_json = Column(Text, nullable=True)        # derived Proof-of-Work artifact
    # Which trace produced this event. Deliberately outside the hashed core:
    # the trace says *when* and *under which request* the record was written,
    # not what the record claims. Folding it into data_json would change every
    # event hash and break verification of every run already on disk, so it
    # rides in its own unhashed column -- like proof_json, an observation about
    # the record rather than part of it.
    trace = Column(String(48), nullable=True, index=True)

    run = relationship("LedgerRun", back_populates="events")


class LedgerClaim(Base):
    """A content-addressed assertion, so downstream trust is traceable.

    ``claim_hash`` is a pure function of the claim's own content (text +
    citations). Two agents asserting the same thing produce the same hash,
    which makes "did B simply parrot A?" answerable, and lets a reviewer pull
    the full blast radius of a bad claim from one hash.
    """

    __tablename__ = "ledger_claims"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(String(64), ForeignKey("ledger_runs.id", ondelete="CASCADE"),
                    nullable=False, index=True)
    claim_hash = Column(String(64), nullable=False, index=True)
    seq = Column(Integer, nullable=True)             # event seq that emitted it
    actor = Column(String(120), nullable=True)
    text = Column(Text, nullable=False)
    citations_json = Column(Text, nullable=True)     # JSON [{source, quote, verified}]
    n_sources = Column(Integer, nullable=False, default=0)
    confidence = Column(String(10), nullable=True)   # high|medium|low|none
    verdict = Column(String(20), nullable=True)      # supported|unsupported|uncertain|unverified
    verifier = Column(String(40), nullable=True)     # verbatim|corroboration|reviewer|human
    created_at = Column(DateTime, default=_now)


class LedgerAuditDrop(Base):
    """An audit record the ledger failed to write.

    The chain is the product's evidence that its agents did what they said. A
    write that fails is a hole in that evidence, and a hole that exists only as
    a line on stderr is a hole nobody reads -- it scrolls past, it is not
    queryable, and it leaves no count. This table is where a dropped record
    goes instead: durable, countable, and joinable to the run it belonged to,
    so "did we lose anything?" has an answer after the fact.

    Deliberately not part of the chain. It cannot be: a row here usually
    exists *because* the chain write failed. It is the place to look when
    ``verify_chain`` reports a gap, and the place an operator watches to see a
    failing database before it silently starts dropping real work.
    """

    __tablename__ = "ledger_audit_drops"

    id = Column(Integer, primary_key=True, index=True)
    ts = Column(DateTime, default=_now, index=True)
    run_id = Column(String(64), nullable=True, index=True)
    recorder = Column(String(40), nullable=True, index=True)  # which helper failed
    actor = Column(String(120), nullable=True)
    error = Column(Text, nullable=True)
    detail_json = Column(Text, nullable=True)   # redacted arg summary


class LedgerApproval(Base):
    """A human decision point. The decision is itself a chained event, so an
    approval cannot be forged into the record after the fact."""

    __tablename__ = "ledger_approvals"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(String(64), ForeignKey("ledger_runs.id", ondelete="CASCADE"),
                    nullable=False, index=True)
    seq = Column(Integer, nullable=True)             # event seq of approval.request
    kind = Column(String(40), nullable=False, index=True)
    subject_hash = Column(String(64), nullable=True, index=True)  # claim/event being approved
    summary = Column(Text, nullable=True)
    requested_by = Column(String(120), nullable=True)
    requested_at = Column(DateTime, default=_now)
    decision = Column(String(10), nullable=True)     # grant|deny (null = pending)
    decided_by = Column(String(120), nullable=True)
    decided_at = Column(DateTime, nullable=True)
    note = Column(Text, nullable=True)
    event_hash = Column(String(64), nullable=True)  # decision event hash, for the chain


class LeadershipAlertState(Base):
    """What a person did about a leadership alert.

    :func:`app.leadership.alerts` recomputes its alert list from live state on
    every call, which is right for the finding and wrong for the response: an
    alert nobody can dismiss reappears on every poll and trains people to ignore
    the panel. This table stores the *acknowledgement* only -- never the finding
    -- so dismissing an alert can never hide a risk that is still true.

    Keyed by the stable alert id (never by row id), because the whole point is
    that the same condition keeps producing the same id across reloads. The
    payload is hashed into ``finding_hash`` so a changed finding shows up as
    ``stale`` instead of silently inheriting an old acknowledgement.
    """

    __tablename__ = "leadership_alert_states"
    __table_args__ = (
        UniqueConstraint("alert_id", name="uq_leadership_alert_states_alert_id"),
    )

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String(200), nullable=False, index=True)
    finding_hash = Column(String(64), nullable=True, index=True)
    status = Column(String(20), nullable=False, default="acknowledged")  # acknowledged|snoozed|resolved
    acknowledged_by = Column(String(200), nullable=True)
    acknowledged_at = Column(DateTime, default=_now)
    note = Column(Text, nullable=True)
    snoozed_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=_now)
    updated_at = Column(DateTime, default=_now, onupdate=_now)
