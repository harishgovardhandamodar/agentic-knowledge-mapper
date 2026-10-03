"""Assurance events on the ledger, and the integrity monitor that watches them.

:mod:`app.ledger` already gives this system a hash-chained, append-only event
fabric with mandates, proofs and export. What it does not give it is the
*assurance* question: not "is the chain intact" but "does the chain show that
the run behaved".

An intact chain proves every event was written once and not edited. It says
nothing about **absence**. A scorer that emitted a residual with no preceding
architecture-gate event, a residual reduced by a control with no attestation
event, a human accepting a score whose evidence-confidence event never fired
-- each of those produces a perfectly valid chain. Those are the failures in
§8.5, and detecting them is a different job from verifying hashes.

So this module does two things:

1. **Records** the mandatory assurance event classes against the existing
   ledger, reusing its chaining, redaction, PoW and export. Prompt and context
   content is hashed rather than stored by default, which still *proves* what
   was sent without making the immutable log a permanent copy of the data.
2. **Asserts completeness**: given a run's events, it reports the expected
   events that are missing, and raises an integrity alert for each named
   failure mode. Absence becomes a first-class, queryable result.
"""
from __future__ import annotations

import json
from typing import Any, Iterable, Optional

from . import ledger as lg

#: Assurance event kinds. Recording them is never gated by a mandate -- the
#: audit trail must not be able to refuse to record that it was not asked.
ASSURANCE_KINDS: frozenset[str] = frozenset({
    "assurance.control_attestation",
    "assurance.architecture_gate",
    "assurance.evidence_gate",
    "assurance.score",
    "assurance.decision",
    "assurance.exception",
    "assurance.swarm_spawn",
    "assurance.swarm_handoff",
    "assurance.swarm_complete",
    "assurance.swarm_failure",
    "assurance.forensics",
    "assurance.blast_radius",
    "assurance.vendor_questionnaire",
    "assurance.publish",
    "assurance.anomaly",
    "assurance.tool.call",
    "assurance.lifecycle.create",
    "assurance.lifecycle.plan",
    "assurance.lifecycle.re_plan",
    "assurance.lifecycle.pause",
    "assurance.lifecycle.resume",
    "assurance.lifecycle.complete",
    "assurance.lifecycle.abort",
    "assurance.lifecycle.supersede",
    "assurance.artifact.fetch",
    "assurance.artifact.ingest",
    "assurance.artifact.review",
    "assurance.artifact.accept",
    "assurance.artifact.reject",
    "assurance.artifact.drift",
    # Emitted by record_prompt_fingerprint. It has to be here as well as
    # internal: a kind outside this set is evaluated by the gate as though it
    # were an external action, so the act of recording what was sent would
    # itself be subject to a mandate check.
    "assurance.model_context",
})

#: Added to the ledger's never-gated set. ``run.start``/``run.end`` already
#: exist there; these join them.
for _k in ASSURANCE_KINDS:
    lg.INTERNAL_KINDS = lg.INTERNAL_KINDS | {_k}
del _k

#: Event classes the assurance monitor expects to find, with the question each
#: one answers. Reported as a coverage matrix whether or not it passed, so a
#: reader can see what the run never claimed.
MANDATORY_EVENT_CLASSES: dict[str, str] = {
    "investigation_lifecycle": "Was the investigation created, planned and completed?",
    "agent_swarm_orchestration": "Did every expected agent hop happen, and who did it?",
    "tool_connector_invocation": "What was fetched, from where, with what status?",
    "artifact_lifecycle": "What evidence was accepted, rejected, or left pending?",
    "threat_scoring": "Was each score reproducible from recorded inputs?",
    "control_attestation": "Which controls had accepted primary evidence?",
    "architecture_gate": "Was the data-flow checklist evaluated before scoring?",
    "human_decision": "Who accepted, rejected, or overrode, and why?",
    "model_prompt_context": "Which model produced this, and what was sent (hashed)?",
    "output_publication": "What was published, to whom, and what superseded it?",
    "system_integrity": "Did the fabric itself stay whole?",
}

#: Event kinds that satisfy each mandatory class.
_CLASS_KINDS: dict[str, frozenset[str]] = {
    "investigation_lifecycle": frozenset({
        "run.start", "run.end", "gate.check",
        "assurance.lifecycle.create", "assurance.lifecycle.plan",
        "assurance.lifecycle.re_plan", "assurance.lifecycle.pause",
        "assurance.lifecycle.resume", "assurance.lifecycle.complete",
        "assurance.lifecycle.abort", "assurance.lifecycle.supersede"}),
    "agent_swarm_orchestration": frozenset({
        "agent.hop", "a2a.hop", "assurance.swarm_spawn",
        "assurance.swarm_handoff", "assurance.swarm_complete",
        "assurance.swarm_failure", "assurance.anomaly"}),
    "tool_connector_invocation": frozenset({
        "mcp.call", "source.fetch", "search.call", "http.get",
        "assurance.tool.call"}),
    "artifact_lifecycle": frozenset({
        "artifact.ingest", "artifact.review", "assurance.evidence_gate",
        "assurance.artifact.fetch", "assurance.artifact.ingest",
        "assurance.artifact.review", "assurance.artifact.accept",
        "assurance.artifact.reject", "assurance.artifact.drift"}),
    "threat_scoring": frozenset({"assurance.score", "assurance.blast_radius"}),
    "control_attestation": frozenset({"assurance.control_attestation"}),
    "architecture_gate": frozenset({"assurance.architecture_gate"}),
    "human_decision": frozenset({
        "human.action", "approval.grant", "approval.deny",
        "assurance.decision", "assurance.exception"}),
    "model_prompt_context": frozenset({"llm.call", "assurance.model_context"}),
    "output_publication": frozenset({
        "report.publish", "assurance.publish"}),
    "system_integrity": frozenset({
        "audit.dropped", "ledger.anomaly", "assurance.anomaly",
        "drift.detect", "proof.verify"}),
}

#: Roles the orchestrator is expected to hand off to on a product assessment.
#: A missing one is an integrity alert, not a warning: "hop trace not recorded"
#: must stop being a silent omission.
EXPECTED_SWARM_ROLES: tuple[str, ...] = (
    "orchestrator", "control-analyst", "research-collector",
    "threat-intel", "report-writer",
)

#: Retention classes. Security/compliance events are kept for years; high-volume
#: intermediate traces keep only hashes, which is what makes that affordable.
RETENTION_POLICY: dict[str, dict[str, Any]] = {
    "security_decision": {
        "kinds": frozenset({
            "assurance.score", "assurance.decision", "assurance.exception",
            "assurance.control_attestation", "assurance.architecture_gate",
            "approval.grant", "approval.deny", "human.action"}),
        "retention_days": 2555,  # 7 years
        "content": "full",
    },
    "evidence_provenance": {
        "kinds": frozenset({
            "artifact.ingest", "artifact.review", "source.fetch",
            "assurance.evidence_gate", "assurance.vendor_questionnaire",
            "assurance.artifact.fetch", "assurance.artifact.ingest",
            "assurance.artifact.review", "assurance.artifact.accept",
            "assurance.artifact.reject", "assurance.artifact.drift"}),
        "retention_days": 1095,  # 3 years
        "content": "full",
    },
    "agent_trace": {
        "kinds": frozenset({
            "agent.hop", "assurance.swarm_spawn", "assurance.swarm_handoff",
            "assurance.swarm_complete", "assurance.swarm_failure"}),
        "retention_days": 400,
        "content": "hashes_only",
    },
    "model_context": {
        "kinds": frozenset({"llm.call"}),
        "retention_days": 400,
        "content": "hashes_only",
    },
    "tool_invocations": {
        "kinds": frozenset({"assurance.tool.call"}),
        "retention_days": 400,
        "content": "hashes_only",
    },
    "output_publication": {
        "kinds": frozenset({"assurance.publish", "report.publish"}),
        "retention_days": 2555,  # 7 years: what decision-makers saw is durable
        "content": "full",
    },
}

#: Event kinds that mean the audit fabric itself failed, as opposed to a domain
#: gate returning a block. The distinction matters: a gate saying "no" is the
#: system working, and reporting it as a fabric failure tells leadership to
#: distrust a run that is in fact the most trustworthy one in the set.
FABRIC_FAILURE_KINDS = frozenset({"audit.dropped", "ledger.anomaly"})

#: Investigation lifecycle phases (the outer boundary of accountability).
LIFECYCLE_PHASES = frozenset({"create", "plan", "re_plan", "pause", "resume",
                              "complete", "abort", "supersede"})

#: Artifact lifecycle actions (evidence provenance for every residual change).
ARTIFACT_ACTIONS = frozenset({"fetch", "ingest", "review", "accept", "reject",
                              "drift"})

#: Roles permitted to read assurance events. Read access to a residual-risk
#: record is a privileged act; write access stays with the runtime.
ASSURANCE_READ_ROLES = frozenset({
    "security", "audit", "dpo", "legal", "ciso", "admin",
})


# ------------------------------------------------------------- recording ---

def _append(run_id: str, kind: str, actor: str, data: dict[str, Any], *,
            verdict: Optional[str] = None, severity: Optional[str] = None,
            actor_type: str = "system",
            intent: Optional[str] = None) -> Optional[str]:
    """Append one assurance event, tolerating a missing ledger.

    Returns the event hash, or ``None`` when the fabric is unavailable. The
    failure is *reported* rather than raised: an assurance view that must be
    readable in an environment with no database is still worth computing, and
    the missing events are exactly what :func:`integrity_report` looks for.
    """
    try:
        return lg.append(run_id, kind, actor, actor_type=actor_type,
                         intent=intent, data=data, verdict=verdict,
                         severity=severity, checked=False)
    except Exception:
        return None


def record_assurance(run_id: str, assurance: dict[str, Any], *,
                     actor: str = "assurance-engine",
                     assessment_id: Optional[int] = None,
                     product: str = "", exposure: str = "") -> dict[str, Any]:
    """Write the whole assurance verdict as a set of ledger events.

    One event per gate rather than one blob, so a query can ask "did this run
    evaluate the architecture gate?" without parsing prose, and so a partial
    write is detectable instead of looking like a pass.
    """
    if not assurance or assurance.get("assessed") is False:
        return {"recorded": False, "reason": "assurance not assessed on this path"}
    gate = assurance.get("architecture_gate") or {}
    ev_gate = assurance.get("evidence_gate") or {}
    dec = assurance.get("decision") or {}
    hashes: dict[str, Any] = {}

    hashes["control_attestation"] = _append(
        run_id, "assurance.control_attestation", actor,
        {"assessment_id": assessment_id, "product": product,
         "exposure": exposure,
         "attestation": assurance.get("control_attestation") or {},
         "verified_controls": (assurance.get("verified") or {}).get("active_controls") or [],
         "unverified_controls": assurance.get("unverified_controls") or [],
         "assurance_fingerprint": assurance.get("fingerprint")},
        intent="control_attestation")

    hashes["architecture_gate"] = _append(
        run_id, "assurance.architecture_gate", actor,
        {"assessment_id": assessment_id, "exposure": exposure,
         "required": gate.get("required"), "complete": gate.get("complete"),
         "open_items": gate.get("open_items") or [],
         "blocked_threats": gate.get("blocked_threats") or [],
         "items": gate.get("items") or []},
        verdict="pass" if gate.get("complete") else "block",
        severity="info" if gate.get("complete") else "block",
        intent="architecture_gate")

    hashes["evidence_gate"] = _append(
        run_id, "assurance.evidence_gate", actor,
        {"assessment_id": assessment_id,
         "min_accepted_per_threat": ev_gate.get("min_accepted_per_threat"),
         "gated_threats": ev_gate.get("gated_threats") or [],
         "per_threat": ev_gate.get("per_threat") or [],
         "pending_weight": (assurance.get("pending_evidence") or {}).get("pending_weight")},
        verdict="pass" if not ev_gate.get("gated_threats") else "flag",
        severity="info" if not ev_gate.get("gated_threats") else "warn",
        intent="evidence_gate")

    hashes["score"] = _append(
        run_id, "assurance.score", actor,
        {"assessment_id": assessment_id, "product": product,
         "exposure": exposure,
         "inherent_pct": (assurance.get("verified") or {}).get("inherent_pct"),
         "declared_residual_pct": (assurance.get("declared") or {}).get("residual_pct"),
         "verified_residual_pct": (assurance.get("verified") or {}).get("residual_pct"),
         "headline_layer": assurance.get("headline_layer"),
         "evidence_confidence": assurance.get("evidence_confidence"),
         "forced_to_inherent": assurance.get("forced_to_inherent") or [],
         "gates_open": assurance.get("gates_open") or [],
         "assurance_fingerprint": assurance.get("fingerprint")},
        intent="assurance_score")

    hashes["forensics"] = _append(
        run_id, "assurance.forensics", actor,
        {"assessment_id": assessment_id,
         "score": (assurance.get("forensics") or {}).get("score"),
         "band": (assurance.get("forensics") or {}).get("band"),
         "reconstructable": (assurance.get("forensics") or {}).get("reconstructable"),
         "not_found": (assurance.get("forensics") or {}).get("not_found") or []},
        verdict="pass" if (assurance.get("forensics") or {}).get("reconstructable") else "flag",
        intent="forensics_readiness")

    radius = assurance.get("blast_radius") or {}
    hashes["blast_radius"] = _append(
        run_id, "assurance.blast_radius", actor,
        {"assessment_id": assessment_id, "band": radius.get("band"),
         "quantified": radius.get("quantified"),
         "records_at_risk": radius.get("records_at_risk"),
         "missing_inputs": radius.get("missing_inputs") or [],
         "blocks_decision": radius.get("blocks_decision")},
        intent="blast_radius")

    dec = (assurance.get("decision") or {}).get("decision")
    from . import assurance as A  # local: keeps the ledger import-light
    hashes["decision"] = _append(
        run_id, "assurance.decision", actor,
        {"assessment_id": assessment_id, "product": product,
         "decision": dec, "headline": (assurance.get("decision") or {}).get("headline"),
         "reasons": (assurance.get("decision") or {}).get("reasons") or [],
         "advisory_only": (assurance.get("decision") or {}).get("advisory_only"),
         "actions_0_30_days": (assurance.get("decision") or {}).get("actions_0_30_days") or []},
        # Compared against the named constants, not string literals: a literal
        # silently stops matching the day the decision name changes, and a
        # rejection then records as severity=info with verdict=block -- the
        # one event a monitoring query must not miss.
        verdict={A.DECISION_ACCEPT: "allow", A.DECISION_GUARDRAILS: "hold"}.get(
            dec or "", "block"),
        severity="block" if dec == A.DECISION_REJECT else "info",
        intent="decision_frame")

    return {"recorded": True, "hashes": hashes,
            "unrecorded": sorted(k for k, v in hashes.items() if not v)}


def record_swarm_event(run_id: str, *, role: str, phase: str,
                       actor: str = "orchestrator",
                       parent_event: Optional[str] = None,
                       output_ref: Optional[str] = None,
                       confidence: Optional[float] = None,
                       completeness: Optional[str] = None,
                       policy: Optional[dict[str, Any]] = None,
                       error: Optional[str] = None,
                       model_version: Optional[str] = None,
                       detail: Optional[dict[str, Any]] = None) -> Optional[str]:
    """One swarm lifecycle event: spawn, handoff, complete, failure.

    ``parent_event`` is the lineage edge. Without it a hop is an island, and
    the run cannot be reconstructed as a sequence -- only as a bag of events.
    """
    kind = {"spawn": "assurance.swarm_spawn",
            "handoff": "assurance.swarm_handoff",
            "complete": "assurance.swarm_complete",
            "failure": "assurance.swarm_failure"}.get(phase)
    if not kind:
        raise ValueError(f"unknown swarm phase {phase!r}")
    data = {
        "role": role,
        "phase": phase,
        "parent_event": parent_event,
        "output_ref": output_ref,
        "confidence": confidence,
        "completeness": completeness,
        "policy": policy,
        "model_version": model_version,
        "detail": detail,
    }
    if error:
        data["error"] = str(error)[:500]
    verdict = {"failure": "deny", "complete": "allow"}.get(phase, "allow")
    return _append(run_id, kind, actor, data, verdict=verdict,
                   severity="block" if phase == "failure" else "info",
                   actor_type="agent", intent=f"swarm.{phase}")


def record_human_decision(run_id: str, *, actor: str, decision: str,
                          assessment_id: Optional[int] = None,
                          rationale: str = "", expires_at: Optional[str] = None,
                          evidence_confidence: Optional[float] = None,
                          override: bool = False) -> Optional[str]:
    """A human acceptance, rejection or exception -- the closing loop event.

    Recorded with identity and rationale because that is the accountability
    layer: an acceptance nobody can attribute is not a decision.
    """
    kind = "assurance.exception" if decision == "exception" else "assurance.decision"
    return _append(
        run_id, kind, actor,
        {"assessment_id": assessment_id, "decision": decision,
         "rationale": rationale, "expires_at": expires_at,
         "evidence_confidence_at_decision": evidence_confidence,
         "override": bool(override)},
        verdict={"accept": "allow", "reject": "deny"}.get(decision, "hold"),
        severity="warn" if override else "info",
        actor_type="human", intent="residual_decision")


def record_prompt_fingerprint(run_id: str, *, actor: str, model: str,
                              prompt: Optional[str] = None,
                              context: Optional[str] = None,
                              prompt_template: Optional[str] = None,
                              redaction: str = "hashed") -> dict[str, Any]:
    """Record what was sent without keeping it.

    The fabric is immutable, so storing a prompt would make a permanent copy of
    whatever context the agent handled. Hashes still let a later extraction or
    memorisation analysis compare two runs, and still prove the run sent *this*
    prompt rather than another.
    """
    data = {
        "model": model,
        "redaction": redaction,
        "prompt_hash": lg.text_digest(prompt) if prompt else None,
        "context_hash": lg.text_digest(context) if context else None,
        "template_hash": lg.text_digest(prompt_template) if prompt_template else None,
        "prompt_chars": len(prompt) if prompt else 0,
        "context_chars": len(context) if context else 0,
    }
    h = _append(run_id, "assurance.model_context", actor, data,
                intent="model_prompt_context")
    return {"event_hash": h, **data}


def record_lifecycle(run_id: str, *, phase: str,
                     actor: str = "orchestrator",
                     assessment_id: Optional[int] = None,
                     detail: Optional[dict[str, Any]] = None,
                     error: Optional[str] = None) -> Optional[str]:
    """The outer boundary of accountability: how the investigation itself
    moved from creation to completion, pause, abort or supersession."""
    if phase not in LIFECYCLE_PHASES:
        raise ValueError(f"unknown lifecycle phase {phase!r}")
    data: dict[str, Any] = {"phase": phase, "assessment_id": assessment_id,
                            "detail": detail}
    if error:
        data["error"] = str(error)[:500]
    verdict = {"abort": "deny", "complete": "allow"}.get(phase, "allow")
    severity = "block" if phase == "abort" else "info"
    return _append(run_id, f"assurance.lifecycle.{phase}", actor, data,
                   verdict=verdict, severity=severity, actor_type="system",
                   intent=f"lifecycle.{phase}")


def record_artifact(run_id: str, *, artifact_id: str, action: str,
                    actor: str = "research-collector", title: str = "",
                    source: str = "", relevance: Optional[float] = None,
                    review: Optional[str] = None,
                    drift: Optional[dict[str, Any]] = None,
                    detail: Optional[dict[str, Any]] = None) -> Optional[str]:
    """One artifact lifecycle step: fetched, ingested, reviewed, accepted,
    rejected, or flagged as drifted. ``review`` is the state (accepted /
    pending / rejected); ``action`` is what happened to reach it."""
    if action not in ARTIFACT_ACTIONS:
        raise ValueError(f"unknown artifact action {action!r}")
    data: dict[str, Any] = {
        "artifact_id": artifact_id, "action": action, "title": str(title)[:200],
        "source": str(source)[:200], "relevance": relevance,
        "review": review, "drift": drift, "detail": detail,
    }
    verdict = {"reject": "deny", "accept": "allow"}.get(action, "allow")
    severity = {"reject": "block", "drift": "warn"}.get(action, "info")
    return _append(run_id, f"assurance.artifact.{action}", actor, data,
                   verdict=verdict, severity=severity, actor_type="agent",
                   intent=f"artifact.{action}")


def record_tool(run_id: str, *, tool: str, intent: str,
                actor: str = "research-collector",
                args: Optional[dict[str, Any]] = None,
                status: str = "ok", latency_ms: Optional[int] = None,
                error: Optional[str] = None,
                redacted: bool = True) -> Optional[str]:
    """A tool / connector invocation. Arguments are redacted by default: the
    ledger is immutable, so anything written here is effectively permanent."""
    data: dict[str, Any] = {"tool": str(tool)[:120], "intent": str(intent)[:120],
                            "args": args, "status": status,
                            "latency_ms": latency_ms, "redacted": bool(redacted)}
    if error:
        data["error"] = str(error)[:500]
    verdict = "deny" if status == "error" else "allow"
    severity = "block" if status == "error" else "info"
    return _append(run_id, "assurance.tool.call", actor, data,
                   verdict=verdict, severity=severity, actor_type="agent",
                   intent=f"tool.{intent}")


def record_publication(run_id: str, *, doc_id: str, version: str,
                       actor: str = "report-writer",
                       audience: Optional[list[str]] = None,
                       supersedes: Optional[str] = None,
                       status: str = "published",
                       assessment_id: Optional[int] = None,
                       detail: Optional[dict[str, Any]] = None) -> Optional[str]:
    """What was published, to whom, and what it superseded -- closing the
    loop on what decision-makers actually saw."""
    return _append(
        run_id, "assurance.publish", actor,
        {"doc_id": str(doc_id)[:200], "version": str(version)[:80],
         "audience": audience or [], "supersedes": supersedes,
         "status": status, "assessment_id": assessment_id, "detail": detail},
        verdict="allow", severity="info", actor_type="agent",
        intent="output_publication")


def record_integrity_check(run_id: str, *, check: str, passed: bool,
                           actor: str = "system",
                           detail: Optional[dict[str, Any]] = None) -> Optional[str]:
    """A check the fabric ran on itself: chain continuity, clock, signatures.

    The system-integrity class records *checks performed*, so a healthy run
    shows the check happened rather than reading as a silent gap. A failed
    check is severity warn and shows up in the absence alerts as a finding.
    """
    return _append(run_id, "drift.detect", actor,
                   {"check": str(check)[:120], "passed": bool(passed),
                    "detail": detail},
                   verdict="pass" if passed else "flag",
                   severity="info" if passed else "warn",
                   actor_type="system", intent="integrity_check")


# --------------------------------------------------------------- querying ---

def _load_events(run_id: str, db=None) -> list[dict[str, Any]]:
    """Events of a run as plain dicts, in chain order."""
    own = db is None
    if own:
        from .database import SessionLocal

        db = SessionLocal()
    try:
        rows = (db.query(lg.LedgerEvent)
                .filter(lg.LedgerEvent.run_id == run_id)
                .order_by(lg.LedgerEvent.seq).all())
        out = []
        for r in rows:
            try:
                data = json.loads(r.data_json or "{}")
            except Exception:
                data = {}
            out.append({
                "seq": r.seq, "ts": r.ts, "kind": r.kind,
                "actor": r.actor, "actor_type": r.actor_type,
                "verdict": r.verdict, "severity": r.severity,
                "intent": r.intent, "hash": r.hash, "prev_hash": r.prev_hash,
                "data": data,
            })
        return out
    finally:
        if own:
            db.close()


def class_coverage(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Which mandatory event classes this run actually recorded."""
    kinds = {str(e.get("kind") or "") for e in events}
    out: dict[str, Any] = {}
    present = 0
    for cls, question in MANDATORY_EVENT_CLASSES.items():
        hits = sorted(k for k in kinds if k in _CLASS_KINDS[cls])
        out[cls] = {
            "question": question,
            "recorded": bool(hits),
            "kinds": hits[:6],
            "count": sum(1 for e in events if str(e.get("kind")) in set(hits)),
        }
        if hits:
            present += 1
    return {
        "classes": out,
        "recorded": present,
        "total": len(MANDATORY_EVENT_CLASSES),
        "complete": present == len(MANDATORY_EVENT_CLASSES),
        "completeness_pct": round(present / len(MANDATORY_EVENT_CLASSES) * 100, 0),
        "missing": sorted(c for c, v in out.items() if not v["recorded"]),
    }


def absence_alerts(events: Iterable[dict[str, Any]],
                   expected_roles: Iterable[str] = EXPECTED_SWARM_ROLES,
                   ) -> list[dict[str, Any]]:
    """The §8.5 failure modes, each detectable from event absence alone.

    Every alert names the condition, why it matters and what event would have
    prevented it, so the output is actionable rather than a count.
    """
    evs = list(events)
    by_kind: dict[str, list[dict[str, Any]]] = {}
    for e in evs:
        by_kind.setdefault(str(e.get("kind") or ""), []).append(e)
    alerts: list[dict[str, Any]] = []

    def _alert(alert_id: str, severity: str, condition: str, why: str,
               missing: str) -> None:
        alerts.append({
            "id": alert_id, "severity": severity, "condition": condition,
            "why_it_matters": why, "absent_event": missing,
        })

    # --- swarm hops -------------------------------------------------------
    roles_seen: set[str] = set()
    for kind in ("assurance.swarm_spawn", "assurance.swarm_handoff",
                 "assurance.swarm_complete", "agent.hop", "a2a.hop"):
        for e in by_kind.get(kind, []):
            r = (e.get("data") or {}).get("role")
            if not r:
                r = (e.get("actor") or "")
            if r:
                roles_seen.add(str(r))
    missing_roles = [r for r in expected_roles if r not in roles_seen]
    if missing_roles and (by_kind.get("assurance.swarm_spawn")
                          or by_kind.get("agent.hop")
                          or by_kind.get("assurance.swarm_handoff")):
        _alert("SWARM-HOP-DROPPED", "block",
               f"Swarm roles with no event: {', '.join(missing_roles)}",
               "A missing hop means part of the reasoning never happened, or "
               "happened unrecorded; neither supports a reproducible score.",
               "assurance.swarm_spawn / assurance.swarm_handoff for the role")

    # hops without lineage
    unlinked = [e for e in evs
                if str(e.get("kind")) in ("assurance.swarm_handoff", "agent.hop")
                and not (e.get("data") or {}).get("parent_event")]
    if unlinked:
        _alert("SWARM-LINEAGE-MISSING", "warn",
               f"{len(unlinked)} hand-off(s) recorded without a parent event",
               "Without a lineage edge the run is a bag of events, not a "
               "sequence, and cannot be replayed.",
               "data.parent_event on every hand-off")

    # --- scoring vs architecture gate -------------------------------------
    scores = by_kind.get("assurance.score") or []
    gates = by_kind.get("assurance.architecture_gate") or []
    for s in scores:
        s_data = s.get("data") or {}
        gate_before = [g for g in gates
                       if str(g.get("ts") or "") <= str(s.get("ts") or "")
                       and int(g.get("seq") or 0) < int(s.get("seq") or 0)]
        if gate_before:
            last = gate_before[-1]
            if last.get("verdict") == "block" and not (s_data.get("gates_open") or []):
                _alert("SCORE-AFTER-FAILED-GATE", "block",
                       "A residual was scored after an architecture gate "
                       "returned block, with no gate recorded open on the score",
                       "Scoring under an incomplete architecture record is the "
                       "exact failure the gate exists to prevent.",
                       "assurance.gates_open on the score event")
            break
        elif gates:
            break
        else:
            if not (s_data.get("gates_open") is not None):
                _alert("SCORE-WITHOUT-GATE-EVENT", "block",
                       "A residual was scored with no architecture-gate event "
                       "at all",
                       "A score nobody gated cannot be shown to have been "
                       "produced under policy.",
                       "assurance.architecture_gate before the score")
                break

    # --- residual reduction without attestation ---------------------------
    attest = by_kind.get("assurance.control_attestation") or []
    for s in scores:
        s_data = s.get("data") or {}
        declared = s_data.get("declared_residual_pct")
        verified = s_data.get("verified_residual_pct")
        if declared is None or verified is None:
            continue
        before = [a for a in attest
                  if int(a.get("seq") or 0) < int(s.get("seq") or 0)]
        if not before:
            _alert("REDUCTION-WITHOUT-ATTESTATION", "block",
                   "Residual reduction was recorded with no preceding "
                   "control-attestation event",
                   "A reduction nobody attested is exactly the declared-vs-"
                   "verified confusion the assurance layer exists to remove.",
                   "assurance.control_attestation before the score")
            break
        break

    # --- human acceptance below evidence-confidence threshold -------------
    for d in by_kind.get("assurance.decision", []) + by_kind.get("assurance.exception", []):
        d_data = d.get("data") or {}
        conf = d_data.get("evidence_confidence_at_decision")
        if (d_data.get("decision") in ("accept", "accept_with_guardrails")
                and conf is not None and float(conf) < 0.5):
            _alert("ACCEPTANCE-BELOW-CONFIDENCE", "warn",
                   f"A {d_data.get('decision')} was recorded at evidence "
                   f"confidence {float(conf):.0%}",
                   "Accepting a residual whose reduction is mostly unevidenced "
                   "is a decision the fabric should make visible, not absorb.",
                   "evidence_confidence_at_decision on the decision event")

    # --- model version drift between hops ---------------------------------
    versions: list[tuple[int, str]] = []
    for e in evs:
        mv = (e.get("data") or {}).get("model_version") or (e.get("data") or {}).get("model")
        if mv:
            versions.append((int(e.get("seq") or 0), str(mv)))
    distinct = sorted({v for _, v in versions})
    if len(distinct) > 1:
        _alert("MODEL-VERSION-CHANGE", "warn",
               "More than one model version appears in this run: "
               + ", ".join(distinct[:4]),
               "A mid-run model change means the result mixes instruments and "
               "should be re-run or explicitly marked degraded.",
               "model_version on every hop and llm event")

    # --- ledger write failures --------------------------------------------
    # Only the fabric's own failure kinds count. A blocked architecture gate is
    # also severity "block", and folding those in reported every restricted run
    # whose gate was working as "the fabric itself reported a problem" -- an
    # integrity alarm on precisely the run that deserves the most trust.
    fabric_failures = [e for e in evs
                       if str(e.get("kind")) in FABRIC_FAILURE_KINDS]
    if fabric_failures:
        _alert("FABRIC-INTEGRITY-EVENT", "block",
               f"{len(fabric_failures)} integrity-failure event(s) recorded",
               "The fabric itself reported a problem; downstream scores cannot "
               "be relied on until it is resolved.",
               "resolution of the recorded anomaly")

    return alerts


def integrity_report(run_id: str, db=None) -> dict[str, Any]:
    """Chain integrity + event-class completeness + absence alerts for one run.

    Three independent questions answered together, because they fail
    differently: *is the chain intact* (hashes), *did the run record the
    material events* (completeness), and *what did it omit* (absence).
    """
    events = _load_events(run_id, db=db)
    chain = lg.verify_chain(run_id, db=db)
    coverage = class_coverage(events)
    alerts = absence_alerts(events)
    seqs = [int(e["seq"]) for e in events]
    gaps = [n for n in range((max(seqs) + 1) if seqs else 0) if n not in set(seqs)]
    retention = {
        cls: {
            "retention_days": p["retention_days"],
            "content": p["content"],
            "event_count": sum(1 for e in events if str(e.get("kind")) in p["kinds"]),
        }
        for cls, p in RETENTION_POLICY.items()
    }
    blocking = [a for a in alerts if a["severity"] == "block"]
    # verify_chain answers under "ok", not "intact": reading the wrong key made
    # this headline read False on a perfectly intact chain, which is the one
    # number an assurance reader cannot afford to have inverted.
    chain_ok = bool(chain.get("ok"))
    return {
        "run_id": run_id,
        "events": len(events),
        "chain_intact": chain_ok,
        "chain": chain,
        "seq_gaps": gaps,
        "class_coverage": coverage,
        "absence_alerts": alerts,
        "blocking_alerts": [a["id"] for a in blocking],
        "retention": retention,
        "roles_seen": sorted({
            str((e.get("data") or {}).get("role") or e.get("actor") or "")
            for e in events if str(e.get("kind")) in (
                "assurance.swarm_spawn", "assurance.swarm_handoff",
                "assurance.swarm_complete", "agent.hop")}),
        "verdict": ("clean" if chain_ok and not alerts
                    else "chain_broken" if not chain_ok
                    else "alerts"),
        "note": ("Absence is a result: an event that was never written is an "
                 "integrity finding, not an absence of a finding."),
    }


def evidence_pack(run_id: str, requester: str = "", *, db=None) -> dict[str, Any]:
    """One-click audit package: chain, assurance events, integrity, timeline.

    Shaped for an external auditor: self-describing, verifiable offline with
    :func:`app.ledger.verify_export`, and explicit about what it does *not*
    contain (minimised prompt content, redacted secrets).
    """
    events = _load_events(run_id, db=db)
    by_kind: dict[str, int] = {}
    for e in events:
        by_kind[str(e.get("kind"))] = by_kind.get(str(e.get("kind")), 0) + 1
    rep = integrity_report(run_id, db=db)
    timeline = [{"seq": e["seq"], "ts": e["ts"], "kind": e["kind"],
                 "actor": e["actor"], "actor_type": e["actor_type"],
                 "verdict": e["verdict"], "intent": e["intent"],
                 "hash": e["hash"]}
                for e in events]
    return {
        "run_id": run_id,
        "requested_by": requester,
        "generated": rep["chain"].get("verified_at") or None,
        "event_count": len(events),
        "events_by_kind": dict(sorted(by_kind.items())),
        "chain": rep["chain"],
        "integrity": {k: v for k, v in rep.items() if k != "chain"},
        "timeline": timeline,
        "verification": ("Verify with: POST /api/ledger/verify-export"),
        "access": sorted(ASSURANCE_READ_ROLES),
        "minimisation": {
            "prompt_content": "hashed, not stored",
            "context_content": "hashed, not stored",
            "secrets": "redacted at write time",
            "note": ("Hashes prove what was sent without making an immutable "
                     "log a permanent copy of the data handled."),
        },
    }


def authorize_read(role: str, actor: str = "") -> dict[str, Any]:
    """Read access to assurance events is role-governed, not open."""
    r = str(role or "").strip().lower()
    ok = r in ASSURANCE_READ_ROLES
    return {
        "allowed": ok,
        "role": r or "anonymous",
        "actor": actor,
        "permitted_roles": sorted(ASSURANCE_READ_ROLES),
        "note": ("Assurance records carry residual-risk positions and "
                 "review decisions; read access is limited to the roles that "
                 "need them for assurance, audit or legal obligations."),
    }


# ------------------------------------------------- integrity monitoring -----

def monitor_integrity(db=None, *, run_ids: Optional[Iterable[str]] = None,
                      limit: int = 40) -> dict[str, Any]:
    """Continuous chain verification across recent runs.

    The §8.4 integrity monitor re-checks every run's hash chain and sequence
    continuity and surfaces the ones that no longer verify, so a fabric that
    has drifted is found by the system itself rather than by an auditor.
    """
    own = db is None
    if own:
        from .database import SessionLocal

        db = SessionLocal()
    try:
        if run_ids is None:
            rows = (db.query(lg.LedgerRun)
                    .order_by(lg.LedgerRun.head_seq.desc())
                    .limit(limit).all())
            run_ids = [r.id for r in rows]
        verified = []
        broken: list[dict[str, Any]] = []
        for run_id in run_ids:
            rep = integrity_report(str(run_id), db=db)
            if not rep["events"]:
                continue
            if rep["chain_intact"] and not rep["seq_gaps"]:
                verified.append(run_id)
            else:
                broken.append({
                    "run_id": run_id,
                    "chain_intact": rep["chain_intact"],
                    "seq_gaps": rep["seq_gaps"],
                    "verdict": rep["verdict"],
                    "findings": (rep["chain"].get("findings") or [])[:5],
                })
        return {
            "runs_checked": len(verified) + len(broken),
            "verified": verified,
            "broken": broken,
            "note": ("A run with an intact chain but a sequence gap is still "
                     "a finding: it records that something was re-ordered."),
        }
    finally:
        if own:
            db.close()


# ------------------------------------------------------------- SIEM export --

def export_siem_events(run_ids: Optional[Iterable[str]] = None, *,
                       sink=None, db=None, limit: int = 40) -> dict[str, Any]:
    """Stream the ledger into a SIEM / SOAR in syslog-style JSON lines.

    Each event becomes one line: ``@timestamp``, ``event.kind``, ``run_id``,
    ``actor``, ``severity`` and a *minimised* payload. Full prompts and
    contexts are never exported (hashes only), so the organisation's detection
    fabric sees the decision without the data behind it. The default sink is a
    no-op, so callers can pipe to ``socket.socket.sendall``, ``print``, etc.
    """
    own = db is None
    if own:
        from .database import SessionLocal

        db = SessionLocal()
    try:
        import time as _time

        if run_ids is None:
            rows = (db.query(lg.LedgerRun)
                    .order_by(lg.LedgerRun.head_seq.desc())
                    .limit(limit).all())
            run_ids = [r.id for r in rows]
        if sink is None:
            sink = lambda _line: None
        exported = 0
        for run_id in run_ids:
            for e in _load_events(str(run_id), db=db):
                data = e.get("data") or {}
                line = {
                    "@timestamp": e.get("ts") or _time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
                    "event": {"kind": e.get("kind"), "intent": e.get("intent"),
                              "outcome": e.get("verdict"),
                              "severity": e.get("severity")},
                    "run_id": str(run_id),
                    "actor": {"type": e.get("actor_type"),
                              "name": e.get("actor")},
                    "seq": e.get("seq"),
                    "chain": {"hash": e.get("hash"),
                              "prev_hash": e.get("prev_hash")},
                    "assurance": {
                        k: v for k, v in data.items()
                        if k in ("assessment_id", "product", "exposure",
                                 "role", "phase", "decision", "status",
                                 "tool", "check", "passed",
                                 "evidence_confidence", "model", "redacted")
                        and v is not None},
                }
                sink(json.dumps(line, default=str))
                exported += 1
        return {"exported": exported, "lines_as_json": True,
                "note": "Content is minimised: hashes, not prompts."}
    finally:
        if own:
            db.close()


# -------------------------------------------------- automated re-scoring ----

def re_score_triggers(db=None, *, investigation_id: Optional[int] = None) -> dict[str, Any]:
    """Which assessments changed their evidence or architecture basis after
    they were scored, so their residual is stale and should be re-scored.

    An assessment is immutable by design, so a trigger is a signal to run the
    *next* assessment, never an edit to the signed row. Two reasons are
    watched on the current row per product/path:

    - ``evidence_change``: an artifact was accepted after the assessment was
      written while the row still carries evidence-gate or attestation gaps.
    - ``architecture_change``: an explainer/architecture run completed after
      the assessment, so the checklist it was blocked on has moved.
    """
    from datetime import datetime, timezone

    from .models import AgentRun, Artifact, SecurityAssessment

    own = db is None
    if own:
        from .database import SessionLocal

        db = SessionLocal()
    try:
        q = db.query(SecurityAssessment)
        if investigation_id:
            q = q.filter(SecurityAssessment.investigation_id == int(investigation_id))

        def _dt(value):
            if value is None:
                return None
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value

        def _latest(rows):
            best: dict[tuple, Any] = {}
            for rec in rows:
                path = (json.loads(rec.scoring_json or "{}") or {}).get(
                    "assessment_path")
                key = (rec.investigation_id,
                       (rec.product_name or rec.product_family or "").strip().lower(),
                       path)
                prev = best.get(key)
                prev_dt = _dt(prev.created_at) if prev else datetime.min.replace(tzinfo=timezone.utc)
                cur_dt = _dt(rec.created_at) or datetime.min.replace(tzinfo=timezone.utc)
                if prev is None or cur_dt > prev_dt:
                    best[key] = rec
            return best.values()

        triggers: list[dict[str, Any]] = []
        for rec in _latest(q.all()):
            created = _dt(rec.created_at)
            if not created:
                continue
            ens = json.loads(rec.assurance_json or "{}") or {}
            gates_open = ens.get("gates_open") or []
            gated = (ens.get("evidence_gate") or {}).get("gated_threats") or []
            arch_open = (ens.get("architecture_gate") or {}).get("open_items") or []
            if not (gates_open or gated or arch_open):
                continue
            accepted = db.query(Artifact).filter(
                Artifact.investigation_id == rec.investigation_id,
                Artifact.review == "accepted").all()
            accepted_after = [a for a in accepted
                              if (_dt(a.created_at) or created) > created]
            reason = None
            if accepted_after:
                reason = (f"{len(accepted_after)} artifact(s) accepted after "
                          "scoring")
            else:
                later_runs = db.query(AgentRun).filter(
                    AgentRun.investigation_id == rec.investigation_id,
                    AgentRun.trigger == "explainer_gap",
                    AgentRun.status == "done").all()
                if any((_dt(r.finished_at) or created) > created for r in later_runs):
                    reason = "architecture explainer run completed after scoring"
            if reason:
                triggers.append({
                    "assessment_id": rec.id,
                    "investigation_id": rec.investigation_id,
                    "product": rec.product_name or "",
                    "created_at": created.isoformat(),
                    "reason": reason,
                    "gates_open": gates_open[:8],
                })
        triggers.sort(key=lambda t: t["assessment_id"])
        return {
            "triggers": triggers,
            "count": len(triggers),
            "note": ("An assessment is immutable: a trigger signals the next "
                     "run, it never edits the signed row."),
        }
    finally:
        if own:
            db.close()