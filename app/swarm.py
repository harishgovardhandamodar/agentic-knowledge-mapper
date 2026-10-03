"""Swarm runtime — four swarms over shared MCP tools, A2A bus.

GUI → API → Job queue → Swarm (orchestrators → specialists → MCP) → SQLite/Ledger
Orchestrators delegate via A2A envelopes (task_id = ledger run id); specialists
call MCP tools; deterministic core (risk_scoring, pack math, FTS, KB) is never
reimplemented in prompts.

On top of the routing above this module carries the *governance* layer: role
contracts, a policy enforcement point the scorer must pass, and the health
metrics leadership reads. The premise is that a multi-agent system which
underwrites residual risk has to be able to say which roles ran, what each was
required to produce, and what happened when one of them failed. "It produced
a number" is not a topology; a graph of contracted roles with an enforced
pre-scoring gate is.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from . import agents as A

# Swarm definitions: long-lived agent types, many short-lived tasks
SWARMS = {
    "knowledge": ["collector-orchestrator", "research-collector", "explainer", "drift-judge"],
    "assessment": ["security-orchestrator", "model-eval-orchestrator", "control-analyst",
                   "model-mitigation-analyst", "threat-intel", "model-adv-intel",
                   "provider-posture", "report-writer",
                   # model-assessment workflows (agents.py run_model_a2a_workflow,
                   # run_model_adversarial_a2a_workflow, run_hypothesis_a2a_workflow)
                   "model-orchestrator", "adversary-orchestrator",
                   "model-profiler", "model-internals", "model-privacy",
                   "model-reporter", "model-adversary", "misuse-scout",
                   "model-adoption-analyst", "hypothesis-analyst",
                   "hypothesis-verifier", "hypothesis-reporter",
                   "mitigation-advisor", "experiment-planner"],
    "risk": ["risk-orchestrator", "risk-intake", "risk-triage", "risk-treatment", "risk-monitor", "risk-governance", "risk-reporter"],
    "portfolio": ["manager-orchestrator", "synthesizer"],
}

# Shared tools across swarms
SHARED_TOOLS = ["research-collector", "profiler", "mcp-search"]


def swarm_for_agent(agent: str) -> str | None:
    for swarm, agents in SWARMS.items():
        if agent in agents:
            return swarm
    return None


def mcp_for_intent(intent: str) -> str | None:
    mapping = {
        "collect_research": "mcp-search",
        "map_attacks": "mcp-catalog",
        "ingest_findings": "mcp-register",
        "score_priority": "mcp-score",
        "propose_treatment": "mcp-score",
        "detect_stale": "mcp-register",
        "draft_brief": "mcp-brief",
        "search": "mcp-index",
        "suggest": "mcp-index",
        "upsert_risk": "mcp-register",
        "score_risk": "mcp-score",
    }
    return mapping.get(intent)


# --------------------------------------------------------------- contracts ---
# Every role declares what it must be given, what it must produce, and what
# happens when it cannot. A hand-off that violates a precondition is a
# programming or policy error, not something to discover from a wrong number.

ROLE_CONTRACTS: dict[str, dict[str, Any]] = {
    "orchestrator": {
        "responsibility": "Decompose the investigation, allocate roles, enforce gates",
        "requires": ["investigation_charter", "data_tier"],
        "produces": ["plan", "role_assignments", "success_criteria"],
        "on_failure": "abort_or_replan",
        "may_advance_past_gates": True,
    },
    "research-collector": {
        "responsibility": "Acquire artifacts from web, arXiv, RSS, vendor docs",
        "requires": ["plan", "allowed_sources", "redaction_policy"],
        "produces": ["artifacts_with_provenance", "relevance", "fetch_metadata",
                     "coverage_gaps"],
        "on_failure": "partial_set_with_explicit_gaps",
        "may_advance_past_gates": False,
    },
    "architecture-analyst": {
        "responsibility": "Resolve data-flow, retention, residency, subprocessor questions",
        "requires": ["artifacts", "architecture_checklist"],
        "produces": ["architecture_completeness_record", "gaps"],
        "on_failure": "block_scoring_on_restricted_tier",
        "may_advance_past_gates": False,
    },
    "threat-intel": {
        "responsibility": "Map findings to the threat catalogue, exploits, OWASP/STRIDE",
        "requires": ["artifacts", "architecture_record"],
        "produces": ["threat_instances", "exploit_chains", "confidence"],
        "on_failure": "emit_only_evidence_supported_threats",
        "may_advance_past_gates": False,
    },
    "control-analyst": {
        "responsibility": "Map controls, assess coverage, separate declared from verified",
        "requires": ["threats", "control_catalogue", "evidence"],
        "produces": ["control_attestation_records"],
        "on_failure": "coverage_zero_without_accepted_evidence",
        "may_advance_past_gates": False,
    },
    "scorer": {
        "responsibility": "Compute inherent/verified residual, confidence, blast radius",
        "requires": ["verified_control_map", "architecture_gate_result",
                     "exposure_inventory"],
        "produces": ["residual_score", "evidence_confidence", "gate_status",
                     "decision_frame"],
        "on_failure": "refuse_to_emit_residual_when_gate_fails",
        "may_advance_past_gates": False,
    },
    "report-writer": {
        "responsibility": "Produce the decision-grade summary and appendices",
        "requires": ["scorer_output", "ledger_extract"],
        "produces": ["versioned_assessment", "executive_view"],
        "on_failure": "surface_confidence_and_gaps_prominently",
        "may_advance_past_gates": False,
    },
    "explainer": {
        "responsibility": "Answer specific open questions with grounded reasoning",
        "requires": ["question", "relevant_artifacts"],
        "produces": ["deep_dive_with_sources"],
        "on_failure": "mark_unanswered_never_invent_closure",
        "may_advance_past_gates": False,
    },
    "human-reviewer": {
        "responsibility": "Accept/reject evidence, approve residual, grant exceptions",
        "requires": ["decision_package"],
        "produces": ["ledger_event_with_identity_and_rationale"],
        "on_failure": "time_bounded_expiry_triggers_reevaluation",
        "may_advance_past_gates": True,
    },
    # §13.4 critic: a second pass that samples the swarm's own record for
    # contradictions, unsupported claims and missing hops. It never scores,
    # so it carries no gate authority.
    "critic": {
        "responsibility": "Sample the run's record for contradictions, unsupported claims, missing hops",
        "requires": ["ledger_extract", "assurance_verdict"],
        "produces": ["critic_findings", "consistency_report"],
        "on_failure": "report_record_insufficient_to_judge",
        "may_advance_past_gates": False,
    },
    # Knowledge-swarm roles. These run on every investigation, so leaving them
    # uncontracted meant leadership's System Health counted them and could not
    # judge them: "a number was produced" stood in for a success criterion.
    "drift-judge": {
        "responsibility": "Decide whether drift is a material change or noise",
        "requires": ["drift_candidates", "previous_baseline"],
        "produces": ["drift_verdicts", "reevaluation_triggers"],
        "on_failure": "hold_last_baseline_and_flag_unknown",
        "may_advance_past_gates": False,
    },
    # Risk-register swarm roles.
    "risk-intake": {
        "responsibility": "Normalise reported risks into register entries",
        "requires": ["intake_payload"],
        "produces": ["risk_entries", "duplicates_flagged"],
        "on_failure": "quarantine_with_reason_not_drop_silently",
        "may_advance_past_gates": False,
    },
    "risk-triage": {
        "responsibility": "Score likelihood and impact for register entries",
        "requires": ["risk_entries", "triage_criteria"],
        "produces": ["triage_scores", "priority_order"],
        "on_failure": "keep_entry_untriaged_with_gap_noting",
        "may_advance_past_gates": False,
    },
    "risk-treatment": {
        "responsibility": "Propose treatments with owner, cost and residual effect",
        "requires": ["triage_scores", "treatment_options"],
        "produces": ["treatment_plan", "residual_effect_estimate"],
        "on_failure": "record_no_feasible_treatment",
        "may_advance_past_gates": False,
    },
    "risk-monitor": {
        "responsibility": "Track indicators and trigger re-evaluation on change",
        "requires": ["risk_entries", "indicator_sources"],
        "produces": ["indicator_state", "monitoring_gaps"],
        "on_failure": "declare_monitoring_gap_explicitly",
        "may_advance_past_gates": False,
    },
    "risk-governance": {
        "responsibility": "Apply appetite, escalation and review cadence policy",
        "requires": ["risk_entries", "appetite_policy"],
        "produces": ["appetite_breaches", "escalations", "review_schedule"],
        "on_failure": "escalate_to_human_reviewer",
        "may_advance_past_gates": False,
    },
    "risk-reporter": {
        "responsibility": "Render the register and its open governance items",
        "requires": ["risk_entries", "escalations"],
        "produces": ["register_report"],
        "on_failure": "surface_breaches_and_gaps_prominently",
        "may_advance_past_gates": False,
    },
    # Portfolio swarm roles.
    "synthesizer": {
        "responsibility": "Merge assessments into one portfolio view without averaging away confidence",
        "requires": ["per_product_assessments"],
        "produces": ["portfolio_view", "cross_product_patterns"],
        "on_failure": "keep_products_separate_rather_than_merge_blindly",
        "may_advance_past_gates": False,
    },
}

#: The only roles permitted to advance past a gate. Everything else treats a
#: gate failure as a hard stop for residual reduction.
GATE_AUTHORITIES = frozenset(
    role for role, c in ROLE_CONTRACTS.items() if c.get("may_advance_past_gates"))


def role_contract(role: str) -> dict[str, Any]:
    """The contract for a role, or an explicit "uncontracted" marker.

    An unknown role is reported as uncontracted rather than treated as
    unconstrained: a role nobody wrote a contract for has no declared failure
    behaviour, which is exactly the gap the contracts exist to close.
    """
    c = ROLE_CONTRACTS.get(str(role or ""))
    if c:
        return {"role": role, "contracted": True, **c}
    return {
        "role": role, "contracted": False,
        "responsibility": "undeclared",
        "requires": [], "produces": [],
        "on_failure": "undeclared",
        "may_advance_past_gates": False,
        "note": ("No contract for this role: its inputs, outputs and failure "
                 "behaviour are undeclared, so nothing can be asserted about "
                 "what it was required to do."),
    }


def check_contract(role: str, payload: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Validate a hand-off against a role's contract.

    Reports missing inputs by name. Never raises: a blocked hand-off is data
    the orchestrator routes on, not an exception that unwinds the run.
    """
    c = role_contract(role)
    got = set((payload or {}).keys())
    missing = sorted(r for r in c.get("requires") or [] if r not in got)
    return {
        "role": role,
        "contracted": c["contracted"],
        "ok": bool(c["contracted"]) and not missing,
        "missing_inputs": missing,
        "required": list(c.get("requires") or []),
        "expected_outputs": list(c.get("produces") or []),
        "on_failure": c.get("on_failure"),
        "authority": ("gate_authority" if role in GATE_AUTHORITIES
                      else "blocked_by_gate"),
    }


# --------------------------------------------------- policy enforcement ----

def policy_enforcement_point(*, exposure: str, architecture_gate: dict[str, Any],
                             evidence_gate: dict[str, Any],
                             forensics: Optional[dict[str, Any]] = None,
                             threat_pack_stale: Optional[bool] = None,
                             min_evidence_confidence: float = 0.0,
                             evidence_confidence: Optional[float] = None,
                             ) -> dict[str, Any]:
    """The single check the scorer must pass before a residual may be emitted.

    Policy-as-code at the orchestration layer: architecture completeness,
    minimum accepted evidence, forensics readiness and pack currency are
    evaluated here, once, so no downstream agent can skip them by calling the
    scorer directly. Failure produces a decision, not an exception.
    """
    from . import assurance as A2

    checks: list[dict[str, Any]] = []

    checks.append({
        "id": "architecture_completeness",
        "passed": not architecture_gate.get("gate_blocked_applied"),
        "severity": "block",
        "detail": architecture_gate.get("banner"),
        "open_items": architecture_gate.get("open_items") or [],
    })
    gated = evidence_gate.get("gated_threats") or []
    checks.append({
        "id": "evidence_threshold",
        "passed": not gated,
        "severity": "warn",
        "detail": (f"{len(gated)} top threat(s) below the accepted-evidence "
                   f"threshold of {evidence_gate.get('min_accepted_per_threat')}"),
        "open_items": gated,
    })
    f = forensics or {}
    checks.append({
        "id": "forensics_readiness",
        "passed": bool(f.get("reconstructable")) or not f,
        "severity": "warn",
        "detail": (f"readiness {f.get('score')}/{f.get('max_score')} "
                   f"({f.get('band')})" if f else "not evaluated"),
        "open_items": f.get("not_found") or [],
    })
    checks.append({
        "id": "threat_pack_currency",
        "passed": threat_pack_stale is not True,
        "severity": "warn",
        "detail": ("current" if threat_pack_stale is not True
                   else "a newer pack is available; re-run recommended"),
        "open_items": [],
    })
    if min_evidence_confidence:
        conf = evidence_confidence
        checks.append({
            "id": "evidence_confidence_floor",
            "passed": conf is not None and float(conf) >= min_evidence_confidence,
            "severity": "warn",
            "detail": (f"{float(conf):.0%} vs floor "
                       f"{min_evidence_confidence:.0%}" if conf is not None
                       else "not computed"),
            "open_items": [],
        })

    blocked = [c for c in checks if not c["passed"] and c["severity"] == "block"]
    warned = [c for c in checks if not c["passed"] and c["severity"] == "warn"]
    restricted = str(exposure or "").lower() in A2.RESTRICTED_TIERS
    return {
        "allowed": not blocked,
        "restricted_tier": restricted,
        "checks": checks,
        "blocked_by": [c["id"] for c in blocked],
        "warnings": [c["id"] for c in warned],
        # The architecture gate is a completeness claim about the customer's
        # own system. It blocks scoring whatever the data tier is: for a public
        # tier an open item only means we do not know, which is a warning, not
        # a refusal.
        "decision": ("scorer_blocked" if blocked else
                     "scorer_allowed_with_confidence_penalty" if warned else
                     "scorer_allowed"),
        "confidence_penalty": round(0.1 * len(warned), 2),
        "note": ("Blocked means no residual is emitted: the affected threats "
                 "stay at inherent and the run reports a scoring-incomplete "
                 "state. Warnings lower evidence confidence instead."),
    }


#: Kinds that describe a role acting. Everything else in the ledger -- gates,
#: attestations, decisions -- carries an actor too, and folding those in made
#: the engine that wrote a gate look like a role nobody wrote a contract for.
ROLE_EVENT_KINDS = frozenset({
    "assurance.swarm_spawn", "assurance.swarm_handoff",
    "assurance.swarm_complete", "assurance.swarm_failure", "agent.hop",
})


def _role_events(events: Optional[Iterable[dict[str, Any]]]):
    """The subset of events that describe a role acting, in order."""
    return [e for e in (events or [])
            if str(e.get("kind") or "") in ROLE_EVENT_KINDS]


# -------------------------------------------------------------- topology ----

def topology(events: Optional[Iterable[dict[str, Any]]] = None) -> dict[str, Any]:
    """Live swarm view: which roles ran, are running, failed, or never started."""
    state: dict[str, dict[str, Any]] = {}
    for r in ROLE_CONTRACTS:
        state[r] = {"role": r, "state": "pending", "hops": 0, "failures": 0,
                    "last_seq": None, "authority": r in GATE_AUTHORITIES,
                    "contracted": True}
    for e in _role_events(events):
        data = e.get("data") or {}
        role = str(data.get("role") or e.get("actor") or "")
        if role not in state:
            # Keep the fact that nobody wrote a contract for this role: the
            # state field below moves on to active/complete, so a role's
            # lack of a contract has to live somewhere it cannot be overwritten.
            state[role] = {"role": role, "state": "uncontracted", "hops": 0,
                           "failures": 0, "last_seq": None,
                           "authority": role in GATE_AUTHORITIES,
                           "contracted": False}
        rec = state[role]
        rec["hops"] += 1
        rec["last_seq"] = e.get("seq")
        phase = str(data.get("phase") or "")
        kind = str(e.get("kind") or "")
        if phase == "failure" or kind.endswith("swarm_failure") or e.get("severity") == "block":
            rec["failures"] += 1
            rec["state"] = "failed"
        elif phase in ("complete",) or kind.endswith("swarm_complete"):
            rec["state"] = "complete"
        elif rec["state"] != "failed":
            rec["state"] = "active"
    return {
        "roles": list(state.values()),
        "pending": sorted(r for r, v in state.items() if v["state"] == "pending"),
        "failed": sorted(r for r, v in state.items() if v["state"] == "failed"),
        "complete": sorted(r for r, v in state.items() if v["state"] == "complete"),
        "uncontracted": sorted(r for r, v in state.items() if not v["contracted"]),
        "gate_authorities": sorted(GATE_AUTHORITIES),
    }


def health(events: Optional[Iterable[dict[str, Any]]] = None) -> dict[str, Any]:
    """Swarm success metrics by role, for the leadership System Health view."""
    per_role: dict[str, dict[str, int]] = {}
    hops = retries = failures = gate_failures = 0
    for e in _role_events(events):
        data = e.get("data") or {}
        role = str(data.get("role") or e.get("actor") or "unknown")
        rec = per_role.setdefault(role, {"spawns": 0, "completions": 0, "failures": 0})
        kind = str(e.get("kind") or "")
        phase = str(data.get("phase") or "")
        if phase == "spawn" or kind.endswith("swarm_spawn"):
            rec["spawns"] += 1
            hops += 1
        elif phase == "handoff" or kind.endswith("swarm_handoff") or kind == "agent.hop":
            hops += 1
        if phase == "complete" or kind.endswith("swarm_complete"):
            rec["completions"] += 1
        if phase == "failure" or kind.endswith("swarm_failure"):
            rec["failures"] += 1
            failures += 1
            # A failure the policy enforcement point caused is the number
            # leadership needs separately: it means the gate did its job, not
            # that the fabric is flaky. Folding it into one rate hid that.
            policy = data.get("policy") or {}
            if (policy.get("decision") == "scorer_blocked"
                    or policy.get("blocked_by")):
                gate_failures += 1
        if str(e.get("intent") or "").endswith("retry"):
            retries += 1
    rows = []
    for role, rec in sorted(per_role.items()):
        attempts = rec["completions"] + rec["failures"]
        rows.append({
            "role": role,
            "attempts": attempts,
            "completions": rec["completions"],
            "failures": rec["failures"],
            "success_rate": (round(rec["completions"] / attempts, 2) if attempts else None),
            "contracted": role in ROLE_CONTRACTS,
        })
    return {
        "roles": rows,
        "hops": hops,
        "failures": failures,
        "gate_failures": gate_failures,
        "retries": retries,
        "overall_success_rate": (
            round(sum(r["completions"] for r in rows)
                  / max(1, sum(r["attempts"] for r in rows)), 2) if rows else None),
        "gate_failure_rate": (round(gate_failures / max(1, failures), 2)
                              if failures else None),
        "note": ("A role with no contract is counted but not judged: nothing "
                 "was declared about what success means for it."),
    }


# ------------------------------------------- durable resume from the ledger --

def resume_state(events: Optional[Iterable[dict[str, Any]]] = None) -> dict[str, Any]:
    """Reconstruct a run's execution state from its ledger events alone.

    The ledger is the source of truth for a restart: nothing the swarm did is
    kept in a worker's memory, so a process death at any point can be rebuilt
    from the last committed event. Returns the next phase to execute and the
    per-role verdicts, so the orchestrator resumes rather than re-plans from
    scratch (and re-runs roles that already committed outputs).
    """
    evs = list(events or [])
    per_role: dict[str, dict[str, Any]] = {}
    seen_lifecycle: set[str] = set()
    last_seq: Optional[int] = None
    for e in evs:
        seq = e.get("seq")
        if seq is not None:
            last_seq = max(last_seq or -1, int(seq))
        kind = str(e.get("kind") or "")
        data = e.get("data") or {}
        if kind.startswith("assurance.lifecycle."):
            seen_lifecycle.add(kind.split(".")[-1])
        role = str(data.get("role") or e.get("actor") or "")
        if not role or kind not in ROLE_EVENT_KINDS:
            continue
        rec = per_role.setdefault(role, {"spawned": False, "completed": False,
                                         "failed": False, "hops": 0})
        rec["hops"] += 1
        phase = str(data.get("phase") or "")
        if phase == "spawn" or kind.endswith("swarm_spawn"):
            rec["spawned"] = True
        elif phase == "complete" or kind.endswith("swarm_complete"):
            rec["completed"] = True
        elif phase == "failure" or kind.endswith("swarm_failure"):
            rec["failed"] = True

    done = sorted(r for r, v in per_role.items() if v["completed"] or v["failed"])
    pending = sorted(r for r in ROLE_CONTRACTS
                     if r not in per_role or not per_role[r]["completed"])
    # Only roles that are contracted and not yet settled are outstanding; a role
    # that never spawned is pending, a role that settled is finished.
    resumed = sorted(r for r in ROLE_CONTRACTS
                     if per_role.get(r, {}).get("spawned")
                     and not (per_role[r]["completed"] or per_role[r]["failed"]))
    return {
        "events": len(evs),
        "last_seq": last_seq,
        "lifecycle_phases": sorted(seen_lifecycle),
        "roles": {r: v for r, v in sorted(per_role.items())},
        "completed": done,
        "pending": pending,
        "resume_these": resumed,
        "phase": ("completed" if "complete" in seen_lifecycle
                  else "scoring" if "scorer" in per_role
                  else "collect" if any(r in per_role
                                        for r in ("research-collector",
                                                  "architecture-analyst"))
                  else "plan"),
        "restartable": bool(evs) and "complete" not in seen_lifecycle,
        "note": ("Resume-from-ledger: replay the committed events, skip roles "
                 "already marked complete, re-run the ones in resume_these."),
    }


# ---------------------------------------------------------- typed hand-offs --

#: Mandatory fields on every inter-agent hand-off, with the reason the field is
#: non-negotiable. A hand-off that fails this schema is a defect, not a warning.
HANDOFF_SCHEMA: dict[str, dict[str, Any]] = {
    "run_id": {"required": True, "reason": "scopes the event to one investigation"},
    "parent_event": {"required": True, "reason": "lineage edge: without it a hop is an island"},
    "from_role": {"required": True, "reason": "who is handing off"},
    "to_role": {"required": True, "reason": "who must receive and act"},
    "model_version": {"required": True, "reason": "a mid-run model change must be visible"},
    "confidence": {"required": True, "reason": "a hand-off without confidence cannot gate"},
    "input_refs": {"required": False,
                   "reason": "hashes of what the receiving role must consume"},
}


def validate_handoff(message: dict[str, Any]) -> dict[str, Any]:
    """Schema-check a typed inter-agent message (never raises).

    Returns ``ok`` plus the missing fields and their reasons, so the
    orchestrator can refuse a malformed hand-off instead of routing it on.
    """
    missing = [k for k, spec in HANDOFF_SCHEMA.items()
               if spec["required"] and message.get(k) in (None, "", [])]
    return {
        "ok": not missing,
        "missing": missing,
        "reasons": {k: HANDOFF_SCHEMA[k]["reason"] for k in missing},
        "keys_present": sorted(k for k in HANDOFF_SCHEMA if message.get(k)),
    }


def record_typed_handoff(run_id: str, message: dict[str, Any],
                         actor: str = "orchestrator",
                         detail: Optional[dict[str, Any]] = None) -> Optional[str]:
    """Validate and, if valid, record one typed hand-off as a ledger event.

    An invalid hand-off returns ``None`` without writing: the missing fields
    are the point, and recording a message the schema rejects would make the
    ledger itself assert something false.
    """
    check = validate_handoff(message)
    if not check["ok"]:
        return None
    from . import assurance_ledger as _al
    return _al.record_swarm_event(
        run_id, role=message["to_role"], phase="handoff", actor=actor,
        parent_event=message.get("parent_event"),
        confidence=message.get("confidence"),
        model_version=message.get("model_version"),
        detail=dict(detail or {}, from_role=message.get("from_role"),
                    input_refs=message.get("input_refs") or []))


# --------------------------------------------------------- critic / critic --

def critic_review(events: Optional[Iterable[dict[str, Any]]] = None,
                  assurance: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """A lightweight self-consistency pass over a completed run.

    The §13.4 critic samples the ledger for the failures an opaque swarm hides:
    claims with no accepted artifact behind them, a residual reduction with no
    attestation, contradictory gate verdicts, and hops that never happened.
    These are *findings*, not judgments of the score itself -- the point is to
    surface what a plausible-looking report would otherwise absorb.
    """
    from . import assurance_ledger as _al

    evs = list(events or [])
    findings: list[dict[str, Any]] = []
    if evs:
        for a in _al.absence_alerts(evs):
            if a["severity"] == "block":
                findings.append({"type": "ledger", "id": a["id"],
                                 "condition": a["condition"],
                                 "why_it_matters": a["why_it_matters"]})
    att = (assurance or {}).get("control_attestation") or {}
    acc = (assurance or {}).get("declared") or {}
    ver = (assurance or {}).get("verified") or {}
    acc_r, ver_r = acc.get("residual_pct"), ver.get("residual_pct")
    if acc_r is not None and ver_r is not None and acc_r != ver_r and not att:
        findings.append({
            "type": "consistency",
            "id": "REDUCTION-WITHOUT-ATTESTATION",
            "condition": "a residual reduction is claimed (declared != verified) "
                         "but no control attestation was recorded",
            "why_it_matters": "a reduction with no attested controls is a "
                              "claimed cut, not an evidenced one."})
    # Contradiction: a gate marked complete that the checklist says blocked.
    gate = (assurance or {}).get("architecture_gate") or {}
    if gate.get("complete") and gate.get("gate_blocked_applied"):
        findings.append({
            "type": "contradiction",
            "id": "GATE-CONTRADICTION",
            "condition": "architecture gate is both complete and blocked",
            "why_it_matters": "the two flags cannot both be true; one of them "
                              "is wrong and the score must not rest on it."})
    return {
        "checked": len(evs) > 0 or bool(assurance),
        "findings": findings,
        "clean": not findings,
        "note": "The critic is a second pass, not a scorer: it asks whether "
                "the record supports the claim.",
    }


# ------------------------------------------------------ rate & scope control --

#: Default per-investigation budget (queries, tokens, wall-clock minutes).
DEFAULT_BUDGET = {"queries": 200, "tokens": 2_000_000, "minutes": 120}


def check_scope(tool: str, source: str = "",
                allowed_sources: Optional[Iterable[str]] = None) -> dict[str, Any]:
    """Source allow-list check before any external call that could carry
    sensitive context. A source outside the investigation's allow-list is a
    deny, not a warning: purpose-binding means the swarm fetches only what the
    charter permits."""
    allowed = {str(s).strip().lower() for s in (allowed_sources or []) if s}
    src = str(source or "").strip().lower()
    return {
        "tool": tool,
        "source": src,
        "allowed": (not allowed) or src in allowed,
        "allow_list": sorted(allowed),
        "verdict": "allow" if (not allowed or src in allowed) else "deny",
        "reason": ("allow-list empty" if not allowed
                   else "in allow-list" if src in allowed
                   else f"not in allow-list ({src})"),
    }


def budget_allows(used: dict[str, float], budget: Optional[dict[str, float]] = None,
                  ) -> dict[str, Any]:
    """Enforce the per-investigation research budget. Returns the limit hit
    first, or an allow verdict when no limit is exceeded."""
    b = dict(DEFAULT_BUDGET)
    if budget:
        b.update({k: v for k, v in budget.items() if v is not None})
    used = {k: float(v or 0) for k, v in used.items()}
    exceeded = [k for k in ("queries", "tokens", "minutes") if used.get(k, 0) > b[k]]
    return {
        "allowed": not exceeded,
        "limits": b,
        "used": {k: round(used.get(k, 0), 1) for k in ("queries", "tokens", "minutes")},
        "exceeded": exceeded,
        "verdict": "allow" if not exceeded else "deny",
        "note": "A research agent over budget is paused, not silently continued.",
    }
