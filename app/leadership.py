"""Leadership dashboard: the leadership decision view, not another score card.

:mod:`app.executive` answers "how much risk is open and where does it sit".
This module answers the four questions a person who has to *sign* a residual
risk actually asks:

1. What is our current exposure, and how confident are we in it?
2. Which decisions are waiting on us, and what would change the answer?
3. Is the evaluation system itself healthy and auditable?
4. What has changed since the last review?

The design rules that follow from "a residual number arrives without its
confidence" being the anti-pattern:

- **Residual is never printed alone.** Every occurrence carries evidence
  confidence, architecture-gate status and blast-radius quantification.
- **The evaluation system is itself a risk surface.** Ledger integrity,
  interrupted runs, dropped swarm hops and the pending-evidence backlog are
  first-class tiles, not a footnote.
- **One screen, progressive disclosure.** :func:`board` returns five views
  layered so the executive layer fits a screen and the rest drills down.
- **No decision without an event.** :func:`record_decision` writes the
  acceptance, rejection or exception to the ledger with identity and
  rationale, and an exception expires on a date rather than living forever.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from . import assurance as A
from . import assurance_ledger as AL
from . import swarm as SW

#: Decision states a leadership view counts. The derived assurance decision is
#: the starting point; a recorded human decision overrides it and is shown as
#: such rather than replacing the derivation.
STATE_OPEN = "open"
STATE_GUARDRAILS = "guardrails_required"
STATE_ACCEPTED = "accepted"
STATE_REJECTED = "rejected"
STATE_BLOCKED = "blocked_on_architecture"

#: Default exception window. A time-bounded exception with no expiry is just a
#: permanent override wearing a temporary label.
DEFAULT_EXCEPTION_DAYS = 90

TIER_ORDER = ("restricted_data", "confidential_data", "internal", "public")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _load(raw: Any, default: Any = None) -> Any:
    if not raw:
        return default if default is not None else {}
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return default if default is not None else {}


def _assessment_dict(rec: Any) -> dict[str, Any]:
    """Read one stored assessment into the fields the views need.

    ``assurance_json`` is the whole assurance pass, stored at score time, so
    the dashboard reports the verdict the assessment was actually written
    under rather than re-deriving it against today's pack.
    """
    scoring = _load(rec.scoring_json, {})
    ens = _load(rec.assurance_json, {})
    threats = _load(rec.threats_json, [])
    created = rec.created_at
    if created and created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return {
        "assessment_id": rec.id,
        "run_id": rec.run_id,
        "investigation_id": rec.investigation_id,
        "product_name": rec.product_name or "",
        "product_family": rec.product_family or "",
        "exposure": rec.exposure or "confidential_data",
        "inherent_pct": rec.inherent_pct,
        "declared_residual_pct": (rec.residual_pct if rec.inherent_pct is not None else None),
        "verified_residual_pct": ((ens.get("verified") or {}).get("residual_pct")
                                  if ens else None),
        "headline_layer": ens.get("headline_layer") if ens else "declared",
        "evidence_confidence": (rec.evidence_confidence
                                if rec.evidence_confidence is not None
                                else ens.get("evidence_confidence")),
        "assurance_assessed": ens.get("assessed", False) if ens else False,
        "decision_derived": ((ens.get("decision") or {}).get("decision")
                             if ens else None),
        "decision_headline": ((ens.get("decision") or {}).get("headline")
                              if ens else None),
        "architecture_gate": (ens.get("architecture_gate") or {}) if ens else {},
        "forensics": (ens.get("forensics") or {}) if ens else {},
        "blast_radius": (ens.get("blast_radius") or {}) if ens else {},
        "gates_open": (ens.get("gates_open") or []) if ens else [],
        "control_attestation": (ens.get("control_attestation") or {}) if ens else {},
        "threats": threats if isinstance(threats, list) else [],
        "threat_pack_version": rec.threat_pack_version,
        "threat_pack_fingerprint": rec.threat_pack_fingerprint,
        "decision_recorded": rec.assurance_decision,
        "decision_actor": rec.assurance_decided_by,
        "decision_note": rec.assurance_decision_note,
        "decision_at": rec.assurance_decided_at.isoformat() if rec.assurance_decided_at else None,
        "expires_at": (rec.assurance_decision_expires_at.isoformat()
                       if getattr(rec, "assurance_decision_expires_at", None) else None),
        "created_at": created.isoformat() if created else None,
        "scoring_path": scoring.get("assessment_path") or "standard",
    }


def _decision_state(a: dict[str, Any], now: Optional[datetime] = None) -> str:
    """Effective decision state: a recorded human decision wins, else derived."""
    now = now or _now()
    expires = a.get("expires_at")
    expired = False
    if expires:
        try:
            exp = datetime.fromisoformat(str(expires).replace("Z", "+00:00"))
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            expired = exp <= now
        except Exception:
            expired = False
    if a.get("decision_recorded") and not expired:
        rec = str(a["decision_recorded"])
        if rec == A.DECISION_ACCEPT:
            return STATE_ACCEPTED
        if rec == A.DECISION_GUARDRAILS:
            return STATE_GUARDRAILS
        if rec == A.DECISION_REJECT:
            return STATE_REJECTED
    if expired:
        # An expired exception does not silently keep protecting the score.
        return STATE_OPEN
    gate = a.get("architecture_gate") or {}
    if gate.get("gate_blocked_applied"):
        return STATE_BLOCKED
    derived = a.get("decision_derived")
    if derived == A.DECISION_ACCEPT:
        return STATE_ACCEPTED
    if derived == A.DECISION_REJECT:
        return STATE_BLOCKED
    if derived == A.DECISION_GUARDRAILS:
        return STATE_GUARDRAILS
    return STATE_OPEN


def _latest_per_investigation(rows: list[Any]) -> list[dict[str, Any]]:
    """The current row per product and scoring path.

    Superseded rows are not deleted: the change-log view shows them. What the
    headline must not do is print two different residuals for one product
    without saying which is current. Two *different* products in one
    investigation are two rows, so the key carries product identity -- keying
    on the investigation alone would silently drop a product.
    """
    superseded: set[int] = set()
    for rec in rows:
        parent = getattr(rec, "supersedes_id", None)
        if parent:
            superseded.add(int(parent))
    best: dict[tuple, Any] = {}
    for rec in rows:
        if rec.id in superseded:
            continue
        a = _assessment_dict(rec)
        product = (a["product_name"] or a["product_family"] or "").strip().lower()
        key = (a["investigation_id"], product, a["scoring_path"])
        prev = best.get(key)
        if prev is None or (rec.created_at or _now()) > (prev.created_at or _now()):
            best[key] = rec
    return [_assessment_dict(rec) for rec in best.values()]


def _assessments(db, investigation_id: Optional[int] = None) -> list[Any]:
    from .models import SecurityAssessment

    q = db.query(SecurityAssessment)
    if investigation_id:
        q = q.filter(SecurityAssessment.investigation_id == int(investigation_id))
    return q.order_by(SecurityAssessment.created_at.desc()).all()


def _investigations(db, ids: set[int]) -> dict[int, str]:
    from .models import Investigation

    if not ids:
        return {}
    rows = db.query(Investigation).filter(Investigation.id.in_(list(ids))).all()
    return {r.id: (r.title or "Untitled") for r in rows}


# ------------------------------------------- A. Executive risk position ----

def risk_position(db, investigation_id: Optional[int] = None, *,
                  window_days: int = 90) -> dict[str, Any]:
    """Aggregate verified residual by data tier, with confidence beside it.

    Segmented by tier because "Public" and "Restricted" averaged into one
    number is a number nobody can act on. Confidence is reported as its own
    figure: a 24 with 30% evidence confidence is a different decision from a
    24 with 85%.
    """
    rows = _assessments(db, investigation_id)
    latest = _latest_per_investigation(rows)
    titles = _investigations(db, {a["investigation_id"] for a in latest})
    now = _now()
    cutoff = now - timedelta(days=max(1, window_days))

    by_tier: dict[str, dict[str, Any]] = {}
    states: dict[str, int] = {s: 0 for s in (
        STATE_OPEN, STATE_GUARDRAILS, STATE_ACCEPTED, STATE_REJECTED, STATE_BLOCKED)}
    confidences: list[float] = []
    blocked_items: dict[str, int] = {}
    top_threats: list[dict[str, Any]] = []
    # §9.3 A: percentage of the residual reduction that rests on verified
    # primary evidence, not on declared controls nobody has substantiated.
    reductions = {"claimed": 0.0, "verified": 0.0}
    declared_vals: list[float] = []
    verified_vals: list[float] = []

    for a in latest:
        tier = a["exposure"] if a["exposure"] in TIER_ORDER else "internal"
        rec = by_tier.setdefault(tier, {
            "tier": tier, "count": 0, "verified": [], "declared": [],
            "forensics": [], "quantified": 0, "blocked": 0,
        })
        rec["count"] += 1
        v = a.get("verified_residual_pct")
        d = a.get("declared_residual_pct")
        if v is not None:
            rec["verified"].append(float(v))
        if d is not None:
            rec["declared"].append(float(d))
        f = a.get("forensics") or {}
        if f.get("score") is not None:
            rec["forensics"].append(float(f.get("score") or 0))
        radius = a.get("blast_radius") or {}
        if radius.get("quantified"):
            rec["quantified"] += 1
        gate = a.get("architecture_gate") or {}
        if gate.get("gate_blocked_applied"):
            rec["blocked"] += 1
            for item in gate.get("open_items") or []:
                blocked_items[item] = blocked_items.get(item, 0) + 1
        states[_decision_state(a, now)] += 1
        conf = a.get("evidence_confidence")
        if conf is not None:
            confidences.append(float(conf))
        inh = a.get("inherent_pct")
        if (inh is not None and d is not None and v is not None):
            claimed = max(0.0, float(inh) - float(d))
            verified = max(0.0, float(inh) - float(v))
            if claimed > 0:
                reductions["claimed"] += claimed
                reductions["verified"] += min(verified, claimed)
            declared_vals.append(float(d))
            verified_vals.append(float(v))
        for t in (a.get("threats") or [])[:4]:
            if isinstance(t, dict) and t.get("verified_residual") is not None:
                top_threats.append({
                    "threat_id": t.get("id"),
                    "title": str(t.get("title") or "")[:70],
                    "verified_residual": t.get("verified_residual"),
                    "declared_residual": t.get("declared_residual"),
                    "coverage_confidence_pct": t.get("coverage_confidence_pct"),
                    "forced_to_inherent": t.get("forced_to_inherent"),
                    "product": a["product_name"],
                    "assessment_id": a["assessment_id"],
                })

    def _mean(xs: list[float]) -> Optional[float]:
        return round(sum(xs) / len(xs), 1) if xs else None

    for rec in by_tier.values():
        rec["mean_verified_residual"] = _mean(rec.pop("verified"))
        rec["mean_declared_residual"] = _mean(rec.pop("declared"))
        rec["mean_forensics"] = _mean(rec.pop("forensics"))

    top_threats.sort(key=lambda t: -(float(t.get("verified_residual") or 0)))
    trend = _trend(rows, cutoff)

    return {
        "tiers": [by_tier[t] for t in TIER_ORDER if t in by_tier],
        "assessments": len(latest),
        "decisions": states,
        "evidence_confidence": {
            "mean_pct": round(_mean(confidences) * 100, 0) if confidences else None,
            "distribution": _distribution([c for c in confidences]),
            "note": ("Share of the residual reduction that rests on accepted "
                     "primary evidence."),
        },
        "verified_vs_declared": {
            "mean_declared_residual_pct": _mean(declared_vals),
            "mean_verified_residual_pct": _mean(verified_vals),
            "claimed_reduction_pct_points": round(reductions["claimed"], 1),
            "verified_reduction_pct_points": round(reductions["verified"], 1),
            "verified_share_pct": (
                round(100 * reductions["verified"] / reductions["claimed"], 0)
                if reductions["claimed"] else None),
            "note": ("Verified share = residual reduction backed by accepted "
                     "primary evidence / total claimed reduction. A low share "
                     "means the portfolio is carrying declared-only cuts."),
        },
        "architecture_gaps": [{"item": k, "assessments": v}
                              for k, v in sorted(blocked_items.items(),
                                                 key=lambda e: -e[1])],
        "top_residual_threats": top_threats[:10],
        "trend": trend,
        "investigations": [{"id": a["investigation_id"],
                            "title": titles.get(a["investigation_id"], "")}
                           for a in latest],
        "generated": now.isoformat(),
    }


def _distribution(values: list[float]) -> dict[str, int]:
    out = {"0-20%": 0, "20-40%": 0, "40-60%": 0, "60-80%": 0, "80-100%": 0}
    for v in values:
        pct = max(0.0, min(1.0, float(v))) * 100
        for lo, hi in ((0, 20), (20, 40), (40, 60), (60, 80), (80, 101)):
            if lo <= pct < hi:
                out[f"{lo}-{min(hi, 100)}%"] += 1
                break
    return out


def _trend(rows: list[Any], cutoff: datetime) -> dict[str, Any]:
    """Residual and confidence over time, split at the window."""
    buckets: dict[str, dict[str, list[float]]] = {"prior": {"v": [], "c": []},
                                                  "window": {"v": [], "c": []}}
    for rec in rows:
        a = _assessment_dict(rec)
        created = rec.created_at
        if created and created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        if not created:
            continue
        key = "window" if created >= cutoff else "prior"
        v = a.get("verified_residual_pct")
        if v is None:
            v = a.get("declared_residual_pct")
        if v is not None:
            buckets[key]["v"].append(float(v))
        if a.get("evidence_confidence") is not None:
            buckets[key]["c"].append(float(a["evidence_confidence"]))
    def _m(xs): return round(sum(xs) / len(xs), 1) if xs else None
    prior_v, win_v = _m(buckets["prior"]["v"]), _m(buckets["window"]["v"])
    prior_c = _m(buckets["prior"]["c"])
    win_c = _m(buckets["window"]["c"])
    delta = (round(win_v - prior_v, 1)
             if prior_v is not None and win_v is not None else None)
    return {
        "prior_mean_residual": prior_v,
        "window_mean_residual": win_v,
        "delta": delta,
        "direction": ("improving" if delta is not None and delta < 0
                      else "worsening" if delta is not None and delta > 0
                      else "flat" if delta == 0 else "insufficient_history"),
        "prior_mean_confidence_pct": round(prior_c * 100, 0) if prior_c is not None else None,
        "window_mean_confidence_pct": round(win_c * 100, 0) if win_c is not None else None,
        "note": "Prior = everything before the window; a move with no prior cannot be called a trend.",
    }


# ------------------------------------------------- B. Decision queue -------

def decision_queue(db, investigation_id: Optional[int] = None, *,
                   states: Optional[list[str]] = None,
                   limit: int = 25) -> dict[str, Any]:
    """Everything waiting on a leadership decision, with what would change it.

    Each row carries the verified residual *and* its evidence confidence,
    architecture-gate status and blast-radius summary: the four things a
    sign-off is actually accepting.
    """
    rows = _assessments(db, investigation_id)
    latest = _latest_per_investigation(rows)
    titles = _investigations(db, {a["investigation_id"] for a in latest})
    now = _now()
    wanted = set(states) if states else {STATE_OPEN, STATE_GUARDRAILS, STATE_BLOCKED}
    queue = []
    for a in latest:
        state = _decision_state(a, now)
        if state not in wanted:
            continue
        radius = a.get("blast_radius") or {}
        queue.append({
            "assessment_id": a["assessment_id"],
            "investigation_id": a["investigation_id"],
            "investigation_title": titles.get(a["investigation_id"], ""),
            "product": a["product_name"],
            "tier": a["exposure"],
            "state": state,
            "verified_residual_pct": a.get("verified_residual_pct"),
            "declared_residual_pct": a.get("declared_residual_pct"),
            "headline_layer": a.get("headline_layer"),
            "evidence_confidence_pct": (round(float(a["evidence_confidence"]) * 100)
                                        if a.get("evidence_confidence") is not None else None),
            "architecture_gate": a["architecture_gate"].get("banner"),
            "architecture_open_items": a["architecture_gate"].get("open_items") or [],
            "blast_radius": radius.get("summary"),
            "quantified": radius.get("quantified"),
            "forensics_band": (a.get("forensics") or {}).get("band"),
            "recommended_decision": a.get("decision_derived"),
            "recommended_headline": a.get("decision_headline"),
            "gates_open": a.get("gates_open") or [],
            "recorded_decision": a.get("decision_recorded"),
            "expires_at": a.get("expires_at"),
            "dossier_link": f"/api/investigations/{a['investigation_id']}/dossier/markdown",
            "vendor_questionnaire_available": bool(
                (a.get("architecture_gate") or {}).get("open_items")),
        })
    order = {STATE_BLOCKED: 0, STATE_GUARDRAILS: 1, STATE_OPEN: 2}
    queue.sort(key=lambda r: (order.get(r["state"], 9),
                              -(r.get("verified_residual_pct") or 0)))
    return {
        "items": queue[:limit],
        "count": len(queue),
        "states": {s: sum(1 for r in queue if r["state"] == s)
                   for s in (STATE_BLOCKED, STATE_GUARDRAILS, STATE_OPEN)},
        "note": ("Every row shows verified residual with its evidence "
                 "confidence and gate status. A residual without them is not a "
                 "decision item."),
        "generated": now.isoformat(),
    }


# ------------------------------------- C. Control & assurance health -------

def assurance_health(db, investigation_id: Optional[int] = None) -> dict[str, Any]:
    """Controls verified vs declared, forensics across the portfolio, ledger
    integrity, interrupted runs, overdue evidence reviews."""
    rows = _assessments(db, investigation_id)
    latest = _latest_per_investigation(rows)

    verified = declared = unknown = 0
    per_control: dict[str, dict[str, int]] = {}
    forensics_scores: list[float] = []
    unassessed = 0
    for a in latest:
        att = a.get("control_attestation") or {}
        if not att:
            unassessed += 1
        for cid, rec in (att or {}).items():
            st = (rec or {}).get("status") or "unknown"
            if st == "evidenced":
                verified += 1
            elif st == "declared":
                declared += 1
            else:
                unknown += 1
            slot = per_control.setdefault(cid, {"evidenced": 0, "declared": 0,
                                                "unknown": 0})
            slot[st if st in slot else "unknown"] += 1
        f = a.get("forensics") or {}
        if f.get("score") is not None:
            forensics_scores.append(float(f.get("score") or 0))

    total = verified + declared + unknown
    ledger_health = _ledger_health(db, investigation_id)
    stalled = _stalled_runs(db, investigation_id)
    overdue = _overdue_evidence(db, investigation_id)
    close_metrics = _time_to_close(db, investigation_id)

    worst_controls = sorted(
        ((cid, v["evidenced"], v["declared"] + v["unknown"])
         for cid, v in per_control.items()),
        key=lambda e: (e[1], -e[2]))[:8]
    return {
        "controls": {
            "verified": verified,
            "declared": declared,
            "unknown": unknown,
            "verified_pct": round(verified / total * 100, 0) if total else None,
            "least_evidenced": [{"control_id": c, "evidenced": e, "not": n}
                                for c, e, n in worst_controls],
            "assessments_without_attestation": unassessed,
        },
        "forensics": {
            "mean_score": (round(sum(forensics_scores) / len(forensics_scores), 1)
                           if forensics_scores else None),
            "reconstructable": sum(1 for a in latest
                                   if (a.get("forensics") or {}).get("reconstructable")),
            "scored": len(forensics_scores),
        },
        "ledger": ledger_health,
        "stalled_runs": stalled,
        "overdue_evidence": overdue,
        "time_to_close": close_metrics,
        "note": ("The evaluation system is itself a risk surface: a portfolio "
                 "of well-formed scores on a fabric with gaps is not an "
                 "assurance position."),
    }


def _ledger_health(db, investigation_id: Optional[int] = None) -> dict[str, Any]:
    """Chain integrity and event-class completeness across recent runs."""
    from .models import AgentRun

    q = db.query(AgentRun)
    if investigation_id:
        q = q.filter(AgentRun.investigation_id == int(investigation_id))
    runs = q.order_by(AgentRun.id.desc()).limit(40).all()
    intact = 0
    coverage: list[int] = []
    blocking: list[dict[str, Any]] = []
    checked = 0
    for r in runs:
        run_id = f"akm-run-{r.id}"
        try:
            rep = AL.integrity_report(run_id, db=db)
        except Exception:
            continue
        if not rep.get("events"):
            continue
        checked += 1
        if rep.get("chain_intact"):
            intact += 1
        cov = rep.get("class_coverage") or {}
        if cov.get("total"):
            coverage.append(int(cov.get("recorded") or 0))
        for a in rep.get("absence_alerts") or []:
            if a.get("severity") == "block":
                blocking.append({"run_id": run_id, **a})
    return {
        "runs_checked": checked,
        "chains_intact": intact,
        "chains_broken": checked - intact,
        "mean_event_classes_recorded": (round(sum(coverage) / len(coverage), 1)
                                        if coverage else None),
        "mandatory_event_classes": len(AL.MANDATORY_EVENT_CLASSES),
        "blocking_alerts": blocking[:10],
        "note": ("An intact chain proves events were not edited. It does not "
                 "prove the events that should have happened did — that is "
                 "what the completeness and absence checks are for."),
    }


def _stalled_runs(db, investigation_id: Optional[int] = None,
                  ) -> dict[str, Any]:
    """Interrupted and orphaned runs — the gap an explainer_gap leaves."""
    from .models import AgentRun

    q = db.query(AgentRun)
    if investigation_id:
        q = q.filter(AgentRun.investigation_id == int(investigation_id))
    by_status: dict[str, int] = {}
    gap_open: list[dict[str, Any]] = []
    for r in q.all():
        st = r.status or "unknown"
        by_status[st] = by_status.get(st, 0) + 1
        # "Not done" covers error as well as running: an explainer_gap that
        # died is precisely the case where the architecture questions it was
        # meant to answer are still open, so it belongs in the count.
        if (r.trigger or "") == "explainer_gap" and st != "done":
            gap_open.append({"run_id": r.id, "status": st,
                             "investigation_id": r.investigation_id,
                             "failed": st == "error",
                             "error": (r.error or "")[:120]})
    return {
        "by_status": by_status,
        "explainer_gap_open": len(gap_open),
        "explainer_gap_failed": sum(1 for g in gap_open if g["failed"]),
        "explainer_gap_runs": gap_open[:10],
        "note": ("An interrupted explainer_gap leaves architecture questions "
                 "open, which is what blocks the assurance gate."),
    }


def _architecture_gap_intervals(rows: list[Any]) -> list[tuple[str, float | None, float]]:
    """(product/path, close_days | None if still open, open_days) per gap."""
    by_key: dict[tuple, list[tuple[datetime, bool]]] = {}
    for rec in sorted(rows, key=lambda r: r.created_at or _now()):
        a = _assessment_dict(rec)
        gate = a.get("architecture_gate") or {}
        key = ((a["product_name"] or a["product_family"] or "").strip().lower(),
               a["scoring_path"])
        created = rec.created_at
        if created and created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        by_key.setdefault(key, []).append((created or _now(),
                                           bool(gate.get("gate_blocked_applied"))))
    out: list[tuple[str, float | None, float]] = []
    now = _now()
    for (product, _path), events in by_key.items():
        events.sort(key=lambda e: e[0])
        for i, (created, blocked) in enumerate(events):
            if not blocked:
                continue
            later = next((c for c, b in events[i + 1:] if not b), None)
            if later is not None:
                out.append((product, max(0.0, (later - created).total_seconds()
                                         / 86400.0), 0.0))
            else:
                out.append((product, None, max(0.0, (now - created)
                                               .total_seconds() / 86400.0)))
    return out


def _overdue_evidence(db, investigation_id: Optional[int] = None,
                      timeout_days: int = 14) -> dict[str, Any]:
    """Pending artifacts past the ageing threshold, awaiting a human decision."""
    from .models import Artifact

    q = db.query(Artifact).filter(Artifact.review == "pending")
    if investigation_id:
        q = q.filter(Artifact.investigation_id == int(investigation_id))
    rows = q.all()
    now = _now()
    overdue = []
    for a in rows:
        created = a.created_at
        if created and created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age = (now - created).days if created else 0
        if age >= timeout_days:
            overdue.append({"artifact_id": a.id, "age_days": age,
                            "relevance": a.relevance, "drift": bool(a.drift)})
    return {
        "pending": len(rows),
        "overdue": len(overdue),
        "timeout_days": timeout_days,
        "oldest_days": max((o["age_days"] for o in overdue), default=0),
        "items": sorted(overdue, key=lambda o: -o["age_days"])[:10],
        "note": ("Pending artifacts never reduce residual in the verified "
                 "layer; an ageing backlog means the declared view is drifting "
                 "away from the verified one."),
    }


# ------------------------------------------ D. Exposure & blast radius -----

def exposure_lens(db, investigation_id: Optional[int] = None) -> dict[str, Any]:
    """Restricted/Confidential assets, privileged users, materiality flags."""
    rows = _assessments(db, investigation_id)
    latest = _latest_per_investigation(rows)
    restricted = confidential = users = 0
    quantified = unquantified = 0
    material: list[dict[str, Any]] = []
    for a in latest:
        radius = a.get("blast_radius") or {}
        inv = radius.get("inventory") or {}
        restricted += int(inv.get("restricted_assets") or 0)
        confidential += int(inv.get("confidential_assets") or 0)
        users += int(inv.get("privileged_users") or 0)
        if radius.get("quantified"):
            quantified += 1
            res = float(radius.get("residual_pct") or 0)
            at_risk = int(radius.get("records_at_risk") or 0)
            # Materiality needs both a score and a population: a high residual
            # over four assets is a different conversation from the same
            # residual over forty thousand.
            if res >= 50 and at_risk >= 1000:
                material.append({
                    "assessment_id": a["assessment_id"],
                    "product": a["product_name"],
                    "verified_residual_pct": res,
                    "records_at_risk": at_risk,
                    "privileged_users": int(inv.get("privileged_users") or 0),
                    "max_payload_mb": radius.get("max_payload_mb"),
                })
        else:
            unquantified += 1
    return {
        "restricted_assets": restricted,
        "confidential_assets": confidential,
        "privileged_users": users,
        "quantified_assessments": quantified,
        "unquantified_assessments": unquantified,
        "material_items": material,
        "note": ("Blast radius is a required input for a go/no-go on a "
                 "restricted tier; an unquantified assessment is reported as "
                 "unquantified, never as zero exposure."),
    }


# ------------------------------------------ E. System & process integrity ---

def system_integrity(db, investigation_id: Optional[int] = None,
                     limit: int = 20) -> dict[str, Any]:
    """Swarm health, pack currency, ledger completeness, time-to-close."""
    rows = _assessments(db, investigation_id)
    latest = _latest_per_investigation(rows)

    swarm_stats: dict[str, Any] = {"roles": [], "hops": 0, "failures": 0,
                                   "retries": 0, "overall_success_rate": None,
                                   "gate_failure_rate": None}
    pack_rows: list[dict[str, Any]] = []
    stale = 0
    for a in latest:
        try:
            events = AL._load_events(f"akm-run-{a['run_id']}", db=db) if a.get("run_id") else []
        except Exception:
            events = []
        if events:
            h = SW.health(events)
            swarm_stats["hops"] += h["hops"]
            swarm_stats["failures"] += h["failures"]
            swarm_stats["retries"] += h["retries"]
            merged: dict[str, dict[str, Any]] = {}
            for r in h["roles"]:
                slot = merged.setdefault(r["role"], {**r, "attempts": 0,
                                                     "completions": 0, "failures": 0})
                slot["attempts"] += r["attempts"]
                slot["completions"] += r["completions"]
                slot["failures"] += r["failures"]
                slot["success_rate"] = (round(slot["completions"] / slot["attempts"], 2)
                                        if slot["attempts"] else None)
            swarm_stats["roles"] = sorted(merged.values(),
                                          key=lambda r: -(r["failures"] or 0))
        sup = A.pack_supersession(a.get("threat_pack_version"),
                                  a.get("threat_pack_fingerprint"))
        pack_rows.append({"assessment_id": a["assessment_id"],
                          "product": a["product_name"],
                          **sup})
        if sup.get("stale"):
            stale += 1
    total_attempts = sum(r["attempts"] for r in swarm_stats["roles"])
    swarm_stats["overall_success_rate"] = (
        round(sum(r["completions"] for r in swarm_stats["roles"]) / total_attempts, 2)
        if total_attempts else None)
    swarm_stats["gate_failure_rate"] = (
        round(swarm_stats["failures"] / swarm_stats["hops"], 2)
        if swarm_stats["hops"] else None)

    health = assurance_health(db, investigation_id)
    ttc = _time_to_close(db, investigation_id)
    return {
        "swarm": swarm_stats,
        "threat_pack": {
            "assessments": len(pack_rows),
            "stale": stale,
            "currency_pct": round((len(pack_rows) - stale) / len(pack_rows) * 100, 0)
            if pack_rows else None,
            "rows": pack_rows[:limit],
            "note": ("A stale pack is reported, never auto-rescored: "
                     "re-scoring a signed assessment is a decision for whoever "
                     "owns it."),
        },
        "ledger": health["ledger"],
        "time_to_close": ttc,
        "note": ("System health belongs in the risk picture: a portfolio of "
                 "well-formed scores produced by a swarm with dropped hops is "
                 "not an assurance position."),
    }


def _time_to_close(db, investigation_id: Optional[int] = None) -> dict[str, Any]:
    """How long architecture gaps and evidence reviews actually take."""
    from .models import Artifact, Explanation

    q = db.query(Explanation).filter(Explanation.status == "done")
    if investigation_id:
        q = q.filter(Explanation.investigation_id == int(investigation_id))
    spans = []
    for e in q.all():
        if e.created_at and e.finished_at:
            spans.append((e.finished_at - e.created_at).days)
    aq = db.query(Artifact).filter(Artifact.review == "accepted")
    if investigation_id:
        aq = aq.filter(Artifact.investigation_id == int(investigation_id))
    accepts = 0
    aged = []
    for a in aq.all():
        if a.created_at and a.review == "accepted":
            accepts += 1
            aged.append(a.relevance or 0)
    med = sorted(spans)[len(spans) // 2] if spans else None

    # Architecture gaps: closed by a later unblocked assessment of the same
    # product/path; open gaps report their current age instead of a close time.
    now = _now()
    arch_closed: list[float] = []
    arch_open: list[dict[str, Any]] = []
    for product, close_days, open_days in _architecture_gap_intervals(
            _assessments(db, investigation_id)):
        if close_days is None:
            arch_open.append({"product": product, "open_days": open_days})
        else:
            arch_closed.append(close_days)

    pq = db.query(Artifact).filter(Artifact.review == "pending")
    if investigation_id:
        pq = pq.filter(Artifact.investigation_id == int(investigation_id))
    pending_ages = []
    for a in pq.all():
        created = a.created_at or a.updated_at or now
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        pending_ages.append(max(0.0, (now - created).total_seconds() / 86400.0))

    return {
        "questions_answered": len(spans),
        "median_days_to_answer": med,
        "artifacts_accepted": accepts,
        "mean_accepted_relevance": round(sum(aged) / len(aged), 3) if aged else None,
        "architecture_gaps": {
            "closed_count": len(arch_closed),
            "mean_close_days": (round(sum(arch_closed) / len(arch_closed), 1)
                                if arch_closed else None),
            "open": arch_open[:10],
            "open_count": len(arch_open),
        },
        "evidence_reviews": {
            "pending_count": len(pending_ages),
            "mean_pending_days": (round(sum(pending_ages) / len(pending_ages), 1)
                                  if pending_ages else None),
            "max_pending_days": (round(max(pending_ages), 1) if pending_ages else None),
        },
        "note": ("Time-to-close is what tells a leadership team whether the "
                 "gap backlog is shrinking or just being reported."),
    }


# ------------------------------------------------------- alerting --------

def alerts(db, investigation_id: Optional[int] = None) -> dict[str, Any]:
    """Notifications, not just tiles: what needs a person now."""
    out: list[dict[str, Any]] = []
    q = decision_queue(db, investigation_id)
    for item in q["items"]:
        if item["state"] == STATE_BLOCKED:
            out.append({
                "id": f"gate-blocked-{item['assessment_id']}",
                "severity": "block",
                "title": f"{item['product']}: scoring blocked on architecture",
                "detail": (f"Open: {', '.join(item['architecture_open_items'])}"
                           if item["architecture_open_items"]
                           else "architecture gate incomplete"),
                "link": item["dossier_link"],
            })
        if item["quantified"] is False and str(item["tier"]) in A.RESTRICTED_TIERS:
            out.append({
                "id": f"unquantified-{item['assessment_id']}",
                "severity": "warn",
                "title": f"{item['product']}: blast radius not quantified",
                "detail": "A go/no-go on this tier requires an exposure inventory.",
                "link": item["dossier_link"],
            })
        conf = item.get("evidence_confidence_pct")
        if conf is not None and conf < 40:
            out.append({
                "id": f"low-confidence-{item['assessment_id']}",
                "severity": "warn",
                "title": f"{item['product']}: evidence confidence {conf}%",
                "detail": ("Most of the residual reduction rests on unevidenced "
                           "controls; the verified residual is the one to read."),
                "link": item["dossier_link"],
            })
    h = assurance_health(db, investigation_id)
    for alert in (h["ledger"].get("blocking_alerts") or []):
        out.append({
            "id": f"ledger-{alert.get('run_id')}-{alert.get('id')}",
            "severity": "block",
            "title": f"Ledger: {alert.get('condition')}",
            "detail": alert.get("why_it_matters"),
            "link": "/api/ledger/verify-export",
        })
    if h["overdue_evidence"]["overdue"]:
        out.append({
            "id": "evidence-backlog",
            "severity": "warn",
            "title": (f"{h['overdue_evidence']['overdue']} evidence review(s) "
                      "overdue"),
            "detail": h["overdue_evidence"]["note"],
            "link": "/api/investigations",
        })
    if h["stalled_runs"]["explainer_gap_open"]:
        failed = h["stalled_runs"].get("explainer_gap_failed") or 0
        out.append({
            "id": "explainer-gap-open",
            "severity": "warn" if not failed else "block",
            "title": (f"{h['stalled_runs']['explainer_gap_open']} interrupted "
                      f"explainer_gap run(s), {failed} failed"),
            "detail": h["stalled_runs"]["note"],
            "link": "/api/investigations",
        })
    order = {"block": 0, "warn": 1, "info": 2}
    out.sort(key=lambda a: order.get(a["severity"], 9))
    return {"alerts": out, "blocking": sum(1 for a in out if a["severity"] == "block"),
            "warnings": sum(1 for a in out if a["severity"] == "warn")}


# --------------------------------------------------- the layered board ----

def board(db, investigation_id: Optional[int] = None, *,
          window_days: int = 90, persona: str = "executive") -> dict[str, Any]:
    """The layered dashboard: one executive screen, drill-down beneath it.

    Same underlying data for every persona, different default emphasis — a
    role-based view is a lens, not a separate number, so two personas can never
    quote different residuals for the same assessment.
    """
    persona = (persona or "executive").lower()
    emphasis = {
        "executive": ["risk_position", "decision_queue", "alerts"],
        "ciso": ["risk_position", "assurance_health", "system_integrity", "decision_queue"],
        "dpo": ["exposure_lens", "risk_position", "decision_queue"],
        "legal": ["assurance_health", "system_integrity", "decision_queue"],
        "audit": ["assurance_health", "system_integrity"],
        # Security Engineering owns the evaluation system itself: swarm health,
        # ledger completeness and rate/scope control are its first screen.
        "security_engineering": ["system_integrity", "assurance_health",
                                 "risk_position", "alerts", "decision_queue"],
    }.get(persona, ["risk_position", "decision_queue", "alerts"])
    return {
        "persona": persona,
        "emphasis": emphasis,
        "risk_position": risk_position(db, investigation_id, window_days=window_days),
        "decision_queue": decision_queue(db, investigation_id),
        "assurance_health": assurance_health(db, investigation_id),
        "exposure_lens": exposure_lens(db, investigation_id),
        "system_integrity": system_integrity(db, investigation_id),
        "alerts": alerts(db, investigation_id),
        "contract": {
            "residual_always_with_confidence": True,
            "gate_status_always_shown": True,
            "acceptance_requires_ledger_event": True,
            "note": ("Anti-patterns this board is built to avoid: residual "
                     "without confidence, snapshots detached from the ledger, "
                     "and swarm health hidden from leadership."),
        },
    }


# --------------------------------------- acceptance / exception register ---

def record_decision(db, assessment_id: int, decision: str, *, actor: str,
                    rationale: str = "", expires_days: Optional[int] = None,
                    override: bool = False,
                    investigation_id: Optional[int] = None) -> dict[str, Any]:
    """Record a leadership decision: accept, guardrails, reject, or exception.

    Written to the assessment and to the ledger with identity and rationale,
    because an acceptance nobody can attribute is not a decision. An exception
    is always time-bounded: expiry drops the row back to open and is what
    triggers re-evaluation, so an override cannot quietly become permanent.
    """
    from .models import SecurityAssessment

    rec = db.get(SecurityAssessment, int(assessment_id))
    if not rec:
        raise LookupError("assessment not found")
    decision = str(decision or "").strip().lower()
    allowed = {A.DECISION_ACCEPT, A.DECISION_GUARDRAILS, A.DECISION_REJECT,
               "exception"}
    if decision not in allowed:
        raise ValueError(f"decision must be one of {sorted(allowed)}")
    if not str(actor or "").strip():
        raise ValueError("a decision must be attributable to a named actor")
    if decision == "exception" and not str(rationale or "").strip():
        raise ValueError("an exception requires a written rationale")

    ens = _load(rec.assurance_json, {})
    derived = (ens.get("decision") or {}).get("decision")
    now = _now()
    expires = None
    if decision == "exception":
        days = expires_days if expires_days and expires_days > 0 else DEFAULT_EXCEPTION_DAYS
        expires = now + timedelta(days=days)

    rec.assurance_decision = decision
    rec.assurance_decided_by = str(actor)
    rec.assurance_decided_at = now
    rec.assurance_decision_note = str(rationale or "")
    rec.assurance_decision_expires_at = expires
    db.commit()

    ledger_hash = AL.record_human_decision(
        f"akm-run-{rec.run_id}" if rec.run_id else f"akm-assessment-{rec.id}",
        actor=str(actor), decision=decision, assessment_id=rec.id,
        rationale=str(rationale or ""),
        expires_at=expires.isoformat() if expires else None,
        evidence_confidence=(ens.get("evidence_confidence")
                             if isinstance(ens, dict) else None),
        override=bool(override or (decision != derived and decision != "exception")))

    return {
        "assessment_id": rec.id,
        "decision": decision,
        "decision_derived": derived,
        "overrode_derivation": bool(decision != derived and decision != "exception"),
        "actor": actor,
        "rationale": rationale,
        "recorded_at": now.isoformat(),
        "expires_at": expires.isoformat() if expires else None,
        "ledger_event": ledger_hash,
        "recorded_in_ledger": bool(ledger_hash),
        "note": ("An override of the derived recommendation is kept visible "
                 "as one, so a later reader can see the human disagreed with "
                 "the computation."),
    }


def exception_register(db, investigation_id: Optional[int] = None,
                       ) -> dict[str, Any]:
    """Time-bounded exceptions, with expiry status."""
    rows = _assessments(db, investigation_id)
    now = _now()
    out = []
    for rec in rows:
        if (rec.assurance_decision or "") != "exception":
            continue
        exp = rec.assurance_decision_expires_at
        if exp and exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        out.append({
            "assessment_id": rec.id,
            "product": rec.product_name or "",
            "investigation_id": rec.investigation_id,
            "actor": rec.assurance_decided_by,
            "rationale": rec.assurance_decision_note,
            "expires_at": exp.isoformat() if exp else None,
            "expired": bool(exp and exp <= now),
            "days_remaining": (exp - now).days if exp else None,
            "reevaluation_due": bool(exp and exp <= now),
        })
    return {
        "exceptions": out,
        "count": len(out),
        "expired": sum(1 for e in out if e["expired"]),
        "note": ("An expired exception stops protecting the score: the row "
                 "returns to open and re-evaluation is due."),
    }


def change_log(db, investigation_id: int) -> dict[str, Any]:
    """Superseded assessments as a short change-log.

    §6's redundancy complaint: multiple overlapping assessments with slight
    threat-list drift, and a reader who has to dig for the current number.
    History stays queryable, but the current row is unambiguous.
    """
    rows = _assessments(db, investigation_id)
    current = _latest_per_investigation(rows)
    current_ids = {a["assessment_id"] for a in current}
    superseded = []
    for rec in rows:
        a = _assessment_dict(rec)
        if a["assessment_id"] in current_ids:
            continue
        a["supersedes_id"] = rec.supersedes_id
        a["threat_pack_version"] = rec.threat_pack_version
        superseded.append(a)
    superseded.sort(key=lambda a: a.get("created_at") or "", reverse=True)
    return {
        "current": [{"assessment_id": a["assessment_id"], "product": a["product_name"],
                     "path": a["scoring_path"],
                     "verified_residual_pct": a.get("verified_residual_pct"),
                     "evidence_confidence_pct": (
                         round(float(a["evidence_confidence"]) * 100)
                         if a.get("evidence_confidence") is not None else None),
                     "created_at": a.get("created_at")}
                    for a in current],
        "superseded": [{"assessment_id": a["assessment_id"],
                        "product": a["product_name"],
                        "path": a["scoring_path"],
                        "verified_residual_pct": a.get("verified_residual_pct"),
                        "declared_residual_pct": a.get("declared_residual_pct"),
                        "evidence_confidence_pct": (
                            round(float(a["evidence_confidence"]) * 100)
                            if a.get("evidence_confidence") is not None else None),
                        "threat_pack_version": a.get("threat_pack_version"),
                        "supersedes_id": a.get("supersedes_id"),
                        "created_at": a.get("created_at")}
                       for a in superseded],
        "superseded_count": len(superseded),
        "note": ("History is retained, never deleted. The current row is "
                 "identified per (investigation, scoring path) so a reader is "
                 "never shown two current residuals for one product."),
    }