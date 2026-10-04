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

#: How long a decision may sit in the queue before leadership is told. An SLA is
#: only useful if something raises its voice when it is missed, so
#: :func:`alerts` turns an overdue item into a notification rather than leaving
#: "overdue" as a column nobody reads.
DECISION_SLA_DAYS = 14

TIER_ORDER = ("restricted_data", "confidential_data", "internal", "public")

#: Layers an assessment row can belong to. A model assessment carries model_json;
#: everything else assessed a product. Privacy and supply-chain rows are register
#: risks, not assessments, so they cannot appear in this view at all.
LAYER_ORDER = ("product", "model")

#: Accepted spellings for a recorded decision, mapped onto the stored constants.
#: The short forms are what a person says out loud in a review, so the API takes
#: them and canonicalises once, here -- rather than 422-ing a caller who typed
#: the word the UI shows.
DECISION_ALIASES: dict[str, str] = {
    A.DECISION_ACCEPT: A.DECISION_ACCEPT,
    "accepted": A.DECISION_ACCEPT,
    A.DECISION_GUARDRAILS: A.DECISION_GUARDRAILS,
    "guardrails": A.DECISION_GUARDRAILS,
    A.DECISION_REJECT: A.DECISION_REJECT,
    "reject": A.DECISION_REJECT,
    "rejected": A.DECISION_REJECT,
    "exception": "exception",
}

#: Every decision state a queue row can hold, for filters and counts.
ALL_STATES = (STATE_BLOCKED, STATE_GUARDRAILS, STATE_OPEN,
              STATE_ACCEPTED, STATE_REJECTED)

#: Sort orders for the decision queue. ``residual`` puts the biggest exposure in
#: front; ``age`` puts the longest-waiting in front, which is the order a
#: backlog is actually cleared in; ``confidence`` surfaces the rows whose number
#: is least trustworthy.
QUEUE_SORTS = ("residual", "age", "confidence", "product")


def canonical_decision(value: str) -> Optional[str]:
    """Map any accepted spelling of a decision onto its stored constant.

    Returns ``None`` for anything unrecognised so the caller can raise with the
    full set of accepted spellings rather than silently persisting a value that
    no reader of the row will recognise.
    """
    return DECISION_ALIASES.get(str(value or "").strip().lower())


def _layer_of(rec: Any) -> str:
    """Which layer an assessment row belongs to, from what it actually stores."""
    return "model" if getattr(rec, "model_json", None) else "product"


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
        "layer": _layer_of(rec),
        "initiative_id": getattr(rec, "initiative_id", None),
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


def resolve_scope(investigation_id: Optional[int] = None, *,
                  initiative_id: Optional[int] = None,
                  layer: Optional[str] = None,
                  exposure: Optional[str] = None,
                  window_days: int = 90) -> dict[str, Any]:
    """Validate and normalise the board's read scope.

    A filter is never applied silently: an unknown layer or a bad window raises
    rather than quietly widening or narrowing the population, because a board
    that silently drops rows is worse than one that refuses.
    """
    try:
        window = max(1, int(window_days))
    except (TypeError, ValueError):
        raise ValueError(f"window_days must be a number, got {window_days!r}")
    if layer and layer not in LAYER_ORDER:
        raise ValueError(f"unknown layer: {layer} (expected one of {list(LAYER_ORDER)})")
    if exposure and exposure not in TIER_ORDER:
        raise ValueError(f"unknown exposure tier: {exposure}")
    return {
        "investigation_id": int(investigation_id) if investigation_id else None,
        "initiative_id": int(initiative_id) if initiative_id else None,
        "layer": layer or None,
        "exposure": exposure or None,
        "window_days": window,
    }


def _assessments(db, investigation_id: Optional[int] = None, *,
                 initiative_id: Optional[int] = None,
                 layer: Optional[str] = None,
                 exposure: Optional[str] = None) -> list[Any]:
    """Assessment rows in scope, newest first.

    ``initiative_id`` and ``exposure`` are stored columns and filter in SQL;
    ``layer`` is derived from whether the row carries model metadata, so it is
    applied in Python where that derivation lives.
    """
    from .models import SecurityAssessment

    q = db.query(SecurityAssessment)
    if investigation_id:
        q = q.filter(SecurityAssessment.investigation_id == int(investigation_id))
    if initiative_id:
        q = q.filter(SecurityAssessment.initiative_id == int(initiative_id))
    if exposure:
        q = q.filter(SecurityAssessment.exposure == exposure)
    rows = q.order_by(SecurityAssessment.created_at.desc()).all()
    if layer:
        rows = [r for r in rows if _layer_of(r) == layer]
    return rows


def _in_scope(rows: list[Any], *, initiative_id: Optional[int] = None,
              layer: Optional[str] = None) -> list[Any]:
    """Apply the derived filters to an already-investigation-narrowed list."""
    out = rows
    if initiative_id:
        out = [r for r in out
               if getattr(r, "initiative_id", None) == int(initiative_id)]
    if layer:
        out = [r for r in out if _layer_of(r) == layer]
    return out


def _investigations(db, ids: set[int]) -> dict[int, str]:
    from .models import Investigation

    if not ids:
        return {}
    rows = db.query(Investigation).filter(Investigation.id.in_(list(ids))).all()
    return {r.id: (r.title or "Untitled") for r in rows}


# ------------------------------------------- A. Executive risk position ----

def risk_position(db, investigation_id: Optional[int] = None, *,
                  window_days: int = 90,
                  initiative_id: Optional[int] = None,
                  layer: Optional[str] = None,
                  exposure: Optional[str] = None) -> dict[str, Any]:
    """Aggregate verified residual by data tier, with confidence beside it.

    Segmented by tier because "Public" and "Restricted" averaged into one
    number is a number nobody can act on. Confidence is reported as its own
    figure: a 24 with 30% evidence confidence is a different decision from a
    24 with 85%.
    """
    rows = _assessments(db, investigation_id, initiative_id=initiative_id,
                        layer=layer, exposure=exposure)
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
    # Per-tier threat dominance: which T##s actually drive a tier's residual, so
    # "restricted is the worst tier" can be answered with the specific threat
    # rather than left as a mood.
    threats_by_tier: dict[str, dict[str, dict[str, Any]]] = {}
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
                entry = {
                    "threat_id": t.get("id"),
                    "title": str(t.get("title") or "")[:70],
                    "verified_residual": t.get("verified_residual"),
                    "declared_residual": t.get("declared_residual"),
                    "coverage_confidence_pct": t.get("coverage_confidence_pct"),
                    "forced_to_inherent": t.get("forced_to_inherent"),
                    "product": a["product_name"],
                    "assessment_id": a["assessment_id"],
                    "tier": tier,
                }
                top_threats.append(entry)
                bucket = threats_by_tier.setdefault(tier, {})
                key = str(t.get("id") or entry["title"])
                # One threat id can appear on several products; keep the worst
                # instance so the tier list ranks by severity, not by how many
                # rows happened to mention it.
                prev = bucket.get(key)
                if prev is None or (float(entry["verified_residual"] or 0)
                                    > float(prev["verified_residual"] or 0)):
                    entry["products"] = 1 if prev is None else int(prev.get("products") or 1) + 1
                    bucket[key] = entry

    def _mean(xs: list[float]) -> Optional[float]:
        return round(sum(xs) / len(xs), 1) if xs else None

    for rec in by_tier.values():
        rec["mean_verified_residual"] = _mean(rec.pop("verified"))
        rec["mean_declared_residual"] = _mean(rec.pop("declared"))
        rec["mean_forensics"] = _mean(rec.pop("forensics"))

    top_threats.sort(key=lambda t: -(float(t.get("verified_residual") or 0)))
    trend = _trend(rows, cutoff)

    tier_threats = []
    for tier in TIER_ORDER:
        bucket = threats_by_tier.get(tier)
        if not bucket:
            continue
        ranked = sorted(bucket.values(),
                        key=lambda t: -(float(t.get("verified_residual") or 0)))[:5]
        tier_threats.append({
            "tier": tier,
            "threats": ranked,
            "distinct_threats": len(bucket),
            "forced_to_inherent": sum(1 for t in ranked if t.get("forced_to_inherent")),
            "note": ("forced_to_inherent counts threats the evidence gate could "
                     "not substantiate, so the score fell back to inherent risk."),
        })

    return {
        "scope": {"investigation_id": investigation_id,
                  "initiative_id": initiative_id, "layer": layer,
                  "exposure": exposure, "window_days": window_days},
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
        "top_threats_by_tier": tier_threats,
        "trend": trend,
        "trend_windows": _trend_windows(rows),
        "portfolio_series": _portfolio_series(rows, window_days),
        # The per-tier trend has to use the window the caller asked for.
        # Hard-coding 90 here meant a 365-day board reported per-tier movement
        # over a different period than its own headline trend.
        "tier_trends": _tier_trends(rows, window_days),
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


#: Windows the trend strip reports at once. One number answers "is it getting
#: better"; three answer "over what horizon", which is the question a reviewer
#: actually asks when a quarter looks worse than a week.
TREND_WINDOWS = (30, 90, 365)


def _row_point(rec: Any) -> tuple[Optional[datetime], Optional[float], Optional[float]]:
    """(created_at, residual_pct, confidence) for one row, normalised once."""
    created = rec.created_at
    if created and created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    a = _assessment_dict(rec)
    v = a.get("verified_residual_pct")
    if v is None:
        v = a.get("declared_residual_pct")
    conf = a.get("evidence_confidence")
    return (created, float(v) if v is not None else None,
            float(conf) if conf is not None else None)


def _trend_windows(rows: list[Any], windows=TREND_WINDOWS) -> list[dict[str, Any]]:
    """Residual and confidence at several horizons, so short and long views can
    disagree honestly instead of one window being chosen to suit the story."""
    now = _now()
    points = [(c, v, cf) for (c, v, cf) in (_row_point(r) for r in rows) if c]
    out = []
    for days in windows:
        cutoff = now - timedelta(days=days)
        win = [p for p in points if p[0] >= cutoff]
        prior = [p for p in points if p[0] < cutoff]
        wv = [p[1] for p in win if p[1] is not None]
        pv = [p[1] for p in prior if p[1] is not None]
        wc = [p[2] for p in win if p[2] is not None]
        pc = [p[2] for p in prior if p[2] is not None]
        wm = round(sum(wv) / len(wv), 1) if wv else None
        pm = round(sum(pv) / len(pv), 1) if pv else None
        delta = round(wm - pm, 1) if (wm is not None and pm is not None) else None
        out.append({
            "window_days": days,
            "mean_residual_pct": wm,
            "prior_mean_residual_pct": pm,
            "delta_pct_points": delta,
            "direction": ("improving" if delta is not None and delta < 0
                          else "worsening" if delta is not None and delta > 0
                          else "flat" if delta == 0 else "insufficient_history"),
            "mean_confidence_pct": (round(sum(wc) / len(wc) * 100)
                                    if wc else None),
            "prior_mean_confidence_pct": (round(sum(pc) / len(pc) * 100)
                                          if pc else None),
            "samples": len(win),
            "prior_samples": len(prior),
        })
    return out


def _tier_trends(rows: list[Any], window_days: int = 90) -> list[dict[str, Any]]:
    """Per-tier residual at the window and before it.

    Averaging the tiers together to draw one trend line is the same mistake as
    averaging them into one score, one level up: a flat portfolio line can be
    four tiers moving in opposite directions.
    """
    cutoff = _now() - timedelta(days=max(1, window_days))
    buckets: dict[str, dict[str, list[float]]] = {}
    for rec in rows:
        a = _assessment_dict(rec)
        tier = a["exposure"] if a["exposure"] in TIER_ORDER else "internal"
        created, v, _cf = _row_point(rec)
        if v is None or created is None:
            continue
        slot = buckets.setdefault(tier, {"prior": [], "window": []})
        slot["window" if created >= cutoff else "prior"].append(v)
    out = []
    for tier in TIER_ORDER:
        slot = buckets.get(tier)
        if not slot:
            continue
        wv = slot["window"]
        pv = slot["prior"]
        wm = round(sum(wv) / len(wv), 1) if wv else None
        pm = round(sum(pv) / len(pv), 1) if pv else None
        out.append({
            "tier": tier,
            "window_mean_residual_pct": wm,
            "prior_mean_residual_pct": pm,
            "delta_pct_points": (round(wm - pm, 1)
                                 if (wm is not None and pm is not None) else None),
            "window_samples": len(wv),
            "prior_samples": len(pv),
            "series": _sparkline((pv or []) + (wv or [])),
        })
    return out


def _portfolio_series(rows: list[Any], window_days: int,
                      buckets: int = 24) -> list[dict[str, Any]]:
    """A dated residual+confidence series for charting.

    ``_sparkline`` folds values into fixed-width buckets with no dates, which is
    the right shape for a 12-glyph hint and the wrong shape for a chart: a line
    with no x-axis cannot show that the last point is six months old. Every point
    here carries the window it covers, so the renderer can label the axis and a
    reader can see how much history actually exists.

    A bucket with no assessments is omitted rather than zero-filled. Drawing a
    zero for a quiet fortnight would read as "risk fell to nothing", which is the
    single most misleading thing this chart could do.
    """
    cutoff = _now() - timedelta(days=max(1, window_days))
    edges: list[datetime] = []
    span = max(1, window_days)
    for i in range(buckets + 1):
        edges.append(cutoff + timedelta(days=span * i / float(buckets)))
    acc: list[dict[str, list[float]]] = [{"v": [], "c": []} for _ in range(buckets)]
    for rec in rows:
        created, v, cf = _row_point(rec)
        if created is None or created < cutoff:
            continue
        idx = int((created - cutoff).total_seconds()
                  / max(1.0, (edges[-1] - edges[0]).total_seconds()) * buckets)
        idx = min(buckets - 1, max(0, idx))
        if v is not None:
            acc[idx]["v"].append(v)
        if cf is not None:
            acc[idx]["c"].append(cf * 100.0 if cf <= 1.0 else cf)
    out: list[dict[str, Any]] = []
    for i, slot in enumerate(acc):
        vv, cc = slot["v"], slot["c"]
        if not vv and not cc:
            continue
        out.append({
            "bucket_start": edges[i].date().isoformat(),
            "samples": len(vv) or len(cc),
            "mean_verified_residual_pct": (round(sum(vv) / len(vv), 1)
                                           if vv else None),
            "mean_confidence_pct": (round(sum(cc) / len(cc), 1) if cc else None),
            "worst_residual_pct": round(max(vv), 1) if vv else None,
        })
    return out


def _sparkline(values: list[float], buckets: int = 12) -> list[Optional[int]]:
    """Residual values folded into a fixed-width series for a sparkline.

    Values are counts, not risk: a bucket with no rows is ``None`` so the
    renderer leaves a gap rather than drawing a zero that reads as "safe".
    """
    if not values:
        return []
    if len(values) <= buckets:
        return [int(round(v)) for v in values]
    out: list[Optional[int]] = []
    size = len(values) / float(buckets)
    for i in range(buckets):
        chunk = values[int(i * size):max(int((i + 1) * size), int(i * size) + 1)]
        if chunk:
            out.append(int(round(sum(chunk) / len(chunk))))
    return out


# ------------------------------------------------- B. Decision queue -------

def decision_queue(db, investigation_id: Optional[int] = None, *,
                   states: Optional[list[str]] = None,
                   limit: int = 25, offset: int = 0,
                   tier: Optional[str] = None,
                   sort: str = "residual",
                   sla_days: int = DECISION_SLA_DAYS,
                   initiative_id: Optional[int] = None,
                   layer: Optional[str] = None,
                   exposure: Optional[str] = None) -> dict[str, Any]:
    """Everything waiting on a leadership decision, with what would change it.

    Each row carries the verified residual *and* its evidence confidence,
    architecture-gate status and blast-radius summary: the four things a
    sign-off is actually accepting. Age is on the row too, because a queue
    nobody can tell is stale is a queue that only ever grows.
    """
    if sort not in QUEUE_SORTS:
        raise ValueError(f"unknown sort: {sort} (expected one of {list(QUEUE_SORTS)})")
    # The board takes `exposure` from the URL and the queue filter takes `tier`.
    # Accept both spellings here so a caller cannot silently get an unfiltered
    # queue because it used the other word.
    if tier and exposure and tier != exposure:
        raise ValueError(f"conflicting tiers: tier={tier} exposure={exposure}")
    tier = tier or exposure
    if tier and tier not in TIER_ORDER:
        raise ValueError(f"unknown exposure tier: {tier}")
    rows = _assessments(db, investigation_id, initiative_id=initiative_id, layer=layer,
                        exposure=tier)
    latest = _latest_per_investigation(rows)
    titles = _investigations(db, {a["investigation_id"] for a in latest})
    now = _now()
    wanted = set(states) if states else {STATE_OPEN, STATE_GUARDRAILS, STATE_BLOCKED}
    unknown_states = sorted(wanted - set(ALL_STATES))
    if unknown_states:
        raise ValueError(f"unknown state(s): {unknown_states} "
                         f"(expected from {list(ALL_STATES)})")
    queue = []
    for a in latest:
        state = _decision_state(a, now)
        if state not in wanted:
            continue
        norm_tier = a["exposure"] if a["exposure"] in TIER_ORDER else "internal"
        if tier and norm_tier != tier:
            continue
        radius = a.get("blast_radius") or {}
        # Age is measured from the assessment, and an accepted row is aged from
        # when it was signed rather than from when it was scored: a decision
        # taken in week one does not stay "waiting" forever.
        anchor = a.get("created_at")
        if state == STATE_ACCEPTED:
            # Falls back to the scoring date for a row the scorer accepted
            # automatically. Those rows have no signature, so ageing them from
            # `None` would report every derived acceptance as brand new.
            anchor = a.get("decision_at") or anchor
        age_days = _days_between(anchor, now)
        queue.append({
            "assessment_id": a["assessment_id"],
            "investigation_id": a["investigation_id"],
            "investigation_title": titles.get(a["investigation_id"], ""),
            "initiative_id": a.get("initiative_id"),
            "layer": a.get("layer"),
            "product": a["product_name"],
            "tier": norm_tier,
            "state": state,
            "verified_residual_pct": a.get("verified_residual_pct"),
            "declared_residual_pct": a.get("declared_residual_pct"),
            "headline_layer": a.get("headline_layer"),
            "evidence_confidence_pct": (round(float(a["evidence_confidence"]) * 100)
                                        if a.get("evidence_confidence") is not None else None),
            "architecture_gate": a["architecture_gate"].get("banner"),
            "architecture_open_items": a["architecture_gate"].get("open_items") or [],
            "blast_radius": radius.get("summary"),
            # The numeric figures beside the summary sentence. Without them a
            # client can only sort a blast-radius column as text, which orders
            # "1,000" after "90,000".
            "records_at_risk": (int(radius["records_at_risk"])
                                if radius.get("records_at_risk") is not None
                                else None),
            "privileged_users": (int(radius["privileged_users"])
                                 if radius.get("privileged_users") is not None
                                 else None),
            "max_payload_mb": radius.get("max_payload_mb"),
            "quantified": radius.get("quantified"),
            "forensics_band": (a.get("forensics") or {}).get("band"),
            "recommended_decision": a.get("decision_derived"),
            "recommended_headline": a.get("decision_headline"),
            "gates_open": a.get("gates_open") or [],
            "recorded_decision": a.get("decision_recorded"),
            "decision_actor": a.get("decision_actor"),
            "decision_note": a.get("decision_note"),
            "decision_at": a.get("decision_at"),
            "expires_at": a.get("expires_at"),
            "created_at": a.get("created_at"),
            "age_days": age_days,
            "sla_days": sla_days,
            "over_sla": bool(age_days is not None and age_days > sla_days),
            "dossier_link": f"/api/investigations/{a['investigation_id']}/dossier/markdown",
            "assessment_link": f"/api/security/assessments/{a['assessment_id']}",
            "vendor_questionnaire_available": bool(
                (a.get("architecture_gate") or {}).get("open_items")),
            "vendor_questionnaire_link": (
                f"/api/security/assessments/{a['assessment_id']}/vendor-questionnaire"
                if (a.get("architecture_gate") or {}).get("open_items") else None),
            "review_queue_link": f"/api/security/assessments/{a['assessment_id']}/review-queue",
        })
    queue.sort(key=_queue_sort_key(sort))
    total = len(queue)
    off = max(0, int(offset or 0))
    lim = max(1, int(limit or 25))
    page = queue[off:off + lim]
    return {
        "items": page,
        "count": total,
        "returned": len(page),
        "offset": off,
        "limit": lim,
        "has_more": (off + len(page)) < total,
        "over_sla": sum(1 for r in page if r["over_sla"]),
        "over_sla_total": sum(1 for r in queue if r["over_sla"]),
        "sort": sort,
        "tier": tier,
        "states": {s: sum(1 for r in queue if r["state"] == s) for s in ALL_STATES},
        "by_tier": {t: sum(1 for r in queue if r["tier"] == t) for t in TIER_ORDER},
        "sla_days": sla_days,
        "note": ("Every row shows verified residual with its evidence "
                 "confidence and gate status. A residual without them is not a "
                 "decision item."),
        "generated": now.isoformat(),
    }


def _days_between(anchor: Optional[str], now: datetime) -> Optional[float]:
    """Whole-ish days from an ISO timestamp to now, or None when unknown."""
    if not anchor:
        return None
    try:
        ts = datetime.fromisoformat(str(anchor).replace("Z", "+00:00"))
    except Exception:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return max(0, int((now - ts).total_seconds() // 86400))


def _queue_sort_key(sort: str):
    """Sort key for one queue order, always with a stable tiebreak.

    Every order falls back to the same severity key, so two rows with equal
    residual do not swap places between page loads and make a paginated queue
    feel like it is shuffling.
    """
    state_order = {STATE_BLOCKED: 0, STATE_GUARDRAILS: 1, STATE_OPEN: 2,
                   STATE_ACCEPTED: 3, STATE_REJECTED: 4}

    def tiebreak(r: dict[str, Any]):
        return (state_order.get(r["state"], 9), str(r.get("product") or ""),
                r["assessment_id"])

    if sort == "age":
        return lambda r: (-(r.get("age_days") or 0),) + tiebreak(r)
    if sort == "confidence":
        # Ascending: the least trustworthy number is the one needing a decision.
        return lambda r: (r.get("evidence_confidence_pct")
                          if r.get("evidence_confidence_pct") is not None else 101,
                          ) + tiebreak(r)
    if sort == "product":
        return lambda r: (str(r.get("product") or "").lower(),) + tiebreak(r)
    return lambda r: (-(r.get("verified_residual_pct") or 0),) + tiebreak(r)


# ------------------------------------- C. Control & assurance health -------

def assurance_health(db, investigation_id: Optional[int] = None, *,
                     initiative_id: Optional[int] = None,
                     layer: Optional[str] = None,
                     exposure: Optional[str] = None) -> dict[str, Any]:
    """Controls verified vs declared, forensics across the portfolio, ledger
    integrity, interrupted runs, overdue evidence reviews."""
    rows = _assessments(db, investigation_id, initiative_id=initiative_id,
                        layer=layer, exposure=exposure)
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
        "scope": {"investigation_id": investigation_id,
                  "initiative_id": initiative_id, "layer": layer,
                  "exposure": exposure},
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

def exposure_lens(db, investigation_id: Optional[int] = None, *,
                  initiative_id: Optional[int] = None,
                  layer: Optional[str] = None,
                  exposure: Optional[str] = None) -> dict[str, Any]:
    """Restricted/Confidential assets, privileged users, materiality flags."""
    rows = _assessments(db, investigation_id, initiative_id=initiative_id,
                        layer=layer, exposure=exposure)
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
        "scope": {"investigation_id": investigation_id,
                  "initiative_id": initiative_id, "layer": layer,
                  "exposure": exposure},
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
                     limit: int = 20, *,
                     initiative_id: Optional[int] = None,
                     layer: Optional[str] = None,
                     exposure: Optional[str] = None) -> dict[str, Any]:
    """Swarm health, pack currency, ledger completeness, time-to-close."""
    rows = _assessments(db, investigation_id, initiative_id=initiative_id,
                        layer=layer, exposure=exposure)
    latest = _latest_per_investigation(rows)

    swarm_stats: dict[str, Any] = {"roles": [], "hops": 0, "failures": 0,
                                   "gate_failures": 0,
                                   "retries": 0, "overall_success_rate": None,
                                   "failure_rate": None, "gate_failure_rate": None}
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
            swarm_stats["gate_failures"] += h["gate_failures"]
            swarm_stats["retries"] += h["retries"]
            merged: dict[str, dict[str, Any]] = {}
            for r in h["roles"]:
                slot = merged.setdefault(r["role"], {**r, "attempts": 0,
                                                     "completions": 0, "failures": 0,
                                                     "gate_failures": 0})
                slot["attempts"] += r["attempts"]
                slot["completions"] += r["completions"]
                slot["failures"] += r["failures"]
                # `.get`, not `[]`: SW.health reports gate failures in its
                # portfolio total only, so the per-role rows have no such key.
                # Indexing it raised KeyError on the first investigation that
                # had any swarm activity at all.
                slot["gate_failures"] += r.get("gate_failures") or 0
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
    # Two different rates, because they answer two different questions. Fabric
    # reliability is failures over role attempts; the gate rate is the share of
    # failures the policy engine caused -- a gate doing its job, not flakiness.
    # Reporting one as the other made a working gate look like a broken swarm.
    swarm_stats["failure_rate"] = (
        round(swarm_stats["failures"] / total_attempts, 2)
        if total_attempts else None)
    swarm_stats["gate_failure_rate"] = (
        round(swarm_stats["gate_failures"] / swarm_stats["failures"], 2)
        if swarm_stats["failures"] else None)
    swarm_stats["rate_note"] = (
        "failure_rate = role failures / role attempts (fabric reliability). "
        "gate_failure_rate = gate-caused failures / all failures (a high share "
        "means the architecture gate is working, not that the swarm is broken)."
    )

    health = assurance_health(db, investigation_id, initiative_id=initiative_id,
                              layer=layer)
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
        "scope": {"investigation_id": investigation_id,
                  "initiative_id": initiative_id, "layer": layer,
                  "exposure": exposure},
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

def alerts(db, investigation_id: Optional[int] = None, *,
           initiative_id: Optional[int] = None,
           layer: Optional[str] = None,
           exposure: Optional[str] = None,
           sla_days: int = DECISION_SLA_DAYS,
           include_acknowledged: bool = False,
           queue_states: Optional[list[str]] = None) -> dict[str, Any]:
    """Notifications, not just tiles: what needs a person now."""
    out: list[dict[str, Any]] = []
    q = decision_queue(db, investigation_id, sla_days=sla_days,
                       initiative_id=initiative_id, layer=layer,
                       exposure=exposure, states=queue_states,
                       limit=1000)
    for item in q["items"]:
        if item["state"] == STATE_BLOCKED:
            out.append({
                "id": f"gate-blocked-{item['assessment_id']}",
                "severity": "block",
                "category": "architecture_gate",
                "title": f"{item['product']}: scoring blocked on architecture",
                "detail": (f"Open: {', '.join(item['architecture_open_items'])}"
                           if item["architecture_open_items"]
                           else "architecture gate incomplete"),
                "assessment_id": item["assessment_id"],
                "age_days": item["age_days"],
                "link": item["dossier_link"],
                "action": "close the architecture questions, then re-score",
            })
        if item["quantified"] is False and str(item["tier"]) in A.RESTRICTED_TIERS:
            out.append({
                "id": f"unquantified-{item['assessment_id']}",
                "severity": "warn",
                "category": "blast_radius",
                "title": f"{item['product']}: blast radius not quantified",
                "detail": "A go/no-go on this tier requires an exposure inventory.",
                "assessment_id": item["assessment_id"],
                "age_days": item["age_days"],
                "link": item["dossier_link"],
                "action": "supply the exposure inventory for this assessment",
            })
        conf = item.get("evidence_confidence_pct")
        if conf is not None and conf < 40:
            out.append({
                "id": f"low-confidence-{item['assessment_id']}",
                "severity": "warn",
                "category": "evidence_confidence",
                "title": f"{item['product']}: evidence confidence {conf}%",
                "detail": ("Most of the residual reduction rests on unevidenced "
                           "controls; the verified residual is the one to read."),
                "assessment_id": item["assessment_id"],
                "age_days": item["age_days"],
                "link": item["dossier_link"],
                "action": "accept evidence, or sign the higher declared residual",
            })
        if item["over_sla"]:
            out.append({
                "id": f"over-sla-{item['assessment_id']}",
                "severity": "warn",
                "category": "decision_sla",
                "title": (f"{item['product']}: decision {item['age_days']}d old "
                          f"(SLA {sla_days}d)"),
                "detail": ("A leadership decision has been waiting past the "
                           "review window; an unrecorded residual is still an "
                           "open risk, not a managed one."),
                "assessment_id": item["assessment_id"],
                "age_days": item["age_days"],
                "link": item["dossier_link"],
                "action": f"record accept, guardrails, reject or exception",
            })
    h = assurance_health(db, investigation_id, initiative_id=initiative_id,
                         layer=layer)
    for alert in (h["ledger"].get("blocking_alerts") or []):
        out.append({
            "id": f"ledger-{alert.get('run_id')}-{alert.get('id')}",
            "severity": "block",
            "category": "ledger_integrity",
            "title": f"Ledger: {alert.get('condition')}",
            "detail": alert.get("why_it_matters"),
            "age_days": None,
            "link": "/api/ledger/verify-export",
            "action": "investigate the ledger gap before relying on these scores",
        })
    if h["overdue_evidence"]["overdue"]:
        out.append({
            "id": "evidence-backlog",
            "severity": "warn",
            "category": "evidence_backlog",
            "title": (f"{h['overdue_evidence']['overdue']} evidence review(s) "
                      "overdue"),
            "detail": h["overdue_evidence"]["note"],
            "age_days": h["overdue_evidence"]["oldest_days"],
            "link": "/api/investigations",
            "action": f"review or reject the {h['overdue_evidence']['overdue']} "
                      f"ageing artifact(s)",
        })
    if h["stalled_runs"]["explainer_gap_open"]:
        failed = h["stalled_runs"].get("explainer_gap_failed") or 0
        out.append({
            "id": "explainer-gap-open",
            "severity": "warn" if not failed else "block",
            "category": "stalled_runs",
            "title": (f"{h['stalled_runs']['explainer_gap_open']} interrupted "
                      f"explainer_gap run(s), {failed} failed"),
            "detail": h["stalled_runs"]["note"],
            "age_days": None,
            "link": "/api/investigations",
            "action": "re-run the interrupted explainer_gap jobs",
        })
    order = {"block": 0, "warn": 1, "info": 2}
    out.sort(key=lambda a: (order.get(a["severity"], 9), str(a["id"])))
    # Annotate the full set first, then decide what to show. Counting the
    # responses off the full set matters: filtering acknowledged alerts out of the
    # panel and then reporting "0 acknowledged" would read as "nobody has
    # responded" when the truth is "everybody already has".
    annotated = _apply_alert_state(db, out, include_acknowledged=True)
    responded = sum(1 for a in annotated if a.get("suppressed"))
    shown = annotated if include_acknowledged else [
        a for a in annotated if not a.get("suppressed")]
    return {"alerts": shown,
            "blocking": sum(1 for a in shown if a["severity"] == "block"),
            "warnings": sum(1 for a in shown if a["severity"] == "warn"),
            "acknowledged": responded,
            "open_blocking": sum(1 for a in shown
                                 if a["severity"] == "block"
                                 and not a.get("suppressed")),
            "sla_days": sla_days,
            "generated": _now().isoformat()}


def _alert_finding_hash(alert: dict[str, Any]) -> str:
    """Stable digest of what the alert is *about*.

    The acknowledgement is bound to this, so a condition that changes substance
    (a different open question, a new residual) reads as stale rather than
    inheriting somebody's "seen it" for the previous version.
    """
    import hashlib

    payload = json.dumps({k: alert.get(k) for k in
                          ("severity", "title", "detail", "assessment_id",
                           "category")},
                         sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def _aware(ts: Optional[datetime]) -> Optional[datetime]:
    """Coerce a stored timestamp to UTC-aware.

    SQLite hands back naive datetimes and Postgres hands back aware ones, so a
    direct comparison against ``_now()`` works on one backend and raises
    ``TypeError`` on the other. Normalising at the boundary means the snooze and
    expiry comparisons are written once and hold on both.
    """
    if ts is None:
        return None
    return ts if ts.tzinfo is not None else ts.replace(tzinfo=timezone.utc)


def _apply_alert_state(db, alerts_in: list[dict[str, Any]], *,
                       include_acknowledged: bool = False
                       ) -> list[dict[str, Any]]:
    """Annotate alerts with acknowledgement state; drop acknowledged ones unless
    asked for. The finding is never suppressed -- only its acknowledgement."""
    from .ledger_models import LeadershipAlertState

    if not alerts_in:
        return []
    ids = [str(a["id"]) for a in alerts_in]
    stored = {r.alert_id: r for r in db.query(LeadershipAlertState)
              .filter(LeadershipAlertState.alert_id.in_(ids)).all()}
    now = _now()
    out: list[dict[str, Any]] = []
    for a in alerts_in:
        row = stored.get(str(a["id"]))
        a = {**a, "finding_hash": _alert_finding_hash(a)}
        if row is None:
            a.update({"acknowledged": False, "suppressed": False,
                      "acknowledged_by": None,
                      "acknowledged_at": None, "acknowledged_note": None,
                      "snoozed_until": None, "acknowledgement_stale": False})
        else:
            snoozed_until = _aware(row.snoozed_until)
            snoozed = bool(snoozed_until and snoozed_until > now)
            # ``acknowledged`` means "a named person responded"; ``suppressed``
            # is what the filter acts on. A live snooze is a response, so it
            # suppresses too -- otherwise "snooze 7 days" would be a button that
            # changes nothing at all.
            acked = (row.status in ("acknowledged", "resolved") and not snoozed)
            suppress = acked or snoozed
            a.update({
                "acknowledged": acked,
                "suppressed": suppress,
                "acknowledged_by": row.acknowledged_by,
                "acknowledged_at": (row.acknowledged_at.isoformat()
                                    if row.acknowledged_at else None),
                "acknowledged_note": row.note,
                "snoozed_until": (snoozed_until.isoformat()
                                  if snoozed_until else None),
                "snoozed": snoozed,
                "acknowledgement_stale": bool(
                    row.finding_hash and row.finding_hash != a["finding_hash"]),
            })
            # A stale acknowledgement does not carry over: the person was looking
            # at a different finding.
            if a["acknowledgement_stale"]:
                a["acknowledged"] = False
                a["suppressed"] = False
        if a.get("suppressed") and not include_acknowledged:
            continue
        out.append(a)
    return out


def acknowledge_alert(db, alert_id: str, *, actor: str,
                      status: str = "acknowledged", note: str = "",
                      snooze_days: Optional[int] = None,
                      finding_hash: Optional[str] = None) -> dict[str, Any]:
    """Record that a named person has seen an alert, and optionally snoozed it.

    Only the response is stored. A snooze has an end date because an alert
    silenced with no expiry is a risk switched off, not a risk triaged.
    """
    from .ledger_models import LeadershipAlertState

    actor = str(actor or "").strip()
    if not actor:
        raise ValueError("acknowledging an alert requires a named actor")
    status = str(status or "acknowledged").strip().lower()
    if status not in ("acknowledged", "snoozed", "resolved", "unacknowledged"):
        raise ValueError("status must be one of acknowledged|snoozed|resolved|"
                         "unacknowledged")
    alert_id = str(alert_id or "").strip()
    if not alert_id:
        raise ValueError("alert_id is required")
    now = _now()
    snoozed_until = None
    if status == "snoozed":
        days = snooze_days if snooze_days and snooze_days > 0 else 7
        snoozed_until = now + timedelta(days=days)
    row = db.query(LeadershipAlertState).filter(
        LeadershipAlertState.alert_id == alert_id).first()
    if row is None:
        row = LeadershipAlertState(alert_id=alert_id)
        db.add(row)
    row.status = status
    row.acknowledged_by = actor
    row.acknowledged_at = now
    row.note = str(note or "")
    row.snoozed_until = snoozed_until
    row.finding_hash = finding_hash
    db.commit()
    return {
        "alert_id": alert_id,
        "status": status,
        "acknowledged_by": actor,
        "acknowledged_at": now.isoformat(),
        "note": row.note,
        "snoozed_until": snoozed_until.isoformat() if snoozed_until else None,
        "note_text": ("Acknowledgement hides a notification, never the "
                      "condition. The alert is still derived from live state "
                      "and returns if the underlying finding changes."),
    }


# --------------------------------------------------- the layered board ----

#: The persona lenses. Each entry is a *lens*, not a separate number: every
#: persona reads the same rows, so two people cannot quote two residuals.
PERSONAS: dict[str, dict[str, Any]] = {
    "executive": {
        "label": "Executive",
        "blurb": "One screen: exposure, confidence, and what needs a signature.",
        "emphasis": ["risk_position", "decision_queue", "alerts"],
    },
    "ciso": {
        "label": "CISO",
        "blurb": "The security position plus the health of the system that produced it.",
        "emphasis": ["risk_position", "assurance_health", "system_integrity",
                     "decision_queue"],
    },
    "dpo": {
        "label": "DPO",
        "blurb": "Where the data actually sits and how big the exposure is.",
        "emphasis": ["exposure_lens", "risk_position", "decision_queue"],
    },
    "legal": {
        "label": "Legal",
        "blurb": "Defensibility: is the record complete and the system auditable.",
        "emphasis": ["assurance_health", "system_integrity", "decision_queue"],
    },
    "audit": {
        "label": "Audit",
        "blurb": "Evidence trail and change history, with no forward-looking noise.",
        "emphasis": ["assurance_health", "system_integrity", "change_log"],
    },
    "security_engineering": {
        "label": "Security Engineering",
        "blurb": ("Owns the evaluation system itself: swarm health, ledger "
                  "completeness, rate and scope control."),
        "emphasis": ["system_integrity", "assurance_health", "risk_position",
                     "alerts", "decision_queue"],
    },
}


def persona_names() -> list[dict[str, Any]]:
    """The lenses, each with the sections it emphasises.

    A client can build its persona selector from this instead of hard-coding the
    list, so adding a lens does not mean editing the UI in two places.
    """
    return [{"id": k, "name": k, "label": v["label"], "blurb": v["blurb"],
             "emphasis": list(v["emphasis"])}
            for k, v in PERSONAS.items()]


def persona_card(name: str) -> dict[str, Any]:
    """One lens, resolved by name."""
    if name not in PERSONAS:
        raise ValueError(f"unknown persona: {name} "
                         f"(expected one of {sorted(PERSONAS)})")
    return persona_names()[[p["id"] for p in PERSONAS].index(name)]


def _row_experiment_coverage(rec: Any) -> dict[str, Any]:
    """One model row's experiment plan, read from stored columns only.

    Experiments are plan-only by design (the product never executes them), so
    "covered" means an open falsifier has a probe mapped onto it, never that
    the probe has run. The plan can live in either the model or the hypothesis
    payload, and hypotheses can be stored under either name, so both are read
    and the first non-empty wins -- the same fallback order model_kb uses.
    """
    mj = _load(getattr(rec, "model_json", None), {}) or {}
    hj = _load(getattr(rec, "hypothesis_json", None), {}) or {}
    scoring = _load(getattr(rec, "scoring_json", None), {}) or {}
    experiments = mj.get("experiments") or hj.get("experiments") or []
    if not isinstance(experiments, list):
        experiments = []
    hypotheses = (hj.get("hypotheses") or hj.get("claims")
                  or scoring.get("hypotheses") or [])
    if not isinstance(hypotheses, list):
        hypotheses = []
    targeted = {str(x) for e in experiments
                for x in ((e.get("targets") or {}).get("hypothesis_ids") or [])}
    open_falsifiers = [str(c.get("hypothesis_id")) for c in hypotheses
                       if str(c.get("status") or "untested")
                       in ("untested", "contested")
                       and str(c.get("hypothesis_id"))]
    return {
        "planned": len(experiments),
        "open_falsifiers": len(open_falsifiers),
        "covered_falsifiers": len([h for h in open_falsifiers
                                   if h in targeted]),
        "planner_unavailable": bool(mj.get("experiment_plan_error")
                                    or hj.get("experiment_plan_error")),
    }


def coverage(db, investigation_id: Optional[int] = None, *,
             initiative_id: Optional[int] = None,
             layer: Optional[str] = None,
             exposure: Optional[str] = None) -> dict[str, Any]:
    """Coverage of the scope: which investigations have been assessed, and
    which model assessments carry an experiment plan over the open questions.

    Two different kinds of coverage, kept separate because they mean different
    things to a board member:
    - investigation coverage: of the investigations in scope, how many have at
      least one assessment. An unassessed investigation is a hole in the board
      -- nothing can be said about it, so it cannot be shown as a residual.
    - experiment coverage: of the latest model-layer assessments, how many
      carry a plan of experiments, and how much of the open-falsifier space
      those plans target. Both numbers count the same scope the rest of the
      board reads, so a tier filter that narrows the risk table also narrows
      the coverage claim.
    """
    from .models import Investigation

    rows = _assessments(db, investigation_id, initiative_id=initiative_id,
                        layer=layer, exposure=exposure)
    latest = _latest_per_investigation(rows)
    by_id = {r.id: r for r in rows}
    recs = [by_id[a["assessment_id"]] for a in latest
            if a["assessment_id"] in by_id]

    # ---- investigation coverage -------------------------------------------
    if investigation_id:
        total_inv = 1
    else:
        total_inv = db.query(Investigation).count()
    assessed_inv = len({a["investigation_id"] for a in latest})
    unassessed = max(0, total_inv - assessed_inv)
    inv_pct = (round(100.0 * assessed_inv / total_inv)
               if total_inv else None)

    # ---- experiment coverage ----------------------------------------------
    model_recs = [r for r in recs if _layer_of(r) == "model"]
    exp_rows = [_row_experiment_coverage(r) for r in model_recs]
    with_plan = sum(1 for e in exp_rows if e["planned"] > 0)
    planned = sum(e["planned"] for e in exp_rows)
    open_falsifiers = sum(e["open_falsifiers"] for e in exp_rows)
    covered_falsifiers = sum(e["covered_falsifiers"] for e in exp_rows)
    planner_unavailable = sum(1 for e in exp_rows
                              if e["planner_unavailable"])
    plan_pct = (round(100.0 * with_plan / len(model_recs))
                if model_recs else None)
    falsifier_pct = (round(100.0 * covered_falsifiers / open_falsifiers)
                     if open_falsifiers else None)

    return {
        "investigations": {
            "total": total_inv,
            "assessed": assessed_inv,
            "unassessed": unassessed,
            "coverage_pct": inv_pct,
        },
        "experiments": {
            "model_assessments": len(model_recs),
            "with_plan": with_plan,
            "planned": planned,
            "planner_unavailable": planner_unavailable,
            "plan_coverage_pct": plan_pct,
            "open_falsifiers": open_falsifiers,
            "covered_falsifiers": covered_falsifiers,
            "falsifier_coverage_pct": falsifier_pct,
        },
        "note": ("Investigation coverage counts investigations with at least "
                 "one assessment in this scope; experiment coverage is "
                 "plan-only by design -- 'covered' means an open falsifier has "
                 "a planned probe, never that the probe has run."),
    }


def board(db, investigation_id: Optional[int] = None, *,
          window_days: int = 90, persona: str = "executive",
          initiative_id: Optional[int] = None,
          layer: Optional[str] = None,
          exposure: Optional[str] = None,
          tier: Optional[str] = None,
          queue_states: Optional[list[str]] = None,
          sort: str = "residual",
          limit: int = 25,
          offset: int = 0,
          sla_days: int = DECISION_SLA_DAYS,
          include_acknowledged: bool = False) -> dict[str, Any]:
    """The layered dashboard: one executive screen, drill-down beneath it.

    Same underlying data for every persona, different default emphasis — a
    role-based view is a lens, not a separate number, so two personas can never
    quote different residuals for the same assessment.
    """
    scope = resolve_scope(investigation_id, initiative_id=initiative_id,
                          layer=layer, exposure=exposure, window_days=window_days)
    persona = (persona or "executive").strip().lower()
    if persona not in PERSONAS:
        raise ValueError(f"unknown persona: {persona} "
                         f"(expected one of {sorted(PERSONAS)})")
    emphasis = PERSONAS[persona]["emphasis"]
    shared = {"investigation_id": scope["investigation_id"],
              "initiative_id": scope["initiative_id"],
              "layer": scope["layer"]}
    queue = decision_queue(db, scope["investigation_id"],
                           initiative_id=scope["initiative_id"],
                           layer=scope["layer"], states=queue_states,
                           sort=sort, limit=limit, offset=offset,
                           sla_days=sla_days, exposure=scope["exposure"])
    return {
        "persona": persona,
        "persona_label": PERSONAS[persona]["label"],
        "persona_blurb": PERSONAS[persona]["blurb"],
        "personas": persona_names(),
        "emphasis": emphasis,
        "scope": scope,
        "risk_position": risk_position(db, scope["investigation_id"],
                                       window_days=scope["window_days"],
                                       initiative_id=scope["initiative_id"],
                                       layer=scope["layer"],
                                       exposure=scope["exposure"]),
        "coverage": coverage(db, scope["investigation_id"],
                             initiative_id=scope["initiative_id"],
                             layer=scope["layer"],
                             exposure=scope["exposure"]),
        "decision_queue": queue,
        # Every section reads the same resolved scope. A tier filter that
        # narrowed the risk table but not the queue or the alerts would show a
        # reader a coherent-looking board about a portfolio nobody is looking at.
        "assurance_health": assurance_health(db, scope["investigation_id"],
                                            initiative_id=scope["initiative_id"],
                                            layer=scope["layer"],
                                            exposure=scope["exposure"]),
        "exposure_lens": exposure_lens(db, scope["investigation_id"],
                                       initiative_id=scope["initiative_id"],
                                       layer=scope["layer"],
                                       exposure=scope["exposure"]),
        "system_integrity": system_integrity(db, scope["investigation_id"],
                                             initiative_id=scope["initiative_id"],
                                             layer=scope["layer"],
                                             exposure=scope["exposure"]),
        "alerts": alerts(db, scope["investigation_id"],
                         initiative_id=scope["initiative_id"],
                         layer=scope["layer"], sla_days=sla_days,
                         exposure=scope["exposure"],
                         include_acknowledged=include_acknowledged),
        "exceptions": exception_register(db, scope["investigation_id"],
                                         initiative_id=scope["initiative_id"],
                                         layer=scope["layer"],
                                         exposure=scope["exposure"]),
        "change_log": change_log(db, scope["investigation_id"],
                                 initiative_id=scope["initiative_id"],
                                 layer=scope["layer"],
                                 exposure=scope["exposure"]),
        "decisions_available": {
            "options": [
                {"value": A.DECISION_ACCEPT, "label": "Accept"},
                {"value": A.DECISION_GUARDRAILS,
                 "label": "Accept with mandatory guardrails"},
                {"value": A.DECISION_REJECT,
                 "label": "Reject until architecture gate closes"},
                {"value": "exception",
                 "label": "Time-bounded exception (requires rationale + expiry)"},
            ],
            "aliases": sorted(DECISION_ALIASES),
            "endpoint": "/api/security/assessments/{assessment_id}/decision",
            "requires_actor": True,
            "exception_requires_rationale": True,
            "default_exception_days": DEFAULT_EXCEPTION_DAYS,
        },
        "queue_filters": {
            "sorts": list(QUEUE_SORTS),
            "states": list(ALL_STATES),
            "tiers": list(TIER_ORDER),
            "layers": list(LAYER_ORDER),
            "default_states": [STATE_OPEN, STATE_GUARDRAILS, STATE_BLOCKED],
            "sla_days": sla_days,
        },
        "contract": {
            "residual_always_with_confidence": True,
            "gate_status_always_shown": True,
            "acceptance_requires_ledger_event": True,
            "note": ("Anti-patterns this board is built to avoid: residual "
                     "without confidence, snapshots detached from the ledger, "
                     "and swarm health hidden from leadership."),
        },
        "generated": _now().isoformat(),
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
    raw = str(decision or "").strip().lower()
    decision = canonical_decision(raw) or ""
    if not decision:
        raise ValueError(
            f"decision must be one of {sorted(set(DECISION_ALIASES))} "
            f"(stored as accept | {A.DECISION_GUARDRAILS} | {A.DECISION_REJECT} "
            f"| exception)")
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
        "decision_requested": raw,
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


def exception_register(db, investigation_id: Optional[int] = None, *,
                       initiative_id: Optional[int] = None,
                       layer: Optional[str] = None,
                       exposure: Optional[str] = None) -> dict[str, Any]:
    """Time-bounded exceptions, with expiry status."""
    rows = _assessments(db, investigation_id, initiative_id=initiative_id,
                        layer=layer, exposure=exposure)
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
            "tier": rec.exposure,
            "actor": rec.assurance_decided_by,
            "rationale": rec.assurance_decision_note,
            "granted_at": (rec.assurance_decided_at.isoformat()
                           if rec.assurance_decided_at else None),
            "expires_at": exp.isoformat() if exp else None,
            "expired": bool(exp and exp <= now),
            "days_remaining": (exp - now).days if exp else None,
            "reevaluation_due": bool(exp and exp <= now),
            "residual_pct": rec.residual_pct,
            "evidence_confidence_pct": (round(float(rec.evidence_confidence) * 100)
                                        if rec.evidence_confidence is not None else None),
            "re_evaluate_link": f"/api/security/assessments/{rec.id}/rescore",
        })
    order = {"expired": 0}
    out.sort(key=lambda e: (order.get("expired" if e["expired"] else "active", 1),
                            -(e["days_remaining"] if e["days_remaining"] is not None else 1e9)))
    return {
        "scope": {"investigation_id": investigation_id,
                  "initiative_id": initiative_id, "layer": layer,
                  "exposure": exposure},
        "exceptions": out,
        "count": len(out),
        "expired": sum(1 for e in out if e["expired"]),
        "active": sum(1 for e in out if not e["expired"]),
        "next_expiry": next((e["expires_at"] for e in out if not e["expired"]), None),
        "note": ("An expired exception stops protecting the score: the row "
                 "returns to open and re-evaluation is due."),
        "generated": now.isoformat(),
    }


def change_log(db, investigation_id: Optional[int] = None, *,
               initiative_id: Optional[int] = None,
               layer: Optional[str] = None,
               exposure: Optional[str] = None) -> dict[str, Any]:
    """Superseded assessments as a short change-log.

    §6's redundancy complaint: multiple overlapping assessments with slight
    threat-list drift, and a reader who has to dig for the current number.
    History stays queryable, but the current row is unambiguous.

    With no investigation the view is portfolio-wide and groups the superseded
    rows by investigation, because a portfolio board is exactly where a
    "which number is current" question appears.
    """
    rows = _assessments(db, investigation_id, initiative_id=initiative_id,
                        layer=layer, exposure=exposure)
    current = _latest_per_investigation(rows)
    current_ids = {a["assessment_id"] for a in current}
    titles = _investigations(db, {r.investigation_id for r in rows})
    # `supersedes_id` lives on the *new* row and points at the row it replaced, so
    # it is the old row that is missing its own successor. Resolve the link here
    # rather than reporting a null on exactly the rows a reader wants to trace.
    replaced_by = {int(rec.supersedes_id): rec.id for rec in rows
                   if getattr(rec, "supersedes_id", None)}
    superseded = []
    for rec in rows:
        a = _assessment_dict(rec)
        if a["assessment_id"] in current_ids:
            continue
        a["superseded_by_id"] = replaced_by.get(int(a["assessment_id"]))
        a["threat_pack_version"] = rec.threat_pack_version
        a["investigation_title"] = titles.get(a["investigation_id"], "")
        superseded.append(a)
    superseded.sort(key=lambda a: a.get("created_at") or "", reverse=True)
    payload = {
        "investigation_id": investigation_id,
        "scope": {"investigation_id": investigation_id,
                  "initiative_id": initiative_id, "layer": layer,
                  "exposure": exposure},
        "current": [{"assessment_id": a["assessment_id"], "product": a["product_name"],
                     "path": a["scoring_path"], "tier": a["exposure"],
                     # Named on every row so the portfolio-wide grouping below
                     # and any drill-down can attribute a row to its owner
                     # without having to look it up again.
                     "investigation_id": a["investigation_id"],
                     "investigation_title": titles.get(a["investigation_id"], ""),
                     "verified_residual_pct": a.get("verified_residual_pct"),
                     "evidence_confidence_pct": (
                         round(float(a["evidence_confidence"]) * 100)
                         if a.get("evidence_confidence") is not None else None),
                     "created_at": a.get("created_at")}
                    for a in current],
        "superseded": [{"assessment_id": a["assessment_id"],
                        "product": a["product_name"],
                        "path": a["scoring_path"],
                        "investigation_id": a["investigation_id"],
                        "investigation_title": a.get("investigation_title", ""),
                        "verified_residual_pct": a.get("verified_residual_pct"),
                        "declared_residual_pct": a.get("declared_residual_pct"),
                        "evidence_confidence_pct": (
                            round(float(a["evidence_confidence"]) * 100)
                            if a.get("evidence_confidence") is not None else None),
                        "threat_pack_version": a.get("threat_pack_version"),
                        "superseded_by_id": a.get("superseded_by_id"),
                        "created_at": a.get("created_at")}
                       for a in superseded],
        "superseded_count": len(superseded),
        "note": ("History is retained, never deleted. The current row is "
                 "identified per (investigation, scoring path) so a reader is "
                 "never shown two current residuals for one product."),
        "generated": _now().isoformat(),
    }
    if investigation_id is None:
        # Portfolio-wide, so group by investigation. Only counting superseded
        # rows would report an empty grouping for an investigation that is
        # perfectly current, which reads as "nothing here" rather than
        # "nothing was rewritten here".
        by_inv: dict[int, dict[str, Any]] = {}
        for group, key in ((payload["current"], "current"),
                           (superseded, "superseded")):
            for a in group:
                inv_id = int(a["investigation_id"])
                slot = by_inv.setdefault(
                    inv_id, {"investigation_id": inv_id,
                             "title": titles.get(inv_id, ""),
                             "current": 0, "superseded": 0})
                slot[key] += 1
        payload["by_investigation"] = sorted(
            by_inv.values(), key=lambda r: (-r["current"], -r["superseded"]))
    return payload


# -------------------------------------------------- board export -----------

def export_markdown(db, investigation_id: Optional[int] = None, *,
                    window_days: int = 90, persona: str = "executive",
                    initiative_id: Optional[int] = None,
                    layer: Optional[str] = None,
                    exposure: Optional[str] = None) -> str:
    """The whole board as one Markdown snapshot.

    A regulator asks for a document, not a live endpoint. This is that
    document: the same rows the screen shows, with every number carrying its
    confidence and gate status, plus the generation time so a snapshot cannot
    be mistaken for the live position.
    """
    b = board(db, investigation_id, window_days=window_days, persona=persona,
              initiative_id=initiative_id, layer=layer, exposure=exposure)
    rp = b["risk_position"]
    q = b["decision_queue"]
    ah = b["assurance_health"]
    si = b["system_integrity"]
    ex = b["exceptions"]
    sc = b["scope"]
    L: list[str] = []
    L.append("# Leadership board snapshot")
    L.append("")
    L.append(f"- Generated: {b['generated']}")
    L.append(f"- Persona lens: **{b['persona_label']}** — {b['persona_blurb']}")
    L.append(f"- Scope: investigation={sc['investigation_id'] or 'all'} "
             f"· initiative={sc['initiative_id'] or 'all'} · layer={sc['layer'] or 'all'} "
             f"· tier={sc['exposure'] or 'all'} · window={sc['window_days']}d")
    L.append("")
    L.append("> A residual without its evidence confidence is not a decision "
             "item. Every figure below carries both.")
    L.append("")

    L.append("## Risk position")
    L.append("")
    L.append("| Tier | Assessments | Verified residual | Declared residual | Forensics | "
             "Blast radius quantified | Gate-blocked |")
    L.append("|---|---:|---:|---:|---:|---:|---:|")
    for t in rp["tiers"]:
        L.append(f"| {t['tier']} | {t['count']} | "
                 f"{_pct_or_dash(t.get('mean_verified_residual'))} | "
                 f"{_pct_or_dash(t.get('mean_declared_residual'))} | "
                 f"{_pct_or_dash(t.get('mean_forensics'))} | "
                 f"{t.get('quantified', 0)}/{t['count']} | {t.get('blocked', 0)} |")
    L.append("")
    vvd = rp["verified_vs_declared"]
    L.append(f"- Verified share of claimed reduction: "
             f"{_pct_or_dash(vvd.get('verified_share_pct'))} "
             f"({vvd.get('verified_reduction_pct_points')} of "
             f"{vvd.get('claimed_reduction_pct_points')} points evidenced)")
    L.append(f"- Mean evidence confidence: "
             f"{_pct_or_dash(rp['evidence_confidence'].get('mean_pct'))}")
    tr = rp.get("trend") or {}
    L.append(f"- Trend ({sc['window_days']}d window): {tr.get('direction', 'unknown')} "
             f"· delta {_num(tr.get('delta'))} points")
    L.append("")
    series = rp.get("portfolio_series") or []
    if series:
        # The printed snapshot carries the same dated series the chart draws, so
        # the page a regulator reads can be checked against the screen.
        L.append("Dated residual and confidence (the charted series):")
        L.append("")
        L.append("| From | Mean verified residual | Worst in bucket | Mean confidence | Assessments |")
        L.append("|---|---:|---:|---:|---:|")
        for pt in series:
            L.append(f"| {pt.get('bucket_start')} | "
                     f"{_pct_or_dash(pt.get('mean_verified_residual_pct'))} | "
                     f"{_pct_or_dash(pt.get('worst_residual_pct'))} | "
                     f"{_pct_or_dash(pt.get('mean_confidence_pct'))} | "
                     f"{pt.get('samples', 0)} |")
        L.append("")
    if rp.get("architecture_gaps"):
        L.append("Open architecture gate items:")
        for g in rp["architecture_gaps"][:10]:
            L.append(f"- {g['item']} ({g['assessments']} assessment(s))")
        L.append("")
    if rp.get("top_threats_by_tier"):
        L.append("Dominant threats per tier:")
        for tb in rp["top_threats_by_tier"]:
            names = ", ".join(f"{t.get('threat_id')} ({_num(t.get('verified_residual'))})"
                              for t in tb["threats"][:3])
            L.append(f"- **{tb['tier']}**: {names or 'none scored'}")
        L.append("")

    # Coverage of the scope itself: how much of the portfolio has an
    # assessment at all, and how much of the model space has an experiment
    # plan. A board that reports residuals without saying how much it could
    # not assess is reporting a number with a hole in the denominator.
    cov = b["coverage"]
    inv = cov["investigations"]
    exp = cov["experiments"]
    L.append("## Coverage")
    L.append("")
    if inv["total"]:
        L.append(f"- Investigations assessed: **{inv['assessed']}/{inv['total']}** "
                 f"({_pct_or_dash(inv.get('coverage_pct'))}) — "
                 f"{inv['unassessed']} with no assessment in this scope")
    else:
        L.append("- Investigations assessed: **0/0** — no investigations in this scope")
    L.append(f"- Model assessments with an experiment plan: "
             f"**{exp['with_plan']}/{exp['model_assessments']}** "
             f"({_pct_or_dash(exp.get('plan_coverage_pct'))}) — "
             f"{exp['planned']} experiment(s) planned")
    L.append(f"- Open falsifiers targeted by a planned experiment: "
             f"**{exp['covered_falsifiers']}/{exp['open_falsifiers']}** "
             f"({_pct_or_dash(exp.get('falsifier_coverage_pct'))})"
             + (f" · {exp['planner_unavailable']} plan(s) could not be built"
                if exp["planner_unavailable"] else ""))
    L.append("")
    L.append(f"> {cov['note']}")
    L.append("")

    L.append(f"## Decision queue ({q['count']} item(s))")
    L.append("")
    if not q["items"]:
        L.append("Nothing is waiting on a leadership decision.")
    else:
        L.append("| Product | Tier | State | Verified residual | Confidence | Age | SLA | Recommendation |")
        L.append("|---|---|---|---:|---:|---:|---|---|")
        for r in q["items"]:
            L.append(f"| {r['product']} | {r['tier']} | {r['state']} | "
                     f"{_pct_or_dash(r.get('verified_residual_pct'))} | "
                     f"{_pct_or_dash(r.get('evidence_confidence_pct'))} | "
                     f"{_num(r.get('age_days'))}d | "
                     f"{'OVER' if r.get('over_sla') else 'ok'} | "
                     f"{r.get('recommended_decision') or '—'} |")
    L.append("")

    L.append("## Assurance health")
    L.append("")
    c = ah["controls"]
    L.append(f"- Controls: {c['verified']} evidenced · {c['declared']} declared · "
             f"{c['unknown']} unknown ({_pct_or_dash(c.get('verified_pct'))} evidenced)")
    f = ah["forensics"]
    L.append(f"- Forensics: mean {_num(f.get('mean_score'))} · "
             f"{f.get('reconstructable')}/{f.get('scored')} reconstructable")
    lg = ah["ledger"]
    L.append(f"- Ledger: {lg.get('chains_intact')}/{lg.get('runs_checked')} chains "
             f"intact · mean {lg.get('mean_event_classes_recorded')} of "
             f"{lg.get('mandatory_event_classes')} mandatory event classes recorded")
    oe = ah["overdue_evidence"]
    L.append(f"- Evidence backlog: {oe.get('pending')} pending, "
             f"{oe.get('overdue')} overdue (oldest {oe.get('oldest_days')}d)")
    L.append("")

    L.append("## System integrity")
    L.append("")
    sw = si["swarm"]
    L.append(f"- Swarm: {sw.get('hops')} hops · {sw.get('failures')} failures "
             f"({sw.get('gate_failures')} gate-caused) · "
             f"success rate {_num(sw.get('overall_success_rate'))}")
    L.append(f"- Failure rate {_num(sw.get('failure_rate'))} · "
             f"gate failure rate {_num(sw.get('gate_failure_rate'))}")
    tp = si["threat_pack"]
    L.append(f"- Threat pack currency: {_pct_or_dash(tp.get('currency_pct'))} "
             f"({tp.get('stale')} of {tp.get('assessments')} stale)")
    L.append("")

    L.append("## Alerts")
    L.append("")
    al = b["alerts"]
    if not al["alerts"]:
        L.append("No open alerts.")
    else:
        for a_ in al["alerts"]:
            L.append(f"- **{a_['severity'].upper()}** {a_['title']} — {a_['detail']} "
                     f"_(next: {a_['action']})_")
    L.append("")

    L.append(f"## Exception register ({ex['count']})")
    L.append("")
    if not ex["exceptions"]:
        L.append("No time-bounded exceptions are in force.")
    else:
        for e in ex["exceptions"]:
            L.append(f"- {e['product']} — granted by {e['actor']}, "
                     f"expires {e.get('expires_at')} "
                     f"({e.get('days_remaining')}d remaining)"
                     + (" — **EXPIRED, re-evaluation due**" if e["expired"] else ""))
            if e.get("rationale"):
                L.append(f"  - Rationale: {e['rationale']}")
    L.append("")

    cl = b["change_log"]
    L.append(f"## Change log ({cl['superseded_count']} superseded)")
    L.append("")
    for s in cl["superseded"][:15]:
        L.append(f"- {s['created_at']} · {s['product']} · "
                 f"verified {_pct_or_dash(s.get('verified_residual_pct'))} · "
                 f"pack {s.get('threat_pack_version') or 'unversioned'}"
                 + (f" · superseded by assessment {s['superseded_by_id']}"
                    if s.get("superseded_by_id") else ""))
    L.append("")
    L.append("---")
    L.append("")
    L.append(f"_{b['contract']['note']}_")
    return "\n".join(L)


def _num(v: Any) -> str:
    if v is None:
        return "—"
    try:
        f = float(v)
    except (TypeError, ValueError):
        return str(v)
    return str(int(f)) if f == int(f) else f"{f:g}"


def _pct_or_dash(v: Any) -> str:
    return "—" if v is None else f"{_num(v)}%"
