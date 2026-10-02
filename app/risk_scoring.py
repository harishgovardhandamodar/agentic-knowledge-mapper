"""Register risk scoring — deterministic, reproducible, no LLM.

Pure functions producing inherent, residual, priority, confidence, band.
Versioned + fingerprinted; stored on each row. No second opaque AI score.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

RISK_SCORING_METHOD = "register-risk-scoring-v1"
RISK_SCORING_VERSION = "1.0.0"

# Floor: cannot erase risk entirely (mirror pack _MIN_RESIDUAL)
MIN_RESIDUAL_FACTOR = 0.15

# Exposure weight from situation / assessment tier (0.3–1.0)
EXPOSURE_WEIGHTS = {
    "restricted_data": 1.0,
    "restricted": 1.0,
    "confidential_data": 0.85,
    "confidential": 0.85,
    "internal": 0.55,
    "public": 0.35,
    "public_data": 0.35,
}

# Scope weights: own > cascade > inherited (tunable)
SCOPE_WEIGHTS = {
    "own": 1.0,
    "cascade": 0.85,
    "inherited": 0.75,
    "method_general": 0.35,
}

# Band thresholds on residual (or inherent if residual null)
BAND_THRESHOLDS = [
    ("Critical", 18.0),
    ("High", 12.0),
    ("Medium", 6.0),
    ("Low", 0.0),
]

# Treatment coverage: product C* efficacies, model MM* hints, playbook steps
# Small fixed priors for playbook steps (process)
PLAYBOOK_EFFICACY = 0.25
DECLARED_FACTOR = 0.5  # declared-only vs evidenced

# Priority weights (tunable in one place)
PRIORITY_WEIGHTS = {
    "residual": 0.45,
    "aging": 0.15,
    "unowned": 0.15,
    "untreated": 0.10,
    "uncertainty": 0.10,
    "cascade": 0.05,
}

CHANGE_POLICY = {
    "register-risk-scoring-v1": {
        "major": "change formula, inputs, or band thresholds",
        "minor": "re-tune weights, efficacy priors, scope weights",
        "patch": "wording or rationale only",
        "version": RISK_SCORING_VERSION,
    }
}


def _fingerprint(payload: Any) -> str:
    canon = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha1(canon.encode("utf-8")).hexdigest()[:12]


def risk_scoring_fingerprint() -> str:
    return _fingerprint(
        {
            "id": RISK_SCORING_METHOD,
            "version": RISK_SCORING_VERSION,
            "exposure": EXPOSURE_WEIGHTS,
            "scope": SCOPE_WEIGHTS,
            "bands": BAND_THRESHOLDS,
            "priority_weights": PRIORITY_WEIGHTS,
            "min_residual": MIN_RESIDUAL_FACTOR,
        }
    )


def _exposure_weight(exposure: str | None) -> float:
    if not exposure:
        return 0.6
    return EXPOSURE_WEIGHTS.get(str(exposure).lower(), 0.6)


def _scope_weight(scope: str | None) -> float:
    return SCOPE_WEIGHTS.get(str(scope or "").lower(), 0.75)


def _band_for(score: float | None) -> str:
    if score is None:
        return "Unknown"
    for name, thresh in BAND_THRESHOLDS:
        if score >= thresh:
            return name
    return "Low"


def _inputs_hash(row: dict[str, Any]) -> str:
    keys = ["layer", "severity", "exposure", "scope", "evidence_ids", "treatment_coverage", "status", "aging_days", "has_owner"]
    payload = {k: row.get(k) for k in keys}
    # normalize evidence_ids order
    if isinstance(payload.get("evidence_ids"), list):
        payload["evidence_ids"] = sorted(payload["evidence_ids"])
    return _fingerprint(payload)


def inherent_for_row(row: dict[str, Any]) -> tuple[float | None, float, str]:
    """Layer-specific inherent scoring. Returns (inherent, confidence, source)."""
    layer = (row.get("layer") or "").lower()
    exposure_w = _exposure_weight(row.get("exposure"))
    scope_w = _scope_weight(row.get("scope"))
    evidence = row.get("evidence_ids") or []
    evidence_strength = min(1.0, len(evidence) / 3.0) if evidence else 0.0
    # confidence is evidence strength, not a silent upgrade
    confidence = evidence_strength if evidence else 0.2

    # Product: reuse pack residual/inherent if stored (prefer assessment snapshot)
    if layer == "product":
        # If row carries pack residual/inherent, prefer it
        if row.get("residual_score") is not None and row.get("inherent_score") is not None:
            # This path is for re-scoring; for initial inherent, use severity if available
            pass
        # Severity is likelihood*impact already scaled; use it as inherent proxy
        sev = row.get("severity")
        if sev is None:
            return None, confidence, "no severity"
        # scale by exposure and scope, evidence dampens if weak
        base = float(sev) * scope_w
        # weak evidence → don't max out
        inherent = base * (0.5 + 0.5 * (evidence_strength if evidence_strength else 0.5)) * (0.7 + 0.3 * exposure_w)
        return round(min(25.0, inherent), 1), confidence, "product pack proxy"

    if layer == "model":
        # Attack class severity prior * scope * exposure, evidence dampens
        sev = row.get("severity")
        if sev is None:
            # try attack class severity fallback
            sev = 60.0
        base = float(sev) * scope_w * exposure_w
        inherent = base * (0.5 + 0.5 * evidence_strength) if evidence else None
        if inherent is None:
            return None, 0.2, "no evidence"
        return round(min(25.0, inherent), 1), confidence, "model base*scope*exposure"

    if layer == "privacy":
        # PDP/RLHF/pathway: map fields to discrete factors
        # For MVP, use severity if present, else map from confidence_band
        sev = row.get("severity")
        if sev is None:
            # try to map from standing
            band = (row.get("confidence_band") or "").lower()
            if band in ("supported", "partial"):
                sev = 15.0 if band == "partial" else 18.0
            elif band == "unknown":
                return None, 0.2, "unknown policy fields"
            else:
                sev = 10.0
        inherent = float(sev) * scope_w * (0.6 + 0.4 * exposure_w)
        return round(min(25.0, inherent), 1), confidence, "privacy discrete map"

    if layer == "supply_chain":
        sev = row.get("severity") or 12.0
        inherent = float(sev) * scope_w * exposure_w
        return round(min(25.0, inherent), 1), confidence, "supply_chain"

    # fallback
    sev = row.get("severity")
    if sev is None:
        return None, 0.2, "unknown"
    return round(float(sev) * scope_w, 1), confidence, "fallback"


def treatment_coverage_for_row(row: dict[str, Any], db_evidence_factor: float = 1.0) -> float:
    """Coverage 0..1 from mapped controls/playbook efficacy. Declared-only capped."""
    # Expect row to carry mitigation_ids or control_ids; for MVP, use simple heuristic:
    # If row has mitigation_ids, coverage is based on count and efficacy priors
    mids = row.get("mitigation_ids") or row.get("control_ids") or row.get("controls") or []
    if not mids:
        # also check assessment's treatment plan
        plan = row.get("treatment_plan") or {}
        mids = plan.get("control_ids", []) if isinstance(plan, dict) else []
    if not mids:
        return 0.0
    # product C* efficacies: approximate 0.6 avg, model MM* hints 0.5 avg, playbook steps 0.25
    # For deterministic pin, use fixed per-id efficacy map
    eff_map = {
        "C01": 0.6, "C02": 0.6, "C03": 0.6, "C04": 0.6, "C05": 0.6,
        "MM01": 0.5, "MM05": 0.5, "MM16": 0.5, "PB07": 0.25,
    }
    # coverage = 1 - Π(1 - eff * applicability * evidence_factor)
    # applicability 0.8 avg, evidence_factor from db_evidence_factor
    cov = 1.0
    for mid in mids:
        eff = eff_map.get(str(mid), 0.5)
        # declared-only controls count half
        is_declared = row.get("declared_only") and mid in (row.get("declared_only") or [])
        if is_declared:
            eff *= DECLARED_FACTOR
        cov *= (1 - eff * 0.8 * db_evidence_factor)
    coverage = 1 - cov
    return round(max(0.0, min(0.95, coverage)), 3)


def residual_for_row(inherent: float | None, coverage: float) -> float | None:
    if inherent is None:
        return None
    residual = inherent * max(MIN_RESIDUAL_FACTOR, 1 - coverage)
    return round(residual, 1)


def priority_for_row(row: dict[str, Any], residual: float | None, inherent: float | None) -> tuple[float, str]:
    """Priority 0..100, with rationale. Accepted/closed drop out unless overdue."""
    status = (row.get("status") or "open").lower()
    if status in ("accepted", "closed"):
        # check if review overdue
        review_by = row.get("review_by")
        if review_by:
            try:
                rb = datetime.fromisoformat(str(review_by).replace("Z", "+00:00"))
                if rb.tzinfo is None:
                    rb = rb.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) > rb:
                    pass  # overdue, keep priority
                else:
                    return 0.0, "accepted/closed not overdue"
            except Exception:
                return 0.0, "accepted/closed"
        else:
            return 0.0, "accepted/closed no review date"
    # normalize residual 0-25 → 0-1
    residual_norm = min(1.0, (residual or inherent or 0) / 25.0)
    aging_days = row.get("aging_days") or 0
    try:
        aging_days = int(aging_days)
    except Exception:
        aging_days = 0
    aging_norm = min(1.0, aging_days / 90.0)
    has_owner = 1 if row.get("owner") else 0
    has_treatment = 1 if (row.get("mitigation_ids") or row.get("treatment_plan")) else 0
    # uncertainty: confidence low → high uncertainty
    conf = row.get("confidence")
    try:
        conf_f = float(conf) if conf is not None else 0.2
    except Exception:
        conf_f = 0.2
    uncertainty_norm = 1 - max(0.0, min(1.0, conf_f))
    cascade_boost = 1 if (row.get("scope") or "").lower() == "cascade" else 0
    w = PRIORITY_WEIGHTS
    score = (
        w["residual"] * residual_norm
        + w["aging"] * aging_norm
        + w["unowned"] * (0 if has_owner else 1)
        + w["untreated"] * (0 if has_treatment else 1)
        + w["uncertainty"] * uncertainty_norm
        + w["cascade"] * cascade_boost
    ) * 100
    # rationale: top factors
    factors = []
    if residual_norm > 0.5:
        factors.append(f"residual {residual}")
    if not has_owner:
        factors.append("unowned")
    if not has_treatment:
        factors.append("no treatment")
    if aging_norm > 0.3:
        factors.append(f"aging {aging_days}d")
    if uncertainty_norm > 0.5:
        factors.append("high uncertainty")
    if cascade_boost:
        factors.append("cascade")
    rationale = ", ".join(factors) if factors else "baseline"
    return round(max(0.0, min(100.0, score)), 1), rationale


def score_risk(row: dict[str, Any]) -> dict[str, Any]:
    """Score a single register row dict. No DB writes."""
    # normalize inputs for hashing
    aging_days = row.get("aging_days")
    if aging_days is None and row.get("created_at"):
        try:
            ca = row["created_at"]
            if isinstance(ca, str):
                ca = datetime.fromisoformat(ca.replace("Z", "+00:00"))
            aging_days = (datetime.now(timezone.utc) - ca).days if ca.tzinfo else (datetime.now(timezone.utc) - ca).days
        except Exception:
            aging_days = 0
    row["aging_days"] = aging_days
    row["has_owner"] = bool(row.get("owner"))
    inherent, confidence, source = inherent_for_row(row)
    coverage = treatment_coverage_for_row(row)
    residual = residual_for_row(inherent, coverage)
    band = _band_for(residual if residual is not None else inherent)
    priority, rationale = priority_for_row({**row, "confidence": confidence}, residual, inherent)
    inputs_hash = _inputs_hash(
        {
            "layer": row.get("layer"),
            "severity": row.get("severity"),
            "exposure": row.get("exposure"),
            "scope": row.get("scope"),
            "evidence_ids": row.get("evidence_ids"),
            "treatment_coverage": coverage,
            "status": row.get("status"),
            "aging_days": aging_days,
            "has_owner": bool(row.get("owner")),
        }
    )
    return {
        "inherent_score": inherent,
        "residual_score": residual,
        "priority_score": priority,
        "band": band,
        "confidence": round(confidence, 2),
        "scoring_method": RISK_SCORING_METHOD,
        "scoring_fingerprint": risk_scoring_fingerprint(),
        "score_rationale": f"{rationale} (source: {source})",
        "inputs_hash": inputs_hash,
        "scored_at": datetime.now(timezone.utc).isoformat(),
        "treatment_coverage": coverage,
    }


def portfolio_aggregates(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts by layer and band, not one number. Separate strips per layer."""
    from collections import Counter

    open_rows = [r for r in rows if (r.get("status") or "open").lower() in ("open", "mitigating")]
    by_layer: dict[str, Any] = {}
    for r in open_rows:
        layer = r.get("layer") or "unknown"
        by_layer.setdefault(layer, {"count": 0, "by_band": Counter(), "residuals": []})
        by_layer[layer]["count"] += 1
        by_layer[layer]["by_band"][r.get("band") or "Unknown"] += 1
        if r.get("residual_score") is not None:
            by_layer[layer]["residuals"].append(r["residual_score"])
    # compute per-layer means separately
    for layer, data in by_layer.items():
        residuals = data.pop("residuals")
        data["by_band"] = dict(data["by_band"])
        if residuals:
            data["mean_residual"] = round(sum(residuals) / len(residuals), 1)
        else:
            data["mean_residual"] = None
    # attention index: mean top_k priority
    top_k = sorted([r.get("priority_score") or 0 for r in open_rows], reverse=True)[:5]
    attention_index = round(sum(top_k) / len(top_k), 1) if top_k else 0.0
    return {
        "by_layer": by_layer,
        "open_total": len(open_rows),
        "attention_index": attention_index,
        "note": "Stacked counts by layer and band, not one blended risk number",
    }
