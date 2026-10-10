"""Residual scoring: the arithmetic that turns threats and controls into a number.

Extracted from :mod:`app.security`, which stays the public façade and
re-exports everything here, so no caller had to change. The split exists
because the scoring core had become unreachable by inspection inside a
4,000-line module that also owns the catalogue, the renderers and the model
paths: a reader looking for "how is the residual computed" had to page past
three unrelated subsystems to find it.

The scoring block below is identical to what it replaced except that reads
of catalogue-owned names go through ``_s`` -- e.g. ``_MIN_RESIDUAL_LIKELIHOOD``
became ``_s._MIN_RESIDUAL_LIKELIHOOD``. ``_s`` resolves each name against
:mod:`app.security` at call time, which keeps one source of truth for the
catalogue (the renderers and the threat pack need it too) while letting this
module be imported first without a circular import. The arithmetic itself is
untouched: this is the function that produces every number the tool quotes, so
a refactor that also edited it would be a refactor nobody could review.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

#: Re-exported by :mod:`app.security` for backwards compatibility.
__all__ = [
    "control_catalog", "_combine_efficacy", "_coverage_for", "_score_rows",
    "_is_floor_bound", "_floor_diagnostics", "_aggregate", "_aggregate_pct",
    "_posture", "score_assessment", "_scale_likelihood",
]

class _SecurityProxy:
    """Live view of the catalogue names owned by :mod:`app.security`.

    Attribute access imports ``security`` at *call* time and reads the current
    value, so this stays correct even for the three constants the ablation
    harness mutates (:func:`benchmarks.ablation_report` sets them on
    ``security`` and restores them afterwards). A value copied at import time
    would silently ignore those mutations and report the unablated headline --
    exactly the kind of lie this split exists to prevent. Importing lazily
    also means ``scoring`` and ``security`` can be imported in either order.
    """

    def __getattr__(self, name: str):
        from . import security
        return getattr(security, name)


_s = _SecurityProxy()


def control_catalog() -> list[dict[str, Any]]:
    """Control catalogue plus how many threats each control covers (for the GUI).

    Each row carries its efficacy *provenance* alongside the value, so no
    consumer can display 0.70 without the fact that it is an unvalidated
    analyst prior being one attribute lookup away.
    """
    out = []
    for c in _s._CONTROL_CATALOG:
        item = {k: v for k, v in c.items()}
        item["threat_count"] = len(c["threats"])
        item["max_coverage"] = round(_combine_efficacy(
            [c["efficacy"] * w for w in c["threats"].values()]) * 100, 1)
        item["evidence"] = _s.control_evidence(c["id"])
        item["efficacy_is_prior"] = not _s.control_evidence(c["id"])["validated"]
        out.append(item)
    return out


def _combine_efficacy(parts: list[float]) -> float:
    """Diminishing-returns combination: 1 - Π(1 - efficacy_i)."""
    survive = 1.0
    for p in parts:
        survive *= (1.0 - max(0.0, min(0.95, p)))
    return max(0.0, min(1.0, 1.0 - survive))


def _coverage_for(
        threat_id: str, active_controls: Iterable[str]
) -> tuple[float, list[str]]:
    """(coverage 0..1, contributing control ids) for one threat."""
    parts: list[float] = []
    used: list[str] = []
    for cid in active_controls:
        c = _s._CONTROL_BY_ID.get(cid)
        if not c:
            continue
        w = c["threats"].get(threat_id)
        if not w:
            continue
        parts.append(c["efficacy"] * float(w))
        used.append(cid)
    return _combine_efficacy(parts), used


def _score_rows(inherent_threats: list[dict[str, Any]],
                active: list[str], app: dict[str, float]) -> list[dict[str, Any]]:
    """One scored row per threat: inherent + residual + coverage + floor flag.

    Split out of :func:`score_assessment` so the floor ablation
    (:func:`_floor_diagnostics`) re-scores under the identical arithmetic — a
    second implementation here would let the ablation disagree with the
    headline it is explaining, which is exactly the bug the diagnostics exist
    to surface.
    """
    rows: list[dict[str, Any]] = []
    for t in inherent_threats:
        tid = t["id"]
        try:
            a = float(app.get(tid, 1.0))
        except (TypeError, ValueError):
            a = 1.0
        a = max(0.0, min(1.0, a))
        cov, contributors = _coverage_for(tid, active)
        lik_i = float(t["likelihood"])
        impact = float(t["impact"])
        inherent = lik_i * impact
        lik_r = max(lik_i * _s._MIN_RESIDUAL_LIKELIHOOD, lik_i * (1.0 - cov))
        residual = lik_r * impact
        rows.append({
            "id": tid,
            "title": t.get("title", ""),
            "stride": t.get("stride", ""),
            "owasp": t.get("owasp", ""),
            "description": t.get("description", ""),
            "mitigations": list(t.get("mitigations", [])),
            "likelihood": lik_i,
            "impact": impact,
            "inherent_score": round(inherent, 2),
            "inherent_severity": _s._severity(int(round(inherent))),
            "residual_likelihood": round(lik_r, 2),
            "residual_score": round(residual, 2),
            "residual_severity": _s._severity(int(round(residual))),
            "coverage": round(cov * 100, 1),
            "controls": contributors,
            "applicability": round(a, 2),
            "applicable": a >= _s._MIN_APPLICABILITY,
            "floor_capped": _is_floor_bound(cov),
        })
    return rows


def _is_floor_bound(coverage: float) -> bool:
    """True when ``_MIN_RESIDUAL_LIKELIHOOD`` — not coverage — sets the row.

    ``lik_r = max(lik_i * floor, lik_i * (1 - cov))``. The floor wins exactly
    when ``1 - cov < floor``, i.e. ``cov < 1 - floor``. The epsilon keeps the
    tie (cov exactly at the threshold) on the "covered" side, because there the
    two branches agree and coverage is a fair description of the value.
    """
    return coverage < (1.0 - _s._MIN_RESIDUAL_LIKELIHOOD) - 1e-9


def _floor_diagnostics(inherent_threats: list[dict[str, Any]],
                       active: list[str], app: dict[str, float],
                       rows: list[dict[str, Any]],
                       ) -> dict[str, Any]:
    """How much of the residual score the 35% floor is responsible for.

    Answers the question a reviewer actually asks — "I attested more controls
    and the headline did not move" — by counting, for each active control, its
    marginal effect on the headline when removed. A control whose removal moves
    the score by less than :data:`FLOOR_NOISE_EPS` is *beyond the floor*: it is
    real mitigation whose effect the model can no longer represent, and saying
    so is more useful than reporting a headline that appears not to move.

    This is a leave-one-out ablation over the same arithmetic the headline uses,
    so the counts cannot disagree with ``residual_pct``.
    """
    base_rows = _score_rows(inherent_threats, active, app)
    _, base_pct, applicable = _aggregate_pct(base_rows, app)
    applicable_ids = {r["id"] for r in applicable}

    beyond: list[dict[str, Any]] = []
    moving: list[dict[str, Any]] = []
    for cid in active:
        trial = [c for c in active if c != cid]
        _, alt_pct, _ = _aggregate_pct(_score_rows(inherent_threats, trial, app), app)
        delta = round(base_pct - alt_pct, 2)
        record = {
            "control_id": cid,
            "headline_delta_if_removed": delta,
            "affects_included_threats": any(
                cid in r["controls"] for r in base_rows
                if r["id"] in applicable_ids
            ),
        }
        (beyond if abs(delta) < _s.FLOOR_NOISE_EPS else moving).append(record)

    capped = [r["id"] for r in rows if r.get("floor_capped")]
    return {
        "floor": _s._MIN_RESIDUAL_LIKELIHOOD,
        # True when at least one included threat's residual is set by the floor.
        "floor_capped": bool(capped),
        "floor_capped_threats": sorted(capped),
        "floor_capped_count": len(capped),
        "floor_capped_pct": round(
            100.0 * len(capped) / len(rows), 1) if rows else 0.0,
        # Controls whose marginal effect on the headline is below the model's
        # own noise threshold. Attesting more of them will not move the score.
        "controls_beyond_floor": len(beyond),
        "controls_beyond_floor_ids": [r["control_id"] for r in beyond],
        "controls_effective": len(moving),
        "controls_effective_ids": [r["control_id"] for r in moving],
        # Every active control that touches no included threat also lands in
        # `beyond` (removing it changes nothing); name them separately so the
        # "your control does nothing" reading is disambiguated from the
        # "your control is floored" reading.
        "controls_orphaned": sorted(r["control_id"] for r in beyond
                                    if not r["affects_included_threats"]),
        "noise_epsilon": _s.FLOOR_NOISE_EPS,
        "note": (
            "residual_pct is an ordinal risk score, not a measured quantity. "
            f"Likelihood never falls below {int(_s._MIN_RESIDUAL_LIKELIHOOD * 100)}% "
            "of inherent, so residual saturates once coverage exceeds "
            f"{int((1 - _s._MIN_RESIDUAL_LIKELIHOOD) * 100)}%. Controls listed in "
            "controls_beyond_floor_ids are real mitigation the model cannot "
            "represent further."
        ),
    }


def _aggregate(values: list[float]) -> float:
    """Weighted worst/breadth aggregate normalized from the 1..25 L×I range."""
    if not values:
        return 0.0
    top = sorted(values, reverse=True)[:_s._TOP_N]
    worst = sum(top) / len(top)
    breadth = sum(values) / len(values)
    return _s._WORST_WEIGHT * worst + _s._BREADTH_WEIGHT * breadth


def _aggregate_pct(rows: list[dict[str, Any]],
                   applicability: dict[str, float] | None = None,
                   ) -> tuple[float, float, list[dict[str, Any]]]:
    """(inherent_pct, residual_pct, applicable_rows) from already-scored rows.

    Split out of :func:`score_assessment` so exactly one implementation of the
    aggregate exists. The assurance layer re-scores rows whose residual has been
    forced back to inherent by an evidence or architecture gate; it must land on
    the same arithmetic the headline uses, or the two layers would disagree
    about the same inputs.
    """
    if not rows:
        return 0.0, 0.0, []
    applicable = [r for r in rows if r.get("applicable", True)]
    if not applicable:  # never produce a meaningless 0 for an empty scope
        applicable = rows
    weights = []
    for r in applicable:
        try:
            weights.append(
                max(0.0, min(1.0, float((applicability or {}).get(r["id"], 1.0)))))
        except (TypeError, ValueError):
            weights.append(1.0)
    norm = (sum(weights) / len(weights)) if weights else 0.0
    if norm <= 0:
        # nothing claims relevance: fall back to the unweighted aggregate
        # rather than manufacturing a zero
        weights = [1.0] * len(applicable)
        norm = 1.0
    inh = _aggregate([s * w for s, w in zip(
        [r["inherent_score"] for r in applicable],
        weights, strict=False)]) / (25.0 * norm)
    res = _aggregate([s * w for s, w in zip(
        [r["residual_score"] for r in applicable],
        weights, strict=False)]) / (25.0 * norm)
    return (round(min(100.0, inh * 100.0), 1),
            round(min(100.0, res * 100.0), 1), applicable)


def _posture(pct: float) -> str:
    if pct >= 75:
        return ("HIGH RISK — do not enable for this data tier "
                "without the mitigations below")
    elif pct >= 50:
        return "ELEVATED RISK — enable only with guardrails and steward review"
    elif pct >= 30:
        return "MODERATE RISK — standard hardening sufficient"
    return "LOW RISK — routine controls sufficient"


def score_assessment(
    exposure: str,
    inherent_threats: list[dict[str, Any]],
    active_controls: Iterable[str] | None = None,
    applicability: dict[str, float] | None = None,
) -> dict[str, Any]:
    """Pure function: inherent + residual scoring for a threat set.

    Deterministic and side-effect free, so the same inputs always produce the
    same numbers — used by the assessment run, the what-if re-scorer and the
    control-analyst agent alike.

    - ``inherent_threats``: entries with ``id``, ``likelihood`` (already exposure-
      scaled), ``impact``.
    - ``active_controls``: control ids the organisation has in place.
    - ``applicability``: per-threat 0..1 relevance; threats below
      ``_MIN_APPLICABILITY`` are reported but excluded from the aggregate,
      and the rest weight the aggregate by relevance (renormalized, so a
      uniform map scores exactly as unweighted).

    Returns threats (inherent + residual per threat), the aggregates, the
    posture, and a full breakdown so the UI can explain every number.
    """
    active = sorted({str(c).strip().upper() for c in (active_controls or [])
                     if str(c).strip().upper() in _s._KNOWN_CIDS
                     and str(c).strip().upper() not in _s.DEPRECATED_CONTROLS})
    app = dict(applicability or {})
    control_analyst = (applicability is not None)

    rows = _score_rows(inherent_threats, active, app)

    inherent_pct, residual_pct, applicable = _aggregate_pct(rows, app)
    floor = _floor_diagnostics(inherent_threats, active, app, rows)

    def _dist(key: str) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in applicable:
            out[r[key]] = out.get(r[key], 0) + 1
        return out

    return {
        "threats": sorted(
            rows, key=lambda r: (-r["residual_score"], -r["inherent_score"], r["id"])),
        # The marker every consumer keys on. The model scorers stamp their
        # own paths; without this, a fresh catalog row is indistinguishable
        # from a legacy unmarked one and gets re-derived from its wording --
        # a gamble no reader should have to take.
        "assessment_path": "standard",
        "inherent_pct": inherent_pct,
        "residual_pct": residual_pct,
        "delta": round(residual_pct - inherent_pct, 1),
        # Floor diagnostics live at the top level, not only inside breakdown:
        # every consumer (markdown, PDF, GUI, API) reads the top level, and the
        # point of the change is that no reader can miss it.
        "floor_capped": floor["floor_capped"],
        "floor": floor,
        # How much of this residual rests on numbers nobody has measured.
        "efficacy_evidence": _s.efficacy_evidence_summary(active),
        "posture": _posture(residual_pct),
        "inherent_posture": _posture(inherent_pct),
        "active_controls": active,
        "distribution": {
            "inherent": _dist("inherent_severity"),
            "residual": _dist("residual_severity"),
        },
        "breakdown": {
            "method": ("weighted worst-case (55%) + breadth (45%), normalized "
                       "to the 1-25 LxI range; "
                      "threat contributions scale by applicability and renormalize "
                      "(uniform maps score as unweighted); "
                      "residual applies control efficacy with diminishing returns; "
                      "controls never reduce likelihood below 35% of inherent "
                      "(so the residual saturates once coverage exceeds 65% -- see "
                      "the `floor` block for how much of this score the floor "
                      "accounts for; treat it as an ordinal ranking, not a "
                      "measurement"),
            "worst_weight": _s._WORST_WEIGHT,
            "breadth_weight": _s._BREADTH_WEIGHT,
            "top_n": _s._TOP_N,
            "min_residual_floor": _s._MIN_RESIDUAL_LIKELIHOOD,
            "min_applicability": _s._MIN_APPLICABILITY,
            "exposure": exposure,
            "exposure_weight": _s.EXPOSURE_META.get(exposure, {}).get("weight"),
            "exposure_label": _s.EXPOSURE_META.get(exposure, {}).get("label", exposure),
            "applicable_threats": len(applicable),
            "total_threats": len(rows),
            "n_threats_included": len(applicable),
            "n_threats_excluded": len(rows) - len(applicable),
            "max_inherent": max((r["inherent_score"] for r in rows), default=0),
            "max_residual": max((r["residual_score"] for r in rows), default=0),
            "mean_coverage": round(
                sum(r["coverage"] for r in applicable) / len(applicable), 1)
            if applicable else 0.0,
        },
        "control_analyst": control_analyst,
    }


def _scale_likelihood(base: int, weight: float) -> int:
    """Exposure weight scales likelihood mildly: restricted=full, public=reduced."""
    scaled = round(base * (0.55 + 0.45 * weight))
    return max(1, min(5, scaled))
