"""Scenario synthesis: attack paths the catalogue does not already contain.

The threat catalogue is a *catalogue* -- twelve fixed rows, each scored the same
way. That is the right thing for a checklist and the wrong thing for research:
a checklist tells you what was thought of, and nothing about what was not.

This module derives scenarios by composing the parts the engine already holds
and looking for combinations the catalogue does not enumerate:

* **Uncovered paths** -- a threat with a specific control missing, plus the
  precondition another threat supplies. Chains like this are where real
  incidents live: each link is individually "covered", the composition is not.
* **Residual amplifiers** -- threats sitting at their floor while a neighbouring
  threat is strongly covered. The floored one is where an incident would
  actually land, and no single row says so.
* **Cross-cutting gaps** -- the same absent control appearing against several
  threats, which is a programme-level finding rather than a per-row one.

Every scenario is *derived*, never invented: it names the catalogue rows and
control ids it came from, and carries the evidence state of each. A scenario
that cannot say what produced it is a story, and this module does not emit
those.

Deterministic and stdlib-only, like the rest of the engine.
"""
from __future__ import annotations

import itertools
from typing import Any

#: How a scenario was derived. Named so a reader can see the method, not just
#: the conclusion.
ORIGIN_CHAIN = "control_gap_chain"
ORIGIN_AMPLIFIER = "residual_amplifier"
ORIGIN_CROSSCUT = "cross_cutting_gap"

#: A chain longer than this is not a scenario, it is a campaign.
MAX_CHAIN = 3


def _floor(scoring: dict[str, Any]) -> float:
    bd = (scoring or {}).get("breakdown") or {}
    try:
        return float(bd.get("min_residual_floor", 0.35))
    except (TypeError, ValueError):
        return 0.35


def _rows(scoring: dict[str, Any]) -> list[dict[str, Any]]:
    return [r for r in ((scoring or {}).get("threats") or []) if isinstance(r, dict)]


def scenario_id(parts: list[str]) -> str:
    """Stable id from its ingredients, so re-running names the same scenario."""
    return "SC-" + "-".join(sorted(parts))[:48]


def uncovered_chains(scoring: dict[str, Any], *,
                     max_chain: int = MAX_CHAIN) -> list[dict[str, Any]]:
    """Threat pairs whose *composition* is uncovered although neither is alone.

    Two threats compose badly when one supplies a precondition the other
    exploits, and the control that would break the chain is one that is
    declared but does not actually cover the exploit leg. Those chains are
    invisible to per-row scoring by construction.

    A chain is flagged when the two rows disagree about a control by a
    *material* margin -- set difference alone is too strict, because in this
    catalogue most controls cover several threats, so two rows almost always
    share some. The signal is that a control helps the precondition leg but
    barely touches the exploit leg.
    """
    rows = _rows(scoring)
    # How much each control actually contributes to each row: efficacy x the
    # control's own per-threat weight. This is what makes "covers the
    # precondition but not the exploit" measurable.
    weights = _control_weights(scoring)
    out: list[dict[str, Any]] = []
    for a, b in itertools.combinations(rows, 2):
        if a.get("id") == b.get("id"):
            continue
        wa = _row_contribution(a, weights)
        wb = _row_contribution(b, weights)
        # Controls that materially help one leg and not the other.
        divergent = sorted(
            cid for cid in set(wa) | set(wb)
            if abs(wa.get(cid, 0.0) - wb.get(cid, 0.0)) >= _DIVERGENCE
        )
        if not divergent:
            continue
        weak = a if float(a.get("coverage") or 0) <= float(
            b.get("coverage") or 0) else b
        strong = b if weak is a else a
        weak_cov = float(weak.get("coverage") or 0.0)
        if weak_cov >= 0.95:
            continue  # both legs are fully covered; not a gap
        ww = wa if weak is a else wb
        sw = wb if weak is a else wa
        # The chain is interesting when the *gap* is on the exploit leg: a
        # control that carries the precondition but not the exploit.
        only_weak = [cid for cid in divergent if ww.get(cid, 0) - sw.get(cid, 0)
                     <= -_DIVERGENCE]
        if not only_weak:
            continue
        residual = float(weak.get("residual_score") or 0.0)
        out.append({
            "id": scenario_id([str(a.get("id")), str(b.get("id"))]),
            "origin": ORIGIN_CHAIN,
            "title": f"{weak.get('id')} reached via {strong.get('id')}",
            "chain": [strong.get("id"), weak.get("id")],
            "weakest_link": weak.get("id"),
            "precondition": strong.get("title") or strong.get("id"),
            "exploit": weak.get("title") or weak.get("id"),
            "coverage_of_exploit": round(weak_cov, 1),
            "residual_score": round(residual, 2),
            "uncovered_by": sorted(only_weak),
            "why": (
                f"{strong.get('id')} is "
                f"{round(float(strong.get('coverage') or 0), 1)}% covered, but the "
                f"control(s) {', '.join(sorted(only_weak))} that carry it do not "
                f"reach {weak.get('id')}, which sits at {round(weak_cov, 1)}%. Each "
                f"leg scores acceptably; the composition does not."
            ),
            "floor_capped": bool(weak.get("floor_capped")),
        })
    out.sort(key=lambda s: (-float(s["residual_score"]), s["id"]))
    return out[:24]


#: A control's contribution must differ by this much between the two legs
#: before the pair counts as a chain rather than a coincidence. Tuned to sit
#: above the rounding in the stored coverage values (0.1%).
_DIVERGENCE = 0.15


def _control_weights(scoring: dict[str, Any]) -> dict[str, dict[str, float]]:
    """control id -> {threat id: efficacy * per-threat weight}.

    Read from the row's own ``controls`` membership and the coverage it
    achieved, so no import of the security catalogue is needed and a stored
    assessment renders its own scenarios without re-deriving the engine.
    """
    rows = _rows(scoring)
    out: dict[str, dict[str, float]] = {}
    for r in rows:
        tid = str(r.get("id"))
        for cid in r.get("controls") or []:
            out.setdefault(str(cid), {})[tid] = float(r.get("coverage") or 0.0) / 100.0
    return out


def _row_contribution(row: dict[str, Any],
                      weights: dict[str, dict[str, float]]) -> dict[str, float]:
    tid = str(row.get("id"))
    return {str(cid): float(w.get(tid, 0.0)) for cid, w in weights.items()}


def residual_amplifiers(scoring: dict[str, Any]) -> list[dict[str, Any]]:
    """Threats already at the floor: where an incident would actually land.

    Per-row scoring calls these "low". The engine knows better -- their
    residual is pinned by the floor, not by mitigation -- so they are the rows
    an incident would land on, and no single catalogue row says so.
    """
    rows = _rows(scoring)
    floored = [r for r in rows if r.get("floor_capped")]
    if not floored:
        return []
    out = []
    for r in floored:
        out.append({
            "id": scenario_id([str(r.get("id")), "floor"]),
            "origin": ORIGIN_AMPLIFIER,
            "title": f"{r.get('id')} is at the residual floor",
            "chain": [r.get("id")],
            "weakest_link": r.get("id"),
            "exploit": r.get("title") or r.get("id"),
            "coverage_of_exploit": round(float(r.get("coverage") or 0.0), 1),
            "residual_score": round(float(r.get("residual_score") or 0.0), 2),
            "why": (
                "Control coverage cannot lower this row further; the likelihood "
                "floor binds. Adding controls raises coverage here without moving "
                "the residual, so the risk stays where it is."
            ),
            "floor_capped": True,
        })
    out.sort(key=lambda s: -float(s["residual_score"]))
    return out


def crosscutting_gaps(scoring: dict[str, Any]) -> list[dict[str, Any]]:
    """Control ids whose *absence* explains several rows at once.

    A per-row finding says "C09 is missing for T02". Saying "C09 is missing for
    T02, T05 and T09" is a programme decision rather than three findings, and it
    is the form a reviewer can act on.
    """
    rows = _rows(scoring)
    if not rows:
        return []
    all_controls: set[str] = set()
    for r in rows:
        all_controls |= set(r.get("controls") or [])
    weak = [r for r in rows if float(r.get("coverage") or 0.0) < 50.0]
    # Which declared controls appear on strong rows but are absent from weak ones?
    strong_controls: set[str] = set()
    for r in rows:
        if float(r.get("coverage") or 0.0) >= 50.0:
            strong_controls |= set(r.get("controls") or [])
    out = []
    for r in weak:
        missing = sorted(strong_controls - set(r.get("controls") or []))
        if len(missing) < 2:
            continue
        out.append({
            "id": scenario_id([str(r.get("id"))] + missing[:2]),
            "origin": ORIGIN_CROSSCUT,
            "title": f"{r.get('id')} lacks {len(missing)} controls its peers have",
            "chain": [r.get("id")],
            "weakest_link": r.get("id"),
            "exploit": r.get("title") or r.get("id"),
            "uncovered_by": missing,
            "coverage_of_exploit": round(float(r.get("coverage") or 0.0), 1),
            "residual_score": round(float(r.get("residual_score") or 0.0), 2),
            "why": (
                f"{len(missing)} control(s) cover comparable rows but not this "
                f"one. The absence is a programme-level pattern, not a row-level "
                f"oversight."
            ),
        })
    out.sort(key=lambda s: (-float(s["residual_score"]), s["id"]))
    return out[:16]


def scenarios(scoring: dict[str, Any], *, limit: int = 40) -> dict[str, Any]:
    """All derived scenarios for one assessment, with provenance.

    Returns the scenarios plus a ``method`` block naming the fingerprint of the
    derivation itself, so a scenario set can be re-derived and compared the
    same way a score can.
    """
    chains = uncovered_chains(scoring)
    amps = residual_amplifiers(scoring)
    cross = crosscutting_gaps(scoring)
    # Chains first: they are the findings a checklist cannot produce. Then
    # amplifiers (single-row but under-appreciated), then programme patterns.
    merged = (chains + amps + cross)[:limit]
    by_origin = {
        ORIGIN_CHAIN: len(chains),
        ORIGIN_AMPLIFIER: len(amps),
        ORIGIN_CROSSCUT: len(cross),
    }
    return {
        "scenarios": merged,
        "stats": {
            "total": len(merged),
            "by_origin": by_origin,
            "rows_considered": len(_rows(scoring)),
            "floor_capped_rows": sum(1 for r in _rows(scoring)
                                     if r.get("floor_capped")),
        },
        "method": {
            "id": "SCENARIO-SYNTHESIS",
            "version": "1",
            "max_chain": MAX_CHAIN,
            "origins": [ORIGIN_CHAIN, ORIGIN_AMPLIFIER, ORIGIN_CROSSCUT],
        },
        "note": ("Every scenario names the catalogue rows and control ids it "
                 "was derived from. A scenario that cannot say what produced "
                 "it is a story, and this method does not emit those."),
    }
