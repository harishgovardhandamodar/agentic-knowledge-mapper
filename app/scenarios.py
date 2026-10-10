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
    """Attack paths whose *composition* is uncovered although no single leg is.

    A chain is flagged when two legs disagree about a control by a *material*
    margin. Set difference alone is too strict, because in this catalogue most
    controls cover several threats, so two rows almost always share some. The
    signal is that a control helps the precondition leg but barely touches the
    exploit leg.

    Chains longer than two are assembled separately by :func:`attack_tree` and
    merged in here, so ``max_chain`` is a real bound on path length rather than
    a declared constant.
    """
    rows = _rows(scoring)
    weights = _control_weights(scoring)
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for a, b in itertools.combinations(rows, 2):
        if a.get("id") == b.get("id"):
            continue
        wa = _row_contribution(a, weights)
        wb = _row_contribution(b, weights)
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
        only_weak = [cid for cid in divergent if ww.get(cid, 0) - sw.get(cid, 0)
                     <= -_DIVERGENCE]
        if not only_weak:
            continue
        out.append(_chain_record([strong, weak], only_weak, weights))
        seen.add(out[-1]["id"])

    if max_chain > 2:
        for path in _long_chains(rows, weights, max_chain):
            rec = _chain_record(path, _path_gap(path, weights), weights)
            if rec["id"] in seen:
                continue
            seen.add(rec["id"])
            out.append(rec)

    out.sort(key=lambda s: (-float(s["residual_score"]), s["id"]))
    return out[:24]


def _chain_record(legs: list[dict[str, Any]], gap: list[str],
                  weights: dict[str, dict[str, float]]) -> dict[str, Any]:
    """Build a scenario record for an ordered path of threat rows."""
    ids = [str(r.get("id")) for r in legs]
    weak = min(legs, key=lambda r: float(r.get("coverage") or 0.0))
    strong = legs[0] if legs and legs[0] is not weak else (legs[-1] if legs else weak)
    return {
        "id": scenario_id(ids),
        "origin": ORIGIN_CHAIN,
        "title": f"{ids[-1]} reached via {' → '.join(ids[:-1])}"
        if len(ids) > 2 else f"{weak.get('id')} reached via {strong.get('id')}",
        "chain": ids,
        "hops": len(ids),
        "weakest_link": weak.get("id"),
        "precondition": strong.get("title") or strong.get("id"),
        "exploit": weak.get("title") or weak.get("id"),
        "coverage_of_exploit": round(float(weak.get("coverage") or 0.0), 1),
        "residual_score": round(float(weak.get("residual_score") or 0.0), 2),
        "uncovered_by": sorted(gap),
        "why": (
            f"{' → '.join(ids)}: the control(s) {', '.join(sorted(gap)) or 'none'} "
            f"that carry the early legs do not reach {weak.get('id')}, which "
            f"sits at {round(float(weak.get('coverage') or 0.0), 1)}% coverage. "
            f"Each leg scores acceptably; the composition does not."
        ),
        "floor_capped": bool(weak.get("floor_capped")),
    }


def _path_gap(path: list[dict[str, Any]],
              weights: dict[str, dict[str, float]]) -> list[str]:
    """Controls that carry the path's early legs but miss the final one."""
    if len(path) < 2:
        return []
    last = str(path[-1].get("id"))
    prev = {str(r.get("id")) for r in path[:-1]}
    gap = []
    for cid, per_threat in weights.items():
        on_last = per_threat.get(last, 0.0)
        on_prev = max((per_threat.get(t, 0.0) for t in prev), default=0.0)
        if on_prev - on_last >= _DIVERGENCE:
            gap.append(cid)
    return sorted(gap)


def _long_chains(rows: list[dict[str, Any]],
                 weights: dict[str, dict[str, float]],
                 max_chain: int) -> list[list[dict[str, Any]]]:
    """Enumerate paths of length 3..max_chain that degrade along the way.

    The ordering constraint is what makes this tractable and meaningful: a
    path is interesting when coverage *falls* as it goes, because each leg is
    assumed to be handled by the controls for the previous one. Without a
    monotone decline the enumeration is combinatorial and says nothing.
    """
    ordered = sorted(rows, key=lambda r: -float(r.get("coverage") or 0.0))
    found: list[list[dict[str, Any]]] = []
    cap = min(max_chain, len(ordered))

    def walk(path: list[dict[str, Any]]) -> None:
        if len(path) >= cap:
            return
        last_cov = float(path[-1].get("coverage") or 0.0)
        for r in ordered:
            if any(r.get("id") == p.get("id") for p in path):
                continue
            cov = float(r.get("coverage") or 0.0)
            if cov >= last_cov:
                continue  # must decline
            if _path_gap(path + [r], weights):
                found.append(path + [r])
                walk(path + [r])

    for r in ordered:
        walk([r])
    # Longest paths first: they are the findings a pairwise scan cannot produce.
    found.sort(key=lambda p: (-len(p), [str(x.get("id")) for x in p]))
    return found[:12]


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


def attack_tree(scoring: dict[str, Any], *, limit: int = 24) -> dict[str, Any]:
    """The uncovered chains as a graph, for rendering as an attack tree.

    Nodes are threat rows, edges are the derived composition paths, and an
    edge's weight is the coverage the path fails to carry to its target. Kept
    separate from :func:`scenarios` so a renderer can lay it out without
    re-deriving anything, and so the graph can be diffed between assessments.
    """
    chains = uncovered_chains(scoring, max_chain=MAX_CHAIN)
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    for ch in chains[:limit]:
        ids = ch.get("chain") or []
        for tid in ids:
            row = next((r for r in _rows(scoring) if r.get("id") == tid), {})
            nodes.setdefault(str(tid), {
                "id": str(tid),
                "title": row.get("title") or str(tid),
                "coverage": round(float(row.get("coverage") or 0.0), 1),
                "residual": round(float(row.get("residual_score") or 0.0), 2),
                "floor_capped": bool(row.get("floor_capped")),
            })
        for a, b in zip(ids, ids[1:], strict=False):
            edges.append({
                "from": str(a), "to": str(b),
                "uncovered_by": ch.get("uncovered_by") or [],
                "weakest": ch.get("weakest_link") == b,
            })
    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "stats": {"nodes": len(nodes), "edges": len(edges),
                  "max_hops": max((int(c.get("hops") or 2) for c in chains),
                                  default=0)},
        "note": ("Edges are derived compositions, not observed attack paths. "
                 "They say where coverage stops carrying, not that anyone "
                 "tried it."),
    }


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
