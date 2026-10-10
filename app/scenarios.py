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

#: Default ceiling on path length. Longer paths enumerate fast (beam search),
#: but each extra hop is a less likely composition; 5 is where the shipped
#: catalogue stops yielding distinct findings.
MAX_CHAIN = 5


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
    # Deduplicate route variants: paths to the same endpoint with the same gap
    # are one finding reached different ways, not several findings. Keep the
    # longest route -- it carries the most information about how the endpoint
    # is reached -- and drop the rest before stratifying.
    best: dict[tuple[str, tuple[str, ...]], dict[str, Any]] = {}
    for sc in out:
        key = (str(sc.get("endpoint") or sc.get("weakest_link")),
               tuple(sorted(sc.get("uncovered_by") or [])))
        if key not in best or int(sc.get("hops") or 2) > int(
                best[key].get("hops") or 2):
            best[key] = sc
    out = list(best.values())
    # Stratify by path length before capping: long paths share high-residual
    # endpoints and would otherwise crowd out every shorter finding. A reader
    # needs the best 2-hop, 3-hop and longer paths each, not 24 variants of
    # the same endpoint.
    by_hops: dict[int, list[dict[str, Any]]] = {}
    for sc in out:
        by_hops.setdefault(int(sc.get("hops") or 2), []).append(sc)
    stratified: list[dict[str, Any]] = []
    while len(stratified) < 24 and any(by_hops.values()):
        for hops in sorted(by_hops):
            if by_hops[hops]:
                stratified.append(by_hops[hops].pop(0))
                if len(stratified) >= 24:
                    break
    return stratified


def _chain_record(legs: list[dict[str, Any]], gap: list[str],
                  weights: dict[str, dict[str, float]]) -> dict[str, Any]:
    """Build a scenario record for an ordered path of threat rows.

    The endpoint is the finding (what the composition reaches); the weakest
    leg is where coverage fails most. On a strictly declining path they are
    the same node, but a lateral move can put the minimum mid-path -- and
    conflating the two would misplace the scenario on the coverage scatter.
    """
    ids = [str(r.get("id")) for r in legs]
    weak = min(legs, key=lambda r: float(r.get("coverage") or 0.0))
    endpoint = legs[-1]
    strong = legs[0]
    return {
        "id": scenario_id(ids),
        "origin": ORIGIN_CHAIN,
        "title": f"{ids[-1]} reached via {' → '.join(ids[:-1])}",
        "chain": ids,
        "hops": len(ids),
        "weakest_link": weak.get("id"),
        "endpoint": endpoint.get("id"),
        "precondition": strong.get("title") or strong.get("id"),
        "exploit": endpoint.get("title") or endpoint.get("id"),
        "coverage_of_exploit": round(float(endpoint.get("coverage") or 0.0), 1),
        "residual_score": round(float(endpoint.get("residual_score") or 0.0), 2),
        "uncovered_by": sorted(gap),
        "why": (
            f"{' → '.join(ids)}: the control(s) {', '.join(sorted(gap)) or 'none'} "
            f"that carry the early legs do not reach {endpoint.get('id')}, which "
            f"sits at {round(float(endpoint.get('coverage') or 0.0), 1)}% coverage. "
            f"Each leg scores acceptably; the composition does not."
        ),
        "floor_capped": bool(endpoint.get("floor_capped")),
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


#: Beam width for multi-hop path search. Wide enough to keep genuinely
#: different routes, narrow enough that the search stays instant.
PATH_BEAM = 24

#: A lateral move (coverage flat or rising slightly) costs this much against
#: the path score. Pivots are how real attackers traverse, but an unconstrained
#: lateral walk is combinatorial and says nothing -- so each one must pay.
LATERAL_COST = 0.5


def _long_chains(rows: list[dict[str, Any]],
                 weights: dict[str, dict[str, float]],
                 max_chain: int) -> list[list[dict[str, Any]]]:
    """Enumerate paths up to ``max_chain`` with beam search over a cost model.

    The old version required strict monotone decline and stopped at 3 hops.
    That blinds it to lateral moves -- same-coverage pivots, which is how real
    attackers traverse -- while an unconstrained walk explodes
    combinatorially. The beam keeps the 24 best-scoring partial paths at each
    length, where the score rewards declining coverage and charges for lateral
    moves. A path that only ever moves sideways scores itself out of the beam.
    """
    by_id = {str(r.get("id")): r for r in rows}
    # Beam entries: (score, path_ids). Higher is better.
    beam: list[tuple[float, list[str]]] = [
        (0.0, [str(r.get("id"))]) for r in rows]
    found: list[list[dict[str, Any]]] = []
    seen: set[tuple[str, ...]] = set()

    for _length in range(2, min(max_chain, len(rows)) + 1):
        candidates: list[tuple[float, list[str]]] = []
        for score, path in beam:
            last = by_id[path[-1]]
            last_cov = float(last.get("coverage") or 0.0)
            for r in rows:
                tid = str(r.get("id"))
                if tid in path:
                    continue
                cov = float(r.get("coverage") or 0.0)
                decline = last_cov - cov
                step = decline if decline > 0 else -LATERAL_COST
                new_score = score + step
                # A path that never declines is pivoting in place, not
                # attacking: require at least one real decline overall.
                trial = path + [tid]
                if all(float(by_id[t].get("coverage") or 0.0)
                       >= float(by_id[path[0]].get("coverage") or 0.0)
                       for t in trial[1:]):
                    continue
                if not _path_gap([by_id[t] for t in trial], weights):
                    continue
                key = tuple(trial)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append((new_score, trial))
        candidates.sort(key=lambda c: -c[0])
        beam = candidates[:PATH_BEAM]
        for _, trial in beam:
            if len(trial) == _length:
                found.append([by_id[t] for t in trial])
        if not beam:
            break
    # Longest paths first -- they are the findings a pairwise scan cannot
    # produce -- but stratified by length, so 5-hop paths do not crowd out
    # every 3-hop one before the caller ever sees it.
    by_len: dict[int, list[list[dict[str, Any]]]] = {}
    for p in found:
        by_len.setdefault(len(p), []).append(p)
    for paths in by_len.values():
        paths.sort(key=lambda p: [str(x.get("id")) for x in p])
    out: list[list[dict[str, Any]]] = []
    while len(out) < 12 and any(by_len.values()):
        for length in sorted(by_len, reverse=True):
            if by_len[length]:
                out.append(by_len[length].pop(0))
                if len(out) >= 12:
                    break
    return out


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


# --------------------------------------------------------------------------
# Scenario to probe wiring
# --------------------------------------------------------------------------
#
# A derived scenario that cannot be tested is a story with provenance. This
# section turns each scenario into the probe plan that would test it, so the
# scenarios page and the probes page are two ends of one loop rather than
# adjacent tabs with no wire between them.
#
# The mapping is deliberately explicit and narrow: a threat's STRIDE family
# selects the probe family, and the scenario's uncovered controls select the
# attribution. Anything the mapping cannot cover yields no probe rather than
# a guessed one.

#: Threat STRIDE family -> probe attack classes that exercise it.
STRIDE_TO_PROBES: dict[str, tuple[str, ...]] = {
    "information disclosure": ("verbatim_extraction", "canary_exfiltration",
                               "membership_probe"),
    "spoofing": ("prompt_injection",),
    "elevation": ("prompt_injection", "scope_probe"),
    "tampering": ("prompt_injection", "scope_probe"),
    "repudiation": ("scope_probe",),
    "compliance": (),
}


def _probes_for_threat(threat: dict[str, Any]) -> list[str]:
    stride = str((threat or {}).get("stride") or "").lower()
    out: list[str] = []
    for family, probes in STRIDE_TO_PROBES.items():
        if family in stride:
            out.extend(probes)
    seen: set[str] = set()
    return [p for p in out if not (p in seen or seen.add(p))]


def scenario_probe_plan(scenario: dict[str, Any], *,
                        threats_by_id: dict[str, dict[str, Any]] | None = None,
                        n_trials: int = 20) -> dict[str, Any]:
    """Turn one derived scenario into an executable probe plan.

    Returns the probe ids that exercise the scenario's weakest link, the
    controls to attribute the outcome to, and the pre-registration parameters
    -- so the caller can go from "T05 reached via T01" to running probes in
    one step, without inventing a method. A scenario whose threat family maps
    to no probe yields an empty plan with the reason stated, never a guessed
    probe.
    """
    from . import probes as _pr

    threats_by_id = threats_by_id or {}
    weak_id = scenario.get("weakest_link")
    weak = threats_by_id.get(str(weak_id)) or {}
    probe_ids = _probes_for_threat(weak)
    # Probes that do not exist in the harness are filtered, not assumed.
    probe_ids = [p for p in probe_ids if p in _pr.PROBES]
    controls = list(scenario.get("uncovered_by") or [])
    if not probe_ids:
        return {
            "scenario_id": scenario.get("id"),
            "probes": [],
            "attribute_to": [],
            "n_trials": n_trials,
            "reason": ("No probe in the harness exercises this threat family; "
                       "the scenario stands untested rather than tested by "
                       "an unrelated probe."),
        }
    return {
        "scenario_id": scenario.get("id"),
        "scenario_title": scenario.get("title"),
        "weakest_link": weak_id,
        "probes": [{"probe_id": p,
                    "attack_class": _pr.PROBES[p]["attack_class"],
                    "description": _pr.PROBES[p]["description"]}
                   for p in probe_ids],
        "attribute_to": controls,
        "n_trials": n_trials,
        "rationale": (
            f"{weak_id} is the scenario's weakest link at "
            f"{scenario.get('coverage_of_exploit')}% coverage. These probes "
            f"exercise its threat family; attributing the outcome to "
            f"{', '.join(controls) or 'no controls'} records an efficacy "
            f"trial for each."),
    }


def scenarios_probe_plan(scoring: dict[str, Any], *,
                         limit: int = 10, n_trials: int = 20) -> dict[str, Any]:
    """Probe plans for an assessment's top scenarios, ranked by residual.

    Returns plans only for scenarios that map to a real probe. The count of
    untestable scenarios is reported alongside, so "we tested everything we
    could" is distinguishable from "we tested everything".
    """
    derived = scenarios(scoring, limit=limit)
    threats_by_id = {str(t.get("id")): t for t in _rows(scoring)}
    plans = []
    untestable = 0
    for sc in derived["scenarios"]:
        plan = scenario_probe_plan(sc, threats_by_id=threats_by_id,
                                   n_trials=n_trials)
        if plan["probes"]:
            plans.append(plan)
        else:
            untestable += 1
    return {
        "plans": plans,
        "untestable_scenarios": untestable,
        "n_trials_each": n_trials,
        "note": ("Each plan names the scenario it tests, the probes that "
                 "exercise it, and the controls an outcome is attributed to. "
                 "Untestable scenarios are counted, not hidden."),
    }
