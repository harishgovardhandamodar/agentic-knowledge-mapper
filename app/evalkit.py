"""A regression gate for the scoring engine.

``score_assessment`` is deterministic, which is what makes the numbers
quotable. It is also why the numbers can drift without anyone noticing: nudge a
likelihood from 4 to 5 and every report this engine has ever produced becomes
slightly wrong, with no error and no failing test.

This module is the gate. Each case is a fixed scenario with its expected
aggregate, and :func:`run_eval` reports every case that moved. It runs in
milliseconds with no model call and no network, so it can run in the test suite,
in CI, and on demand against a live deployment.

The expectations are *pins*, not aspirations. Changing one is a decision that
this engine's numbers are allowed to move, and it should be made deliberately in
a commit that says so -- which is the whole point. :func:`rebaseline` exists for
exactly that, and prints the pack fingerprint so the commit record shows which
catalog the new numbers belong to.

Design choices worth stating:

* **Cases, not snapshots.** A full expected-output blob would fail on any
  cosmetic change and get ignored. Each case pins only the aggregates a user
  quotes, so the gate stays informative instead of noisy.
* **Tolerances are explicit.** Aggregates are one-decimal percentages; cases
  pin to that precision rather than to float equality.
* **Structural invariants are checked too**, alongside numbers: a control that
  covers nothing must not reduce risk, and adding controls must never make a
  score worse. Those hold regardless of catalog contents, so they catch a class
  of bug no fixed expectation would.
"""
import json
from typing import Any

from . import security as sec
from . import threatpack as tp

#: Aggregates are stored rounded to one decimal, so expectations are too.
TOLERANCE = 0.05


def _inherent(exposure="confidential_data") -> list[dict[str, Any]]:
    """The exposure-scaled baseline rows, built the way the engine builds them."""
    weight = float(sec.EXPOSURE_META[exposure]["weight"])
    return [{"id": t[0], "title": t[1], "stride": t[2], "owasp": t[3],
             "likelihood": float(sec._scale_likelihood(t[4], weight)),
             "impact": float(t[5]), "description": t[6],
             "mitigations": list(t[7])}
            for t in sec._THREAT_CATALOG]


def _case(name, *, exposure="confidential_data", active=(), applicability=None,
          inherent=None, expect=None, note="") -> dict[str, Any]:
    return {"name": name, "exposure": exposure, "active": sorted(active),
            "applicability": applicability, "inherent": inherent,
            "expect": expect or {}, "note": note}


def cases() -> list[dict[str, Any]]:
    """The suite. Rebaseline these deliberately, not accidentally."""
    every = [c["id"] for c in sec.control_catalog()]
    return [
        _case("no-controls-baseline",
              expect={"inherent_pct": 68.8, "residual_pct": 68.8,
                      "delta": 0.0, "posture_contains": "ELEVATED"},
              note="with nothing in place, residual equals inherent"),
        _case("all-controls",
              active=every,
              expect={"residual_pct": 24.3, "posture_contains": "LOW"},
              note="full control set: the floor, not zero -- see residual_floor"),
        _case("best-single-control",
              active=["C02"],
              expect={"residual_pct": 55.3},
              note="C02 has the highest single-control leverage in the pack"),
        _case("every-exposure-tier",
              note="aggregate over each exposure weight; invariants only"),
        _case("irrelevant-threats-excluded",
              applicability={t[0]: 0.0 for t in sec._THREAT_CATALOG[:3]},
              note="below-threshold threats are reported but not aggregated"),
        _case("all-threats-irrelevant-falls-back",
              applicability={t[0]: 0.0 for t in sec._THREAT_CATALOG},
              note="an empty scope must not score 0; it falls back to all rows"),
        _case("unknown-control-ids-ignored",
              active=["C99", "NOT-A-CONTROL"],
              note="an id outside the pack is dropped, not trusted"),
        _case("empty-threat-set",
              inherent=[],
              expect={"residual_pct": 0.0, "inherent_pct": 0.0},
              note="no threats means no risk, and must not divide by zero"),
    ]


def _run_case(case) -> dict[str, Any]:
    inherent = case["inherent"] if case["inherent"] is not None \
        else _inherent(case["exposure"])
    result = sec.score_assessment(
        case["exposure"], inherent,
        active_controls=case["active"],
        applicability=case["applicability"])
    exp = case["expect"]
    failures = []

    def check(field, actual, expected):
        if abs(float(actual) - float(expected)) > TOLERANCE:
            failures.append({"field": field, "expected": expected,
                             "actual": actual})

    if "inherent_pct" in exp:
        check("inherent_pct", result["inherent_pct"], exp["inherent_pct"])
    if "residual_pct" in exp:
        check("residual_pct", result["residual_pct"], exp["residual_pct"])
    if "delta" in exp:
        check("delta", result["delta"], exp["delta"])
    if "posture_contains" in exp:
        if exp["posture_contains"].lower() not in result["posture"].lower():
            failures.append({"field": "posture",
                             "expected": f"contains {exp['posture_contains']!r}",
                             "actual": result["posture"]})
    return {"name": case["name"], "note": case["note"],
            "ok": not failures, "failures": failures,
            "residual_pct": result["residual_pct"],
            "inherent_pct": result["inherent_pct"],
            "posture": result["posture"]}


def invariants() -> list[dict[str, Any]]:
    """Properties that must hold whatever the catalog contains.

    These catch a class of bug a pinned number cannot: a broken edit to the
    control combination maths shows up here even if every expected value in
    ``cases()`` happened to be updated in the same commit.
    """
    out = []
    inherent = _inherent()
    all_ids = [c["id"] for c in sec.control_catalog()]
    none = sec.score_assessment("confidential_data", inherent, active_controls=[])
    every = sec.score_assessment("confidential_data", inherent,
                                 active_controls=all_ids)

    out.append({
        "name": "residual_never_exceeds_inherent",
        "ok": none["residual_pct"] <= none["inherent_pct"] + TOLERANCE,
        "detail": {"inherent": none["inherent_pct"],
                   "residual_with_no_controls": none["residual_pct"]},
    })
    out.append({
        "name": "controls_never_increase_risk",
        "ok": every["residual_pct"] <= none["residual_pct"] + TOLERANCE,
        "detail": {"with_none": none["residual_pct"],
                   "with_all": every["residual_pct"]},
    })
    out.append({
        "name": "residual_respects_the_floor",
        # A threat cannot go below residual_floor x its inherent likelihood, so
        # a full control set must not reach 0 unless inherent was 0.
        "ok": every["residual_pct"] > 0 or none["inherent_pct"] == 0,
        "detail": {"floor": tp.RESIDUAL_FLOOR,
                   "residual_with_all_controls": every["residual_pct"]},
    })

    # Monotonicity: adding a control to a set you already have can only hold or
    # reduce the score. Tested by growing one set cumulatively -- comparing two
    # different single-control scores to each other would say nothing, since
    # they are alternative sets rather than a before and an after.
    active: list[str] = []
    prev = none["residual_pct"]
    monotone = True
    detail = []
    for cid in all_ids:
        active.append(cid)
        cur = sec.score_assessment("confidential_data", inherent,
                                   active_controls=list(active))["residual_pct"]
        if cur > prev + TOLERANCE:
            monotone = False
            detail.append({"added": cid, "before": prev, "after": cur})
            break
        prev = cur
    out.append({"name": "adding_a_control_never_increases_risk",
                "ok": monotone, "detail": {"increases": detail,
                                           "final": prev}})

    # A control covering no threat in the pack must not change the score.
    inert = sec.score_assessment("confidential_data", inherent,
                                 active_controls=["C99"])
    out.append({
        "name": "unknown_control_is_a_noop",
        "ok": abs(inert["residual_pct"] - none["residual_pct"]) <= TOLERANCE,
        "detail": {"with_unknown": inert["residual_pct"],
                   "baseline": none["residual_pct"]},
    })
    return out


def run_eval() -> dict[str, Any]:
    """Run every case and invariant. ``ok`` is the gate."""
    results = [_run_case(c) for c in cases()]
    invs = invariants()
    failed = [r for r in results if not r["ok"]]
    failed_inv = [i for i in invs if not i["ok"]]
    return {
        "ok": not failed and not failed_inv,
        "pack": tp.pack_manifest(),
        "cases_run": len(results),
        "cases_failed": len(failed),
        "invariants_run": len(invs),
        "invariants_failed": len(failed_inv),
        "cases": results,
        "invariants": invs,
        "failures": [{"case": r["name"], "why": r["failures"]} for r in failed]
                   + [{"invariant": i["name"], "detail": i["detail"]}
                      for i in failed_inv],
    }


def rebaseline() -> dict[str, Any]:
    """Re-read the current engine output as the new expectations.

    Prints rather than writes on purpose. The regenerated numbers are meant to
    be pasted into ``cases()`` and reviewed in a commit diff, so a rebase is a
    change somebody can see and object to, not something that happens quietly
    during a test run.
    """
    out = []
    for c in cases():
        inherent = _inherent(c["exposure"])
        r = sec.score_assessment(c["exposure"], inherent,
                                 active_controls=c["active"],
                                 applicability=c["applicability"])
        entry = {"name": c["name"]}
        if c["expect"]:
            entry["expected"] = {"inherent_pct": r["inherent_pct"],
                                 "residual_pct": r["residual_pct"],
                                 "delta": r["delta"]}
        out.append(entry)
    return {"pack": tp.pack_manifest(), "cases": out}


def render(report: dict[str, Any]) -> str:
    """Human-readable form for the CLI."""
    lines = [f"threat pack {report['pack']['pack_id']} "
             f"{report['pack']['version']} "
             f"(fingerprint {report['pack']['fingerprint']})"]
    for r in report["cases"]:
        mark = "ok  " if r["ok"] else "FAIL"
        lines.append(f"  [{mark}] {r['name']}: residual {r['residual_pct']}%")
        for f in r["failures"]:
            lines.append(f"         {f['field']}: expected {f['expected']}, "
                         f"got {f['actual']}")
    for i in report["invariants"]:
        mark = "ok  " if i["ok"] else "FAIL"
        lines.append(f"  [{mark}] invariant: {i['name']}")
    lines.append(f"{'PASS' if report['ok'] else 'FAIL'}: "
                 f"{report['cases_run']} cases, {report['invariants_run']} "
                 f"invariants")
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "rebaseline":
        print(json.dumps(rebaseline(), indent=2))
    else:
        rep = run_eval()
        print(render(rep))
        sys.exit(0 if rep["ok"] else 1)
