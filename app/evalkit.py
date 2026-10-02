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
              expect={"residual_pct": 24.2, "posture_contains": "LOW"},
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


def model_cases() -> list[dict[str, Any]]:
    """Pinned W1/W2 cases. Rebaseline deliberately, not accidentally."""
    from . import model_eval as _me
    return [
        {"name": "w1-open-weights-diffusion-with-extraction-literature",
         "kind": "w1",
         "findings": [
             {"attack_class": "extraction", "applies_to": "model_specific",
              "confidence": 0.8},
             {"attack_class": "membership_inference", "applies_to": "family",
              "confidence": 0.6}],
         "expect": {"overall_pct": 46.6, "coverage_pct": 25.0},
         "note": "model-specific extraction dominates; family evidence counts less"},
        {"name": "w1-api-only-model-no-public-attacks",
         "kind": "w1",
         "findings": [],
         "expect": {"overall_pct": None, "coverage_pct": 0.0},
         "note": "no evidence is no score, never a low one"},
        {"name": "w2-sensitive-tabular-high-memorization",
         "kind": "w2",
         "dimensions": [
             {"dimension": "memorization", "rating": "high"},
             {"dimension": "data_processing", "rating": "high"},
             {"dimension": "governance_documentation", "rating": "low"}],
         "expect": {"overall_pct": 60.0, "uncertainty_pct": 50.0},
         "note": "two rated dimensions carry the score; six unknown raise uncertainty"},
        {"name": "w2-documented-api-model-with-zdr",
         "kind": "w2",
         "dimensions": [{"dimension": d[0], "rating": "low"}
                         for d in _me.ADOPTION_DIMENSIONS],
         "expect": {"overall_pct": 25.0, "uncertainty_pct": 0.0},
         "note": "fully rated low is genuinely low"},
        {"name": "w3-tabular-open-prioritizes-dp-canaries",
         "kind": "mit",
         "meta": {"model_family": "tabular_fm",
                  "weights_source": "open_weights"},
         "attacks": [{"attack_class": "extraction",
                      "applies_to": "model_specific", "confidence": 0.8}],
         "dimensions": [{"dimension": "memorization", "rating": "high"}],
         "expect": {"top_contains": ["MM05"],
                    "proposed_contains": ["MM01", "MM03"],
                    "deferred_contains": ["MM04"]},
         "note": "high memorization + training access: canaries first, DP "
                 "and unlearning proposed; output watermarking deferred "
                 "for tabular"},
        {"name": "w4-high-memorization-plans-canary-probes",
         "kind": "exp",
         "meta": {"model_family": "tabular_fm",
                  "weights_source": "open_weights"},
         "attacks": [],
         "dimensions": [{"dimension": "memorization", "rating": "unknown"}],
         "hypotheses": [],
         "mitigation_plan": [],
         "expect": {"contains_methods": ["canary"], "non_empty": True},
         "note": "unknown memorization must produce privacy probes"},
        {"name": "w4-api-only-generative-no-weight-experiments",
         "kind": "exp",
         "meta": {"model_family": "diffusion",
                  "weights_source": "api_only"},
         "attacks": [{"attack_class": "extraction",
                      "applies_to": "family", "confidence": 0.6}],
         "dimensions": [],
         "hypotheses": [],
         "mitigation_plan": [],
         "expect": {"non_empty": True},
         "note": "API-only plans carry query_api, never bare weight access"},
        {"name": "w4-falsifier-maps-to-targeted-experiment",
         "kind": "exp",
         "meta": {"model_family": "llm", "weights_source": "api_only"},
         "attacks": [],
         "dimensions": [],
         "hypotheses": [{"hypothesis_id": "H01", "status": "untested",
                         "falsifiers": ["vendor retains prompts for training"]}],
         "mitigation_plan": [],
         "expect": {"covers_hypotheses": ["H01"], "non_empty": True},
         "note": "every open falsifier maps to an experiment or is explicit"},
        {"name": "w3-empty-context-empty-plan",
         "kind": "mitempty",
         "meta": {"model_family": "tabular_fm",
                  "weights_source": "open_weights"},
         "attacks": [], "dimensions": [], "evidence": [],
         "expect": {"empty": True},
         "note": "zero risk context is an explicit empty plan, never silent"},
        {"name": "w3-api-only-generative-no-weight-controls",
         "kind": "mit",
         "meta": {"model_family": "diffusion",
                  "weights_source": "api_only"},
         "attacks": [{"attack_class": "extraction",
                      "applies_to": "family", "confidence": 0.6}],
         "dimensions": [{"dimension": "memorization", "rating": "medium"}],
         "expect": {"proposed_excludes": ["MM01", "MM10"],
                    "deferred_contains": ["MM01", "MM10"]},
"note": "API-only customers cannot operate training or weight "
                  "controls: API-side measures only"},
        # --- model-security knowledge base: the partition is the invariant ---
        {"name": "kb-model-specific-finding-is-own",
         "kind": "kb",
         "finding": {"applies_to": "model_specific", "confidence": 0.8},
         "expect": {"scope": "own", "weight": 1.0,
                    "partition": {"own": 1},
                    "confidence_is_null": False},
         "note": "model-specific evidence is own risk"},
        {"name": "kb-family-finding-is-inherited",
         "kind": "kb",
         "finding": {"applies_to": "family", "confidence": 0.6},
         "expect": {"scope": "inherited", "weight": 0.6,
                    "partition": {"inherited": 1}},
         "note": "family evidence is inherited, and weighs less than own"},
        {"name": "kb-modality-finding-is-inherited",
         "kind": "kb",
         "finding": {"applies_to": "modality", "confidence": 0.4},
         "expect": {"scope": "inherited", "weight": 0.4,
                    "partition": {"inherited": 1}},
         "note": "modality evidence is the weakest transferable kind"},
        {"name": "kb-composition-evidence-is-cascade-not-own",
         "kind": "kb",
         "finding": {"attack_class": "cascade", "applies_to": "modality",
                     "mechanism": "fine_tune", "confidence": 0.7},
         "expect": {"scope": "cascade", "partition": {"cascade": 1}},
         "note": "a cascade row can never be filed as own risk: the base-model "
                 "control that would close own risk does not close a "
                 "composition path"},
        {"name": "kb-missing-confidence-stays-null",
         "kind": "kb",
         "finding": {"applies_to": "model_specific"},
         "expect": {"scope": "own", "confidence_is_null": True},
         "note": "absent confidence is unknown, never zero"},
    ]


def _run_model_case(case: dict[str, Any]) -> dict[str, Any]:
    from . import model_eval as _me
    if case["kind"] == "kb":
        from . import model_kb as _kb
        exp = case.get("expect", {})
        failures = []
        finding = dict(case["finding"])
        finding.setdefault("attack_class", "extraction")
        finding.setdefault("attack_label", case["name"])
        scope, evidence_scope = _kb.scope_of_finding(finding)
        row = {"risk_id": f"{case['name']}:{scope}", "model_key": "kb-case",
               "attack_class": finding["attack_class"],
               "attack_label": finding["attack_label"], "scope": scope,
               "evidence_scope": evidence_scope,
               "severity": case.get("severity", 70),
               "scope_weight": _me.scope_weight(finding.get("applies_to")),
               "confidence": finding.get("confidence"),
               "mechanism": finding.get("mechanism"),
               "exposure": finding.get("exposure")}
        if "scope" in exp and scope != exp["scope"]:
            failures.append({"field": "scope", "expected": exp["scope"],
                             "actual": scope})
        if "weight" in exp and abs(row["scope_weight"] - exp["weight"]) > 1e-9:
            failures.append({"field": "scope_weight",
                             "expected": exp["weight"],
                             "actual": row["scope_weight"]})
        if exp.get("confidence_is_null") and row["confidence"] is not None:
            failures.append({"field": "confidence", "expected": None,
                             "actual": row["confidence"]})
        part = _kb.partition_risks([row])
        if "partition" in exp:
            got = {k: len(v) for k, v in part.items() if v}
            if got != exp["partition"]:
                failures.append({"field": "partition",
                                 "expected": exp["partition"], "actual": got})
        # composition signals are read from the brief text, exactly as the
        # snapshot reads them: a topic word is a labelled inference
        for text, want in (case.get("briefs") or []):
            got = sorted({s["mechanism"] for s in
                          _kb.cascade_signals({}, use_case=text)})
            if want not in got:
                failures.append({"field": f"mechanisms in {text!r}",
                                 "expected": want, "actual": got})
        return {"name": case["name"], "note": case.get("note", ""),
                "ok": not failures, "failures": failures,
                "result": {"scope": scope,
                           "scope_weight": row["scope_weight"],
                           "partition": {k: len(v) for k, v in part.items()}}}
    if case["kind"] == "exp":
        plan = _me.plan_experiments(
            case["meta"], case.get("attacks", []),
            case.get("dimensions", []), case.get("hypotheses", []),
            case.get("mitigation_plan", []))
        exp = case.get("expect", {})
        failures = []
        got_ids = [e["id"] for e in plan["experiments"]]
        for mid in exp.get("contains_methods", []):
            if mid not in {e["method_type"] for e in plan["experiments"]}:
                failures.append({"field": f"contains method {mid}",
                                 "expected": True,
                                 "actual": [e["method_type"]
                                            for e in plan["experiments"]]})
        for hid in exp.get("covers_hypotheses", []):
            targets = [t for e in plan["experiments"]
                       for t in e["targets"].get("hypothesis_ids", [])]
            if hid not in targets:
                failures.append({"field": f"covers hypothesis {hid}",
                                 "expected": True, "actual": targets})
        if exp.get("non_empty") and not plan["experiments"]:
            failures.append({"field": "non_empty", "expected": True,
                             "actual": []})
        return {"name": case["name"], "note": case.get("note", ""),
                "ok": not failures, "failures": failures,
                "result": {"experiments": got_ids}}
    if case["kind"] == "mitempty":
        plan = _me.plan_or_empty(case["meta"], case.get("attacks", []),
                                 case.get("dimensions", []),
                                 case.get("evidence", []))
        exp = case.get("expect", {})
        failures = []
        if exp.get("empty") and plan:
            failures.append({"field": "empty plan", "expected": True,
                             "actual": [p["control_id"] for p in plan]})
        if exp.get("non_empty") and not plan:
            failures.append({"field": "non-empty plan", "expected": True,
                             "actual": []})
        return {"name": case["name"], "note": case.get("note", ""),
                "ok": not failures, "failures": failures,
                "result": {"plan": [p["control_id"] for p in plan]}}
    if case["kind"] == "mit":
        applicable, deferred = _me.prefilter_mitigations(case["meta"])
        plan = _me.rank_mitigations(case["meta"], case.get("attacks", []),
                                    case.get("dimensions", []))
        exp = case.get("expect", {})
        failures = []
        top = [p["control_id"] for p in plan[:5]]
        proposed = {p["control_id"] for p in plan}
        deferred_ids = {d["control_id"] for d in deferred}
        for cid in exp.get("top_contains", []):
            if cid not in top:
                failures.append({"field": f"top5 contains {cid}",
                                 "expected": True, "actual": top})
        for cid in exp.get("proposed_contains", []):
            if cid not in proposed:
                failures.append({"field": f"proposed contains {cid}",
                                 "expected": True,
                                 "actual": sorted(proposed)})
        for cid in exp.get("proposed_excludes", []):
            if cid in proposed:
                failures.append({"field": f"proposed excludes {cid}",
                                 "expected": True, "actual": sorted(proposed)})
        for cid in exp.get("deferred_contains", []):
            if cid not in deferred_ids:
                failures.append({"field": f"deferred contains {cid}",
                                 "expected": True,
                                 "actual": sorted(deferred_ids)})
        return {"name": case["name"], "note": case.get("note", ""),
                "ok": not failures, "failures": failures,
                "result": {"top5": top,
                           "deferred": sorted(deferred_ids)}}
    if case["kind"] == "w1":
        result = _me.score_adversarial(case["findings"])
    else:
        result = _me.score_adoption(case["dimensions"])
    exp = case.get("expect", {})
    failures = []
    for field in ("overall_pct", "coverage_pct", "uncertainty_pct"):
        if field in exp:
            actual, expected = result.get(field), exp[field]
            if expected is None:
                if actual is not None:
                    failures.append({"field": field, "expected": None,
                                     "actual": actual})
            elif actual is None or abs(float(actual) - float(expected)) > TOLERANCE:
                failures.append({"field": field, "expected": expected,
                                 "actual": actual})
    return {"name": case["name"], "note": case.get("note", ""),
            "ok": not failures, "failures": failures,
            "result": {k: result.get(k) for k in
                       ("overall_pct", "coverage_pct", "uncertainty_pct")}}


def model_invariants() -> list[dict[str, Any]]:
    """Properties the model methods must hold whatever the evidence is."""
    from . import model_eval as _me
    out = []
    base = [{"dimension": "memorization", "rating": "high"}]
    scored = _me.score_adoption(base)["overall_pct"]
    plus_unknown = _me.score_adoption(
        base + [{"dimension": "cascade", "rating": "unknown"}])["overall_pct"]
    out.append({
        "name": "unknown-never-lowers-risk",
        "ok": abs((plus_unknown or 0) - (scored or 0)) <= TOLERANCE,
        "detail": {"without": scored, "with_unknown": plus_unknown},
    })
    same = {"attack_class": "extraction", "confidence": 0.8}
    fam = _me.score_adversarial([{**same, "applies_to": "family"}])["overall_pct"]
    own = _me.score_adversarial(
        [{**same, "applies_to": "model_specific"}])["overall_pct"]
    out.append({
        "name": "model-specific-outranks-family",
        "ok": (own or 0) > (fam or 0),
        "detail": {"family": fam, "model_specific": own},
    })
    out.append({
        "name": "empty-w1-has-no-score",
        "ok": _me.score_adversarial([])["overall_pct"] is None,
        "detail": {},
    })
    out.append({
        "name": "all-unknown-w2-has-no-score",
        "ok": _me.score_adoption([])["overall_pct"] is None
        and _me.score_adoption([])["uncertainty_pct"] == 100.0,
        "detail": {},
    })
    return out


def run_eval() -> dict[str, Any]:
    """Run every case and invariant. ``ok`` is the gate."""
    results = [_run_case(c) for c in cases()]
    invs = invariants()
    model_results = [_run_model_case(c) for c in model_cases()]
    model_invs = model_invariants()
    failed = [r for r in results if not r["ok"]]
    failed_inv = [i for i in invs if not i["ok"]]
    failed_model = [r for r in model_results if not r["ok"]]
    failed_model_inv = [i for i in model_invs if not i["ok"]]
    return {
        "ok": not failed and not failed_inv and not failed_model
        and not failed_model_inv,
        "pack": tp.pack_manifest(),
        "cases_run": len(results),
        "cases_failed": len(failed),
        "invariants_run": len(invs),
        "invariants_failed": len(failed_inv),
        "cases": results,
        "invariants": invs,
        "model_cases_run": len(model_results),
        "model_cases_failed": len(failed_model),
        "model_invariants_run": len(model_invs),
        "model_invariants_failed": len(failed_model_inv),
        "model_cases": model_results,
        "model_invariants": model_invs,
        "failures": [{"case": r["name"], "why": r["failures"]} for r in failed]
                   + [{"invariant": i["name"], "detail": i["detail"]}
                      for i in failed_inv]
                   + [{"model_case": r["name"], "why": r["failures"]}
                      for r in failed_model]
                   + [{"model_invariant": i["name"], "detail": i["detail"]}
                      for i in failed_model_inv],
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
    for r in report.get("model_cases", []):
        mark = "ok  " if r["ok"] else "FAIL"
        lines.append(f"  [{mark}] model: {r['name']}")
        for f in r["failures"]:
            lines.append(f"         {f['field']}: expected {f['expected']}, "
                         f"got {f['actual']}")
    for i in report.get("model_invariants", []):
        mark = "ok  " if i["ok"] else "FAIL"
        lines.append(f"  [{mark}] model invariant: {i['name']}")
    lines.append(f"{'PASS' if report['ok'] else 'FAIL'}: "
                 f"{report['cases_run']} cases, {report['invariants_run']} "
                 f"invariants, {report.get('model_cases_run', 0)} model cases, "
                 f"{report.get('model_invariants_run', 0)} model invariants")
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "rebaseline":
        print(json.dumps(rebaseline(), indent=2))
    else:
        rep = run_eval()
        print(render(rep))
        sys.exit(0 if rep["ok"] else 1)
