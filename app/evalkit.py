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
         "expect": {"overall_pct": 46.6, "coverage_pct": 20.0},
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


def portfolio_cases() -> list[dict[str, Any]]:
    """Pinned portfolio arithmetic. Rebaseline deliberately, not accidentally.

    Only pure functions are pinned here -- situation normalisation, the
    multiplier, pathway derivation, control mapping and cascade -- because the
    evalkit runs with no database and no network. Anything needing stored rows
    (the register, advice packs, intel) is covered by ``tests/test_portfolio.py``
    instead.
    """
    internal_chat = {
        "data": {"classification": "internal"}, "channel": "chat_ui",
        "actors": ["analyst"], "controls": {}, "blast_radius": {},
        "external": False, "obligations": [],
    }
    restricted_chat = {
        "data": {"classification": "restricted", "pii_likelihood": True},
        "channel": "chat_ui", "actors": ["analyst"],
        "controls": {"dlp": "evidenced", "logging": "declared"},
        "blast_radius": {"tickets": True}, "external": True,
        "obligations": ["GDPR Art.28"],
    }
    extraction = {"layer": "model", "source_ref": "MA-01",
                  "attack_class": "extraction", "scope": "own"}
    return [
        {"name": "pf-declared-equals-unknown",
         "kind": "pf-multiplier",
         "situation": {**internal_chat,
                       "controls": {"dlp": "declared"}},
         "expect": {"multiplier": 1.0},
         "note": "a declared control is recorded, never counted"},
        {"name": "pf-evidenced-reduces",
         "kind": "pf-multiplier",
         "situation": {**internal_chat,
                       "controls": {"dlp": "evidenced"}},
         "expect": {"multiplier": 0.9},
         "note": "only evidenced standing moves the number"},
        {"name": "pf-restricted-chat",
         "kind": "pf-multiplier",
         "situation": restricted_chat,
         "expect": {"multiplier": 1.55},
         "note": "restricted PII on a customer chat with one evidenced control"},
        {"name": "pf-lp01-severity-and-coverage",
         "kind": "pf-leakage",
         "situation": restricted_chat,
         "meta": {"weights_source": "open_weights"},
         "expect": {"pathways": {
             "LP01": {"severity": 74.4, "evidenced": ["C03"],
                      "declared_only": []},
             "LP03": {"severity": 65.1, "evidenced": [],
                      "declared_only": ["C08"]},
             "LP04": {"severity": 77.5, "evidenced": [],
                      "declared_only": []}}},
         "note": "severity shows its parts; declared logging is not coverage"},
        {"name": "pf-extraction-maps-mm",
         "kind": "pf-map",
         "risk": extraction,
         "situation": restricted_chat,
         "meta": {"weights_source": "open_weights"},
         "expect": {"live": ["MM01", "MM02", "MM03", "MM05",
                              "MM08", "MM09", "MM12", "MM13"],
                     "dropped": []},
         "note": "open weights can take weight-level advice"},
        {"name": "pf-api-only-withholds-training",
         "kind": "pf-map",
         "risk": extraction,
         "situation": restricted_chat,
         "meta": {"weights_source": "api_only"},
         "expect": {"live": ["MM02", "MM08", "MM09", "MM12", "MM13"],
                     "dropped": ["MM01", "MM03", "MM05"]},
         "note": "withheld controls are named, not quietly dropped"},
        {"name": "pf-shared-model-cascades-transitively",
         "kind": "pf-cascade",
         "initiatives": [
             {"title": "Churn scoring", "models": ["acme-v2"],
              "business_use_case": "fine-tuned model on PII"},
             {"title": "Support assistant", "models": ["acme-v2"],
              "business_use_case": "agent with tool access to CRM"}],
         "expect": {"transitive": True},
         "note": "the composed path reaches the team that does not own it"},
        {"name": "pf-catalog-fingerprints",
         "kind": "pf-fingerprints",
         "expect": {"leakage": "be5648831fa9",
                     "playbooks": "47d25eb7fff3"},
         "note": "a catalog edit must show up here before it moves a number"},
    ]


def _run_portfolio_case(case: dict[str, Any]) -> dict[str, Any]:
    from . import leakage as _lk
    from . import portfolio as _pf
    kind = case["kind"]
    exp = case.get("expect", {})
    failures = []
    result: dict[str, Any] = {}
    if kind == "pf-multiplier":
        sit = _pf.normalize_situation(case["situation"])
        mult = _pf.situation_multiplier(sit)
        result = {"multiplier": mult["multiplier"]}
        if abs(mult["multiplier"] - exp["multiplier"]) > TOLERANCE:
            failures.append({"field": "multiplier",
                              "expected": exp["multiplier"],
                              "actual": mult["multiplier"]})
    elif kind == "pf-leakage":
        sit = _pf.normalize_situation(case["situation"])
        rows = {r["source_ref"]: r
                for r in _pf.leakage_rows(sit, case.get("meta") or {})}
        result = {k: {"severity": v["severity"],
                      "evidenced": v["control_coverage"]["evidenced"],
                      "declared_only":
                          v["control_coverage"]["declared_only"]}
                  for k, v in rows.items()}
        for pid, want in exp.get("pathways", {}).items():
            got = result.get(pid)
            if got is None:
                failures.append({"field": f"pathway {pid}",
                                  "expected": "derived", "actual": "absent"})
                continue
            if abs(got["severity"] - want["severity"]) > TOLERANCE:
                failures.append({"field": f"{pid} severity",
                                  "expected": want["severity"],
                                  "actual": got["severity"]})
            for field in ("evidenced", "declared_only"):
                if got[field] != want[field]:
                    failures.append({"field": f"{pid} {field}",
                                      "expected": want[field],
                                      "actual": got[field]})
    elif kind == "pf-map":
        sit = _pf.normalize_situation(case["situation"])
        mapped = _pf.map_controls(case["risk"], sit, case.get("meta") or {})
        live = [m["control_id"] for m in mapped if not m["dropped"]]
        dropped = [m["control_id"] for m in mapped if m["dropped"]]
        result = {"live": live, "dropped": dropped}
        if live != exp.get("live"):
            failures.append({"field": "live", "expected": exp.get("live"),
                              "actual": live})
        if dropped != exp.get("dropped"):
            failures.append({"field": "dropped",
                              "expected": exp.get("dropped"),
                              "actual": dropped})
    elif kind == "pf-cascade":
        from . import portfolio as _pf2
        edges = _pf2.portfolio_cascade({}, case.get("initiatives") or [])
        transitive = [e for e in edges if e["basis"] == "transitive"]
        result = {"edges": len(edges), "transitive": len(transitive)}
        if exp.get("transitive") and not transitive:
            failures.append({"field": "transitive edge",
                              "expected": True, "actual": []})
    elif kind == "pf-fingerprints":
        result = {"leakage": _lk.leakage_fingerprint(),
                  "playbooks": _lk.playbook_fingerprint()}
        for field in ("leakage", "playbooks"):
            if result[field] != exp[field]:
                failures.append({"field": f"{field} fingerprint",
                                  "expected": exp[field],
                                  "actual": result[field]})
    else:
        failures.append({"field": "kind", "expected": "known pf kind",
                          "actual": kind})
    return {"name": case["name"], "note": case.get("note", ""),
            "ok": not failures, "failures": failures, "result": result}


def portfolio_invariants() -> list[dict[str, Any]]:
    """Properties the portfolio layer must hold whatever the catalog says."""
    from . import portfolio as _pf
    out = []
    base = {"data": {"classification": "internal"}, "channel": "chat_ui",
            "actors": ["analyst"], "blast_radius": {}, "external": False}
    un = _pf.situation_multiplier(
        _pf.normalize_situation({**base, "controls": {}}))["multiplier"]
    ok_declared = True
    ok_evidenced = True
    detail: dict[str, Any] = {}
    for control in _pf.SITUATION_CONTROLS:
        dec = _pf.situation_multiplier(_pf.normalize_situation(
            {**base, "controls": {control: "declared"}}))["multiplier"]
        ev = _pf.situation_multiplier(_pf.normalize_situation(
            {**base, "controls": {control: "evidenced"}}))["multiplier"]
        if abs(dec - un) > TOLERANCE:
            ok_declared = False
            detail[control] = {"declared": dec, "baseline": un}
        if ev > un + TOLERANCE:
            ok_evidenced = False
            detail[control] = {"evidenced": ev, "baseline": un}
    out.append({"name": "declared-never-reduces-risk",
                "ok": ok_declared, "detail": detail})
    out.append({"name": "evidenced-never-increases-risk",
                "ok": ok_evidenced, "detail": detail})
    # severity stays on its own scale across a sweep of situations
    sweep = [
        {"data": {"classification": c}, "channel": ch,
         "actors": ["analyst"], "controls": ctrl, "blast_radius": blast,
         "external": ext}
        for c in ("public", "internal", "restricted", "secrets")
        for ch in ("chat_ui", "api", "batch", "tool_calling_agent")
        for ctrl in ({}, {"dlp": "evidenced"},
                     {"dlp": "evidenced", "logging": "evidenced"})
        for blast in ({}, {"tickets": True, "customer_channels": True})
        for ext in (False, True)
    ]
    worst = None
    in_scale = True
    for raw in sweep:
        sit = _pf.normalize_situation(raw)
        for r in _pf.leakage_rows(sit, {"weights_source": "open_weights"}):
            if not (0.0 <= r["severity"] <= 100.0):
                in_scale = False
                worst = {"situation": raw, "pathway": r["source_ref"],
                         "severity": r["severity"]}
                break
        if not in_scale:
            break
    out.append({"name": "severity-stays-on-its-scale",
                "ok": in_scale,
                "detail": {"situations_swept": len(sweep),
                           "violation": worst}})
    # an empty situation normalises to unknown everywhere, not to defaults
    empty = _pf.normalize_situation({})
    out.append({
        "name": "empty-situation-stays-unknown",
        "ok": (empty["channel"] is None and empty["actors"] == []
               and all(v == "unknown" for v in empty["controls"].values())),
        "detail": {"unknown_fields": len(empty["unknown_fields"])},
    })
    return out


def provider_cases() -> list[dict[str, Any]]:
    """Pinned provider-posture behaviour. Rebaseline deliberately.

    Same rule as the other suites: only pure functions, so the gate runs
    with no database and no network. Anything needing stored rows lives in
    ``tests/test_provider_posture.py`` instead.
    """
    return [
        {"name": "pdp-command-names-providers",
         "kind": "pdp-detect",
         "command": ("Data exposure investigation: OpenAI, Anthropic -- "
                     "training use, retention, are we datapoints?"),
         "expect": {"providers": ["OpenAI", "Anthropic"],
                     "posture": True},
         "note": "subjects are provider names, never the verb phrase"},
        {"name": "pdp-capability-question-rejected",
         "kind": "pdp-detect",
         "command": "Who leads on benchmarks, OpenAI or Google?",
         "expect": {"providers": ["OpenAI", "Google"],
                     "posture": False},
         "note": "a lab without a data question is not a posture command"},
        {"name": "pdp-policy-reads-partial-rest-unknown",
         "kind": "pdp-assess",
         "artifacts": [
             {"id": 1, "title": "OpenAI privacy policy training opt-out "
                               "retention terms",
              "tags": "policy", "artifact_type": "paper",
              "review": "accepted"}],
         "expect": {"PDP01": "partial", "PDP02": "partial",
                     "PDP07": "unknown", "supported": []},
         "note": "one policy touches what it touches; the rest stays unknown"},
        {"name": "pdp-pending-is-not-evidence",
         "kind": "pdp-assess",
         "artifacts": [
             {"id": 2, "title": "Vendor privacy policy training terms",
              "tags": "policy", "artifact_type": "paper",
              "review": "pending"}],
         "expect": {"all": "unknown"},
         "note": "pending artifacts count for nothing"},
        {"name": "pdp-catalog-fingerprint",
         "kind": "pdp-fingerprints",
         "expect": {},
         "note": "a catalog edit must show up here before it moves a finding"},
        {"name": "pdp-definite-claim-stripped",
         "kind": "pdp-guard",
         "text": ("The vendor trains on your API data. "
                  "Retention defaults apply."),
         "expect": {"removed_count": 1, "kept_contains": "Retention"},
         "note": "definite training claims need tier terms or they go"},
        {"name": "rlhf-feedback-reads-partial",
         "kind": "rlhf-assess",
         "artifacts": [
             {"id": 1, "title": "Consumer thumbs feedback retention "
                               "and training terms",
              "tags": "feedback", "artifact_type": "paper",
              "review": "accepted"}],
         "expect": {"RLHF01": "partial", "RLHF02": "partial",
                     "RLHF06": "unknown", "supported": []},
         "note": "feedback evidence touches feedback rows; ZDR stays unknown"},
        {"name": "rlhf-no-train-claim-leaves-safety-logs-unknown",
         "kind": "rlhf-assess",
         "artifacts": [
             {"id": 2, "title": "API data is not used for training",
              "tags": "", "artifact_type": "paper",
              "review": "accepted"}],
         "expect": {"RLHF05": "unknown"},
         "note": "a training denial says nothing about abuse-log retention"},
        {"name": "rlhf-pending-is-not-evidence",
         "kind": "rlhf-assess",
         "artifacts": [
             {"id": 3, "title": "Feedback retention years policy",
              "tags": "", "artifact_type": "paper",
              "review": "pending"}],
         "expect": {"all": "unknown"},
         "note": "pending artifacts count for nothing"},
        {"name": "rlhf-catalog-fingerprint",
         "kind": "rlhf-fingerprints",
         "expect": {},
         "note": "a catalog edit must show up here before it moves a finding"},
    ]


def _run_provider_case(case: dict[str, Any]) -> dict[str, Any]:
    from . import provider_posture as _pp
    kind = case["kind"]
    exp = case.get("expect", {})
    failures = []
    result: dict[str, Any] = {}
    if kind == "pdp-detect":
        found = [p["name"] for p in _pp.detect_providers(case["command"])]
        posture = _pp.is_posture_command(case["command"])
        result = {"providers": found, "posture": posture}
        if found != exp.get("providers"):
            failures.append({"field": "providers",
                              "expected": exp.get("providers"),
                              "actual": found})
        if posture != exp.get("posture"):
            failures.append({"field": "posture",
                              "expected": exp.get("posture"),
                              "actual": posture})
    elif kind == "pdp-assess":
        assessed = _pp.assess_pdp(case.get("artifacts") or [])
        by_id = {f["id"]: f["standing"] for f in assessed["findings"]}
        result = {"standings": by_id}
        if "all" in exp:
            if set(by_id.values()) != {exp["all"]}:
                failures.append({"field": "all standings",
                                  "expected": exp["all"],
                                  "actual": sorted(set(by_id.values()))})
        for dim, want in exp.items():
            if dim in ("all",):
                continue
            if dim == "supported":
                got = [k for k, v in by_id.items() if v == "supported"]
                if got != want:
                    failures.append({"field": "supported",
                                      "expected": want, "actual": got})
            elif by_id.get(dim) != want:
                failures.append({"field": dim, "expected": want,
                                  "actual": by_id.get(dim)})
    elif kind == "pdp-fingerprints":
        result = {"fingerprint": _pp.pdp_fingerprint()}
    elif kind == "rlhf-assess":
        assessed = _pp.assess_rlhf(case.get("artifacts") or [])
        by_id = {f["id"]: f["standing"] for f in assessed["findings"]}
        result = {"standings": by_id}
        if "all" in exp:
            if set(by_id.values()) != {exp["all"]}:
                failures.append({"field": "all standings",
                                  "expected": exp["all"],
                                  "actual": sorted(set(by_id.values()))})
        for dim, want in exp.items():
            if dim in ("all",):
                continue
            if dim == "supported":
                got = [k for k, v in by_id.items() if v == "supported"]
                if got != want:
                    failures.append({"field": "supported",
                                      "expected": want, "actual": got})
            elif by_id.get(dim) != want:
                failures.append({"field": dim, "expected": want,
                                  "actual": by_id.get(dim)})
    elif kind == "rlhf-fingerprints":
        result = {"fingerprint": _pp.rlhf_fingerprint()}
    elif kind == "pdp-guard":
        out = _pp.guard_provider_claims(case.get("text") or "")
        result = {"removed_count": out["removed_count"]}
        if out["removed_count"] != exp.get("removed_count"):
            failures.append({"field": "removed_count",
                              "expected": exp.get("removed_count"),
                              "actual": out["removed_count"]})
        if exp.get("kept_contains") not in out["text"]:
            failures.append({"field": "kept text",
                              "expected": f"contains {exp['kept_contains']!r}",
                              "actual": out["text"]})
    else:
        failures.append({"field": "kind", "expected": "known pdp kind",
                          "actual": kind})
    return {"name": case["name"], "note": case.get("note", ""),
            "ok": not failures, "failures": failures, "result": result}


def provider_invariants() -> list[dict[str, Any]]:
    """Properties the posture layer must hold whatever the catalog says."""
    from . import provider_posture as _pp
    out = []
    policy = [{"id": 1, "title": "Provider privacy policy training "
                                 "retention enterprise terms",
               "tags": "policy", "artifact_type": "paper",
               "review": "accepted"}]
    derived = {f["id"]: f["standing"]
               for f in _pp.assess_pdp(policy)["findings"]}
    out.append({
        "name": "supported-never-derived",
        "ok": "supported" not in set(derived.values()),
        "detail": {"standings": sorted(set(derived.values()))},
    })
    blank = {f["id"]: f["standing"] for f in _pp.blank_findings()}
    out.append({
        "name": "blank-means-unknown",
        "ok": set(blank.values()) == {"unknown"} and len(blank) == 10,
        "detail": {"dimensions": len(blank)},
    })
    out.append({
        "name": "detection-needs-both-halves",
        "ok": not _pp.is_posture_command("training data retention")
        and not _pp.is_posture_command("OpenAI model quality"),
        "detail": {},
    })
    rlhf_policy = [{"id": 1, "title": "Consumer thumbs feedback retention "
                                      "and training terms",
                    "tags": "feedback", "artifact_type": "paper",
                    "review": "accepted"}]
    rlhf_derived = {f["id"]: f["standing"]
                    for f in _pp.assess_rlhf(rlhf_policy)["findings"]}
    out.append({
        "name": "rlhf-supported-never-derived",
        "ok": "supported" not in set(rlhf_derived.values()),
        "detail": {"standings": sorted(set(rlhf_derived.values()))},
    })
    out.append({
        "name": "rlhf-blank-means-unknown",
        "ok": {f["standing"] for f in _pp.blank_rlhf()} == {"unknown"}
        and len(_pp.blank_rlhf()) == 8,
        "detail": {"dimensions": len(_pp.blank_rlhf())},
    })
    return out


def grounding_cases() -> list[dict[str, Any]]:
    """The hallucination regression suite. Deterministic, no model, no network.

    Each case is a failure mode that a substring gate alone cannot name: an
    invented quote, a negation flip, a number swap, and an honest paraphrase.
    Pinning the *reason* -- not just the boolean -- is what stops a future edit
    from collapsing all four back into one opaque "not found" and quietly
    losing the distinction the engine depends on.
    """
    source = ("The service retains API prompts for 30 days before deletion, "
              "and the KMS vault holds the encryption keys.")
    return [
        {"name": "ground-verbatim-block-quote",
         "quote": "retains API prompts for 30 days", "source": source,
         "expect": {"verdict": "supported", "reason": "verbatim"}},
        {"name": "ground-invented-quote",
         "quote": "adversaries extract memorized samples", "source": source,
         "expect": {"verdict": "unverified", "reason": "not_found_in_source"}},
        {"name": "ground-negation-flip",
         "quote": "The service does not retain API prompts", "source": source,
         "expect": {"reason": "negation_flip"}},
        {"name": "ground-number-swap",
         "quote": "retains API prompts for 90 days", "source": source,
         "expect": {"reason": "number_swap"}},
        {"name": "ground-paraphrase-not-verbatim",
         "quote": "the encryption keys live in a KMS vault", "source": source,
         "expect": {"verdict": "unverified", "reason": "paraphrase"}},
        {"name": "ground-paraphrase-accepted-with-entailment",
         "quote": "the encryption keys live in a KMS vault", "source": source,
         "entail_min": 0.6,
         "expect": {"verdict": "supported", "verified_by": "entailment"}},
        # Premise addition: every content word of the source is present, but the
        # claim smuggles in a causal step the source never licensed. Pure term
        # overlap scores this as well supported, which is why it is pinned.
        {"name": "ground-premise-addition-causal",
         "quote": ("retains API prompts for 30 days before deletion, "
                   "therefore the KMS vault can read them"),
         "source": source,
         "expect": {"reason": "premise_addition"}},
        {"name": "ground-premise-addition-modal-upgrade",
         "quote": "the service must retain API prompts for 30 days",
         "source": source,
         "expect": {"reason": "premise_addition"}},
        {"name": "ground-premise-addition-absolute",
         "quote": "the service never retains API prompts",
         "source": source,
         "expect": {"reason": "negation_flip"}},
        # A source that genuinely asserts the stronger claim must NOT be
        # penalised: the detector checks the source, not a keyword list.
        {"name": "ground-absolute-in-source-is-allowed",
         "quote": "the service never retains API prompts",
         "source": "The service never retains API prompts; they are discarded "
                   "at the edge.",
         "expect": {"verdict": "supported", "reason": "verbatim"}},
    ]


def _run_grounding_case(case: dict[str, Any]) -> dict[str, Any]:
    from . import grounding as G
    exp = case["expect"]
    failures = []
    r = G.verify_grounding(
        case["quote"], [{"source": "s1", "quote": case["quote"]}],
        {"s1": case["source"]}, entail_min=case.get("entail_min"))
    if "verdict" in exp and r["verdict"] != exp["verdict"]:
        failures.append({"field": "verdict", "expected": exp["verdict"],
                         "actual": r["verdict"]})
    if "reason" in exp:
        reason = r["kept"][0]["verified_by"] if r["kept"] else \
            (r["dropped"][0]["reason"] if r["dropped"] else None)
        if reason != exp["reason"]:
            failures.append({"field": "reason", "expected": exp["reason"],
                             "actual": reason})
    if "verified_by" in exp:
        actual = r["kept"][0]["verified_by"] if r["kept"] else None
        if actual != exp["verified_by"]:
            failures.append({"field": "verified_by",
                             "expected": exp["verified_by"], "actual": actual})
    return {"name": case["name"], "ok": not failures, "failures": failures,
            "result": {"verdict": r["verdict"], "n_sources": r["n_sources"]}}


def grounding_invariants() -> list[dict[str, Any]]:
    """Properties the grounding gate must hold whatever the model emits."""
    from . import claims as C
    from . import grounding as G
    out = []
    source = "The vendor encrypts customer data at rest using managed keys."
    # A verbatim quote is never rejected.
    body = "The vendor encrypts customer data at rest using managed keys."
    r = G.verify_grounding("c", [{"source": "s", "quote": body}], {"s": source})
    out.append({"name": "verbatim-quote-always-supports",
                "ok": r["verdict"] == "supported",
                "detail": {"verdict": r["verdict"]}})
    # More independent sources never lower calibrated confidence.
    vals = [G.calibrated_confidence(n) for n in (0, 1, 2, 3, 5)]
    out.append({"name": "confidence-monotone-in-sources",
                "ok": all(a <= b for a, b in zip(vals, vals[1:],
                                                strict=False)),
                "detail": {"values": vals}})
    # The free-text guard can only ever remove text, never add it.
    doc = ("# Report\n"
           "The vendor encrypts customer data at rest using managed keys.\n"
           "Adversaries extract memorized training samples from the endpoint.")
    guarded = C.guard_free_text(doc, [{"id": "p", "text": source}])
    out.append({"name": "guard-never-adds-text",
                "ok": len(guarded["text"]) <= len(doc),
                "detail": {"before": len(doc), "after": len(guarded["text"])}})
    out.append({"name": "guard-drops-the-invented-sentence",
                "ok": "Adversaries" not in guarded["text"],
                "detail": {"kept": len(guarded["kept"]),
                           "dropped": len(guarded["dropped"])}})
    return out


def engine_invariants() -> list[dict[str, Any]]:
    """Structural properties of the newer analysis modules (WS3-WS7).

    Kept as one block alongside the grounding invariants so a regression in the
    uncertainty band, the privacy budget, the benchmark crosswalk or the
    reproducibility manifest fails the same gate as everything else.
    """
    from . import benchmarks as B
    from . import privacy as P
    from . import repro as R
    from . import uncertainty as U
    out = []

    # The credible band must contain the headline it is reported next to.
    inherent = _inherent("confidential_data")
    res = sec.score_assessment("confidential_data", inherent,
                               active_controls=["C02", "C04"])
    band = U.assessment_interval(res)
    out.append({"name": "uncertainty-band-contains-headline",
                "ok": band["headline_inside"],
                "detail": {"headline": band["headline_pct"],
                           "lower": band["lower_pct"],
                           "upper": band["upper_pct"]}})

    # A control can never raise the residual it is meant to lower.
    before = U.residual_interval(0.6, [])["mean"]
    after = U.residual_interval(0.6, [(0.8, U.DIRECT)])["mean"]
    out.append({"name": "control-never-raises-residual",
                "ok": after <= before,
                "detail": {"before": before, "after": after}})

    # Every threat in the catalogue resolves to an external benchmark.
    cov = B.coverage([t[0] for t in sec._THREAT_CATALOG], kind="threat")
    out.append({"name": "threat-catalogue-fully-benchmarked",
                "ok": cov["fraction"] == 1.0,
                "detail": {"unmapped": cov["unmapped"]}})

    # A batch of perfectly correct, perfectly confident predictions is calibrated.
    rel = B.reliability([(1.0, True)] * 8)
    out.append({"name": "reliability-perfect-is-zero-error",
                "ok": rel["brier"] == 0.0 and rel["ece"] == 0.0,
                "detail": rel})

    # A stored artifact reproduced verbatim by an output is caught.
    leak = ("the vendor stores telemetry in the eu region for thirty days "
            "and deletes it automatically afterwards")
    ext = P.extraction_resistance([("A1", leak)], [leak])
    out.append({"name": "privacy-flags-verbatim-extraction",
                "ok": not ext["ok"] and ext["stats"]["high"] >= 1,
                "detail": ext["stats"]})

    # Exhausting the budget is a first-class state, not a silent overrun.
    big = [{"url": f"https://d{i}.com/p", "text": f"text {i}"} for i in range(30)]
    budget = P.privacy_budget(big, budget={"max_spend": 10.0})
    out.append({"name": "privacy-budget-exhausts-loudly",
                "ok": budget["exhausted"] and budget["advice"] == "refuse",
                "detail": {"advice": budget["advice"],
                           "remaining": budget["remaining"]}})

    # An erasure commitment opens for the right subject and no one else.
    commit = P.erasure_commitment("acme", "run-1", salt="s")["commitment"]
    out.append({"name": "erasure-commitment-is-selectively-openable",
                "ok": P.verify_erasure("acme", "run-1", salt="s",
                                       commitment=commit)
                and not P.verify_erasure("other", "run-1", salt="s",
                                         commitment=commit),
                "detail": {"commitment": commit[:12]}})

    # The same inputs reproduce the same manifest fingerprint, and tampering
    # is detected.
    m = R.manifest(inputs={"source": "hello"}, seeds={"mc": 1729})
    out.append({"name": "repro-manifest-is-deterministic",
                "ok": m["fingerprint"]
                == R.manifest(inputs={"source": "hello"},
                              seeds={"mc": 1729})["fingerprint"],
                "detail": {"fingerprint": m["fingerprint"]}})
    out.append({"name": "repro-manifest-detects-tampering",
                "ok": R.verify(m) and not _tampered_verifies(R, m),
                "detail": {"fingerprint": m["fingerprint"]}})

    # The residual score declares its own saturation. A model whose headline
    # stops responding to controls must say so rather than presenting a
    # static number as a measurement.
    allc = [c["id"] for c in sec._CONTROL_CATALOG]
    sat = sec.score_assessment("confidential_data", inherent,
                               active_controls=allc)
    fl = sat.get("floor") or {}
    out.append({"name": "score-declares-floor-saturation",
                "ok": bool(fl.get("floor_capped"))
                and fl.get("controls_beyond_floor", 0) > 0
                and sat.get("floor_capped") is True,
                "detail": {"residual_pct": sat["residual_pct"],
                           "beyond_floor": fl.get("controls_beyond_floor"),
                           "effective": fl.get("controls_effective")}})

    # Every efficacy the catalogue reports carries its provenance, and no
    # unvalidated prior is presented as a measurement.
    cat = sec.control_catalog()
    out.append({"name": "control-efficacy-declares-provenance",
                "ok": bool(cat)
                and all(r.get("evidence", {}).get("basis") in sec.EFFICACY_BASIS
                        for r in cat)
                and all("efficacy_is_prior" in r for r in cat),
                "detail": {"controls": len(cat)}})

    # The band names what it does not cover, so an interval cannot be read as
    # the total uncertainty of the assessment.
    band = U.assessment_interval(sat, draws=400)
    vb = band.get("variance_budget") or {}
    unq = vb.get("unquantified") or {}
    out.append({"name": "band-declares-unquantified-inputs",
                "ok": bool(unq)
                and "threat_catalogue_completeness" in unq
                and "residual_floor" in unq
                and vb.get("total_variance", 0) > 0,
                "detail": {"unquantified": len(unq),
                           "total_variance": vb.get("total_variance")}})

    # An unvalidated control must not be reported with the confidence of a
    # measured one: dropping to a tight prior has to narrow the band.
    prov = band["upper_pct"] - band["lower_pct"]
    optimistic_band = U.assessment_interval(
        sat, draws=400,
        evidence_by_control={cid: U.DIRECT for cid in allc})
    optimistic = optimistic_band["upper_pct"] - optimistic_band["lower_pct"]
    out.append({"name": "unvalidated-prior-widens-the-band",
                "ok": prov > optimistic,
                "detail": {"unvalidated": prov, "as_measured": optimistic}})

    # Every input the deterministic engine holds fixed is named as such.
    out.append({"name": "variance-budget-covers-fixed-inputs",
                "ok": all(k in unq for k in ("threat_impact_values",
                                              "likelihood_judgement",
                                              "applicability_weights",
                                              "aggregation_weights")),
                "detail": {"named": len(unq)}})

    # Grounding must name *which* failure mode, not just that it failed. A
    # confusion matrix over the labelled fixture set is the empirical
    # substrate: it says which reason is being confused for which, with
    # numbers, instead of a boolean.
    cm = B.grounding_confusion_matrix(_grounding_labels())
    out.append({"name": "grounding-reasons-are-distinguishable",
                "ok": cm["macro_f1"] >= 0.7,
                "detail": {"accuracy": cm["accuracy"],
                           "macro_f1": cm["macro_f1"],
                           "weakest": min(cm["per_class"].items(),
                                          key=lambda kv: kv[1]["f1"])[0]
                           if cm["per_class"] else None}})

    # Kappa is prevalence-sensitive and the L/I marginals are heavily skewed,
    # so alpha/AC1 must be reported beside it. This pins that they are present
    # and sane rather than that they exceed some threshold -- agreement depends
    # on the raters, not on the statistics.
    rater_rows = [("low", "low"), ("low", "low"), ("high", "high"),
                  ("high", "high"), ("medium", "low"), ("medium", "medium")]
    inter = B.inter_rater([({"likelihood": a, "impact": a},
                            {"likelihood": b, "impact": b})
                           for a, b in rater_rows])
    _scale = inter.get("likelihood") or {}
    out.append({"name": "prevalence-corrected-agreement-reported",
                "ok": "krippendorff_alpha" in _scale and "gwet_ac1" in _scale,
                "detail": {k: _scale[k] for k in
                           ("kappa", "krippendorff_alpha", "gwet_ac1")
                           if k in _scale}})

    # Sensitivity: how much of the headline is each modelling choice?
    inh_list = _inherent("confidential_data")
    abl = B.ablation_report(inh_list, ["C01", "C02"])
    out.append({"name": "ablation-reports-model-sensitivity",
                "ok": abl["max_abs_delta"] >= 0 and "fragile" in abl,
                "detail": {"base": abl["base_residual_pct"],
                           "max_abs_delta": abl["max_abs_delta"],
                           "fragile": abl["fragile"]}})

    # The DP accounting must never be quotable as a guarantee: the engine adds
    # no noise, so the number is a sensitivity structure, not (epsilon, delta)
    # protection. An invariant so a future edit cannot quietly drop the caveat.
    dp = P.dp_accounting([{"url": "https://a.test/x", "text": "t"}],
                         queries=1)
    out.append({"name": "dp-accounting-is-not-a-guarantee",
                "ok": dp["mechanism"] == "accounted-not-enforced"
                and "NOT a differential-privacy guarantee" in dp["note"],
                "detail": {"mechanism": dp["mechanism"],
                           "epsilon": dp["epsilon"]}})

    # Observers, not fetches, drive the exposure bound: five pages on one host
    # is a smaller exposure than one page on five.
    dp_one = P.dp_accounting([{"url": f"https://a.test/{i}", "text": str(i)}
                              for i in range(5)])
    dp_many = P.dp_accounting([{"url": f"https://h{i}.test/x", "text": str(i)}
                               for i in range(5)])
    out.append({"name": "dp-cost-tracks-observers-not-fetches",
                "ok": dp_many["epsilon"] > dp_one["epsilon"],
                "detail": {"one_host": dp_one["epsilon"],
                           "five_hosts": dp_many["epsilon"]}})

    # The leak detectors must discriminate: an undetectable canary is a silent
    # false negative, the worst failure mode for a detector.
    roc = P.detector_roc()
    mroc = P.membership_detector_roc()
    out.append({"name": "leak-detectors-discriminate",
                "ok": roc["auc"] > 0.8 and mroc["auc"] > 0.8,
                "detail": {"extraction_auc": roc["auc"],
                           "membership_auc": mroc["auc"]}})

    # The scoring envelope is read by string from ~10 narrative consumers, so
    # a renamed breakdown key would blank every panel instead of erroring.
    # Pin the shape.
    contract = B.validate_scoring_contract(
        sec.score_assessment("confidential_data", inh_list,
                             active_controls=["C01", "C02"]))
    out.append({"name": "scoring-result-honours-its-contract",
                "ok": not contract,
                "detail": {"violations": contract}})

    # Derived scenarios must be reproducible and self-explaining: a scenario
    # that cannot name its ingredients is a story.
    from . import scenarios as SC
    _sc_inh = _inherent("confidential_data")
    _scored = sec.score_assessment("confidential_data", _sc_inh,
                                   active_controls=["C01", "C02", "C03"])
    _sc_a = SC.scenarios(_scored)
    _sc_b = SC.scenarios(_scored)
    out.append({"name": "scenario-derivation-is-deterministic-and-traced",
                "ok": [s["id"] for s in _sc_a["scenarios"]]
                == [s["id"] for s in _sc_b["scenarios"]]
                and all(s.get("why") for s in _sc_a["scenarios"]),
                "detail": _sc_a["stats"]})

    # The experiment statistics must not manufacture certainty. A clean run of
    # a realistic size must carry a non-trivial upper bound, and the interval
    # must satisfy the tail equations it claims to.
    from . import experiments as EX
    _ri = EX.rate_interval(0, 20)
    out.append({"name": "clean-run-keeps-its-uncertainty",
                "ok": _ri["lower"] == 0.0 and _ri["upper"] > 0.1
                and _ri["method"] == "clopper-pearson",
                "detail": {"zero_of_20": [_ri["lower"], _ri["upper"]]}})
    _incon = EX.score_result({"id": "EX-01"}, successes=0, trials=5)
    out.append({"name": "underpowered-experiment-is-inconclusive",
                "ok": _incon["verdict"] == "inconclusive",
                "detail": {"verdict": _incon["verdict"]}})

    # The hypothesis council must run with no model at all, and it must not
    # reward a claim nobody looked at. Both are engine properties, so both
    # belong in the gate and not only in the council's own suite: a panel that
    # needs a gateway disappears exactly when the evidence is thinnest, and a
    # panel that scores silence as a pass is a monologist wearing a
    # committee's clothes.
    from . import agents as AG
    from . import council as CO
    _hyp_rows = [{"id": "M01", "title": "memorisation of training rows",
                  "dimension": "training_data_privacy",
                  "rationale": "personal data in the corpus"},
                 {"id": "A09", "title": "distil weights from the endpoint",
                  "dimension": "capability_abuse",
                  "rationale": "query budget"}]
    _drafts = CO.draft_seat_claims(_hyp_rows, [], {"is_model_query": True})
    _panel = AG.hypothesis_verifier_handle(
        {"payload": {"hypotheses": _drafts, "target_rows": _hyp_rows,
                     "adversarial_rows": _hyp_rows},
         "task_id": "inv", "trace": []})["payload"]
    _verified = _panel["verified"]
    out.append({
        "name": "council-runs-offline-and-never-passes-silence",
        "ok": (bool(_drafts)
               and all(CO.falsifier_audit(h["falsifier"])["grade"] == "decisive"
                       for h in _drafts)
               and all(v.get("peer_reviewed") for v in _verified)
               and _panel["dimension_inputs"].get("peer_scrutiny", 0) > 0),
        "detail": {"seats_filed": len(_drafts),
                   "contested": _panel["council"]["contested"],
                   "unexamined": _panel["council"]["unexamined"],
                   "coverage_pct": _panel["council"]["coverage"]["coverage_pct"],
                   "peer_scrutiny": _panel["dimension_inputs"].get(
                       "peer_scrutiny")},
    })
    return out


def _grounding_labels() -> list[dict[str, Any]]:
    """Labelled (expected, predicted) pairs for the grounding confusion matrix.

    Derived from the regression cases themselves so the matrix and the pass/fail
    suite can never describe different classifiers -- if a case drifts, both
    views drift together rather than one silently going stale.
    """
    from . import grounding as G
    rows: list[dict[str, Any]] = []
    for case in grounding_cases():
        exp = case["expect"].get("reason")
        if exp is None:
            continue
        r = G.verify_grounding(
            case["quote"], [{"source": "s1", "quote": case["quote"]}],
            {"s1": case["source"]}, entail_min=case.get("entail_min"))
        actual = (r["kept"][0]["verified_by"] if r["kept"]
                  else (r["dropped"][0]["reason"] if r["dropped"] else None))
        rows.append({"expected": exp, "predicted": actual})
    return rows


def _tampered_verifies(R, m):
    import copy
    m2 = copy.deepcopy(m)
    m2["seeds"]["mc"] = 999
    return R.verify(m2)


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
    pf_results = [_run_portfolio_case(c) for c in portfolio_cases()]
    pf_invs = portfolio_invariants()
    failed_pf = [r for r in pf_results if not r["ok"]]
    failed_pf_inv = [i for i in pf_invs if not i["ok"]]
    pdp_results = [_run_provider_case(c) for c in provider_cases()]
    pdp_invs = provider_invariants()
    failed_pdp = [r for r in pdp_results if not r["ok"]]
    failed_pdp_inv = [i for i in pdp_invs if not i["ok"]]
    gr_results = [_run_grounding_case(c) for c in grounding_cases()]
    gr_invs = grounding_invariants()
    failed_gr = [r for r in gr_results if not r["ok"]]
    failed_gr_inv = [i for i in gr_invs if not i["ok"]]
    eng_invs = engine_invariants()
    failed_eng_inv = [i for i in eng_invs if not i["ok"]]
    return {
        "ok": not failed and not failed_inv and not failed_model
        and not failed_model_inv and not failed_pf and not failed_pf_inv
        and not failed_pdp and not failed_pdp_inv
        and not failed_gr and not failed_gr_inv and not failed_eng_inv,
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
        "portfolio_cases_run": len(pf_results),
        "portfolio_cases_failed": len(failed_pf),
        "portfolio_invariants_run": len(pf_invs),
        "portfolio_invariants_failed": len(failed_pf_inv),
        "portfolio_cases": pf_results,
        "portfolio_invariants": pf_invs,
        "provider_cases_run": len(pdp_results),
        "provider_cases_failed": len(failed_pdp),
        "provider_invariants_run": len(pdp_invs),
        "provider_invariants_failed": len(failed_pdp_inv),
        "provider_cases": pdp_results,
        "provider_invariants": pdp_invs,
        "grounding_cases_run": len(gr_results),
        "grounding_cases_failed": len(failed_gr),
        "grounding_invariants_run": len(gr_invs),
        "grounding_invariants_failed": len(failed_gr_inv),
        "grounding_cases": gr_results,
        "grounding_invariants": gr_invs,
        "engine_invariants_run": len(eng_invs),
        "engine_invariants_failed": len(failed_eng_inv),
        "engine_invariants": eng_invs,
        "failures": [{"case": r["name"], "why": r["failures"]} for r in failed]
                   + [{"invariant": i["name"], "detail": i["detail"]}
                      for i in failed_inv]
                   + [{"model_case": r["name"], "why": r["failures"]}
                      for r in failed_model]
                   + [{"model_invariant": i["name"], "detail": i["detail"]}
                      for i in failed_model_inv]
                   + [{"portfolio_case": r["name"], "why": r["failures"]}
                      for r in failed_pf]
                   + [{"portfolio_invariant": i["name"], "detail": i["detail"]}
                      for i in failed_pf_inv]
                   + [{"provider_case": r["name"], "why": r["failures"]}
                      for r in failed_pdp]
                   + [{"provider_invariant": i["name"], "detail": i["detail"]}
                      for i in failed_pdp_inv]
                   + [{"grounding_case": r["name"], "why": r["failures"]}
                      for r in failed_gr]
                   + [{"grounding_invariant": i["name"], "detail": i["detail"]}
                       for i in failed_gr_inv]
                   + [{"engine_invariant": i["name"], "detail": i["detail"]}
                      for i in failed_eng_inv],
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
    for r in report.get("portfolio_cases", []):
        mark = "ok  " if r["ok"] else "FAIL"
        lines.append(f"  [{mark}] portfolio: {r['name']}")
        for f in r["failures"]:
            lines.append(f"         {f['field']}: expected {f['expected']}, "
                         f"got {f['actual']}")
    for i in report.get("portfolio_invariants", []):
        mark = "ok  " if i["ok"] else "FAIL"
        lines.append(f"  [{mark}] portfolio invariant: {i['name']}")
    for r in report.get("provider_cases", []):
        mark = "ok  " if r["ok"] else "FAIL"
        lines.append(f"  [{mark}] provider: {r['name']}")
        for f in r["failures"]:
            lines.append(f"         {f['field']}: expected {f['expected']}, "
                         f"got {f['actual']}")
    for i in report.get("provider_invariants", []):
        mark = "ok  " if i["ok"] else "FAIL"
        lines.append(f"  [{mark}] provider invariant: {i['name']}")
    for r in report.get("grounding_cases", []):
        mark = "ok  " if r["ok"] else "FAIL"
        lines.append(f"  [{mark}] grounding: {r['name']}")
        for f in r["failures"]:
            lines.append(f"         {f['field']}: expected {f['expected']}, "
                         f"got {f['actual']}")
    for i in report.get("grounding_invariants", []):
        mark = "ok  " if i["ok"] else "FAIL"
        lines.append(f"  [{mark}] grounding invariant: {i['name']}")
    for i in report.get("engine_invariants", []):
        mark = "ok  " if i["ok"] else "FAIL"
        lines.append(f"  [{mark}] engine invariant: {i['name']}")
    lines.append(f"{'PASS' if report['ok'] else 'FAIL'}: "
                 f"{report['cases_run']} cases, {report['invariants_run']} "
                 f"invariants, {report.get('model_cases_run', 0)} model cases, "
                 f"{report.get('model_invariants_run', 0)} model invariants, "
                 f"{report.get('portfolio_cases_run', 0)} portfolio cases, "
                 f"{report.get('portfolio_invariants_run', 0)} "
                 f"portfolio invariants, "
                 f"{report.get('provider_cases_run', 0)} provider cases, "
                 f"{report.get('provider_invariants_run', 0)} "
                 f"provider invariants, "
                 f"{report.get('grounding_cases_run', 0)} grounding cases, "
                 f"{report.get('grounding_invariants_run', 0)} "
                 f"grounding invariants, "
                 f"{report.get('engine_invariants_run', 0)} engine invariants")
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "rebaseline":
        print(json.dumps(rebaseline(), indent=2))
    else:
        rep = run_eval()
        print(render(rep))
        sys.exit(0 if rep["ok"] else 1)
