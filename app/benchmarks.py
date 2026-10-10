"""Benchmarks and calibration: bind the catalogue to external authority and
check that the numbers the engine emits are actually reliable.

Two separate gaps are closed here.

* **Provenance.** The threat catalogue (*T01*…) and the model mitigation
  catalogue (*MM01*…) are the engine's own ids. They mean nothing to an auditor
  who speaks OWASP, STRIDE or MITRE ATLAS. :data:`THREAT_BENCHMARKS` and
  :data:`MITIGATION_BENCHMARKS` are a small, *versioned* crosswalk from each
  internal id to the external ticket it represents, and :func:`coverage` turns
  the crosswalk into a "how much of the catalogue is even mapped?" number so an
  unmapped id is visible rather than assumed.

* **Reliability.** A risk score is only as good as the agreement behind it.
  :func:`cohens_kappa` measures whether two raters (or two runs) agree on the
  ordered L/I scale beyond chance, and :func:`reliability` turns
  ``(predicted_confidence, outcome)`` pairs into a Brier score and an
  expected-calibration-error -- the check that "70% confident" really happens
  about 70% of the time. A model that is confidently wrong is caught here.

Stdlib only. The benchmark tables carry a version; changing one is a deliberate
act with a diff, matching how the threat pack is versioned.
"""

from typing import Any

#: Bump when any mapping below changes, so a stored assessment names the table
#: it was graded against.
BENCHMARK_VERSION = "2026.1"

#: Internal threat id -> external authority. ``atlas`` is ``None`` where MITRE
#: ATLAS has no first-class tactic and an OWASP/STRIDE ticket is the honest
#: mapping; coverage counts only ids that resolve to *something* external.
THREAT_BENCHMARKS = {
    "T01": {"owasp": "LLM02", "stride": "Information Disclosure",
            "atlas": "AML.T0057"},
    "T02": {"owasp": "LLM02", "stride": "Information Disclosure",
            "atlas": "AML.T0057"},
    "T03": {"owasp": "LLM08", "stride": "Tampering", "atlas": None},
    "T04": {"owasp": "LLM07", "stride": "Information Disclosure",
            "atlas": "AML.T0056"},
    "T05": {"owasp": "LLM01", "stride": "Spoofing / Elevation",
            "atlas": "AML.T0051"},
    "T06": {"owasp": "LLM06", "stride": "Information Disclosure",
            "atlas": "AML.T0057"},
    "T07": {"owasp": "LLM10", "stride": "Information Disclosure",
            "atlas": "AML.T0010"},
    "T08": {"owasp": "LLM09", "stride": "Repudiation", "atlas": None},
    "T09": {"owasp": "LLM09", "stride": "Tampering", "atlas": None},
    "T10": {"owasp": "LLM08", "stride": "Elevation of Privilege",
            "atlas": None},
    "T11": {"owasp": "LLM02", "stride": "Information Disclosure",
            "atlas": "AML.T0057"},
    "T12": {"owasp": "Governance", "stride": "Repudiation", "atlas": None},
}

#: Internal model-mitigation id -> the external practice it implements.
MITIGATION_BENCHMARKS = {
    "MM01": {"owasp": "LLM02", "standard": "NIST AI 100-2e",
             "atlas": "AML.M0004"},
    "MM02": {"owasp": "LLM02", "standard": "NIST AI 100-2e", "atlas": None},
    "MM03": {"owasp": "LLM02", "standard": "GDPR Art.17", "atlas": None},
    "MM04": {"owasp": "LLM06", "standard": "NIST AI 100-2e", "atlas": None},
    "MM05": {"owasp": "LLM02", "standard": "NIST AI 100-2e", "atlas": None},
    "MM06": {"owasp": "LLM01", "standard": "NIST AI 100-2e",
             "atlas": "AML.M0009"},
    "MM07": {"owasp": "LLM01", "standard": "OWASP LLM01", "atlas": None},
    "MM08": {"owasp": "LLM06", "standard": "OWASP LLM06", "atlas": None},
    "MM09": {"owasp": "LLM10", "standard": "OWASP LLM10", "atlas": None},
    "MM10": {"owasp": "LLM10", "standard": "ISO 27001 A.8.24", "atlas": None},
    "MM11": {"owasp": "LLM10", "standard": "OWASP LLM10", "atlas": None},
    "MM12": {"owasp": "LLM09", "standard": "NIST AI RMF", "atlas": None},
    "MM13": {"owasp": "LLM09", "standard": "NIST AI RMF", "atlas": None},
    "MM14": {"owasp": "LLM02", "standard": "ISO 27001 A.8.24", "atlas": None},
    "MM15": {"owasp": "LLM09", "standard": "ISO 27001 A.5.12", "atlas": None},
    "MM16": {"owasp": "LLM06", "standard": "OWASP LLM06", "atlas": None},
}

_TABLES = {
    "threat": THREAT_BENCHMARKS,
    "mitigation": MITIGATION_BENCHMARKS,
}


def benchmark_version() -> str:
    return BENCHMARK_VERSION


def _table(kind: str) -> dict:
    return _TABLES.get(kind, THREAT_BENCHMARKS)


def benchmark_for(node_id: str, *, kind: str = "threat") -> dict | None:
    """External crosswalk for one internal id, or ``None`` if unmapped."""
    return _table(kind).get(node_id)


def external_refs(node_id: str, *, kind: str = "threat") -> list:
    """Flat list of external references (``OWASP LLM01``, ``AML.T0051`` …)."""
    row = benchmark_for(node_id, kind=kind)
    if not row:
        return []
    refs = []
    if row.get("owasp"):
        refs.append(f"OWASP {row['owasp']}")
    if row.get("stride"):
        refs.append(f"STRIDE: {row['stride']}")
    if row.get("atlas"):
        refs.append(row["atlas"])
    if row.get("standard"):
        refs.append(row["standard"])
    return refs


def coverage(ids=None, *, kind: str = "threat") -> dict:
    """How much of a catalogue resolves to an external benchmark.

    ``ids`` defaults to every id in the table. Passing the *live* ids of an
    assessment answers the audit question directly: of the threats this report
    actually names, how many are externally grounded?
    """
    table = _table(kind)
    ids = list(ids) if ids is not None else list(table)
    mapped = [i for i in ids if table.get(i)]
    unmapped = [i for i in ids if i not in table or not table.get(i)]
    return {
        "version": BENCHMARK_VERSION,
        "kind": kind,
        "total": len(ids),
        "mapped": len(mapped),
        "unmapped": unmapped,
        # A fraction, not a pass/fail: partial coverage is normal and the
        # unmapped list is the actionable part.
        "fraction": round(len(mapped) / len(ids), 3) if ids else 1.0,
    }


def cohens_kappa(a, b) -> float:
    """Chance-corrected agreement between two ordered ratings in [0,1]."""
    pairs = [(x, y) for x, y in zip(a, b, strict=False)]
    n = len(pairs)
    if n == 0:
        return 0.0
    cats = sorted({x for x, _ in pairs} | {y for _, y in pairs})
    idx = {c: i for i, c in enumerate(cats)}
    k = len(cats)
    obs = [[0] * k for _ in range(k)]
    for x, y in pairs:
        obs[idx[x]][idx[y]] += 1
    po = sum(obs[i][i] for i in range(k)) / n
    ra = [sum(obs[i]) / n for i in range(k)]
    rb = [sum(obs[j][i] for j in range(k)) / n for i in range(k)]
    pe = sum(ra[i] * rb[i] for i in range(k))
    if abs(1.0 - pe) < 1e-12:
        return 1.0 if abs(po - 1.0) < 1e-12 else 0.0
    return round((po - pe) / (1.0 - pe), 4)


def inter_rater(rows, *, keys=("likelihood", "impact")) -> dict:
    """Agreement across two raters on the ordered L/I scales.

    ``rows`` is an iterable of ``(rater_a_dict, rater_b_dict)``. Each scale gets
    its own kappa; the result also carries a plain-text interpretation band so
    a low agreement is legible ("slight") rather than a bare number.
    """
    pairs = list(rows or [])
    out = {"n": len(pairs)}
    for key in keys:
        a = [r[0].get(key) for r in pairs]
        b = [r[1].get(key) for r in pairs]
        kappa = cohens_kappa(a, b)
        # Kappa is prevalence-sensitive and this catalogue's L/I marginals are
        # heavily skewed, so a low kappa can mean "the distribution is lopsided"
        # rather than "the raters disagree". Alpha and AC1 correct for that by
        # construction; reporting all three says which reading applies.
        out[key] = {
            "kappa": kappa,
            "band": _kappa_band(kappa),
            "krippendorff_alpha": krippendorff_alpha(
                list(zip(a, b, strict=True))),
            "gwet_ac1": gwet_ac1(list(zip(a, b, strict=True))),
        }
    if pairs and len(keys):
        out["mean_kappa"] = round(
            sum(out[k]["kappa"] for k in keys) / len(keys), 4)
        out["band"] = _kappa_band(out["mean_kappa"])
    return out


def _kappa_band(kappa: float) -> str:
    if kappa >= 0.81:
        return "almost perfect"
    if kappa >= 0.61:
        return "substantial"
    if kappa >= 0.41:
        return "moderate"
    if kappa >= 0.21:
        return "fair"
    if kappa > 0.0:
        return "slight"
    return "poor"


def reliability(samples, *, bins: int = 5) -> dict:
    """Calibration of confidence statements against realised outcomes.

    ``samples`` is an iterable of ``(predicted_confidence_in_[0,1], outcome_bool)``.
    Returns the Brier score (lower is better, 0.25 is the no-skill baseline for
    balanced data) and the expected calibration error: how far, on average, each
    confidence bin's realised rate is from its stated confidence. A well-behaved
    engine has a small ECE even if the Brier score is modest.
    """
    s = [(float(p), bool(o)) for p, o in (samples or [])]
    n = len(s)
    if n == 0:
        return {"n": 0, "brier": 0.0, "ece": 0.0, "bins": []}
    brier = sum((p - (1.0 if o else 0.0)) ** 2 for p, o in s) / n
    edges = [i / bins for i in range(bins + 1)]
    detail = []
    ece = 0.0
    for i in range(bins):
        lo, hi = edges[i], edges[i + 1]
        bucket = [(p, o) for p, o in s
                  if (lo < p <= hi) or (i == 0 and p <= hi)]
        if not bucket:
            detail.append({"lo": round(lo, 2), "hi": round(hi, 2),
                           "n": 0, "mean_conf": None, "accuracy": None})
            continue
        mean_conf = sum(p for p, _ in bucket) / len(bucket)
        acc = sum(1 for _, o in bucket if o) / len(bucket)
        ece += (len(bucket) / n) * abs(mean_conf - acc)
        detail.append({"lo": round(lo, 2), "hi": round(hi, 2),
                       "n": len(bucket), "mean_conf": round(mean_conf, 3),
                       "accuracy": round(acc, 3)})
    return {
        "n": n,
        "brier": round(brier, 4),
        "ece": round(ece, 4),
        "band": _ece_band(ece),
        "bins": detail,
    }


def _ece_band(ece: float) -> str:
    if ece <= 0.05:
        return "well-calibrated"
    if ece <= 0.1:
        return "acceptable"
    if ece <= 0.2:
        return "weak"
    return "mis-calibrated"


# --------------------------------------------------------------------------
# Krippendorff's alpha and Gwet's AC1
# --------------------------------------------------------------------------
#
# Cohen's kappa is prevalence-sensitive: it collapses when the marginal
# distribution of a category is heavily skewed, which it is here -- most threat
# rows land on one or two of the L/I values, so an assessor's perfect agreement
# still reports a low kappa. That is a property of the statistic, not a
# disagreement, and quoting kappa alone understates reliability exactly where the
# data is most skewed.
#
# Alpha and AC1 both correct for prevalence by construction, so reporting them
# alongside kappa says which reading applies.


def krippendorff_alpha(rows: list[tuple[str, str]]) -> float:
    """Krippendorff's alpha for two raters over a nominal scale.

    ``rows`` is a list of ``(rater_a, rater_b)`` paired judgements. Returns a
    value in -1..1 where 1 is perfect agreement, corrected for observed
    disagreement beyond what the marginals predict. Unlike kappa it is
    defined at zero observed disagreement (returns 1.0), so it is safe to
    report on a clean run.
    """
    pairs = [(str(a), str(b)) for a, b in rows if a is not None and b is not None]
    n = len(pairs)
    if n < 2:
        return 1.0 if n == 1 else 0.0
    agree = sum(1 for a, b in pairs if a == b)
    # Observed disagreement (D_o) as the proportion of disagreeing units.
    d_o = (n - agree) / n
    # Expected disagreement (D_e) from the two raters' own marginals.
    a_counts: dict[str, int] = {}
    b_counts: dict[str, int] = {}
    for a, b in pairs:
        a_counts[a] = a_counts.get(a, 0) + 1
        b_counts[b] = b_counts.get(b, 0) + 1
    d_e = sum((a_counts[k] / n) * (b_counts[k] / n) for k in a_counts)
    if d_e == 0:
        # Both raters used a single, identical category: perfect (or total)
        # agreement by construction.
        return 1.0
    return round(1.0 - d_o / d_e, 4)


def gwet_ac1(rows: list[tuple[str, str]], categories: list[str] | None = None) -> float:
    """Gwet's AC1: prevalence-corrected agreement, always defined.

    Handles the case alpha reports as 1.0 for degenerate marginals; useful as a
    stable companion to kappa across skewed severities.
    """
    pairs = [(str(a), str(b)) for a, b in rows if a is not None and b is not None]
    n = len(pairs)
    if n < 2:
        return 1.0 if n == 1 else 0.0
    if not categories:
        seen = {a for a, _ in pairs} | {b for _, b in pairs}
        categories = sorted(seen)
    k = max(1, len(categories))
    agree = sum(1 for a, b in pairs if a == b)
    p_a = agree / n
    # Each category's marginal across both raters.
    cat_tot: dict[str, int] = {}
    for a, b in pairs:
        cat_tot[a] = cat_tot.get(a, 0) + 1
        cat_tot[b] = cat_tot.get(b, 0) + 1
    pi = sum((c / (2 * n)) ** 2 for c in cat_tot.values())
    pe = (1.0 / (k - 1)) * (k * pi - 1.0)
    if abs(1.0 - pe) < 1e-12:
        return 1.0
    return round((p_a - pe) / (1.0 - pe), 4)


# --------------------------------------------------------------------------
# Grounding confusion matrix
# --------------------------------------------------------------------------


def grounding_confusion_matrix(samples: list[dict[str, Any]]) -> dict[str, Any]:
    """Per-reason precision/recall for the grounding verdict.

    ``samples`` are ``{"expected": <drop reason or "kept">,
    "predicted": <same>}`` rows from a labelled fixture set. Returns overall
    accuracy plus per-class precision/recall/F1, so a failure mode is named
    with numbers rather than a single pass/fail. ``explain_drop`` reasons are
    treated as a nominal scale; the classifier is only ever reported, never
    tuned against these labels in the same pass.
    """
    classes = sorted({s["expected"] for s in samples}
                  | {s["predicted"] for s in samples})
    tp = {c: 0 for c in classes}
    fp = {c: 0 for c in classes}
    fn = {c: 0 for c in classes}
    correct = 0
    for s in samples:
        e, p = s["expected"], s["predicted"]
        if e == p:
            correct += 1
            tp[e] = tp.get(e, 0) + 1
        else:
            fp[p] = fp.get(p, 0) + 1
            fn[e] = fn.get(e, 0) + 1
    n = len(samples)
    per_class = {}
    for c in classes:
        prec = tp[c] / (tp[c] + fp[c]) if (tp[c] + fp[c]) else 0.0
        rec = tp[c] / (tp[c] + fn[c]) if (tp[c] + fn[c]) else 0.0
        f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
        per_class[c] = {"precision": round(prec, 3), "recall": round(rec, 3),
                        "f1": round(f1, 3), "support": tp[c] + fn[c]}
    return {
        "n": n,
        "accuracy": round(correct / n, 3) if n else 0.0,
        "macro_f1": round(
            sum(v["f1"] for v in per_class.values()) / len(per_class), 3
        ) if per_class else 0.0,
        "per_class": per_class,
        "confusion": {e: {p: (tp.get(p, 0) if e == p else fp.get(p, 0))
                          for p in classes} for e in classes},
    }


# --------------------------------------------------------------------------
# Ablation: how much of the headline each modelling choice is responsible for
# --------------------------------------------------------------------------


def ablation_report(inherent_threats: list[dict[str, Any]],
                    active_controls: list[str], *,
                    exposure: str = "confidential_data") -> dict[str, Any]:
    """Sensitivity of ``residual_pct`` to each modelling choice, one at a time.

    A residual score that only means "rank these risks" should not be quoted as
    if it were a measurement, and this is the check that says by how much each
    choice contributes. Each variant temporarily changes one module constant
    (:func:`security.score_assessment` reads them at call time), re-runs the
    identical arithmetic, and reports the headline delta.

    Returns ``base_residual_pct``, the ``variants``, ``max_abs_delta`` and a
    ``fragile`` flag for any single choice whose removal moves the headline by
    more than 5 points -- i.e. the number is substantially an artefact of that
    choice, and a reviewer should be told which one.
    """
    from . import security as sec

    base = sec.score_assessment(exposure, inherent_threats,
                                active_controls=active_controls)["residual_pct"]

    def _variant(label: str, attr: str, value) -> dict[str, Any]:
        saved = getattr(sec, attr)
        try:
            setattr(sec, attr, value)
            pct = sec.score_assessment(
                exposure, inherent_threats,
                active_controls=active_controls)["residual_pct"]
        finally:
            setattr(sec, attr, saved)  # restore: this mutates a module global
        return {"label": label, "residual_pct": pct,
                "delta_pct_points": round(pct - base, 2)}

    variants = [
        _variant("no residual floor", "_MIN_RESIDUAL_LIKELIHOOD", 0.0),
        _variant("breadth only", "_WORST_WEIGHT", 0.0),
        _variant("worst only", "_BREADTH_WEIGHT", 0.0),
    ]
    deltas = [abs(v["delta_pct_points"]) for v in variants]
    return {
        "base_residual_pct": round(base, 2),
        "variants": variants,
        "max_abs_delta": round(max(deltas), 2),
        "fragile": any(d > 5.0 for d in deltas),
        "note": ("Each variant changes one modelling choice and re-runs the "
                 "same arithmetic. A large delta means the headline is largely "
                 "that choice rather than the threat set."),
    }


# --------------------------------------------------------------------------
# The scoring contract
# --------------------------------------------------------------------------


#: Every key ``score_assessment`` must return, and its type. Consumers --
#: ``_perspective_views``, the markdown renderer, the PDF, the GUI and the API
#: -- all read ``result["scoring"]["breakdown"][key]`` by string across ~10 call
#: sites. A rename there would break every narrative panel silently, because a
#: missing key renders as an empty cell rather than an error. Pinning the shape
#: turns that class of regression into a failing invariant.
SCORING_CONTRACT: dict[str, type] = {
    "method": str,
    "worst_weight": float,
    "breadth_weight": float,
    "top_n": int,
    "min_residual_floor": float,
    "min_applicability": float,
    "exposure": str,
    "applicable_threats": int,
    "total_threats": int,
    "mean_coverage": float,
}

#: Keys the result envelope itself must carry, for the same reason.
RESULT_CONTRACT: tuple[str, ...] = (
    "threats", "assessment_path", "inherent_pct", "residual_pct", "delta",
    "posture", "inherent_posture", "active_controls", "distribution",
    "breakdown", "control_analyst",
    # Calibration block, added alongside the provenance work.
    "floor_capped", "floor", "efficacy_evidence",
)


def validate_scoring_contract(result: dict[str, Any]) -> list[str]:
    """Return the contract violations in one scoring result (empty if clean).

    Checks presence and type only -- not values. A wrong type or a renamed key
    is a defect; an odd number is a finding, and the two must not be conflated.
    """
    problems: list[str] = []
    for key in RESULT_CONTRACT:
        if key not in result:
            problems.append(f"result.{key} missing")
    bd = result.get("breakdown")
    if not isinstance(bd, dict):
        problems.append("result.breakdown missing or not a mapping")
        return problems
    for key, expected in SCORING_CONTRACT.items():
        if key not in bd:
            problems.append(f"breakdown.{key} missing")
        elif not isinstance(bd[key], expected | int | float) or (
                expected is int and isinstance(bd[key], bool)):
            problems.append(
                f"breakdown.{key} is {type(bd[key]).__name__}, "
                f"expected {expected.__name__}")
    return problems


def research_report_sections(*, assessment: dict[str, Any],
                             analysis: dict[str, Any],
                             meta: dict[str, Any]) -> list[dict[str, Any]]:
    """Structured sections for the research report.

    The ordering is the argument: the headline and its interval first, then
    immediately what the interval does *not* cover, then the provenance of the
    inputs and the sensitivity analysis. A limitations section at the end of a
    report is a disclaimer; the same limitations immediately after the number
    are part of the result.
    """
    unc = analysis.get("uncertainty") or {}
    floor = assessment.get("floor") or {}
    ev = assessment.get("efficacy_evidence") or {}
    vb = analysis.get("variance_budget") or unc.get("variance_budget") or {}
    dp = analysis.get("dp_accounting") or {}
    ds = analysis.get("domain_spend") or {}
    sections: list[dict[str, Any]] = []

    sections.append({
        "key": "headline",
        "title": "Result",
        "lines": [
            f"Inherent risk {assessment.get('inherent_pct')}/100 → residual "
            f"{assessment.get('residual_pct')}/100 "
            f"({assessment.get('posture', '')}).",
        ],
    })

    if unc:
        sections.append({
            "key": "interval",
            "title": "Credible interval",
            "lines": [
                f"{unc.get('level', 0.9):.0%} interval "
                f"[{unc.get('lower_pct')}–{unc.get('upper_pct')}] around "
                f"{unc.get('mean_pct')}.",
            ],
        })
    if vb:
        unq = vb.get("unquantified") or {}
        lines = [f"Modelled variance: "
                 f"{vb.get('share_inherent', 0):.0%} inherent likelihood, "
                 f"{vb.get('share_efficacy', 0):.0%} control efficacy."]
        if unq:
            lines.append("")
            lines.append("Not covered by this interval:")
            lines += [f"{k.replace('_', ' ')} — {v}" for k, v in unq.items()]
        sections.append({"key": "variance_budget",
                         "title": "Variance budget", "lines": lines})
    if floor:
        sections.append({
            "key": "saturation",
            "title": "Score saturation",
            "lines": [
                f"Likelihood floored at {floor.get('floor', 0.35):.0%}; the "
                f"score saturates once coverage passes "
                f"{1 - floor.get('floor', 0.35):.0%}.",
                f"{floor.get('controls_beyond_floor', 0)} of the declared "
                f"controls no longer move the headline.",
            ],
        })
    if ev and ev.get("unvalidated_controls"):
        sections.append({
            "key": "provenance",
            "title": "Efficacy provenance",
            "lines": [
                f"{len(ev['unvalidated_controls'])} of {ev.get('n_controls', 0)} "
                f"control efficacies are unvalidated analyst priors; the cited "
                f"standard establishes the control, not its effectiveness.",
            ],
        })
    if dp and dp.get("epsilon") is not None:
        sections.append({
            "key": "privacy",
            "title": "External reach",
            "lines": [
                f"Composed (ε, δ) = ({dp.get('epsilon')}, {dp.get('delta')}) "
                f"across {dp.get('distinct_domains', 0)} observer domain(s).",
                dp.get("note", ""),
            ],
        })
    if ds:
        sections.append({
            "key": "domain_spend",
            "title": "Observer-distinct spend",
            "lines": [
                f"Concave spend {ds.get('concave_spend')} vs linear "
                f"{ds.get('linear_spend')} (fetch count overstates reach by "
                f"{ds.get('spread')}).",
            ],
        })
    abl = ablation_report(
        [{"id": t["id"], "likelihood": t["likelihood"], "impact": t["impact"]}
         for t in (assessment.get("threats") or [])],
        assessment.get("active_controls") or []) if (
            assessment.get("threats")) else None
    if abl:
        lines = [f"Base residual {abl['base_residual_pct']}; max single-choice "
                 f"delta {abl['max_abs_delta']}."]
        lines += [f"{v['label']}: {v['delta_pct_points']:+} points"
                  for v in abl["variants"]]
        sections.append({"key": "sensitivity",
                         "title": "Model sensitivity (ablation)",
                         "lines": lines})
    scen = (analysis.get("scenarios") or {})
    if scen.get("scenarios"):
        chains = [s for s in scen["scenarios"]
                  if s.get("origin") == "control_gap_chain"]
        amps = [s for s in scen["scenarios"]
                if s.get("origin") == "residual_amplifier"]
        lines = [
            f"{len(scen['scenarios'])} derived from this row's own threats and "
            f"controls ({len(chains)} uncovered chains, {len(amps)} at the "
            f"residual floor).",
        ]
        lines += [f"{s['title']} — {s['why']}"
                  for s in (chains or amps)[:3]]
        sections.append({"key": "scenarios",
                         "title": "Derived scenarios", "lines": lines})
    return sections


def render_research_report(*, assessment: dict[str, Any],
                           analysis: dict[str, Any],
                           meta: dict[str, Any]) -> str:
    """Markdown rendering of the research report sections."""
    lines: list[str] = []
    product = meta.get("product_name") or "this subject"
    lines.append(f"# Research report — {product}")
    lines.append("")
    if meta.get("exposure"):
        lines.append(f"_Exposure:_ **{meta['exposure']}** · "
                     f"_Assessment:_ #{meta.get('id')} · "
                     f"_Path:_ {meta.get('assessment_path') or 'standard'}")
    if (meta.get("pack") or {}).get("fingerprint"):
        lines.append(f"_Threat pack:_ `{meta['pack'].get('version')}` "
                     f"({str(meta['pack']['fingerprint'])[:12]})")
    lines.append("")
    lines.append("---")
    for sec in research_report_sections(assessment=assessment,
                                        analysis=analysis, meta=meta):
        lines.append(f"## {sec['title']}")
        lines.append("")
        lines.extend(sec["lines"])
        lines.append("")
    lines.append("---")
    lines.append("*Generated from the measured properties of this assessment; "
                 "the limitations are part of the result, not a disclaimer.*")
    return "\n".join(lines)


def reviewer_disagreement(reviews: list[dict[str, Any]]) -> dict[str, Any]:
    """Where a group of reviewers disagrees, with the agreement to prove it.

    ``reviews`` are ``{"artifact_id", "reviewer", "verdict"}`` rows. Returns
    the artifacts with conflicting verdicts, per-reviewer agreement with the
    majority, and the three agreement coefficients over rater pairs -- kappa,
    Krippendorff's alpha and Gwet's AC1 side by side, because kappa alone
    understates agreement exactly where verdicts skew accept (which they do:
    most reviewed artifacts are accepted).

    A group whose members never disagree has no measurable reliability; an
    empty conflict list with a single reviewer says "unmeasured", not
    "unanimous".
    """
    by_artifact: dict[Any, dict[str, str]] = {}
    for r in reviews or []:
        if not isinstance(r, dict) or not r.get("reviewer"):
            continue
        by_artifact.setdefault(r.get("artifact_id"), {})[r["reviewer"]] = (
            r.get("verdict") or r.get("review") or "pending")

    conflicts = []
    agreements: dict[str, dict[str, int]] = {}
    pair_rows: list[tuple[str, str]] = []
    reviewers: set[str] = set()
    for aid, votes in by_artifact.items():
        reviewers |= set(votes)
        vals = sorted(set(votes.values()))
        # Majority verdict, ties broken toward "accepted" only in the sense
        # that the row is named; the conflict itself is what matters.
        majority = max(vals, key=lambda v: (sum(1 for x in votes.values()
                                                if x == v), v))
        for who, what in votes.items():
            slot = agreements.setdefault(who, {"agree": 0, "total": 0})
            slot["total"] += 1
            slot["agree"] += 1 if what == majority else 0
        who = sorted(votes)
        for i in range(len(who)):
            for j in range(i + 1, len(who)):
                pair_rows.append((votes[who[i]], votes[who[j]]))
        if len(vals) > 1:
            conflicts.append({
                "artifact_id": aid,
                "votes": dict(votes),
                "n_reviewers": len(votes),
                "majority": majority,
            })

    conflicts.sort(key=lambda c: (-c["n_reviewers"], str(c["artifact_id"])))
    stats = {
        "n_reviewers": len(reviewers),
        "reviewers": sorted(reviewers),
        "n_artifacts_judged": len(by_artifact),
        "n_conflicts": len(conflicts),
        "per_reviewer": {
            who: {"agree_with_majority": (round(v["agree"] / v["total"], 3)
                                          if v["total"] else None),
                  "n_judged": v["total"]}
            for who, v in agreements.items()
        },
    }
    if len(pair_rows) >= 2:
        stats["kappa"] = cohens_kappa([a for a, _ in pair_rows],
                                      [b for _, b in pair_rows])
        stats["krippendorff_alpha"] = krippendorff_alpha(pair_rows)
        stats["gwet_ac1"] = gwet_ac1(pair_rows)
    else:
        # Fewer than two paired judgments: agreement is unmeasured, and the
        # absence of a number must not read as perfect agreement.
        stats["kappa"] = None
        stats["krippendorff_alpha"] = None
        stats["gwet_ac1"] = None
        stats["note"] = ("Fewer than two reviewer pairs judged the same "
                         "artifact; agreement is unmeasured, not perfect.")
    return {"conflicts": conflicts, "stats": stats}


def compare_verdict(band_a: dict[str, Any] | None,
                    band_b: dict[str, Any] | None,
                    label_a: str = "a", label_b: str = "b") -> dict[str, Any]:
    """Do two assessments differ by more than their intervals allow?

    Two point estimates invite subtraction; two intervals invite the prior
    question of whether they can be told apart at all. Returns one of three
    verdicts:

    * ``distinguishable`` -- the intervals do not overlap: the move is real
      at the reported level, with the direction stated.
    * ``indistinguishable`` -- the intervals overlap: the numbers differ but
      the difference is inside the measurement noise.
    * ``unmeasured`` -- at least one side has no band, so the question cannot
      be answered rather than answered "no".
    """
    def _iv(band):
        if not isinstance(band, dict):
            return None
        try:
            lo, hi = float(band["lower_pct"]), float(band["upper_pct"])
        except (TypeError, ValueError, KeyError):
            return None
        return (lo, hi)

    ia, ib = _iv(band_a), _iv(band_b)
    if ia is None or ib is None:
        return {"verdict": "unmeasured",
                "reason": (f"{label_a if ia is None else label_b} has no "
                           f"credible interval; the comparison cannot be "
                           f"decided rather than decided against a move.")}
    (lo_a, hi_a), (lo_b, hi_b) = ia, ib
    overlap = max(0.0, min(hi_a, hi_b) - max(lo_a, lo_b))
    width = max(hi_a - lo_a, hi_b - lo_b, 1e-9)
    if overlap <= 0:
        direction = "down" if hi_b < lo_a else "up"
        return {"verdict": "distinguishable", "direction": direction,
                "reason": (f"Intervals [{lo_a:g}, {hi_a:g}] and "
                           f"[{lo_b:g}, {hi_b:g}] do not overlap.")}
    return {"verdict": "indistinguishable",
            "overlap_pct_points": round(overlap, 1),
            "overlap_share": round(overlap / width, 3),
            "reason": (f"Intervals overlap by {overlap:.1f} points; the "
                       f"headline move is inside the measurement noise.")}
