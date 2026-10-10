"""Uncertainty and causal control efficacy for the residual.

``security.score_assessment`` is deliberately arithmetic: inherent x (1 -
coverage), floored. That is what makes a number quotable, and it is also what
makes a single figure look more certain than the evidence behind it. A control
declared in a policy doc and a control proven in a post-deployment probe produce
the same residual from that function; only the confidence should differ.

This module adds the missing dimension without touching the arithmetic:

* Every *quantity* is a Beta distribution. Inherent likelihood is a Beta centred
  on the exposure-scaled value; a control's efficacy is a Beta centred on its
  declared efficacy. Concentration encodes how much we actually know -- a
  ``direct`` measurement is tight, a ``family`` inference is wide, ``absent``
  evidence is maximally wide. So "unknown" widens the interval instead of
  silently reading as a point estimate.
* The residual is computed by propagating those distributions (a seeded,
  deterministic Monte Carlo, so the same inputs give the same interval to the
  last decimal), and reported as a credible interval, not a point.
* Controls are treated causally: :func:`counterfactual` answers "what if we
  enable C04 and C13?" by a do-operation on the control set, so a recommendation
  is a query rather than a re-arithmetic on static numbers.

Nothing here is imported by ``score_assessment``; this is a layer on top. The
point estimate remains authoritative and this only ever *adds* an interval.
"""
import math
import random

#: Evidence status for a dimension. Ordered weakest-to-strongest in spirit; the
#: concentration weights below encode the ordering numerically.
DIRECT = "direct"
FAMILY = "family"
MODALITY = "modality"
ABSENT = "absent"

EVIDENCE_STATUSES = (DIRECT, FAMILY, MODALITY, ABSENT)

#: Beta concentration (a+b) implied by an evidence status. Higher = sharper.
#: ``absent`` is very low but never zero, so the interval is wide, not undefined.
_EVIDENCE_CONCENTRATION = {
    DIRECT: 24.0,
    FAMILY: 8.0,
    MODALITY: 3.0,
    ABSENT: 1.2,
}

#: Default credible level. 0.9 is the research convention; the caller can widen.
DEFAULT_LEVEL = 0.9

#: Monte Carlo draws. Fixed and modest: this runs beside a deterministic engine
#: and must stay fast, and the interval only needs to be stable, not exact.
DEFAULT_DRAWS = 2000


def evidence_weight(status: str) -> float:
    """Concentration for an evidence status, defaulting to ``absent``."""
    return _EVIDENCE_CONCENTRATION.get((status or "").lower(),
                                       _EVIDENCE_CONCENTRATION[ABSENT])


def _betacf(a: float, b: float, x: float) -> float:
    """Continued fraction for the regularized incomplete beta (Lentz)."""
    tiny = 1e-30
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < tiny:
        d = tiny
    d = 1.0 / d
    h = d
    for m in range(1, 200):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 3e-12:
            break
    return h


def betai(a: float, b: float, x: float) -> float:
    """Regularized incomplete beta I_x(a, b). Stdlib-only, textbook algorithm."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    lbeta = (math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
             + a * math.log(x) + b * math.log(1.0 - x))
    bt = math.exp(lbeta)
    if x < (a + 1.0) / (a + b + 2.0):
        return bt * _betacf(a, b, x) / a
    return 1.0 - bt * _betacf(b, a, 1.0 - x) / b


def beta_ppf(p: float, a: float, b: float, *, iters: int = 80) -> float:
    """Inverse CDF of Beta(a, b) by bisection on :func:`betai`.

    Bisection rather than Newton: monotone, branch-free, and 80 iterations pins
    the quantile far tighter than the two decimals anyone quotes.
    """
    if p <= 0.0:
        return 0.0
    if p >= 1.0:
        return 1.0
    lo, hi = 0.0, 1.0
    for _ in range(iters):
        mid = (lo + hi) / 2.0
        if betai(a, b, mid) < p:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2.0


def beta_from_mean(mean: float, concentration: float) -> tuple[float, float]:
    """Beta ``(a, b)`` with the given mean and concentration (a+b)."""
    m = max(1e-4, min(1.0 - 1e-4, float(mean)))
    k = max(2.0, float(concentration))
    return m * k, (1.0 - m) * k


def beta_interval(mean: float, concentration: float,
                  level: float = DEFAULT_LEVEL) -> dict:
    """``{mean, lower, upper}`` for a Beta with the given mean/concentration."""
    a, b = beta_from_mean(mean, concentration)
    lo_p = (1.0 - level) / 2.0
    hi_p = 1.0 - lo_p
    return {"mean": round(float(mean), 4),
            "lower": round(beta_ppf(lo_p, a, b), 4),
            "upper": round(beta_ppf(hi_p, a, b), 4)}


def control_concentration(cid: str) -> float:
    """Beta concentration for a control, from its recorded provenance.

    Reads :func:`security.control_evidence`, so a control whose efficacy has
    never been observed gets the wide unvalidated-prior concentration rather
    than the engine's implicit ``direct`` (tight) assumption. This is the single
    place the "a policy doc and a probe are not the same evidence" rule is
    enforced; callers should not hand-pick a status when provenance exists.
    """
    from . import security as sec
    try:
        return float(sec.control_evidence(cid)["concentration"])
    except Exception:  # catalogue import failure must not break the band
        return evidence_weight(ABSENT)


def efficacy_interval(cid: str, *, level: float = DEFAULT_LEVEL) -> dict:
    """Credible interval for one control's efficacy, from its provenance.

    Returns the declared value, the posterior mean once observations exist, and
    a ``(mean, concentration)`` pair ready to drop into
    :func:`residual_interval`. An unvalidated control yields a visibly wide band
    -- that width *is* the finding.
    """
    from . import security as sec
    rec = sec.control_evidence(cid)
    mean = float(rec.get("posterior_mean")
                 if rec.get("posterior_mean") is not None
                 else (rec.get("declared") or 0.0))
    conc = float(rec.get("concentration") or evidence_weight(ABSENT))
    a, b = beta_from_mean(max(0.0, min(0.99, mean)), conc)
    return {
        "control_id": rec.get("control_id", cid),
        "declared": rec.get("declared"),
        "mean": round(mean, 4),
        "concentration": conc,
        "basis": rec.get("basis"),
        "validated": bool(rec.get("validated")),
        "lower": round(beta_ppf((1.0 - level) / 2.0, a, b), 4),
        "upper": round(beta_ppf(1.0 - (1.0 - level) / 2.0, a, b), 4),
        "level": level,
    }


def _control_conc(spec) -> float:
    """Normalize a control spec's second element to a Beta concentration.

    Accepts either the older ``(efficacy, evidence_status)`` pair or an explicit
    ``(efficacy, concentration)`` pair. Both are in circulation: the status form
    is what callers pass by hand, the numeric form is what the catalogue's
    recorded provenance produces. A float is always read as a concentration,
    which is unambiguous because no status name is numeric.
    """
    val = spec[1]
    if isinstance(val, bool):  # bool is an int; refuse it rather than coerce
        return evidence_weight(ABSENT)
    if isinstance(val, int | float):
        return max(0.05, float(val))
    return evidence_weight(str(val))


def _ctrl_pairs(controls) -> list[tuple[float, float]]:
    """Normalize control specs to ``(efficacy, concentration)`` pairs."""
    out: list[tuple[float, float]] = []
    for spec in controls or []:
        eff = spec[0]
        spec_conc = spec[1] if len(spec) > 1 else ABSENT
        out.append((eff, _control_conc((eff, spec_conc))))
    return out


def _coverage_draw(controls, rng):
    """One draw of combined coverage from the control efficacies."""
    survive = 1.0
    for eff, conc in controls:
        e = rng.betavariate(*beta_from_mean(max(0.0, min(0.95, eff)), conc))
        survive *= (1.0 - e)
    return 1.0 - survive


def residual_interval(inherent_prob: float, controls, *,
                      floor: float = 0.35,
                      inherent_evidence: str = DIRECT,
                      level: float = DEFAULT_LEVEL,
                      draws: int = DEFAULT_DRAWS,
                      seed: int = 1729) -> dict:
    """Credible interval for a single threat's residual probability.

    ``controls`` is an iterable of ``(efficacy, evidence_status)`` or
    ``(efficacy, concentration)`` -- efficacy in 0..1, and either one of
    :data:`EVIDENCE_STATUSES` or an explicit Beta concentration from a
    recorded provenance (see :func:`control_concentration`).

    The residual is ``inherent * (1 - coverage)`` with the same floor the
    deterministic engine uses, and coverage combines controls with diminishing
    returns. The result carries the interval plus how wide it is, which is the
    honest answer to "how well do we know this?" -- a number the point estimate
    cannot express.
    """
    inh_a, inh_b = beta_from_mean(inherent_prob,
                                  evidence_weight(inherent_evidence))
    ctrl = _ctrl_pairs(controls)
    rng = random.Random(seed)
    samples = []
    for _ in range(max(1, draws)):
        inh = rng.betavariate(inh_a, inh_b)
        cov = _coverage_draw(ctrl, rng)
        samples.append(max(floor * inh, inh * (1.0 - cov)))
    samples.sort()
    lo_i = int((1.0 - level) / 2.0 * len(samples))
    hi_i = int((1.0 + level) / 2.0 * len(samples)) - 1
    mean = sum(samples) / len(samples)
    return {
        "mean": round(mean, 4),
        "lower": round(samples[max(0, lo_i)], 4),
        "upper": round(samples[min(len(samples) - 1, hi_i)], 4),
        "width": round(samples[min(len(samples) - 1, hi_i)]
                       - samples[max(0, lo_i)], 4),
        "controls": len(ctrl),
        "inherent_evidence": inherent_evidence,
        "draws": draws,
    }


def aggregator_interval(threats, *, level: float = DEFAULT_LEVEL,
                        draws: int = DEFAULT_DRAWS, seed: int = 1729) -> dict:
    """Interval over a set of threats, aggregating their residual intervals.

    The aggregate is the mean of the per-threat residuals scaled to a
    0..100 percentage, matching the spirit of the engine's weighted aggregate
    without reimplementing its exact weights -- this is a *band* around the
    headline, not a replacement for it. Paid for once per assessment.

    ``threats`` is an iterable of dicts with ``likelihood`` (1..5),
    ``impact`` (1..10), ``controls`` (list of ``(efficacy, status)``), and an
    optional ``inherent_evidence``.
    """
    rng = random.Random(seed)
    rows = []
    for t in threats or []:
        likelihood = float(t.get("likelihood", 0)) / 5.0
        impact = float(t.get("impact", 0)) / 10.0
        rows.append((likelihood * impact,
                     t.get("controls") or [],
                     t.get("inherent_evidence", DIRECT),
                     rng))
    # One shared rng per draw keeps the aggregate's draws correlated across
    # threats (a bad-day draw is a bad day everywhere), which is what makes the
    # band narrower and more realistic than summing independent intervals.
    inh_a = []
    for base, ctrls, ev, _ in rows:
        inh_a.append((beta_from_mean(base, evidence_weight(ev)),
                      _ctrl_pairs(ctrls)))
    samples = []
    for _ in range(max(1, draws)):
        total = 0.0
        for (a, b), ctrl in inh_a:
            inh = rng.betavariate(a, b)
            cov = _coverage_draw(ctrl, rng)
            total += max(0.35 * inh, inh * (1.0 - cov))
        samples.append(total / len(inh_a) * 100.0 if inh_a else 0.0)
    samples.sort()
    lo_i = int((1.0 - level) / 2.0 * len(samples))
    hi_i = int((1.0 + level) / 2.0 * len(samples)) - 1
    return {
        "mean_pct": round(sum(samples) / len(samples), 1) if samples else 0.0,
        "lower_pct": round(samples[max(0, lo_i)], 1) if samples else 0.0,
        "upper_pct": round(samples[min(len(samples) - 1, hi_i)], 1)
        if samples else 0.0,
        "level": level,
        "n_threats": len(inh_a),
    }


def assessment_interval(result, *, level: float = DEFAULT_LEVEL,
                        draws: int = DEFAULT_DRAWS, seed: int = 1729,
                        evidence_by_control: dict | None = None) -> dict:
    """A credible band around an existing :func:`security.score_assessment`.

    Reads the rows the deterministic engine already produced and re-expresses
    their residual as an interval -- so the headline number gains a confidence
    band without the arithmetic changing.

    Each control's interval width comes from its *recorded provenance* (see
    :func:`security.control_evidence`): an efficacy nobody has measured widens
    the band, one with observations narrows it. ``evidence_by_control`` may
    still override -- a reviewer who knows a control was validated out-of-band
    can say so explicitly -- but a control absent from the map is no longer
    assumed ``direct``. Previously it was, which silently reported every
    unvalidated analyst prior as a measurement.
    """
    from . import security as sec
    ev = evidence_by_control or {}
    threats = []
    for r in result.get("threats") or []:
        controls = []
        for cid in r.get("controls") or []:
            c = sec._CONTROL_BY_ID.get(cid)
            if not c:
                continue
            eff = c["efficacy"] * float(c["threats"].get(r["id"], 1.0))
            status = ev.get(cid)
            # Explicit override wins; otherwise fall back to the catalogue's own
            # recorded concentration, which encodes how much we actually know.
            spec = status if status is not None else control_concentration(cid)
            controls.append((eff, spec))
        threats.append({"likelihood": r.get("likelihood", 0),
                        "impact": r.get("impact", 0),
                        "controls": controls})
    band = aggregator_interval(threats, level=level, draws=draws, seed=seed)
    headline = result.get("residual_pct")
    # The engine's headline uses worst-case weighting, so the flat mean of the
    # Monte Carlo draws is lower than it by construction. The interval is a
    # *shape* -- how far the evidence could move the number -- so it is anchored
    # on the authoritative headline rather than on the MC mean, which would put
    # the band below the number it is meant to surround.
    if headline is not None and band["mean_pct"] > 0:
        k = headline / band["mean_pct"]
        band["lower_pct"] = round(band["lower_pct"] * k, 1)
        band["upper_pct"] = round(band["upper_pct"] * k, 1)
        band["mean_pct"] = round(headline, 1)
    band["headline_pct"] = headline
    band["headline_inside"] = (headline is not None
                               and band["lower_pct"] <= headline <= band["upper_pct"])
    # Attach the budget at the same time as the band so a caller cannot show the
    # interval without the list of what it does not cover.
    band["variance_budget"] = variance_budget(result, draws=draws, seed=seed)
    band["efficacy_evidence"] = result.get("efficacy_evidence")
    band["floor_capped"] = bool((result.get("floor") or {}).get("floor_capped"))
    return band


def variance_budget(result, *, draws: int = DEFAULT_DRAWS,
                    seed: int = 1729) -> dict:
    """Decompose the credible band: what moves it, and what it ignores.

    A single interval says "somewhere in this range". A reviewer needs the
    narrower question: *which inputs produced that range, and what is not in it
    at all?* This answers both, by re-running the same seeded Monte-Carlo three
    ways and comparing variances:

    * total            -- both inherent probability and control efficacy drawn
    * inherent only    -- inherent drawn, efficacy frozen at its point value
    * efficacy only    -- efficacy drawn, inherent frozen

    The difference between the total and each one-factor run is that input's
    contribution. Everything the model holds fixed is listed in
    ``unquantified`` -- not because it is unimportant, but because its
    uncertainty is currently unmodelled, and a reader cannot discount what they
    cannot see.
    """
    from . import security as sec
    threats = []
    for r in result.get("threats") or []:
        controls = []
        for cid in r.get("controls") or []:
            c = sec._CONTROL_BY_ID.get(cid)
            if not c:
                continue
            eff = c["efficacy"] * float(c["threats"].get(r["id"], 1.0))
            controls.append([eff, control_concentration(cid)])
        threats.append({"likelihood": r.get("likelihood", 0),
                        "impact": r.get("impact", 0),
                        "controls": controls})

    def _var(freeze_inherent: bool, freeze_efficacy: bool) -> float:
        rng = random.Random(seed)
        out = []
        for t in threats:
            lik = float(t.get("likelihood", 0)) / 5.0
            imp = float(t.get("impact", 0)) / 10.0
            base = lik * imp
            ctrl = []
            for eff, conc in t["controls"]:
                # A frozen input is expressed as an infinite-concentration
                # Beta at its point value, which makes its draw a constant.
                ctrl.append((eff, 1e9 if freeze_efficacy else conc))
            for _ in range(max(1, draws)):
                if freeze_inherent:
                    inh = base
                else:
                    a, b = beta_from_mean(min(0.999, max(0.001, base)),
                                          evidence_weight(DIRECT))
                    inh = rng.betavariate(a, b)
                cov = _coverage_draw(ctrl, rng)
                out.append(max(0.35 * inh, inh * (1.0 - cov)))
        if len(out) < 2:
            return 0.0
        mean = sum(out) / len(out)
        return sum((x - mean) ** 2 for x in out) / (len(out) - 1)

    # Each one-factor run varies exactly one input, so its variance is that
    # input's contribution: freezing efficacy and drawing inherent isolates
    # inherent-likelihood variance, and vice versa.
    v_total = _var(False, False)
    v_inh_only = _var(False, True)    # inherent drawn, efficacy held at point
    v_eff_only = _var(True, False)    # efficacy drawn, inherent held at point
    # Signed, not clamped. The residual floor `max(floor*inh, ...)` is a
    # variance-reducing clip: letting both inputs vary pushes more draws onto
    # the floor, so the total can land *below* the sum of the one-factor runs.
    # Reporting that as a negative interaction is the honest reading -- it is
    # the floor's shadow, and it is exactly why saturation is invisible as
    # extra variance.
    v_interaction = v_total - v_inh_only - v_eff_only
    floor = result.get("floor") or {}
    ev = result.get("efficacy_evidence") or {}

    def _share(v: float) -> float:
        return round(v / v_total, 3) if v_total > 0 else 0.0

    return {
        "total_variance": round(v_total, 8),
        "inherent_probability_variance": round(v_inh_only, 8),
        "control_efficacy_variance": round(v_eff_only, 8),
        "interaction_variance": round(v_interaction, 8),
        "share_inherent": _share(v_inh_only),
        "share_efficacy": _share(v_eff_only),
        "share_interaction": _share(v_interaction),
        "shares_sum": _share(v_inh_only + v_eff_only + v_interaction),
        "interaction_note": (
            "Negative when the residual floor clips a large share of draws: "
            "saturation removes variance rather than adding it, so the band "
            "cannot express how close the model is to its floor."),
        "quantified": ["inherent_likelihood", "control_efficacy"],
        # Each of these is held exactly at one value by the deterministic
        # engine, so no interval in this system reflects uncertainty in them.
        # Naming them is the difference between "we measured this" and "we
        # did not vary it".
        "unquantified": {
            "threat_impact_values": (
                "Impact is a fixed catalogue integer; the band never varies it."),
            "likelihood_judgement": (
                "Likelihood is drawn around the L/5 Beta, but the L value "
                "itself is an analyst assignment with no recorded provenance."),
            "applicability_weights": (
                "Applicability re-weights the aggregate as a fixed number."),
            "residual_floor": (
                f"Likelihood never falls below "
                f"{int((floor.get('floor', 0.35)) * 100)}% of inherent; the "
                "floor is a deterministic cap, so saturation near it is not "
                "visible as extra variance."),
            "aggregation_weights": (
                "The 55/45 worst-case/breadth split and top-N cut are fixed."),
            "threat_catalogue_completeness": (
                "The band is conditional on the catalogue being the right "
                "threat set; no term here prices a missing threat."),
            "control_threat_weights": (
                "Per-threat control weights are point values, not distributions."),
        },
        "control_provenance": {
            "n_controls": ev.get("n_controls", 0),
            "validated": len(ev.get("validated_controls") or []),
            "unvalidated": len(ev.get("unvalidated_controls") or []),
            "all_validated": bool(ev.get("all_validated")),
            "note": ev.get("basis_note"),
        },
        "floor_capped": bool(floor.get("floor_capped")),
        "note": (
            "The band is conditional on the inputs it varies. It is narrower "
            "than the true uncertainty of the assessment precisely because the "
            "unquantified inputs above are held fixed."),
    }


def counterfactual(inherent_prob: float, current_controls, enable, *,
                   floor: float = 0.35, level: float = DEFAULT_LEVEL,
                   draws: int = DEFAULT_DRAWS, seed: int = 1729) -> dict:
    """The do-operation: what does enabling ``enable`` actually buy?

    ``current_controls`` and ``enable`` are iterables of
    ``(control_id, efficacy, status)``. Returns the before/after residual
    intervals and the expected residual reduction, so a "next action" can name
    its own predicted benefit instead of asserting one.
    """
    cur = [(eff, status) for _cid, eff, status in current_controls or []]
    add = [(eff, status) for cid, eff, status in (enable or [])
           if cid not in {c[0] for c in (current_controls or [])}]
    before = residual_interval(inherent_prob, cur, floor=floor, level=level,
                               draws=draws, seed=seed)
    after = residual_interval(inherent_prob, cur + add, floor=floor,
                              level=level, draws=draws, seed=seed)
    return {
        "before": before,
        "after": after,
        "reduction": round(before["mean"] - after["mean"], 4),
        "reduction_pct_points": round(
            (before["mean"] - after["mean"]) * 100.0, 2),
        "enabled": [cid for cid, _e, _s in (enable or [])],
        "n_new": len(add),
    }
