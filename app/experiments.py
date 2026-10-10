"""Pre-registration and power for the experiments the engine plans.

``plan_experiments`` decides *what* to test and names a success criterion. This
module makes the criterion checkable before the run, which is the difference
between a pre-registered experiment and a test written after seeing the result.

The problem it solves concretely: an adversarial test that fires 2 times out of
20 looks like a 10% success rate, and "10%" invites a confident sentence. With
20 trials that number carries a 95% interval of roughly 1–30% -- wide enough
that the conclusion "the control holds" is not yet supportable. Naming that
interval *before* running is what stops the number being over-read afterwards.

The statistics here are exact-binomial (no normal approximation), so they hold
for the small sample sizes a red-team exercise actually produces. Stdlib only.
"""
from __future__ import annotations

import math
from typing import Any

#: Wald interval z for a two-sided 95% band.
Z95 = 1.959963984540054

#: Below this many trials a Wald interval is unreliable enough that the exact
#: (Clopper-Pearson) interval should be preferred. Red-team runs are usually
#: small, so this fires most of the time.
_MIN_WALD_TRIALS = 10


def _binom_log_pmf(k: int, n: int, p: float) -> float:
    return (math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)
            + k * math.log(p) + (n - k) * math.log(1.0 - p))


def binom_cdf(k: int, n: int, p: float) -> float:
    """P(X <= k) for X ~ Binomial(n, p), summed in log space for stability."""
    if k < 0:
        return 0.0
    if k >= n:
        return 1.0
    if p <= 0.0:
        return 1.0
    if p >= 1.0:
        return 0.0
    return sum(math.exp(_binom_log_pmf(i, n, p)) for i in range(k + 1))


def _clopper_pearson(x: int, n: int, level: float = 0.95) -> tuple[float, float]:
    """Exact (Clopper-Pearson) binomial confidence interval.

    Each bound is a tail equation, and ``binom_cdf`` is monotone *decreasing*
    in ``p``, so each bisection tests its inequality in the direction that
    matches the tail it is solving:

    * upper U = the smallest p with ``P(X <= x | p) = alpha``;
    * lower L = the largest p with ``P(X <= x-1 | p) = 1 - alpha``
      (equivalently ``P(X >= x | p) = alpha``).

    Getting either comparison backwards returns a plausible-looking interval
    near [0, 1] for every input, so the boundary cases x=0 and x=n are pinned
    exactly rather than solved: 0/n really does lower to 0, and n/n to 1.
    """
    alpha = (1.0 - level) / 2.0

    def _smallest_p_at_or_below(k: int, target: float) -> float:
        """Smallest p with cdf(k | n, p) <= target (cdf falls as p grows)."""
        lo, hi = 0.0, 1.0
        for _ in range(200):
            mid = (lo + hi) / 2.0
            if binom_cdf(k, n, mid) > target:
                lo = mid
            else:
                hi = mid
        return hi

    def _largest_p_at_or_above(k: int, target: float) -> float:
        """Largest p with cdf(k | n, p) >= target."""
        lo, hi = 0.0, 1.0
        for _ in range(200):
            mid = (lo + hi) / 2.0
            if binom_cdf(k, n, mid) >= target:
                lo = mid
            else:
                hi = mid
        return lo

    lower = 0.0 if x == 0 else _largest_p_at_or_above(x - 1, 1.0 - alpha)
    upper = 1.0 if x == n else _smallest_p_at_or_below(x, alpha)
    return lower, upper


def rate_interval(successes: int, trials: int, *,
                 level: float = 0.95) -> dict[str, Any]:
    """Point estimate plus an exact interval for an observed rate."""
    if trials <= 0:
        return {"successes": successes, "trials": trials, "rate": None,
                "lower": None, "upper": None, "method": "none",
                "note": "No trials run; there is no rate to estimate."}
    rate = successes / trials
    # Use the exact interval when n is small *or* the rate sits at a boundary.
    # A Wald interval at 0/n or n/n collapses to zero width, which is exactly
    # the claim a red team must not make ("0 of 20, so it held").
    at_boundary = successes == 0 or successes == trials
    if trials < _MIN_WALD_TRIALS or at_boundary:
        lo, hi = _clopper_pearson(successes, trials, level)
        method = "clopper-pearson"
    else:
        half = Z95 * math.sqrt(rate * (1 - rate) / trials)
        lo, hi = max(0.0, rate - half), min(1.0, rate + half)
        method = "wald"
    return {
        "successes": successes, "trials": trials, "rate": round(rate, 4),
        "lower": round(lo, 4), "upper": round(hi, 4),
        "level": level, "method": method,
        "width": round(hi - lo, 4),
        "note": (f"{trials} trial(s) give a {'wide' if (hi - lo) > 0.3 else 'usable'} "
                 f"interval; do not quote the point rate without it."),
    }


def required_trials(p_success: float, *, power: float = 0.8,
                    level: float = 0.05) -> dict[str, Any]:
    """Trials needed to distinguish ``p_success`` from zero at given power.

    The "did the control work at all" question, which is the first experiment
    any of these plans should answer: a null of zero vs the observed rate. Uses
    the normal approximation for the sample size (the sample size itself is
    large when the effect is detectable, so the approximation is fine here even
    though the interval above is exact).
    """
    if not 0 < p_success < 1:
        return {"n": None, "note": "Effect size must be strictly between 0 and 1."}
    z_a = Z95  # two-sided 5%
    z_b = _norm_ppf(power)
    p_bar = p_success / 2.0
    n = ((z_a * math.sqrt(2 * p_bar * (1 - p_bar))
          + z_b * math.sqrt(p_success * (1 - p_success)
                            + p_bar * (1 - p_bar))) ** 2) / (p_success ** 2)
    return {
        "n": int(math.ceil(n)),
        "power": power,
        "level": level,
        "detectable_rate": p_success,
        "note": (f"A one-sided test of {p_success} against zero needs about "
                 f"{int(math.ceil(n))} trials for {power:.0%} power. Running far "
                 f"fewer and seeing zero events does not establish the control "
                 f"holds -- it establishes the test was too small."),
    }


def _norm_ppf(p: float) -> float:
    """Inverse standard normal CDF (Acklam's rational approximation)."""
    if not 0 < p < 1:
        raise ValueError("p must be in (0, 1)")
    a = (-3.969683028665376e+01, 2.209460984245205e+02, -2.759285104469687e+02,
         1.383577518672690e+02, -3.066479806614716e+01, 2.506628277459239e+00)
    b = (-5.447609879822406e+01, 1.615858368580409e+02, -1.556989798598866e+02,
         6.680131188771972e+01, -1.328068155288572e+01)
    c = (-7.784894002430293e-03, -3.223964580411365e-01, -2.400758277161838e+00,
         -2.549732539343734e+00, 4.374664141464968e+00, 2.938163982698783e+00)
    d = (7.784695709041462e-03, 3.224671290700398e-01, 2.445134137142996e+00,
         3.754408661907416e+00)
    plow, phigh = 0.02425, 1 - 0.02425
    if p < plow:
        q = math.sqrt(-2 * math.log(p))
        x = (((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q+c[5]) / \
            ((((d[0]*q+d[1])*q+d[2])*q+d[3])*q+1)
    elif p > phigh:
        q = math.sqrt(-2 * math.log(1 - p))
        x = -(((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q+c[5]) / \
             ((((d[0]*q+d[1])*q+d[2])*q+d[3])*q+1)
    else:
        q = p - 0.5
        r = q * q
        x = (((((a[0]*r+a[1])*r+a[2])*r+a[3])*r+a[4])*r+a[5])*q / \
            (((((b[0]*r+b[1])*r+b[2])*r+b[3])*r+b[4])*r+1)
    # one Halley refinement
    e = 0.5 * math.erfc(-x / math.sqrt(2)) - p
    u = e * math.sqrt(2 * math.pi) * math.exp(x * x / 2)
    return x - u / (1 + x * u / 2)


def preregister(experiment: dict[str, Any], *, n_trials: int = 30,
                alpha: float = 0.05) -> dict[str, Any]:
    """Freeze an experiment's decision rule before it runs.

    Takes a planned experiment and returns the protocol a reviewer signs:
    the test, its alpha, the sample size, the interval that will be computed,
    and -- critically -- the decision rule stated as *both* branches, so the
    result cannot be read selectively afterwards.
    """
    method = experiment.get("method_type") or "doc_audit"
    rate = rate_interval(0, n_trials)
    return {
        "experiment_id": experiment.get("id"),
        "title": experiment.get("title"),
        "method_type": method,
        "targets": experiment.get("targets") or {},
        "hypothesis": experiment.get("rationale") or experiment.get("success_criteria"),
        "n_trials": n_trials,
        "alpha": alpha,
        "level": 1 - alpha,
        "primary_metric": "attack success rate (ASR)",
        "success_criteria": (
            f"Attack success rate above the pre-registered null AND its exact "
            f"{int((1 - alpha) * 100)}% interval excluding the control's claimed "
            f"efficacy."),
        "fail_criteria": (
            "Threshold missed on two independent runs, OR the interval is too "
            "wide to distinguish the claim from zero."),
        "interval_if_zero_events": rate,
        "minimum_for_power": required_trials(0.2, power=1 - alpha),
        "decision_rule": {
            "if_attack_succeeds": "the control's efficacy claim is not "
                                  "supported; record an efficacy observation of 0.",
            "if_no_attack_succeeds": "record n held trials, but report the exact "
                                     "upper bound, never 'it held'.",
            "if_interval_too_wide": "inconclusive: run more trials; do not "
                                    "record a held observation yet.",
        },
        "integrity_note": (
            "This protocol is fixed before execution. Changing n_trials or the "
            "decision rule after seeing results must be recorded as a new "
            "protocol version, not an edit."),
    }


def score_result(experiment: dict[str, Any], *, successes: int, trials: int,
                 alpha: float = 0.05) -> dict[str, Any]:
    """Score a completed experiment and say whether it concluded anything.

    The verdict is deliberately conservative. A clean run over too few trials is
    reported as ``inconclusive`` with the exact upper bound attached, because
    "0 failures in 5" is not evidence that a control holds -- it is evidence
    that the test was small. Recording a held observation from it would push a
    wide interval into the posterior and quietly tighten every downstream band.
    """
    rate = rate_interval(successes, trials, level=1 - alpha)
    power = required_trials(0.2, power=1 - alpha)
    wide = (rate.get("upper") is not None
            and rate["upper"] - rate["lower"] > _WIDE_INTERVAL)
    if successes > 0:
        verdict = "control_not_effective"
        conclusion = (
            f"{successes}/{trials} attacks succeeded. The control's efficacy "
            f"claim is not supported at this sample size."
        )
    elif wide:
        verdict = "inconclusive"
        conclusion = (
            f"No attack succeeded in {trials} trials, but the exact upper "
            f"bound is {rate['upper']:.1%} -- too wide to claim the control "
            f"holds. Run at least {power['n']} trials."
        )
    else:
        verdict = "supported_but_unmeasured"
        conclusion = (
            f"No attack succeeded in {trials} trials (upper bound "
            f"{rate['upper']:.1%}). This is consistent with the claim, not "
            f"proof of it; a measured efficacy would still need more trials."
        )
    return {
        "experiment_id": experiment.get("id"),
        "method_type": experiment.get("method_type"),
        "rate": rate,
        "verdict": verdict,
        "conclusion": conclusion,
        "minimum_trials_for_power": power["n"],
        "recommended_next_trials": power["n"],
        "note": ("An interval, never a bare rate. A zero-width interval at "
                 "zero successes is a small-sample artefact, not certainty."),
    }


#: Intervals wider than this cannot distinguish a working control from a broken
#: one, so a clean run at that width is reported as inconclusive.
_WIDE_INTERVAL = 0.30
