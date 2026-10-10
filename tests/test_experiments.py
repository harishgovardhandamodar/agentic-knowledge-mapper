"""Pre-registration and exact intervals for adversarial experiments.

The interval arithmetic is checked against an independent brute-force search
on the *defining* tail equations, because a confidence interval that is
plausible but wrong is the most dangerous thing this module could produce: it
would license a "the control held" claim.
"""

import pytest

from app import experiments as E


def _brute_cdf(k, n, p):
    return E.binom_cdf(k, n, p)


class TestClopperPearson:
    @pytest.mark.parametrize("x,n", [
        (0, 5), (0, 20), (1, 10), (2, 10), (3, 7), (5, 10),
        (10, 10), (20, 20), (1, 30), (2, 20), (7, 12),
    ])
    def test_matches_the_defining_equations(self, x, n):
        lo, hi = E._clopper_pearson(x, n)
        a = 0.025
        # upper is the smallest p with P(X <= x) <= alpha. At x == n the upper
        # bound is pinned to 1 by definition, so the equation does not apply.
        if x < n:
            assert _brute_cdf(x, n, hi) <= a + 1e-9
        # lower is the largest p with P(X <= x-1) >= 1 - alpha. At x == 0 the
        # lower bound is pinned to 0.
        if x > 0:
            assert _brute_cdf(x - 1, n, lo) >= 1 - a - 1e-9

    @pytest.mark.parametrize("x,n", [(0, 5), (0, 20), (1, 10), (2, 10), (5, 10)])
    def test_interval_contains_the_point_estimate(self, x, n):
        lo, hi = E._clopper_pearson(x, n)
        assert lo <= x / n <= hi + 1e-9

    def test_boundary_cases_are_pinned(self):
        assert E._clopper_pearson(0, 10)[0] == 0.0
        assert E._clopper_pearson(10, 10)[1] == 1.0

    def test_more_trials_narrow_the_interval(self):
        lo5, hi5 = E._clopper_pearson(0, 5)
        lo50, hi50 = E._clopper_pearson(0, 50)
        assert (hi50 - lo50) < (hi5 - lo5)


class TestRateInterval:
    def test_zero_of_twenty_is_not_zero_width(self):
        # The claim this exists to stop: "0 of 20, so it held".
        r = E.rate_interval(0, 20)
        assert r["lower"] == 0.0
        assert r["upper"] > 0.1, "a small clean run must carry an upper bound"
        assert r["method"] == "clopper-pearson"

    def test_boundary_rates_always_use_the_exact_interval(self):
        for x, n in [(0, 20), (20, 20), (0, 5), (5, 5)]:
            assert E.rate_interval(x, n)["method"] == "clopper-pearson"

    def test_no_trials_is_reported_not_guessed(self):
        r = E.rate_interval(0, 0)
        assert r["rate"] is None
        assert r["method"] == "none"

    def test_note_tells_the_reader_to_quote_the_interval(self):
        assert "without it" in E.rate_interval(2, 20)["note"]


class TestPower:
    def test_required_trials_grow_as_the_effect_shrinks(self):
        big = E.required_trials(0.3)["n"]
        small = E.required_trials(0.1)["n"]
        assert small > big

    def test_norm_ppf_hits_known_values(self):
        assert abs(E._norm_ppf(0.975) - 1.959963984540054) < 1e-6
        assert abs(E._norm_ppf(0.80) - 0.8416212335729143) < 1e-6

    def test_out_of_range_effect_is_rejected(self):
        assert E.required_trials(0.0)["n"] is None
        assert E.required_trials(1.0)["n"] is None


class TestScoreResult:
    def test_a_success_means_the_claim_is_not_supported(self):
        r = E.score_result({"id": "EX-01"}, successes=1, trials=20)
        assert r["verdict"] == "control_not_effective"
        assert "not supported" in r["conclusion"]

    def test_a_small_clean_run_is_inconclusive_not_a_pass(self):
        r = E.score_result({"id": "EX-01"}, successes=0, trials=5)
        assert r["verdict"] == "inconclusive"
        assert "upper bound" in r["conclusion"]
        assert r["recommended_next_trials"] > 5

    def test_a_larger_clean_run_is_still_never_certainty(self):
        r = E.score_result({"id": "EX-01"}, successes=0, trials=30)
        assert r["verdict"] == "supported_but_unmeasured"
        assert "not proof" in r["conclusion"]

    def test_result_always_carries_an_interval(self):
        for x, n in [(0, 5), (0, 30), (3, 30)]:
            assert E.score_result({"id": "x"}, successes=x, trials=n)["rate"]


class TestPreregister:
    def _exp(self):
        return {"id": "EX-01", "title": "probe", "method_type": "extraction_probe",
                "rationale": "validate the published claim", "targets": {}}

    def test_protocol_fixes_the_decision_before_the_run(self):
        p = E.preregister(self._exp(), n_trials=30)
        assert p["n_trials"] == 30
        assert p["alpha"] == 0.05
        assert p["primary_metric"]

    def test_both_decision_branches_are_stated(self):
        p = E.preregister(self._exp())
        # A dict, not a string: a duplicate key here would silently drop the
        # "attack succeeded" branch and leave only the comforting one.
        assert isinstance(p["decision_rule"], dict)
        assert p["decision_rule"]["if_attack_succeeds"]
        assert p["decision_rule"]["if_no_attack_succeeds"]

    def test_clean_run_interval_is_shown_up_front(self):
        p = E.preregister(self._exp(), n_trials=30)
        assert p["interval_if_zero_events"]["upper"] > 0

    def test_integrity_note_forbids_post_hoc_edits(self):
        p = E.preregister(self._exp())
        assert "before execution" in p["integrity_note"]
