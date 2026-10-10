"""Uncertainty propagation and causal control efficacy (app.uncertainty).

Pins the Beta machinery (incomplete beta, quantiles) against known values and
checks the properties that make the intervals trustworthy: more evidence narrows
them, unknown evidence widens them, a control can never increase the residual,
and the do-operator agrees with simply adding the control.
"""
import unittest

from app import uncertainty as U


class TestIncompleteBeta(unittest.TestCase):
    def test_symmetric_uniform(self):
        # I_x(1,1) = x for the uniform distribution.
        self.assertAlmostEqual(U.betai(1, 1, 0.25), 0.25, places=6)
        self.assertAlmostEqual(U.betai(1, 1, 0.75), 0.75, places=6)

    def test_known_beta_2_2_median(self):
        # Beta(2,2) is symmetric; I_0.5(2,2) = 0.5.
        self.assertAlmostEqual(U.betai(2, 2, 0.5), 0.5, places=6)

    def test_bounds(self):
        self.assertEqual(U.betai(2, 3, 0.0), 0.0)
        self.assertEqual(U.betai(2, 3, 1.0), 1.0)


class TestBetaPpf(unittest.TestCase):
    def test_median_of_symmetric(self):
        self.assertAlmostEqual(U.beta_ppf(0.5, 2, 2), 0.5, places=3)

    def test_ppf_is_inverse_of_betai(self):
        for x in (0.1, 0.3, 0.7, 0.9):
            q = U.beta_ppf(x, 3, 5)
            self.assertAlmostEqual(U.betai(3, 5, q), x, places=4)

    def test_monotone(self):
        qs = [U.beta_ppf(p, 2, 4) for p in (0.1, 0.5, 0.9)]
        self.assertEqual(qs, sorted(qs))


class TestEvidenceWeight(unittest.TestCase):
    def test_ordering(self):
        self.assertGreater(U.evidence_weight(U.DIRECT),
                           U.evidence_weight(U.FAMILY))
        self.assertGreater(U.evidence_weight(U.FAMILY),
                           U.evidence_weight(U.MODALITY))
        self.assertGreater(U.evidence_weight(U.MODALITY),
                           U.evidence_weight(U.ABSENT))

    def test_unknown_status_defaults_to_absent(self):
        self.assertEqual(U.evidence_weight("nonsense"),
                         U.evidence_weight(U.ABSENT))


class TestBetaInterval(unittest.TestCase):
    def test_contains_mean(self):
        iv = U.beta_interval(0.5, 12)
        self.assertLess(iv["lower"], 0.5)
        self.assertGreater(iv["upper"], 0.5)

    def test_more_concentration_is_narrower(self):
        wide = U.beta_interval(0.5, 4)
        tight = U.beta_interval(0.5, 40)
        self.assertLess(tight["upper"] - tight["lower"],
                        wide["upper"] - wide["lower"])


class TestResidualInterval(unittest.TestCase):
    def test_no_controls_mean_near_inherent(self):
        r = U.residual_interval(0.6, [])
        self.assertAlmostEqual(r["mean"], 0.6, delta=0.05)
        self.assertGreater(r["upper"], r["lower"])

    def test_a_control_lowers_the_mean(self):
        none = U.residual_interval(0.6, [])
        one = U.residual_interval(0.6, [(0.8, U.DIRECT)])
        self.assertLess(one["mean"], none["mean"])

    def test_deterministic_for_a_seed(self):
        a = U.residual_interval(0.6, [(0.8, U.DIRECT)], seed=7)
        b = U.residual_interval(0.6, [(0.8, U.DIRECT)], seed=7)
        self.assertEqual(a, b)

    def test_absent_evidence_widens_the_interval(self):
        direct = U.residual_interval(0.6, [(0.8, U.DIRECT)])
        absent = U.residual_interval(0.6, [(0.8, U.ABSENT)])
        self.assertGreater(absent["width"], direct["width"])

    def test_floor_keeps_residual_from_zero(self):
        r = U.residual_interval(0.6, [(0.999, U.DIRECT)])
        self.assertGreaterEqual(r["lower"], 0.0)
        self.assertGreater(r["mean"], 0.3 * 0.6 * 0.5)


class TestAggregatorInterval(unittest.TestCase):
    def test_band_surrounds_the_mean_and_stays_in_scale(self):
        threats = [
            {"likelihood": 4, "impact": 8,
             "controls": [(0.5, U.DIRECT)]},
            {"likelihood": 3, "impact": 6,
             "controls": [(0.3, U.FAMILY)]},
        ]
        agg = U.aggregator_interval(threats)
        self.assertLessEqual(agg["lower_pct"], agg["mean_pct"])
        self.assertGreaterEqual(agg["upper_pct"], agg["mean_pct"])
        self.assertGreaterEqual(agg["lower_pct"], 0.0)
        self.assertLessEqual(agg["upper_pct"], 100.0)

    def test_empty_threats_is_zero(self):
        self.assertEqual(U.aggregator_interval([])["mean_pct"], 0.0)


class TestCounterfactual(unittest.TestCase):
    def test_enabling_a_control_reduces_residual(self):
        cf = U.counterfactual(0.6, [], [("C04", 0.7, U.DIRECT)])
        self.assertGreater(cf["reduction"], 0.0)
        self.assertEqual(cf["enabled"], ["C04"])

    def test_do_operator_matches_direct_application(self):
        current = [("C01", 0.3, U.DIRECT)]
        enable = [("C04", 0.7, U.DIRECT)]
        cf = U.counterfactual(0.6, current, enable)
        direct = U.residual_interval(
            0.6, [(0.3, U.DIRECT), (0.7, U.DIRECT)])
        self.assertEqual(cf["after"], direct)

    def test_re_enabling_an_active_control_is_a_noop(self):
        current = [("C01", 0.3, U.DIRECT)]
        cf = U.counterfactual(0.6, current, [("C01", 0.3, U.DIRECT)])
        self.assertEqual(cf["n_new"], 0)
        self.assertAlmostEqual(cf["reduction"], 0.0, places=6)


class TestAssessmentInterval(unittest.TestCase):
    def _band(self, controls=None, **kw):
        from app import evalkit as E
        from app import security as sec
        inherent = E._inherent("confidential_data")
        res = sec.score_assessment("confidential_data", inherent,
                                   active_controls=controls or [])
        return U.assessment_interval(res, **kw)

    def test_band_surrounds_the_headline(self):
        band = self._band(["C02", "C04"])
        self.assertTrue(band["headline_inside"])
        self.assertLessEqual(band["lower_pct"], band["headline_pct"])
        self.assertGreaterEqual(band["upper_pct"], band["headline_pct"])

    def test_no_controls_band_surrounds_headline(self):
        self.assertTrue(self._band([])["headline_inside"])

    def test_unknown_evidence_widens_the_band(self):
        direct = self._band(["C02", "C04"])
        absent = self._band(["C02", "C04"],
                            evidence_by_control={"C02": U.ABSENT,
                                                 "C04": U.ABSENT})
        self.assertGreater(absent["upper_pct"] - absent["lower_pct"],
                           direct["upper_pct"] - direct["lower_pct"])


if __name__ == "__main__":
    unittest.main()
