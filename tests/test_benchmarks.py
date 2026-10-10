"""Benchmark crosswalk + reliability metrics (app.benchmarks)."""
import unittest

from app import benchmarks as B


class TestCrosswalk(unittest.TestCase):
    def test_threat_mapping_known(self):
        row = B.benchmark_for("T05")
        self.assertEqual(row["owasp"], "LLM01")
        self.assertEqual(row["atlas"], "AML.T0051")

    def test_unknown_id_is_none(self):
        self.assertIsNone(B.benchmark_for("T99"))

    def test_external_refs_are_flat(self):
        refs = B.external_refs("T05")
        self.assertIn("OWASP LLM01", refs)
        self.assertIn("AML.T0051", refs)

    def test_every_catalog_id_has_a_row(self):
        from app import security as sec
        for t in sec._THREAT_CATALOG:
            self.assertIn(t[0], B.THREAT_BENCHMARKS)

    def test_mitigation_table_matches_model_eval(self):
        from app import model_eval as me
        ids = {m["id"] for m in me.MITIGATION_CATALOG}
        self.assertTrue(ids <= set(B.MITIGATION_BENCHMARKS))

    def test_coverage_reports_unmapped(self):
        cov = B.coverage(["T01", "T05", "TZZ"])
        self.assertEqual(cov["total"], 3)
        self.assertEqual(cov["mapped"], 2)
        self.assertIn("TZZ", cov["unmapped"])
        self.assertAlmostEqual(cov["fraction"], 0.667, places=3)

    def test_full_coverage_is_one(self):
        cov = B.coverage()
        self.assertEqual(cov["fraction"], 1.0)
        self.assertEqual(cov["unmapped"], [])


class TestInterRater(unittest.TestCase):
    def test_perfect_agreement(self):
        rows = [({"likelihood": i, "impact": i}, {"likelihood": i, "impact": i})
                for i in range(1, 6)]
        r = B.inter_rater(rows)
        self.assertEqual(r["likelihood"]["kappa"], 1.0)
        self.assertEqual(r["band"], "almost perfect")

    def test_chance_level_agreement_is_near_zero(self):
        a = [1, 1, 1, 1, 2, 2, 2, 2]
        b = [1, 2, 1, 2, 1, 2, 1, 2]
        k = B.cohens_kappa(a, b)
        self.assertLess(abs(k), 0.05)

    def test_empty_is_zero(self):
        r = B.inter_rater([])
        self.assertEqual(r["n"], 0)
        self.assertEqual(r["likelihood"]["kappa"], 0.0)


class TestReliability(unittest.TestCase):
    def test_perfectly_confident_and_correct(self):
        r = B.reliability([(1.0, True)] * 10)
        self.assertEqual(r["brier"], 0.0)
        self.assertEqual(r["ece"], 0.0)
        self.assertEqual(r["band"], "well-calibrated")

    def test_confidently_wrong_is_punished(self):
        r = B.reliability([(0.95, False)] * 10)
        self.assertGreater(r["brier"], 0.8)
        self.assertEqual(r["band"], "mis-calibrated")

    def test_overconfidence_detected(self):
        # Says 90% but is right 50% of the time.
        samples = [(0.9, i % 2 == 0) for i in range(10)]
        r = B.reliability(samples)
        self.assertGreater(r["ece"], 0.2)
        self.assertGreater(r["brier"], 0.25)

    def test_empty(self):
        r = B.reliability([])
        self.assertEqual(r["n"], 0)
        self.assertEqual(r["brier"], 0.0)


if __name__ == "__main__":
    unittest.main()
