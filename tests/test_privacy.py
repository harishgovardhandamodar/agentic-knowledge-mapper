"""Privacy budget, extraction resistance and erasure commitments (app.privacy).

The structural guarantees (digests not content, local inference) are pinned
elsewhere. These tests pin the *measurements*: that novelty is charged and
re-reads are not, that a verbatim reproduction of a stored artifact is caught
and scored, and that an erasure commitment opens for the right subject only.
"""
import unittest

from app import privacy as P


class TestPrivacyBudget(unittest.TestCase):
    def _page(self, url, text):
        return {"url": url, "text": text}

    def test_external_pages_are_charged(self):
        r = P.privacy_budget(
            [self._page("https://example.com/a", "alpha beta")], queries=3)
        self.assertEqual(r["queries"], 3)
        self.assertEqual(r["external_pages"], 1)
        self.assertEqual(r["novel_pages"], 1)
        self.assertGreater(r["spend"], 3)

    def test_already_seen_page_is_not_novel(self):
        page = self._page("https://example.com/a", "alpha beta")
        seen = [P._digest("alpha beta")]
        r = P.privacy_budget([page], queries=0, seen_hashes=seen)
        self.assertEqual(r["novel_pages"], 0)
        self.assertEqual(r["spend"], 0.0)

    def test_local_pages_are_ignored(self):
        r = P.privacy_budget([self._page("", "internal"), {"url": "graph:1"}])
        self.assertEqual(r["external_pages"], 0)

    def test_distinct_domains_counted_once(self):
        pages = [self._page("https://a.com/1", "x"),
                 self._page("https://a.com/2", "y"),
                 self._page("https://b.com/1", "z")]
        r = P.privacy_budget(pages)
        self.assertEqual(r["distinct_domains"], 2)

    def test_exhaustion_advises_refuse(self):
        pages = [self._page(f"https://d{i}.com/p", f"text {i}" * 5)
                 for i in range(50)]
        r = P.privacy_budget(pages, budget={"max_spend": 10.0})
        self.assertTrue(r["exhausted"])
        self.assertEqual(r["advice"], "refuse")

    def test_low_budget_advises_degrade(self):
        r = P.privacy_budget([], queries=0,
                             budget={"max_spend": 10.0})
        self.assertEqual(r["advice"], "ok")
        r2 = P.privacy_budget([self._page("https://a.com/p", "q " * 20)],
                              queries=7, budget={"max_spend": 10.0})
        self.assertEqual(r2["advice"], "degrade")


class TestExtractionResistance(unittest.TestCase):
    ART = ("A1", "the vendor stores telemetry in the eu region for thirty days "
                 "and deletes it automatically afterwards")

    def test_verbatim_reproduction_is_flagged(self):
        r = P.extraction_resistance([self.ART], [self.ART[1]])
        self.assertFalse(r["ok"])
        self.assertEqual(r["findings"][0]["artifact_id"], "A1")
        self.assertEqual(r["findings"][0]["severity_band"], "high")

    def test_unrelated_output_is_clean(self):
        r = P.extraction_resistance([self.ART], ["a completely different sentence"])
        self.assertTrue(r["ok"])
        self.assertEqual(r["findings"], [])

    def test_partial_overlap_scores_lower(self):
        # Only a small slice of the artifact surfaces -> lower severity.
        snippet = "telemetry in the eu region"
        r = P.extraction_resistance([self.ART], [snippet])
        if r["findings"]:
            self.assertLess(r["findings"][0]["severity"],
                            P.extraction_resistance(
                                [self.ART], [self.ART[1]])["findings"][0]["severity"])

    def test_empty_inputs(self):
        r = P.extraction_resistance([], [])
        self.assertTrue(r["ok"])
        self.assertEqual(r["stats"]["extracted"], 0)


class TestMembershipInference(unittest.TestCase):
    CANARY = ("the zephyr protocol marker xq17 shipped quietly during the "
              "migration window")

    def test_canary_surfacing_is_membership(self):
        r = P.membership_inference(self.CANARY, [f"we found {self.CANARY} in logs"])
        self.assertEqual(r["signal"], "member")
        self.assertEqual(r["score"], 1.0)

    def test_absent_canary_is_non_member(self):
        r = P.membership_inference(self.CANARY, ["nothing relevant here"])
        self.assertEqual(r["signal"], "non-member")

    def test_baseline_match_is_inconclusive(self):
        out = [f"mention {self.CANARY}"]
        r = P.membership_inference(self.CANARY, out, baseline_outputs=out)
        self.assertEqual(r["signal"], "inconclusive")


class TestErasureCommitment(unittest.TestCase):
    def test_commitment_is_stable_and_salted(self):
        a = P.erasure_commitment("acme", "run-1", salt="s1")
        b = P.erasure_commitment("acme", "run-1", salt="s1")
        c = P.erasure_commitment("acme", "run-1", salt="s2")
        self.assertEqual(a["commitment"], b["commitment"])
        self.assertNotEqual(a["commitment"], c["commitment"])

    def test_verify_opens_only_for_the_right_subject(self):
        c = P.erasure_commitment("acme", "run-1", salt="s1")["commitment"]
        self.assertTrue(P.verify_erasure("acme", "run-1", salt="s1",
                                         commitment=c))
        self.assertFalse(P.verify_erasure("other", "run-1", salt="s1",
                                          commitment=c))
        self.assertFalse(P.verify_erasure("acme", "run-2", salt="s1",
                                          commitment=c))

    def test_commitment_does_not_expose_the_subject(self):
        c = P.erasure_commitment("acme", "run-1", salt="s1")["commitment"]
        self.assertNotIn("acme", c)
        self.assertEqual(len(c), 64)


if __name__ == "__main__":
    unittest.main()
