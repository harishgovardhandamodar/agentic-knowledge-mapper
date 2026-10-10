"""Span-level provenance and the drop-reason classifier for app.grounding.

The verbatim gate is pinned in ``test_grounding.py``. These tests cover what
was added so a verdict is a *span* -- character offsets into the original
source -- and so a rejected quote is labelled (negation flip, number swap,
paraphrase) rather than flattened into one opaque "not found".
"""
import unittest

from app import grounding as G

PARA = ("Encryption keys are held in a managed KMS vault.\n\n"
        "The service retains API prompts for 30 days before deletion, "
        "and the retention window does not apply to abuse-monitoring logs.")


class TestNormMap(unittest.TestCase):
    def test_matches_norm(self):
        text = "  The   MODEL\nweights "
        normed, _ = G._norm_map(text)
        self.assertEqual(normed, G.norm(text))

    def test_offsets_point_into_original(self):
        text = "alpha   BETA gamma"
        normed, idx = G._norm_map(text)
        self.assertEqual(normed, "alpha beta gamma")
        for i, ch in enumerate(normed):
            if ch != " ":
                self.assertEqual(text[idx[i]].lower(), ch)


class TestLocateQuote(unittest.TestCase):
    def test_exact_span_round_trips(self):
        span = G.locate_quote(PARA, "retains API prompts for 30 days")
        self.assertEqual(span["method"], "exact")
        self.assertEqual(PARA[span["start"]:span["end"]],
                         "retains API prompts for 30 days")

    def test_paragraph_index_counts_blank_lines(self):
        span = G.locate_quote(PARA, "managed KMS vault")
        self.assertEqual(span["paragraph"], 0)
        span2 = G.locate_quote(PARA, "retention window does not apply")
        self.assertEqual(span2["paragraph"], 1)

    def test_headtail_fallback_still_spans(self):
        quote = ("Encryption keys are held in a managed KMS vault. "
                 "unrelated middle text before deletion")
        span = G.locate_quote(PARA, quote)
        self.assertIsNotNone(span)
        self.assertEqual(span["method"], "headtail")

    def test_absent_quote_has_no_span(self):
        self.assertIsNone(G.locate_quote(PARA, "the vendor trains on your data"))

    def test_empty_inputs(self):
        self.assertIsNone(G.locate_quote("", "anything"))
        self.assertIsNone(G.locate_quote(PARA, ""))


class TestEntail(unittest.TestCase):
    def test_paraphrase_has_high_support(self):
        e = G.entail(PARA, "retains API prompts for 30 days before deletion in 30 days")
        self.assertGreaterEqual(e["support"], 0.6)

    def test_negation_flip_detected(self):
        e = G.entail("The API does not retain prompts.", "The API retains prompts")
        self.assertEqual(e["polarity"], "flip")

    def test_number_swap_detected(self):
        e = G.entail("retention is 30 days", "retention is 90 days")
        self.assertEqual(e["numbers"], "swap")
        self.assertIn("90", e["missing_numbers"])

    def test_invention_has_low_support(self):
        e = G.entail(PARA, "adversaries extract memorized samples from the endpoint")
        self.assertLess(e["support"], 0.35)


class TestExplainDrop(unittest.TestCase):
    def test_number_swap_outranks_paraphrase(self):
        reason, _ = G.explain_drop("retention is 30 days", "retention is 90 days")
        self.assertEqual(reason, "number_swap")

    def test_negation_flip(self):
        reason, _ = G.explain_drop("The API does not retain prompts.",
                                   "The API retains prompts")
        self.assertEqual(reason, "negation_flip")

    def test_paraphrase(self):
        reason, _ = G.explain_drop(PARA, "managed KMS vault holds the keys")
        self.assertEqual(reason, "paraphrase")

    def test_invention(self):
        reason, _ = G.explain_drop(PARA, "adversaries extract memorized samples")
        self.assertEqual(reason, "not_found_in_source")


class TestVerifyGroundingSpans(unittest.TestCase):
    def test_kept_citation_carries_span(self):
        r = G.verify_grounding(
            "retains prompts",
            [{"source": "s1", "quote": "retains API prompts for 30 days"}],
            {"s1": PARA})
        self.assertEqual(r["verdict"], "supported")
        self.assertEqual(r["kept"][0]["verified_by"], "verbatim")
        self.assertIsNotNone(r["kept"][0]["span"])

    def test_dropped_citation_carries_reason_and_entailment(self):
        r = G.verify_grounding(
            "retention is 90 days",
            [{"source": "s1", "quote": "retention is 90 days"}],
            {"s1": PARA})
        self.assertTrue(r["violation"])
        self.assertEqual(r["dropped"][0]["reason"], "number_swap")
        self.assertIn("entailment", r["dropped"][0])

    def test_unknown_source_has_its_own_reason(self):
        r = G.verify_grounding("c", [{"source": "ghost", "quote": "x" * 20}],
                               {"s1": PARA})
        self.assertEqual(r["dropped"][0]["reason"], "unknown_source")

    def test_entail_stage_accepts_a_paraphrase(self):
        r = G.verify_grounding(
            "keys are in a vault",
            [{"source": "s1", "quote": "managed KMS vault holds keys"}],
            {"s1": "The KMS vault holds encryption keys."}, entail_min=0.6)
        self.assertEqual(r["verdict"], "supported")
        self.assertEqual(r["kept"][0]["verified_by"], "entailment")

    def test_entail_stage_refuses_a_negation_flip(self):
        r = G.verify_grounding(
            "API retains prompts",
            [{"source": "s1", "quote": "API retains prompts"}],
            {"s1": "The API does not retain prompts."}, entail_min=0.5)
        self.assertTrue(r["violation"])

    def test_default_is_strict_verbatim(self):
        r = G.verify_grounding(
            "c", [{"source": "s1", "quote": "managed KMS vault holds keys"}],
            {"s1": "The KMS vault holds encryption keys."})
        self.assertTrue(r["violation"])


class TestCalibration(unittest.TestCase):
    def test_no_sources_is_exactly_zero(self):
        self.assertEqual(G.calibrated_confidence(0), 0.0)

    def test_one_source_never_exceeds_half(self):
        self.assertLessEqual(G.calibrated_confidence(1), 0.5)

    def test_more_independent_sources_raise_confidence(self):
        vals = [G.calibrated_confidence(n) for n in (1, 2, 3, 5)]
        self.assertEqual(vals, sorted(vals))
        self.assertLess(vals[0], vals[-1])

    def test_discounts_are_multiplicative(self):
        full = G.calibrated_confidence(3)
        discounted = G.calibrated_confidence(3, entailment=0.5, recency=0.5)
        self.assertAlmostEqual(discounted, full * 0.25, places=3)

    def test_label_buckets(self):
        self.assertEqual(G.confidence_label(0.0), "none")
        self.assertEqual(G.confidence_label(0.2), "low")
        self.assertEqual(G.confidence_label(0.5), "medium")
        self.assertEqual(G.confidence_label(0.9), "high")


class TestClaimDigest(unittest.TestCase):
    def test_deterministic(self):
        a = G.claim_digest("x", [1], [{"start": 0, "end": 1}])
        b = G.claim_digest("x", [1], [{"start": 0, "end": 1}])
        self.assertEqual(a, b)

    def test_offsets_matter(self):
        a = G.claim_digest("x", [1], [{"start": 0, "end": 1}])
        b = G.claim_digest("x", [1], [{"start": 5, "end": 6}])
        self.assertNotEqual(a, b)


if __name__ == "__main__":
    unittest.main()
