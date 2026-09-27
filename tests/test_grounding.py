"""Tests for app.grounding -- the shared hallucination gate.

The quote rule used to live twice (ledger.quote_is_verbatim and
explainer._quote_valid). These tests pin the single implementation, so neither
copy can drift, and cover the reference-id check used for quoted prose that
carries no quotes at all.
"""
import unittest

from app import grounding as G


SOURCE = ("The model weights are stored encrypted at rest in object storage, "
          "and the encryption key lives in a managed KMS vault.")


class TestNorm(unittest.TestCase):
    def test_whitespace_collapsed_and_lowercased(self):
        self.assertEqual(G.norm("  The   MODEL\nweights "), "the model weights")

    def test_empty_is_safe(self):
        self.assertEqual(G.norm(None), "")


class TestQuoteIsVerbatim(unittest.TestCase):
    def test_exact_quote_verifies(self):
        self.assertTrue(G.quote_is_verbatim(SOURCE, "stored encrypted at rest"))

    def test_case_and_whitespace_insensitive(self):
        self.assertTrue(G.quote_is_verbatim(SOURCE, "Stored   ENCRYPTED at rest"))

    def test_invented_quote_rejected(self):
        self.assertFalse(G.quote_is_verbatim(
            SOURCE, "the weights are trained on customer support transcripts"))

    def test_short_quote_never_verifies(self):
        # Two words match almost any prose; verifying them would manufacture
        # confidence out of a coincidence.
        self.assertFalse(G.quote_is_verbatim(SOURCE, "at rest"))
        self.assertFalse(G.quote_is_verbatim(SOURCE, "kms"))
        self.assertEqual(G.MIN_QUOTE_CHARS, 12)

    def test_truncated_but_real_quote_verifies(self):
        # The head/tail fallback: a quote the model trimmed mid-sentence still
        # has to be checkable against the full source.
        self.assertTrue(G.quote_is_verbatim(
            SOURCE, "the model weights are stored encrypted at rest in object storage, and"))

    def test_empty_inputs(self):
        self.assertFalse(G.quote_is_verbatim("", "anything long enough to pass"))
        self.assertFalse(G.quote_is_verbatim(SOURCE, ""))


class TestConfidenceLadder(unittest.TestCase):
    def test_ladder(self):
        self.assertEqual(G.confidence_for(0), "none")
        self.assertEqual(G.confidence_for(1), "low")
        self.assertEqual(G.confidence_for(2), "medium")
        self.assertEqual(G.confidence_for(3), "high")
        self.assertEqual(G.confidence_for(9), "high")

    def test_one_source_is_never_high(self):
        # One source agreeing with itself is not corroboration.
        self.assertNotEqual(G.confidence_for(1), "high")


class TestVerifyGrounding(unittest.TestCase):
    def test_mapping_sources_shape(self):
        r = G.verify_grounding("weights are encrypted",
                               [{"source": "s1", "quote": "stored encrypted at rest"}],
                               {"s1": SOURCE})
        self.assertEqual(r["verdict"], "supported")
        self.assertEqual(r["n_sources"], 1)
        self.assertEqual(r["kept"][0]["verified"], True)

    def test_page_list_sources_shape(self):
        pages = [{"id": "p1", "text": SOURCE}]
        r = G.verify_grounding("c", [{"source": "p1", "quote": "stored encrypted at rest"}],
                               pages)
        self.assertEqual(r["n_sources"], 1)

    def test_source_index_addressing(self):
        r = G.verify_grounding("c", [{"sourceIndex": 0,
                                      "quote": "stored encrypted at rest"}],
                               [{"text": SOURCE}])
        self.assertEqual(r["n_sources"], 1)

    def test_invented_quote_is_a_violation(self):
        r = G.verify_grounding("claim", [{"source": "s1", "quote": "trained on our data"}],
                               {"s1": SOURCE})
        self.assertTrue(r["violation"])
        self.assertEqual(r["verdict"], "unverified")
        self.assertEqual(r["dropped"][0]["reason"], "not_found_in_source")

    def test_unknown_source_key_is_dropped(self):
        r = G.verify_grounding("c", [{"source": "nope", "quote": "stored encrypted at rest"}],
                               {"s1": SOURCE})
        self.assertTrue(r["violation"])

    def test_distinct_sources_only(self):
        # The same source cited twice is one source.
        cites = [{"source": "s1", "quote": "stored encrypted at rest"}] * 2
        r = G.verify_grounding("c", cites, {"s1": SOURCE})
        self.assertEqual(r["n_sources"], 1)
        self.assertEqual(r["confidence"], "low")

    def test_malformed_citation_does_not_crash(self):
        r = G.verify_grounding("c", ["not a dict", None],
                               {"s1": SOURCE})
        self.assertTrue(r["violation"])
        self.assertEqual(r["dropped"][0]["reason"], "malformed_citation")

    def test_quote_is_truncated_for_storage(self):
        long_source = "x" * 500 + " needle in a very long haystack sentence here"
        r = G.verify_grounding("c", [{"source": "s1", "quote": long_source}],
                               {"s1": long_source})
        self.assertEqual(len(r["kept"][0]["quote"]), G.QUOTE_STORE_CHARS)


class TestCitedIds(unittest.TestCase):
    def test_ids_in_order_without_duplicates(self):
        self.assertEqual(G.cited_ids("see #3 and #7, then #3 again"), [3, 7])

    def test_no_ids(self):
        self.assertEqual(G.cited_ids("no references here"), [])

    def test_bare_number_is_not_a_reference(self):
        # "#" is required: a bare "3" is a count, not a citation.
        self.assertEqual(G.cited_ids("there were 3 threats"), [])


class TestVerifyCitationIds(unittest.TestCase):
    def test_all_ids_real(self):
        r = G.verify_citation_ids("Confirmed by #1 and #2.", [1, 2, 3])
        self.assertFalse(r["violation"])
        self.assertEqual(r["kept"], [1, 2])
        self.assertEqual(r["invented"], [])

    def test_invented_id_is_caught(self):
        r = G.verify_citation_ids("Confirmed by #1 and #99.", [1, 2])
        self.assertEqual(r["kept"], [1])
        self.assertEqual(r["invented"], [99])

    def test_paragraph_citing_nothing_is_unverified(self):
        r = G.verify_citation_ids("Risk is high because of many factors.", [1, 2])
        self.assertTrue(r["violation"])
        self.assertEqual(r["verdict"], "unverified")

    def test_no_evidence_supplied_means_no_support(self):
        r = G.verify_citation_ids("Confirmed by #1.", [])
        self.assertTrue(r["violation"])
        self.assertEqual(r["invented"], [1])

    def test_string_ids_are_accepted(self):
        r = G.verify_citation_ids("Confirmed by #4.", ["4"])
        self.assertEqual(r["kept"], [4])
        self.assertFalse(r["violation"])

    def test_junk_ids_ignored(self):
        r = G.verify_citation_ids("Confirmed by #4.", ["not-an-int", None])
        self.assertTrue(r["violation"])


class TestSharedImplementation(unittest.TestCase):
    """The point of the module: one rule, not two that drift."""

    def test_ledger_re_exports_this_implementation(self):
        from app import ledger
        self.assertIs(ledger.quote_is_verbatim, G.quote_is_verbatim)
        self.assertIs(ledger.verify_grounding, G.verify_grounding)

    def test_explainer_uses_this_implementation(self):
        from app import explainer
        self.assertTrue(explainer._quote_valid(SOURCE, "stored encrypted at rest"))
        self.assertFalse(explainer._quote_valid(SOURCE, "trained on our data"))


if __name__ == "__main__":
    unittest.main()
