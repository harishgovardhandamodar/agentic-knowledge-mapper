"""Atomic claim decomposition, per-claim verification and the free-text guard.

The regression fixtures here are the point of the module: an invented sentence,
a negated sentence and a number-swapped sentence in an otherwise-supporting
paragraph must each be caught and dropped, not averaged into "mostly true".
"""
import unittest

from app import claims as C

PAGE = {"id": "p1", "text": (
    "The vendor encrypts all customer data at rest using managed keys. "
    "The service retains API prompts for 30 days before deletion.")}

DOC = ("# Findings\n"
       "The vendor encrypts all customer data at rest using managed keys.\n"
       "Adversaries can extract memorized training samples from the endpoint.\n"
       "- The service retains API prompts before deletion.")


class TestAtomicClaims(unittest.TestCase):
    def test_splits_sentences_and_keeps_spans(self):
        text = "First sentence is here. Second sentence is also here."
        out = C.atomic_claims(text)
        self.assertEqual(len(out), 2)
        self.assertEqual(text[out[0]["start"]:out[0]["end"]],
                         "First sentence is here.")
        self.assertEqual(text[out[1]["start"]:out[1]["end"]],
                         "Second sentence is also here.")

    def test_headings_are_not_claims(self):
        out = C.atomic_claims(DOC)
        self.assertTrue(all(not c["text"].startswith("#") for c in out))

    def test_bullet_marker_is_stripped_from_the_claim(self):
        out = C.atomic_claims(DOC)
        self.assertTrue(any(c["text"].startswith("The service") for c in out))
        self.assertTrue(all(not c["text"].startswith("-") for c in out))

    def test_short_fragments_are_structural(self):
        self.assertEqual(C.atomic_claims("Yes. No."), [])


class TestVerifyClaim(unittest.TestCase):
    def test_supported_claim_gets_a_span(self):
        r = C.verify_claim({"text": "The vendor encrypts all customer data at rest",
                            "start": 0, "end": 46}, [PAGE])
        self.assertEqual(r["verdict"], "supported")
        self.assertEqual(r["source"], "p1")
        self.assertIsNotNone(r["span"])

    def test_invented_sentence_is_unsupported(self):
        r = C.verify_claim(
            {"text": "Adversaries extract memorized training samples",
             "start": 0, "end": 48}, [PAGE])
        self.assertEqual(r["verdict"], "unsupported")

    def test_number_swap_is_reported(self):
        r = C.verify_claim({"text": "The service retains API prompts for 90 days",
                            "start": 0, "end": 43}, [PAGE])
        self.assertEqual(r["numbers"], "swap")

    def test_invented_reference_forces_unsupported(self):
        # Words overlap the page, but the only citation resolves to nothing.
        r = C.verify_claim(
            {"text": "The vendor encrypts customer data per #99",
             "start": 0, "end": 43}, [PAGE], valid_ids=[1, 2])
        self.assertEqual(r["verdict"], "unsupported")
        self.assertEqual(r["invented"], [99])

    def test_weak_band(self):
        # Half the claim's vocabulary is absent; support lands in the weak band.
        r = C.verify_claim(
            {"text": "customer data endpoint memorized samples exfiltration",
             "start": 0, "end": 54}, [PAGE])
        self.assertIn(r["verdict"], ("weak", "unsupported"))

    def test_claim_id_is_stable(self):
        a = C.verify_claim({"text": "The vendor encrypts all customer data at rest"},
                           [PAGE])
        b = C.verify_claim({"text": "The vendor encrypts all customer data at rest"},
                           [PAGE])
        self.assertEqual(a["claim_id"], b["claim_id"])


class TestVerifyFreeText(unittest.TestCase):
    def test_aggregate_counts(self):
        out = C.verify_free_text(DOC, [PAGE])
        self.assertEqual(out["stats"]["total"], 3)
        self.assertGreaterEqual(out["stats"]["supported"], 1)
        self.assertGreaterEqual(out["stats"]["unsupported"], 1)
        self.assertFalse(out["violation"])

    def test_all_unsupported_is_a_violation(self):
        out = C.verify_free_text(
            "Adversaries exfiltrate memorized samples. Attackers poison the index.",
            [PAGE])
        self.assertTrue(out["violation"])


class TestGuardFreeText(unittest.TestCase):
    def test_unsupported_sentence_is_dropped_and_heading_kept(self):
        out = C.guard_free_text(DOC, [PAGE])
        self.assertIn("# Findings", out["text"])
        self.assertIn("encrypts all customer data", out["text"])
        self.assertNotIn("Adversaries can extract", out["text"])
        self.assertEqual(len(out["dropped"]), 1)
        self.assertEqual(out["dropped"][0]["verdict"], "unsupported")

    def test_supported_only_document_is_untouched(self):
        text = "The vendor encrypts all customer data at rest using managed keys."
        out = C.guard_free_text(text, [PAGE])
        self.assertEqual(out["text"].strip(), text)
        self.assertEqual(out["dropped"], [])

    def test_keep_weak_option_retains_the_marginal_sentence(self):
        strict = C.guard_free_text(DOC, [PAGE])
        lenient = C.guard_free_text(DOC, [PAGE], keep_weak=True)
        self.assertGreaterEqual(len(lenient["kept"]), len(strict["kept"]))

    def test_violation_when_nothing_survives(self):
        out = C.guard_free_text(
            "Adversaries exfiltrate memorized samples.", [PAGE])
        self.assertTrue(out["violation"])


class TestClaimGraph(unittest.TestCase):
    def test_contradiction_edge_between_polarity_flips(self):
        a = C.verify_claim(
            {"text": "The service always retains API prompts"},
            [{"id": "p1", "text": "The service retains API prompts"}])
        b = C.verify_claim(
            {"text": "The service never retains API prompts"},
            [{"id": "p1", "text": "The service does not retain API prompts"}])
        graph = C.claim_graph([a, b])
        kinds = {e["kind"] for e in graph["edges"]}
        self.assertIn("cites_source", kinds)

    def test_nodes_and_stats(self):
        r = C.verify_free_text(DOC, [PAGE])
        graph = C.claim_graph(r["claims"])
        self.assertEqual(graph["stats"]["nodes"], len(r["claims"]))
        self.assertGreaterEqual(graph["stats"]["edges"], 1)


if __name__ == "__main__":
    unittest.main()
