"""Tests for brief-drift detection (app.drift).

Drift = off-brief topic, kept but flagged. The prefilter is deterministic
(shared vocabulary); the verdict is one LLM batch call per few candidates.
Fail-open everywhere: failures mark nothing.
"""
import unittest

from app import drift as D


class TestDriftTokens(unittest.TestCase):
    def test_stopwords_dropped(self):
        self.assertEqual(D.content_tokens("models and the frontier"),
                         {"models", "frontier"})

    def test_acronyms_are_kept(self):
        """``AI`` is the most common word in a frontier-AI brief.

        Dropping every token under four characters silently threw it away,
        which is what let a biomedical item into an AI investigation on a
        technicality rather than on a judgement.
        """
        self.assertIn("ai", D.content_tokens("AI models and the frontier"))
        self.assertIn("ml", D.content_tokens("ML safety"))
        self.assertIn("llm", D.content_tokens("LLM evaluation"))
        self.assertIn("rlhf", D.content_tokens("RLHF"))

    def test_mixed_case_acronyms_are_kept(self):
        # "any capital", not "all capitals" -- IoT and iOS are real.
        self.assertIn("iot", D.content_tokens("IoT security"))
        self.assertIn("ios", D.content_tokens("iOS privacy"))

    def test_lowercase_short_fragments_still_dropped(self):
        # The noise the old length filter was actually aimed at.
        self.assertNotIn("de", D.content_tokens("der de facto"))
        self.assertNotIn("fr", D.content_tokens("fr有几个"))
        self.assertNotIn("a", D.content_tokens("a b c"))

    def test_stopwords_never_survive_even_uppercase(self):
        self.assertNotIn("the", D.content_tokens("THE models"))

    def test_ngrams_are_format_agnostic(self):
        self.assertEqual(D.ngrams("reward-hacking"), D.ngrams("reward hacking"))
        self.assertNotIn(" ", D.ngrams("reward hacking"))

    def test_ngrams_ignore_case_and_punctuation(self):
        self.assertEqual(D.ngrams("Reward Misspecification"),
                         D.ngrams("reward misspecification!"))

    def test_ngrams_of_tiny_strings(self):
        self.assertEqual(D.ngrams(""), set())
        self.assertEqual(D.ngrams("ab"), {"ab"})
        self.assertEqual(D.ngrams("abc"), {"abc"})

    def test_ngram_size_prevents_incidental_collisions(self):
        """Four letters, not three: "Encephalitis" and "alignment" share
        "ali" and "lit" at three, which is not evidence of a shared topic."""
        brief = "frontier model alignment interpretability"
        item = "Encephalitis in humans"
        shared4 = D.ngrams(item) & D.ngrams(brief)
        self.assertLess(len(shared4), 2)
        # The three-gram version is exactly why four is the bar.
        self.assertGreaterEqual(len(D.ngrams(item, 3) & D.ngrams(brief, 3)), 2)

    def test_punctuation_collapse_cannot_join_unrelated_words(self):
        # "re-ward" is not "reward": the boundary is preserved as a space, so a
        # match can never be manufactured by deleting a delimiter.
        self.assertNotEqual(D.ngrams("re-ward"), D.ngrams("reward"))

    def test_brief_terms_cover_title_keywords_description(self):
        b = D.brief_terms("frontier model", "alignment, RLHF",
                          "mechanistic interpretability research")
        self.assertTrue({"frontier", "model", "alignment", "rlhf",
                         "mechanistic", "interpretability", "research"} <= b)


class TestDriftCandidates(unittest.TestCase):
    BRIEF = D.brief_terms("frontier model", "alignment, interpretability",
                          "mechanistic interpretability research")

    def test_overlapping_items_are_not_candidates(self):
        items = [{"id": 1, "title": "Mechanistic Interpretability Needs Philosophy",
                  "tags": "mechanistic-interpretability,philosophy"}]
        self.assertEqual(D.drift_candidates(self.BRIEF, set(), items), [])

    def test_foreign_items_are_candidates(self):
        items = [{"id": 2, "title": "Encephalitis", "tags": "concept,explainer"}]
        self.assertEqual(D.drift_candidates(self.BRIEF, set(), items), items)

    def test_corpus_overlap_clears_candidates(self):
        items = [{"id": 3, "title": "Reward misspecification", "tags": "concept"}]
        self.assertEqual(D.drift_candidates(self.BRIEF, set(), items), items)
        corpus = {"reward", "misalignment"}
        self.assertEqual(D.drift_candidates(self.BRIEF, corpus, items), [])

    def test_empty_terms_never_candidates(self):
        self.assertEqual(D.drift_candidates(self.BRIEF, set(),
                                            [{"id": 4, "title": "", "tags": ""}]),
                         [])

    def test_description_counts_as_vocabulary(self):
        """A paper titled "A study" says what it is about only in its body."""
        brief = D.brief_terms("frontier model", "alignment", "")
        item = {"id": 5, "title": "A study", "tags": "research",
                "description": "mechanistic interpretability of frontier models"}
        self.assertEqual(D.drift_candidates(brief, set(), [item]), [])

    def test_item_terms_include_description(self):
        self.assertIn("encephalitis", D.item_terms("A study", "",
                                                    "Encephalitis review"))
        # Kept optional so existing two-arg callers keep working.
        self.assertEqual(D.item_terms("Reward hacking", "concept"),
                         D.item_terms("Reward hacking", "concept", ""))

    def test_acronym_only_item_clears_an_acronym_brief(self):
        brief = D.brief_terms("AI safety", "alignment, ML", "")
        item = {"id": 6, "title": "ML governance", "tags": "policy"}
        self.assertEqual(D.drift_candidates(brief, set(), [item]), [])

    def test_acronym_does_not_clear_an_unrelated_brief(self):
        """The risk of keeping short tokens: a stray acronym must not make
        every item look on-brief. This is the false positive that would have
        made acronym-keeping net-negative, so it is pinned."""
        brief = D.brief_terms("Encephalitis", "virology", "")
        item = {"id": 7, "title": "AI safety", "tags": "alignment"}
        self.assertEqual(D.drift_candidates(brief, set(), [item]), [item])

    def test_ngram_net_clears_a_synonym(self):
        """No shared words, same topic.

        This is the recall the vocabulary prefilter structurally cannot have:
        without the n-gram stage an item like this went to the LLM judge as a
        suspected drift item on every pass, forever.
        """
        brief = D.brief_terms("Reward hacking in RLHF", "alignment", "")
        text = "Reward hacking in RLHF"
        item = {"id": 8, "title": "Rewarding the wrong thing", "tags": ""}
        self.assertEqual(D.drift_candidates(brief, set(), [item], brief_text=text),
                         [])
        # And without the text, it is still a candidate -- the boost is opt-in.
        self.assertEqual(D.drift_candidates(brief, set(), [item]), [item])

    def test_verbatim_short_phrase_in_the_brief_is_cleared(self):
        """A two-word title cannot clear an n-gram threshold on its own, but a
        phrase copied out of the brief is on-brief by definition."""
        brief = D.brief_terms("Reward hacking in RLHF", "alignment", "")
        text = "Reward hacking in RLHF"
        item = {"id": 13, "title": "Reward hacking", "tags": ""}
        self.assertEqual(D.drift_candidates(brief, set(), [item], brief_text=text),
                         [])

    def test_verbatim_test_does_not_excuse_a_long_item(self):
        """Otherwise any item could pass by quoting one common phrase."""
        brief = D.brief_terms("frontier model alignment", "interpretability", "")
        text = "frontier model alignment interpretability"
        item = {"id": 14,
                "title": "Encephalitis in humans and other unrelated things",
                "tags": "medicine"}
        self.assertEqual(D.drift_candidates(brief, set(), [item], brief_text=text),
                         [item])

    def test_ngram_net_does_not_clear_genuinely_foreign_items(self):
        brief = D.brief_terms("frontier model alignment", "interpretability", "")
        text = "frontier model alignment interpretability"
        item = {"id": 9, "title": "Encephalitis in humans", "tags": "medicine"}
        self.assertEqual(D.drift_candidates(brief, set(), [item], brief_text=text),
                         [item])

    def test_corpus_text_clears_candidates(self):
        brief = D.brief_terms("frontier model", "alignment", "")
        item = [{"id": 10, "title": "Spiking neural networks", "tags": ""}]
        corpus_text = "spike, spike, spiking neurons in the visual cortex"
        self.assertEqual(D.drift_candidates(brief, set(), item,
                                            corpus_text=corpus_text), [])

    def test_min_ngrams_is_configurable(self):
        brief = D.brief_terms("quantum chromodynamics", "lattice", "")
        text = "quantum chromodynamics lattice"
        item = [{"id": 11, "title": "Quantum chromodynamics", "tags": ""}]
        # Already cleared by vocabulary; the point is the threshold is tunable.
        self.assertEqual(D.drift_candidates(brief, set(), item, brief_text=text,
                                            min_ngrams=99),
                         [])

    def test_missing_text_keeps_legacy_behaviour(self):
        """No *_text means the original term-only filter, not a crash."""
        items = [{"id": 12, "title": "Encephalitis", "tags": "concept"}]
        self.assertEqual(D.drift_candidates(self.BRIEF, set(), items, brief_text=""),
                         items)
        self.assertEqual(D.drift_candidates(self.BRIEF, set(), None), [])

    def test_blank_item_text_is_never_a_candidate(self):
        items = [{"id": 15, "title": "  ", "tags": "", "description": None}]
        self.assertEqual(D.drift_candidates(self.BRIEF, set(), items,
                                            brief_text="anything"), [])


class TestClassifyDrift(unittest.TestCase):
    """The judge reports a verdict report, not a bare set.

    ``ids`` is still "mark these", so a caller that only reads it behaves as
    before. The rest exists so a failed pass is distinguishable from a clean
    one -- the whole reason a dead gateway used to look like a clean corpus.
    """

    def _cands(self, n):
        return [{"id": i, "title": f"item {i}", "tags": "x"} for i in range(n)]

    def _patched(self, fn):
        import app.llm as llm_mod
        orig = llm_mod.chat_json
        llm_mod.chat_json = fn
        self.addCleanup(lambda: setattr(llm_mod, "chat_json", orig))
        return orig

    def test_batches_and_unions(self):
        calls = []

        def fake(*a, **k):
            calls.append(k)
            return {"drift_ids": [0]} if len(calls) == 1 else {"drift_ids": [8]}

        self._patched(fake)
        out = D.classify_drift("brief", self._cands(10), batch=8)
        self.assertEqual(len(calls), 2)
        self.assertEqual(out["ids"], {0, 8})
        self.assertTrue(out["complete"])
        self.assertEqual(out["failed"], 0)

    def test_unknown_ids_ignored(self):
        self._patched(lambda *a, **k: {"drift_ids": [1, 999, "x"]})
        out = D.classify_drift("brief", self._cands(3))
        self.assertEqual(out["ids"], {1})

    def test_llm_failure_marks_nothing_but_reports(self):
        # Retries are on, so the fake must fail every attempt.
        self._patched(lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down")))
        out = D.classify_drift("brief", self._cands(2), retries=1)
        self.assertEqual(out["ids"], set())
        self.assertFalse(out["complete"])
        self.assertEqual(out["failed"], 1)
        self.assertIn("down", out["error"])

    def test_transient_failure_is_retried(self):
        attempts = []

        def flaky(*a, **k):
            attempts.append(1)
            if len(attempts) == 1:
                raise RuntimeError("blip")
            return {"drift_ids": [1]}

        self._patched(flaky)
        out = D.classify_drift("brief", self._cands(2), retries=2)
        self.assertEqual(len(attempts), 2)
        self.assertEqual(out["ids"], {1})
        self.assertTrue(out["complete"])
        self.assertEqual(out["failed"], 0)

    def test_unusable_shape_is_reported(self):
        # A response that is not a dict is a silent-clearing failure mode, not
        # a clean answer: nothing drifted, so say so.
        self._patched(lambda *a, **k: ["not", "a", "dict"])
        out = D.classify_drift("brief", self._cands(2), retries=0)
        self.assertEqual(out["ids"], set())
        self.assertFalse(out["complete"])
        self.assertIn("shape", out["error"])

    def test_empty_list_is_a_valid_clean_verdict(self):
        self._patched(lambda *a, **k: {"drift_ids": []})
        out = D.classify_drift("brief", self._cands(2))
        self.assertEqual(out["ids"], set())
        self.assertTrue(out["complete"])
        self.assertEqual(out["error"], "")

    def test_overflow_is_counted(self):
        self._patched(lambda *a, **k: {"drift_ids": []})
        out = D.classify_drift("brief", self._cands(10), limit=4, batch=8)
        self.assertEqual(out["judged"], 4)
        self.assertEqual(out["overflow"], 6)
        self.assertFalse(out["complete"])

    def test_no_candidates_no_call(self):
        self._patched(lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not call")))
        out = D.classify_drift("brief", [])
        self.assertEqual(out["ids"], set())
        self.assertTrue(out["complete"])

    def test_incomplete_reason_names_the_cause(self):
        self.assertIn("batch", D.incomplete_reason({"failed": 2, "overflow": 0}))
        self.assertIn("limit", D.incomplete_reason({"failed": 0, "overflow": 3}))
        both = D.incomplete_reason({"failed": 1, "overflow": 3})
        self.assertIn("batch", both)
        self.assertIn("limit", both)


class TestDriftJudgeAudit(unittest.TestCase):
    """An incomplete pass must be visible on the ledger, not inferred."""

    def test_clean_verdict_emits_nothing(self):
        import app.ledger as ledger_mod
        calls = []
        orig = ledger_mod.record_internal_event
        ledger_mod.record_internal_event = lambda *a, **k: calls.append(k)
        try:
            D._audit_judge({"ids": set(), "judged": 2, "overflow": 0,
                            "failed": 0, "error": "", "complete": True}, 2)
        finally:
            ledger_mod.record_internal_event = orig
        self.assertEqual(calls, [])

    def test_incomplete_verdict_emits_flag(self):
        import app.ledger as ledger_mod
        calls = []
        orig = ledger_mod.record_internal_event
        ledger_mod.record_internal_event = (
            lambda kind, actor, **k: calls.append((kind, k)))
        try:
            D._audit_judge({"ids": set(), "judged": 2, "overflow": 3,
                            "failed": 0, "error": "", "complete": False}, 5)
        finally:
            ledger_mod.record_internal_event = orig
        self.assertEqual(len(calls), 1)
        kind, kw = calls[0]
        self.assertEqual(kind, "drift.judge")
        self.assertEqual(kw["verdict"], "flag")
        self.assertEqual(kw["data"]["overflow"], 3)


if __name__ == "__main__":
    unittest.main()
