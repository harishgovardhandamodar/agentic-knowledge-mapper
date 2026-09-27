"""Tests for brief-drift detection (app.drift).

Drift = off-brief topic, kept but flagged. The prefilter is deterministic
(shared vocabulary); the verdict is one LLM batch call per few candidates.
Fail-open everywhere: failures mark nothing.
"""
import unittest

from app import drift as D


class TestDriftTokens(unittest.TestCase):
    def test_stopwords_and_short_tokens_dropped(self):
        self.assertEqual(D.content_tokens("AI models and the frontier"),
                         {"models", "frontier"})

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


class TestClassifyDrift(unittest.TestCase):
    def _cands(self, n):
        return [{"id": i, "title": f"item {i}", "tags": "x"} for i in range(n)]

    def test_batches_and_unions(self):
        import app.llm as llm_mod
        calls = []
        orig = llm_mod.chat_json

        def fake(*a, **k):
            calls.append(k)
            return {"drift_ids": [0]} if len(calls) == 1 else {"drift_ids": [8]}

        llm_mod.chat_json = fake
        try:
            out = D.classify_drift("brief", self._cands(10), batch=8)
        finally:
            llm_mod.chat_json = orig
        self.assertEqual(len(calls), 2)
        self.assertEqual(out, {0, 8})

    def test_unknown_ids_ignored(self):
        import app.llm as llm_mod
        orig = llm_mod.chat_json
        llm_mod.chat_json = lambda *a, **k: {"drift_ids": [1, 999, "x"]}
        try:
            out = D.classify_drift("brief", self._cands(3))
        finally:
            llm_mod.chat_json = orig
        self.assertEqual(out, {1})

    def test_llm_failure_marks_nothing(self):
        import app.llm as llm_mod
        orig = llm_mod.chat_json
        llm_mod.chat_json = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down"))
        try:
            out = D.classify_drift("brief", self._cands(2))
        finally:
            llm_mod.chat_json = orig
        self.assertEqual(out, set())

    def test_no_candidates_no_call(self):
        import app.llm as llm_mod
        orig = llm_mod.chat_json
        llm_mod.chat_json = lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not call"))
        try:
            out = D.classify_drift("brief", [])
        finally:
            llm_mod.chat_json = orig
        self.assertEqual(out, set())


if __name__ == "__main__":
    unittest.main()
