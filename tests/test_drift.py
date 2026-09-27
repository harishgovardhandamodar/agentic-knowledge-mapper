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
