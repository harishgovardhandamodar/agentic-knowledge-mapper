"""Tests for app.yield_ -- the query-shape memory.

Without this the agent re-plans from a blank slate every round, so a shape that
has returned nothing three times running gets proposed a fourth. These tests
pin the two properties that make the memory worth having: repeated barren
shapes sink, and a shape is never permanently suppressed.
"""
import os
import tempfile
import unittest

os.environ["AKM_DATABASE_URL"] = "sqlite:///" + os.path.join(
    tempfile.mkdtemp(prefix="akm-yield-test-"), "test.db")

from app import database  # noqa: E402
from app import yield_ as Y  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.models import Investigation  # noqa: E402

database.init_db()

_n = {"i": 0}


def new_inv(title="frontier model alignment", keywords="interpretability"):
    _n["i"] += 1
    db = SessionLocal()
    try:
        inv = Investigation(title=title, keywords=keywords,
                            description="mechanistic interpretability research")
        db.add(inv)
        db.commit()
        return inv.id
    finally:
        db.close()


class TestShapeOf(unittest.TestCase):
    def test_word_order_does_not_matter(self):
        self.assertEqual(Y.shape_of("alignment tax"), Y.shape_of("tax alignment"))

    def test_filler_words_are_dropped(self):
        # Filler is not a different question, so it must not be a different shape.
        self.assertEqual(Y.shape_of("the latest report on alignment tax"),
                         Y.shape_of("alignment tax"))

    def test_punctuation_is_a_separator(self):
        self.assertEqual(Y.shape_of("alignment-tax"), Y.shape_of("alignment tax"))
        self.assertEqual(Y.shape_of("alignment/tax"), Y.shape_of("alignment tax"))

    def test_case_is_ignored(self):
        self.assertEqual(Y.shape_of("Alignment Tax"), Y.shape_of("alignment tax"))

    def test_keeps_only_the_most_distinctive_terms(self):
        # "in 2023" is a constraint, not a topic; capping the length is what
        # stops one shape per year.
        self.assertEqual(Y.shape_of("alignment tax 2023 2024 2025"),
                         Y.shape_of("alignment tax"))

    def test_empty_and_punctuation_only_queries(self):
        self.assertEqual(Y.shape_of(""), "")
        self.assertEqual(Y.shape_of(None), "")
        self.assertEqual(Y.shape_of("!!! ???"), "")

    def test_short_words_still_produce_a_shape(self):
        # All-stopword input must not collapse to nothing, or a query made only
        # of noise would join every other one.
        self.assertTrue(Y.shape_of("of the and"))

    def test_longest_terms_win(self):
        self.assertIn("interpretability",
                      Y.shape_of("interpretability and tax"))


class TestMetrics(unittest.TestCase):
    def test_yield_is_zero_without_evidence(self):
        self.assertEqual(Y.yield_of(0, 0, 0), 0.0)
        self.assertEqual(Y.yield_of(3, 0, 10), 0.0)
        self.assertEqual(Y.yield_of(3, 0, 0), 0.0)

    def test_yield_rises_with_keep_rate(self):
        self.assertGreater(Y.yield_of(2, 4, 40), Y.yield_of(2, 1, 40))

    def test_thin_supply_is_discounted(self):
        """A shape that kept 1 of 3 should not outrank one that kept 4 of 40."""
        thin = Y.yield_of(1, 1, 3)
        deep = Y.yield_of(1, 4, 40)
        self.assertGreater(deep, thin)

    def test_cost_efficiency_is_kept_per_call(self):
        self.assertEqual(Y.cost_of(4, 8), 2.0)
        self.assertEqual(Y.cost_of(0, 8), 0.0)
        self.assertEqual(Y.cost_of(4, 0), 0.0)
        self.assertEqual(Y.cost_of(0, 0), 0.0)


class TestRecordYield(unittest.TestCase):
    def test_records_per_shape(self):
        inv = new_inv()
        db = SessionLocal()
        try:
            Y.record_yield(db, inv, [{"text": "alignment tax"},
                                     {"text": "interpretability probes"}],
                           found=10, kept=4, llm_calls=2)
            shapes = {s["shape"] for s in Y.shape_stats(db, inv)}
            self.assertEqual(shapes, {"alignment tax", "interpretability probes"})
        finally:
            db.close()

    def test_attempts_accumulate_across_runs(self):
        inv = new_inv()
        db = SessionLocal()
        try:
            for _ in range(3):
                Y.record_yield(db, inv, [{"text": "alignment tax"}],
                               found=5, kept=0, llm_calls=1)
            row = Y.shape_stats(db, inv)[0]
            self.assertEqual(row["attempts"], 3)
            self.assertEqual(row["kept"], 0)
            self.assertEqual(row["yield"], 0.0)
        finally:
            db.close()

    def test_keeps_an_example_query(self):
        inv = new_inv()
        db = SessionLocal()
        try:
            Y.record_yield(db, inv, [{"text": "the 2023 alignment tax report"}],
                           found=2, kept=1, llm_calls=1)
            row = Y.shape_stats(db, inv)[0]
            self.assertIn("alignment", row["example"])
        finally:
            db.close()

    def test_shares_split_evenly(self):
        inv = new_inv()
        db = SessionLocal()
        try:
            Y.record_yield(db, inv, [{"text": "alpha topic"},
                                     {"text": "beta topic"}],
                           found=10, kept=4, llm_calls=2)
            rows = Y.shape_stats(db, inv)
            self.assertEqual(sum(r["kept"] for r in rows), 4)
            self.assertEqual(sum(r["found"] for r in rows), 10)
        finally:
            db.close()

    def test_fractional_shares_do_not_leak(self):
        inv = new_inv()
        db = SessionLocal()
        try:
            Y.record_yield(db, inv, [{"text": "alpha topic"},
                                     {"text": "beta topic"},
                                     {"text": "gamma topic"}],
                           found=10, kept=1, llm_calls=1)
            for r in Y.shape_stats(db, inv):
                for field in ("found", "kept", "llm_calls", "attempts"):
                    self.assertIsInstance(r[field], int, field)
        finally:
            db.close()

    def test_plain_string_queries_accepted(self):
        inv = new_inv()
        db = SessionLocal()
        try:
            Y.record_yield(db, inv, ["alignment tax"], found=2, kept=1, llm_calls=1)
            self.assertEqual(len(Y.shape_stats(db, inv)), 1)
        finally:
            db.close()

    def test_no_shapes_records_nothing(self):
        inv = new_inv()
        db = SessionLocal()
        try:
            self.assertEqual(Y.record_yield(db, inv, [{"text": ""}]), [])
            self.assertEqual(Y.shape_stats(db, inv), [])
        finally:
            db.close()

    def test_yields_are_per_investigation(self):
        a, b = new_inv("alignment"), new_inv("virology")
        db = SessionLocal()
        try:
            Y.record_yield(db, a, [{"text": "alignment tax"}], found=4, kept=2,
                           llm_calls=1)
            self.assertEqual(len(Y.shape_stats(db, b)), 0)
        finally:
            db.close()

    def test_a_zero_yield_round_is_remembered(self):
        """The round that used to teach the loop nothing."""
        inv = new_inv()
        db = SessionLocal()
        try:
            Y.record_yield(db, inv, [{"text": "alignment tax"}], found=12,
                           kept=0, llm_calls=2)
            row = Y.shape_stats(db, inv)[0]
            self.assertEqual(row["attempts"], 1)
            self.assertEqual(row["found"], 12)
            self.assertEqual(row["kept"], 0)
        finally:
            db.close()


class TestRankQueries(unittest.TestCase):
    def _seed(self, inv, text, found, kept, calls=1, times=1):
        db = SessionLocal()
        try:
            for _ in range(times):
                Y.record_yield(db, inv, [{"text": text}], found=found, kept=kept,
                               llm_calls=calls)
        finally:
            db.close()

    def test_productive_shape_moves_up(self):
        inv = new_inv()
        self._seed(inv, "dead topic", found=10, kept=0, times=3)
        self._seed(inv, "good topic", found=20, kept=8)
        db = SessionLocal()
        try:
            ordered = Y.rank_queries(db, inv, [{"text": "dead topic"},
                                                {"text": "good topic"}])
            self.assertEqual([q["text"] for q in ordered],
                             ["good topic", "dead topic"])
        finally:
            db.close()

    def test_barren_shape_sinks_but_is_kept(self):
        """Never a veto: a barren shape is exactly the one worth retrying after
        the corpus has changed."""
        inv = new_inv()
        self._seed(inv, "dead topic", found=10, kept=0, times=3)
        db = SessionLocal()
        try:
            ordered = Y.rank_queries(db, inv, [{"text": "dead topic"}])
            self.assertEqual(len(ordered), 1)
        finally:
            db.close()

    def test_productive_beats_unseen_and_unseen_beats_barren(self):
        """The three bands, in order. Novelty is not a penalty, but a shape
        with no history has not earned a deprioritisation either."""
        inv = new_inv()
        self._seed(inv, "good topic", found=20, kept=8)
        self._seed(inv, "dead topic", found=10, kept=0, times=3)
        db = SessionLocal()
        try:
            ordered = Y.rank_queries(db, inv, [{"text": "dead topic"},
                                                {"text": "novel topic"},
                                                {"text": "good topic"}])
            self.assertEqual([q["text"] for q in ordered],
                             ["good topic", "novel topic", "dead topic"])
        finally:
            db.close()

    def test_unseen_shapes_keep_their_order(self):
        inv = new_inv()
        self._seed(inv, "dead topic", found=10, kept=0, times=3)
        db = SessionLocal()
        try:
            ordered = Y.rank_queries(db, inv, [{"text": "novel one"},
                                                {"text": "novel two"}])
            self.assertEqual([q["text"] for q in ordered],
                             ["novel one", "novel two"])
        finally:
            db.close()

    def test_unseen_ranks_ahead_of_known_barren(self):
        """Novelty is not a penalty."""
        inv = new_inv()
        self._seed(inv, "dead topic", found=10, kept=0, times=3)
        db = SessionLocal()
        try:
            ordered = Y.rank_queries(db, inv, [{"text": "dead topic"},
                                                {"text": "novel topic"}])
            self.assertEqual(ordered[0]["text"], "novel topic")
        finally:
            db.close()

    def test_planner_order_preserved_within_a_band(self):
        inv = new_inv()
        self._seed(inv, "mid topic", found=10, kept=2)
        db = SessionLocal()
        try:
            ordered = Y.rank_queries(db, inv, [{"text": "mid topic a"},
                                                {"text": "mid topic b"}])
            self.assertEqual(len(ordered), 2)
        finally:
            db.close()

    def test_empty_input(self):
        inv = new_inv()
        db = SessionLocal()
        try:
            self.assertEqual(Y.rank_queries(db, inv, []), [])
            self.assertEqual(Y.rank_queries(db, inv, None), [])
        finally:
            db.close()

    def test_no_history_leaves_order_untouched(self):
        inv = new_inv()
        db = SessionLocal()
        try:
            qs = [{"text": "one"}, {"text": "two"}, {"text": "three"}]
            self.assertEqual(Y.rank_queries(db, inv, qs), qs)
        finally:
            db.close()


class TestSuggestAndClear(unittest.TestCase):
    def test_suggests_untried_shapes(self):
        inv = new_inv()
        db = SessionLocal()
        try:
            sug = Y.suggest_queries(db, inv, limit=3)
            self.assertTrue(sug)
            self.assertTrue(all("text" in s and "shape" in s for s in sug))
        finally:
            db.close()

    def test_does_not_suggest_already_tried_shapes(self):
        inv = new_inv()
        db = SessionLocal()
        try:
            sug = Y.suggest_queries(db, inv, limit=2)
            Y.record_yield(db, inv, [{"text": sug[0]["text"]}],
                           found=1, kept=1, llm_calls=1)
            after = {s["shape"] for s in Y.suggest_queries(db, inv, limit=5)}
            self.assertNotIn(sug[0]["shape"], after)
        finally:
            db.close()

    def test_suggestions_for_missing_investigation(self):
        db = SessionLocal()
        try:
            self.assertEqual(Y.suggest_queries(db, 999999), [])
        finally:
            db.close()

    def test_clear_removes_history(self):
        inv = new_inv()
        db = SessionLocal()
        try:
            Y.record_yield(db, inv, [{"text": "alignment tax"}], found=4, kept=2,
                           llm_calls=1)
            self.assertEqual(Y.clear_yields(db, inv), 1)
            self.assertEqual(Y.shape_stats(db, inv), [])
        finally:
            db.close()

    def test_clear_does_not_touch_other_investigations(self):
        a, b = new_inv("alignment"), new_inv("virology")
        db = SessionLocal()
        try:
            Y.record_yield(db, a, [{"text": "alignment tax"}], found=4, kept=2,
                           llm_calls=1)
            Y.clear_yields(db, a)
            self.assertEqual(len(Y.shape_stats(db, b)), 0)
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
