"""Yield-aware budget planning and event-triggered re-assessment (app.yield_).

The existing memory records what each query shape returned; these tests pin the
two decisions the memory should drive: how to *split a round budget* by yield
without starving a barren shape, and when changed conditions should *re-trigger*
an assessment rather than wait for a timer.
"""
import unittest
from datetime import UTC, datetime, timedelta

from app import yield_ as Y


def _stat(shape, y):
    return {"shape": shape, "yield": y, "example": shape, "attempts": 3}


class TestAllocateRounds(unittest.TestCase):
    def test_empty_is_empty(self):
        self.assertEqual(Y.allocate_rounds([], 5), [])
        self.assertEqual(Y.allocate_rounds([_stat("a", 0.5)], 0), [])

    def test_spends_exactly_the_budget(self):
        stats = [_stat("a", 0.5), _stat("b", 0.2), _stat("c", 0.0)]
        plan = Y.allocate_rounds(stats, 10)
        self.assertEqual(sum(p["rounds"] for p in plan), 10)

    def test_high_yield_gets_more_rounds(self):
        stats = [_stat("good", 0.6), _stat("bad", 0.01)]
        plan = {p["shape"]: p["rounds"] for p in Y.allocate_rounds(stats, 8)}
        self.assertGreater(plan["good"], plan["bad"])

    def test_barren_shape_is_not_starved(self):
        stats = [_stat("good", 0.9), _stat("dead", 0.0)]
        plan = {p["shape"]: p["rounds"] for p in Y.allocate_rounds(stats, 6)}
        self.assertGreaterEqual(plan["dead"], 1)

    def test_all_zero_yields_split_evenly(self):
        stats = [_stat("a", 0.0), _stat("b", 0.0), _stat("c", 0.0)]
        plan = {p["shape"]: p["rounds"] for p in Y.allocate_rounds(stats, 9)}
        self.assertEqual(set(plan.values()), {3})

    def test_revisit_floor_respected(self):
        stats = [_stat(f"s{i}", 0.1) for i in range(4)]
        plan = Y.allocate_rounds(stats, 8, revisit=2)
        self.assertTrue(all(p["rounds"] >= 2 for p in plan))
        self.assertEqual(sum(p["rounds"] for p in plan), 8)

    def test_sorted_by_allocation(self):
        stats = [_stat("a", 0.0), _stat("b", 0.9)]
        plan = Y.allocate_rounds(stats, 10)
        self.assertEqual(plan[0]["shape"], "b")


class TestStaleShapes(unittest.TestCase):
    def test_old_shapes_surface(self):
        now = datetime(2026, 1, 1, tzinfo=UTC)
        old = (now - timedelta(days=60)).isoformat()
        fresh = (now - timedelta(days=1)).isoformat()
        stats = [{"shape": "old", "last_seen_at": old},
                 {"shape": "fresh", "last_seen_at": fresh}]
        out = Y.stale_shapes(stats, now=now, max_age_days=30)
        self.assertEqual([s["shape"] for s in out], ["old"])

    def test_missing_timestamp_ignored(self):
        now = datetime(2026, 1, 1, tzinfo=UTC)
        self.assertEqual(Y.stale_shapes([{"shape": "x"}], now=now), [])


class TestReassessmentTriggers(unittest.TestCase):
    def test_no_change_does_not_trigger(self):
        r = Y.reassessment_triggers(drift_score=0.01, new_sources=1,
                                    days_since_run=2)
        self.assertFalse(r["triggered"])
        self.assertEqual(r["urgency"], "none")

    def test_drift_triggers(self):
        r = Y.reassessment_triggers(drift_score=0.5)
        self.assertTrue(r["triggered"])
        self.assertEqual(r["urgency"], "normal")

    def test_two_reasons_escalate(self):
        r = Y.reassessment_triggers(drift_score=0.5, new_sources=9)
        self.assertEqual(r["urgency"], "high")
        self.assertEqual(len(r["reasons"]), 2)

    def test_threat_pack_change_is_high(self):
        r = Y.reassessment_triggers(threat_pack_changed=True)
        self.assertTrue(r["triggered"])
        self.assertEqual(r["urgency"], "high")

    def test_custom_thresholds(self):
        r = Y.reassessment_triggers(drift_score=0.2,
                                    thresholds={"drift": 0.15})
        self.assertTrue(r["triggered"])


if __name__ == "__main__":
    unittest.main()
