"""Tests for evidence-aware applicability (agents.heuristic_applicability).

The control-analyst judges applicability before any evidence exists, so
without a re-judge every topic collapses to the 0.45 floor and every
assessment scores the same baseline. These tests pin: the floor, the
original vocabulary (unchanged), focus and evidence lifts, the finance
domain bridges, and the threat-intel merge rule (evidence confirms,
never acquits).
"""
import os
import tempfile
import unittest

# Pin the database before app.database is imported: a module that omits
# this can inherit data/akm.db and write test rows into the live store.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-applicability-"), "test.db"))

from app import agents  # noqa: E402

DIMS_FLOOR = 0.45


class TestHeuristicApplicability(unittest.TestCase):
    def test_empty_world_is_the_floor(self):
        app = agents.heuristic_applicability("Widget", "does things", [], [])
        self.assertEqual(len(app), 12)
        for tid, v in app.items():
            self.assertEqual(v, DIMS_FLOOR, tid)

    def test_original_vocabulary_unchanged(self):
        app = agents.heuristic_applicability(
            "Assistant", "employees paste prompts when drafting", [], [])
        # paste, prompt, employee, assistant = 4 hits -> capped at 1.0
        self.assertEqual(app["T01"], 1.0)
        self.assertEqual(app["T05"], DIMS_FLOOR)

    def test_focus_lifts(self):
        app = agents.heuristic_applicability("P", "u", [], ["customer"])
        for tid in ("T01", "T06"):
            self.assertGreater(app[tid], DIMS_FLOOR, tid)
        # customer alone says nothing about residency or robustness
        self.assertEqual(app["T11"], DIMS_FLOOR)
        self.assertEqual(app["T09"], DIMS_FLOOR)

    def test_evidence_lifts(self):
        ev = [{"artifact_id": 1, "title": "audit log review", "tags": "",
               "snippet": "who accessed the export provenance"}]
        app = agents.heuristic_applicability("P", "u", ev, [])
        self.assertGreater(app["T08"], DIMS_FLOOR)

    def test_finance_bridges(self):
        app = agents.heuristic_applicability(
            "Payments agent", "customer bank transfer PCI", [], [])
        for tid in ("T05", "T07", "T11", "T12"):
            self.assertGreater(app[tid], DIMS_FLOOR, tid)
        # unrelated pillars stay floored
        self.assertEqual(app["T09"], DIMS_FLOOR)
        self.assertEqual(app["T10"], DIMS_FLOOR)


def _intel_env(**kw):
    payload = {"evidence": [], "threat_ids": ["T05", "T08"],
               "declared_controls": [],
               "applicability": {"T05": 0.45, "T08": 0.45}}
    payload.update(kw)
    return {"from": "security-orchestrator", "task_id": "t",
            "trace": [], "payload": payload}


class TestThreatIntelRejudge(unittest.TestCase):
    def test_evidence_lifts_but_never_acquits(self):
        env = _intel_env(
            evidence=[{"artifact_id": 1, "title": "prompt injection incident",
                       "tags": "", "snippet": "injected instruction"}])
        out = agents.threat_intel_handle(env)["payload"]
        self.assertGreater(out["applicability"]["T05"], 0.45)
        self.assertEqual(out["applicability"]["T08"], 0.45)

    def test_higher_prior_survives(self):
        env = _intel_env(applicability={"T05": 0.9, "T08": 0.45},
                         evidence=[{"artifact_id": 1, "title": "x", "tags": "",
                                    "snippet": "injected instruction"}])
        out = agents.threat_intel_handle(env)["payload"]
        self.assertEqual(out["applicability"]["T05"], 0.9)

    def test_missing_context_defaults_hold(self):
        env = {"payload": {"evidence": [], "threat_ids": ["T01"],
                           "declared_controls": [],
                           "applicability": {"T01": 0.45}}}
        out = agents.threat_intel_handle(env)["payload"]
        self.assertEqual(out["applicability"]["T01"], 0.45)


if __name__ == "__main__":
    unittest.main()
