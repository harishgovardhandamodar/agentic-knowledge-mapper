"""Swarm governance: role contracts, policy enforcement and health.

Run with:  python3 -m pytest tests/test_swarm.py -q

The rules under test are the ones that make a multi-agent run auditable: a
scorer may not emit a residual it was not given the inputs for, an authority
cannot pass its own gate, and a dropped hop is visible rather than inferred
from a plausible-looking report.
"""
import os
import tempfile
import unittest

# Pinned before the app import: app.database reads the URL at import time, and
# a test run must never touch the developer's working database.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(
        tempfile.mkdtemp(prefix="akm-swarm-"), "test.db"))

from app import swarm as SW


def _ev(kind, actor="scorer", seq=0, **data):
    return {"kind": kind, "actor": actor, "seq": seq,
            "intent": kind.split(".")[-1], "data": data, "verdict": "allow",
            "severity": "info"}


class TestRoleContracts(unittest.TestCase):
    def test_every_agent_belongs_to_a_declared_swarm(self):
        for swarm, members in SW.SWARMS.items():
            self.assertTrue(members, swarm)
            for agent in members:
                self.assertEqual(SW.swarm_for_agent(agent), swarm, agent)

    def test_every_specialist_agent_has_a_role_contract(self):
        # An agent with no contract is counted but never judged: nothing was
        # declared about what success means for it.
        for swarm, members in SW.SWARMS.items():
            if swarm == "assessment":
                continue
            for agent in members:
                if agent.endswith("-orchestrator"):
                    continue
                self.assertIn(agent, SW.ROLE_CONTRACTS, agent)

    def test_an_unknown_role_is_not_contracted(self):
        self.assertFalse(SW.role_contract("nobody")["contracted"])

    def test_contracts_name_inputs_outputs_and_failure_behaviour(self):
        for role, c in SW.ROLE_CONTRACTS.items():
            self.assertTrue(c["responsibility"], role)
            self.assertTrue(c["requires"], role)
            self.assertTrue(c["produces"], role)
            self.assertTrue(c["on_failure"], role)

    def test_only_a_human_may_advance_past_a_gate(self):
        for role, c in SW.ROLE_CONTRACTS.items():
            if role in SW.GATE_AUTHORITIES:
                continue
            self.assertFalse(c["may_advance_past_gates"], role)

    def test_the_scorer_refuses_to_emit_a_residual_without_a_gate(self):
        self.assertIn("refuse", SW.ROLE_CONTRACTS["scorer"]["on_failure"])
        self.assertFalse(SW.ROLE_CONTRACTS["scorer"]["may_advance_past_gates"])

    def test_check_contract_names_what_is_missing(self):
        out = SW.check_contract("scorer", {})
        self.assertFalse(out["ok"])
        self.assertIn("architecture_gate_result", out["missing_inputs"])
        self.assertEqual(out["authority"], "blocked_by_gate")

    def test_check_contract_passes_with_the_required_inputs(self):
        c = SW.ROLE_CONTRACTS["scorer"]["requires"]
        out = SW.check_contract("scorer", {k: {"present": True} for k in c})
        self.assertTrue(out["ok"])
        self.assertEqual(out["missing_inputs"], [])


class TestPolicyEnforcementPoint(unittest.TestCase):
    CLEAN = dict(exposure="restricted_data",
                 architecture_gate={"gate_blocked_applied": False,
                                   "open_items": []},
                 evidence_gate={"gated_threats": [],
                                "min_accepted_per_threat": 3},
                 forensics={"reconstructable": True, "score": 100.0,
                            "max_score": 100.0, "band": "high"},
                 threat_pack_stale=False, min_evidence_confidence=0.5,
                 evidence_confidence=0.9)

    def test_a_clean_run_is_allowed_without_penalty(self):
        p = SW.policy_enforcement_point(**self.CLEAN)
        self.assertTrue(p["allowed"])
        self.assertEqual(p["decision"], "scorer_allowed")
        self.assertEqual(p["warnings"], [])
        self.assertEqual(p["confidence_penalty"], 0.0)
        self.assertTrue(all(c["passed"] for c in p["checks"]))

    def test_an_open_architecture_gate_blocks_the_scorer(self):
        args = dict(self.CLEAN, architecture_gate={
            "gate_blocked_applied": True, "open_items": ["retention_training"],
            "banner": "gap"})
        p = SW.policy_enforcement_point(**args)
        self.assertEqual(p["decision"], "scorer_blocked")
        self.assertIn("architecture_completeness", p["blocked_by"])

    def test_unreconstructable_forensics_warn(self):
        p = SW.policy_enforcement_point(
            **dict(self.CLEAN, forensics={"reconstructable": False, "score": 10.0}))
        self.assertIn("forensics_readiness", p["warnings"])

    def test_a_stale_threat_pack_warns(self):
        p = SW.policy_enforcement_point(**dict(self.CLEAN, threat_pack_stale=True))
        self.assertIn("threat_pack_currency", p["warnings"])

    def test_thin_evidence_warns(self):
        p = SW.policy_enforcement_point(
            **dict(self.CLEAN, evidence_gate={"gated_threats": ["T02"]}))
        self.assertIn("evidence_threshold", p["warnings"])

    def test_low_confidence_warns_and_penalises_rather_than_blocking(self):
        p = SW.policy_enforcement_point(
            **dict(self.CLEAN, evidence_confidence=0.2))
        self.assertTrue(p["allowed"])
        self.assertIn("evidence_confidence_floor", p["warnings"])
        self.assertEqual(p["decision"], "scorer_allowed_with_confidence_penalty")
        self.assertGreater(p["confidence_penalty"], 0.0)

    def test_the_policy_point_is_the_only_place_a_scorer_can_advance(self):
        c = SW.ROLE_CONTRACTS["scorer"]
        self.assertFalse(c["may_advance_past_gates"])
        self.assertTrue(SW.GATE_AUTHORITIES)


class TestTopology(unittest.TestCase):
    def test_spawned_and_completed_roles_are_separated(self):
        events = [
            _ev("assurance.swarm_spawn", "orchestrator", 0, role="orchestrator",
                phase="spawn"),
            _ev("assurance.swarm_spawn", "scorer", 1, role="scorer",
                phase="spawn"),
            _ev("assurance.swarm_complete", "scorer", 2, role="scorer",
                phase="complete"),
        ]
        t = SW.topology(events)
        self.assertEqual(t["complete"], ["scorer"])
        # A completed role is not also pending: double-counting it made a
        # finished run look unfinished.
        # pending = never started; active = started, not finished. Collapsing
        # the two would hide a run that stalled mid-flight.
        self.assertNotIn("scorer", t["pending"])
        self.assertNotIn("orchestrator", t["pending"])
        active = [r["role"] for r in t["roles"] if r["state"] == "active"]
        self.assertEqual(active, ["orchestrator"])

    def test_a_failed_role_is_pending_not_complete(self):
        events = [
            _ev("assurance.swarm_spawn", "scorer", 0, role="scorer",
                phase="spawn"),
            _ev("assurance.swarm_failure", "scorer", 1, role="scorer",
                phase="failure"),
        ]
        t = SW.topology(events)
        self.assertNotIn("scorer", t["complete"])

    def test_an_empty_run_never_looks_complete(self):
        # Every contracted role stays outstanding: absence of events is not
        # evidence that a role ran.
        t = SW.topology([])
        self.assertEqual(t["complete"], [])
        self.assertEqual(sorted(t["pending"]), sorted(SW.ROLE_CONTRACTS))

    def test_a_role_with_no_contract_is_flagged_uncontracted(self):
        t = SW.topology([_ev("assurance.swarm_spawn", "mystery-agent", 0,
                            role="mystery-agent", phase="spawn")])
        self.assertIn("mystery-agent", t["uncontracted"])


class TestHealth(unittest.TestCase):
    def test_success_rate_is_completions_over_attempts(self):
        events = [
            _ev("assurance.swarm_spawn", "scorer", 0, role="scorer",
                phase="spawn"),
            _ev("assurance.swarm_complete", "scorer", 1, role="scorer",
                phase="complete"),
            _ev("assurance.swarm_spawn", "scorer", 2, role="scorer",
                phase="spawn"),
            _ev("assurance.swarm_failure", "scorer", 3, role="scorer",
                phase="failure"),
        ]
        h = SW.health(events)
        self.assertEqual(h["hops"], 2)
        self.assertEqual(h["failures"], 1)
        self.assertEqual(h["overall_success_rate"], 0.5)

    def test_gate_failures_are_counted_separately_from_ordinary_ones(self):
        events = [
            _ev("assurance.swarm_spawn", "scorer", 0, role="scorer",
                phase="spawn"),
            _ev("assurance.swarm_failure", "scorer", 1, role="scorer",
                phase="failure", policy={"decision": "scorer_blocked"}),
            _ev("assurance.swarm_spawn", "scorer", 2, role="scorer",
                phase="spawn"),
            _ev("assurance.swarm_failure", "scorer", 3, role="scorer",
                phase="failure", policy={"decision": "scorer_allowed"}),
        ]
        h = SW.health(events)
        self.assertEqual(h["failures"], 2)
        self.assertEqual(h["gate_failures"], 1)
        # A gate that blocks is the system working; folding it into one rate
        # with ordinary flakiness hid that.
        self.assertEqual(h["gate_failure_rate"], 0.5)
        self.assertEqual(h["overall_success_rate"], 0.0)

    def test_no_events_is_no_health_claim_not_a_perfect_run(self):
        h = SW.health([])
        self.assertEqual(h["hops"], 0)
        self.assertIsNone(h["overall_success_rate"])


class TestMcpMapping(unittest.TestCase):
    def test_an_unknown_intent_maps_to_nothing(self):
        self.assertIsNone(SW.mcp_for_intent("nonexistent.intent"))


def _swarm_evs(roles=None):
    """A plausible partial run: planner spawned, some roles completed, one
    in flight, none failed -- the shape a restart would resume."""
    evs = []
    seq = 0
    for role, phase in (roles or [
        ("orchestrator", "spawn"), ("orchestrator", "complete"),
        ("research-collector", "spawn"), ("research-collector", "complete"),
        ("threat-intel", "spawn"), ("control-analyst", "spawn"),
    ]):
        evs.append(_ev(f"assurance.swarm_{phase}", role, seq, role=role,
                       phase=phase))
        seq += 1
    return evs


class TestResumeFromLedger(unittest.TestCase):
    def test_resume_state_rebuilds_roles_and_next_phase(self):
        st = SW.resume_state(_swarm_evs())
        self.assertIn("orchestrator", st["completed"])
        self.assertIn("research-collector", st["completed"])
        # control-analyst spawned but never completed -> must be resumed
        self.assertIn("control-analyst", st["resume_these"])
        self.assertTrue(st["restartable"])
        self.assertEqual(st["phase"], "collect")

    def test_a_completed_run_is_not_restartable(self):
        evs = _swarm_evs() + [
            _ev("assurance.swarm_complete", "control-analyst", 99,
                role="control-analyst", phase="complete"),
            {"kind": "assurance.lifecycle.complete", "actor": "orchestrator",
             "seq": 100, "intent": "lifecycle.complete",
             "data": {"phase": "complete"}, "verdict": "allow",
             "severity": "info"},
        ]
        st = SW.resume_state(evs)
        self.assertFalse(st["restartable"])
        self.assertEqual(st["phase"], "completed")

    def test_an_empty_ledger_has_nothing_to_resume(self):
        st = SW.resume_state([])
        self.assertFalse(st["restartable"])
        self.assertEqual(st["events"], 0)

    def test_a_failed_role_is_settled_not_resumed(self):
        evs = _swarm_evs([("scorer", "spawn"), ("scorer", "failure")])
        st = SW.resume_state(evs)
        self.assertIn("scorer", st["completed"])
        self.assertNotIn("scorer", st["resume_these"])


class TestTypedHandoff(unittest.TestCase):
    def test_a_valid_handoff_passes_the_schema(self):
        msg = {"run_id": "akm-run-1", "parent_event": "abc",
               "from_role": "research-collector", "to_role": "threat-intel",
               "model_version": "qwen3.8:27b", "confidence": 0.8,
               "input_refs": ["h1"]}
        check = SW.validate_handoff(msg)
        self.assertTrue(check["ok"])
        self.assertEqual(check["missing"], [])

    def test_a_handoff_missing_lineage_is_rejected(self):
        check = SW.validate_handoff({"run_id": "akm-run-1",
                                    "from_role": "a", "to_role": "b"})
        self.assertFalse(check["ok"])
        self.assertIn("parent_event", check["missing"])
        self.assertIn("model_version", check["missing"])
        self.assertIn("lineage edge", check["reasons"]["parent_event"])

    def test_record_typed_handoff_writes_a_lineage_event(self):
        import os
        from app.database import init_db, SessionLocal
        from app import assurance_ledger as AL
        init_db()
        msg = {"run_id": "akm-run-typed", "parent_event": "p1",
               "from_role": "research-collector", "to_role": "threat-intel",
               "model_version": "m1", "confidence": 0.8}
        h = SW.record_typed_handoff("akm-run-typed", msg)
        self.assertIsNotNone(h)
        db = SessionLocal()
        try:
            rep = AL.integrity_report("akm-run-typed", db=db)
            self.assertTrue(rep["chain_intact"])
        finally:
            db.close()

    def test_record_typed_handoff_refuses_an_invalid_message(self):
        self.assertIsNone(SW.record_typed_handoff(
            "akm-run-typed2", {"from_role": "a"}))


class TestCriticReview(unittest.TestCase):
    def test_a_blocking_absence_is_a_critic_finding(self):
        # only one role spawned -> SWARM-HOP-DROPPED is a block finding
        evs = [_ev("assurance.swarm_spawn", "orchestrator", 0,
                   role="orchestrator", phase="spawn")]
        out = SW.critic_review(events=evs)
        self.assertFalse(out["clean"])
        self.assertTrue(any(f["id"] == "SWARM-HOP-DROPPED"
                            for f in out["findings"]))

    def test_a_reduction_with_no_attestation_is_flagged(self):
        out = SW.critic_review(assurance={
            "declared": {"residual_pct": 20.0},
            "verified": {"residual_pct": 55.0},
            "control_attestation": {}})
        self.assertTrue(any(f["id"] == "REDUCTION-WITHOUT-ATTESTATION"
                            for f in out["findings"]))

    def test_a_clean_run_is_clean(self):
        out = SW.critic_review(assurance={
            "declared": {"residual_pct": 35.4},
            "verified": {"residual_pct": 35.4},
            "control_attestation": {"C1": {"status": "evidenced"}},
            "architecture_gate": {"complete": True,
                                  "gate_blocked_applied": False}})
        self.assertTrue(out["clean"])

    def test_a_contradictory_gate_is_flagged(self):
        out = SW.critic_review(assurance={
            "architecture_gate": {"complete": True,
                                  "gate_blocked_applied": True}})
        self.assertTrue(any(f["id"] == "GATE-CONTRADICTION"
                            for f in out["findings"]))


class TestRateAndScopeControl(unittest.TestCase):
    def test_a_source_outside_the_allow_list_is_denied(self):
        out = SW.check_scope("web-search", source="evil.example.com",
                             allowed_sources=["arxiv.org", "github.com"])
        self.assertFalse(out["allowed"])
        self.assertEqual(out["verdict"], "deny")
        self.assertIn("not in allow-list", out["reason"])

    def test_an_allowed_source_passes(self):
        out = SW.check_scope("web-search", source="arxiv.org",
                             allowed_sources=["arxiv.org"])
        self.assertTrue(out["allowed"])

    def test_an_empty_allow_list_denies_nothing(self):
        out = SW.check_scope("web-search", source="anything.com")
        self.assertTrue(out["allowed"])
        self.assertEqual(out["reason"], "allow-list empty")

    def test_budget_allows_under_the_limits(self):
        out = SW.budget_allows({"queries": 10, "tokens": 1000, "minutes": 5})
        self.assertTrue(out["allowed"])
        self.assertEqual(out["verdict"], "allow")

    def test_budget_denies_when_a_limit_is_exceeded(self):
        out = SW.budget_allows({"queries": 500},
                               budget={"queries": 200})
        self.assertFalse(out["allowed"])
        self.assertEqual(out["exceeded"], ["queries"])
        self.assertEqual(out["verdict"], "deny")


if __name__ == "__main__":
    unittest.main()