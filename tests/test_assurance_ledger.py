"""The assurance ledger: hash chaining, completeness and absence monitoring.

Run with:  python3 -m pytest tests/test_assurance_ledger.py -q

Two separate claims are tested here, because conflating them is the usual way
an audit fabric gets over-claimed:

- **integrity** -- nothing already recorded was edited (the hash chain)
- **completeness** -- the events that should have happened actually did

An intact chain says nothing about the second. The module therefore reports
both, and the tests pin that distinction.
"""
import json
import os
import tempfile
import unittest

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(
        tempfile.mkdtemp(prefix="akm-al-"), "test.db"))

from app import assurance_ledger as AL  # noqa: E402
from app import ledger as lg  # noqa: E402
from app.database import SessionLocal, init_db  # noqa: E402

init_db()

ASSURANCE = {
    "assessed": True,
    "evidence_confidence": 0.31,
    "declared": {"residual_pct": 35.4},
    "verified": {"residual_pct": 62.7},
    "headline_layer": "verified",
    "control_attestation": {"MDR-AI-001": {"status": "declared",
                                           "evidence_ids": []}},
    "architecture_gate": {"gate_blocked_applied": True,
                          "open_items": ["no-logging"], "items": []},
    "evidence_gate": {"gated_threats": ["T02"]},
    "forensics": {"reconstructable": False, "score": 21.0},
    "blast_radius": {"quantified": False},
    "gates_open": ["evidence_threshold"],
    "decision": {"decision": "reject_until_architecture_gate_closed"},
}


class TestEventKinds(unittest.TestCase):
    def test_every_kind_the_recorders_emit_is_known(self):
        # A kind outside this set is evaluated by the gate as an external
        # action, so recording an assurance event would itself need a mandate.
        for kind in ("assurance.model_context", "assurance.decision",
                     "assurance.exception", "assurance.swarm_spawn",
                     "assurance.swarm_handoff", "assurance.swarm_complete",
                     "assurance.swarm_failure"):
            self.assertIn(kind, AL.ASSURANCE_KINDS, kind)

    def test_assurance_kinds_are_never_gated(self):
        for kind in AL.ASSURANCE_KINDS:
            self.assertIn(kind, lg.INTERNAL_KINDS, kind)

    def test_model_prompt_context_class_counts_its_own_event(self):
        self.assertIn("assurance.model_context",
                      AL._CLASS_KINDS["model_prompt_context"])


class TestRecording(unittest.TestCase):
    def _run(self, name):
        return f"akm-run-al-{name}"

    def test_record_assurance_writes_one_event_per_gate(self):
        run = self._run("gates")
        out = AL.record_assurance(run, ASSURANCE, assessment_id=1,
                                  product="copilot",
                                  exposure="restricted_data")
        self.assertTrue(out["recorded"])
        self.assertEqual(out["unrecorded"], [])
        for gate in ("control_attestation", "architecture_gate", "evidence_gate",
                     "score", "forensics", "blast_radius", "decision"):
            self.assertTrue(out["hashes"].get(gate), gate)
        kinds = {e["kind"] for e in AL._load_events(run)}
        self.assertIn("assurance.score", kinds)
        self.assertIn("assurance.architecture_gate", kinds)

    def test_chain_links_every_event(self):
        run = self._run("chain")
        AL.record_assurance(run, ASSURANCE, assessment_id=2)
        events = AL._load_events(run)
        self.assertGreater(len(events), 1)
        for ev in events[1:]:
            self.assertTrue(ev.get("prev_hash"))
        self.assertTrue(lg.verify_chain(run)["ok"])

    def test_an_untampered_run_reports_an_intact_chain(self):
        # Regression: integrity_report read chain.get("intact"), but
        # verify_chain answers under "ok", so this flag was False on every
        # healthy chain -- an inverted headline on an assurance artifact.
        run = "akm-run-al-intact"
        AL.record_assurance(run, ASSURANCE, assessment_id=11)
        rep = AL.integrity_report(run)
        self.assertTrue(rep["chain_intact"])
        self.assertTrue(rep["chain"]["ok"])

    def test_a_broken_chain_is_named_in_the_verdict(self):
        run = "akm-run-al-broken"
        AL.record_assurance(run, ASSURANCE, assessment_id=12)
        db = SessionLocal()
        try:
            row = (db.query(lg.LedgerEvent)
                   .filter(lg.LedgerEvent.run_id == run)
                   .order_by(lg.LedgerEvent.seq.desc()).first())
            import json as _json
            row.data_json = _json.dumps({"injected": True})
            db.commit()
        finally:
            db.close()
        rep = AL.integrity_report(run)
        self.assertFalse(rep["chain_intact"])
        self.assertEqual(rep["verdict"], "chain_broken")

    def test_a_tampered_event_breaks_the_chain(self):
        run = self._run("tamper")
        AL.record_assurance(run, ASSURANCE, assessment_id=3)
        before = AL.integrity_report(run)
        self.assertTrue(before["chain_intact"])
        # Edit a recorded event through the model, as a database edit would.
        db = SessionLocal()
        try:
            row = (db.query(lg.LedgerEvent).filter(lg.LedgerEvent.run_id == run)
                   .order_by(lg.LedgerEvent.seq.desc()).first())
            self.assertIsNotNone(row)
            import json as _json
            row.data_json = _json.dumps({"injected": True})
            db.commit()
        finally:
            db.close()
        after = AL.integrity_report(run)
        self.assertFalse(after["chain_intact"])
        self.assertTrue(any(f.get("issue") == "content_tampered"
                            for f in after["chain"]["findings"]))

    def test_human_decision_records_identity_and_rationale(self):
        run = self._run("decision")
        h = AL.record_human_decision(run, actor="ciso@example.com",
                                     decision="exception", assessment_id=9,
                                     rationale="SIEM pending", expires_at="soon")
        self.assertTrue(h)
        ev = [e for e in AL._load_events(run)
              if e["kind"] == "assurance.exception"][0]
        self.assertEqual(ev["actor"], "ciso@example.com")
        self.assertEqual(ev["data"]["rationale"], "SIEM pending")
        self.assertEqual(ev["actor_type"], "human")

    def test_an_override_is_recorded_as_a_warning(self):
        run = self._run("override")
        AL.record_human_decision(run, actor="ciso", decision="accept",
                                 assessment_id=10, override=True)
        ev = AL._load_events(run)[0]
        self.assertEqual(ev["severity"], "warn")

    def test_prompt_fingerprint_hashes_without_storing_content(self):
        run = self._run("prompt")
        out = AL.record_prompt_fingerprint(
            run, actor="report-writer", model="gpt-x",
            prompt="SENSITIVE patient note", context="MORE SENSITIVE context")
        self.assertTrue(out["prompt_hash"])
        self.assertTrue(out["context_hash"])
        blob = repr(AL._load_events(run))
        # The point of hashing: the fabric is immutable, so storing the prompt
        # would make a permanent copy of whatever it handled.
        self.assertNotIn("SENSITIVE patient note", blob)
        self.assertEqual(out["prompt_chars"], len("SENSITIVE patient note"))

    def test_identical_prompts_hash_identically_across_runs(self):
        a = AL.record_prompt_fingerprint(self._run("p1"), actor="a", model="m",
                                         prompt="same text")
        b = AL.record_prompt_fingerprint(self._run("p2"), actor="a", model="m",
                                         prompt="same text")
        self.assertEqual(a["prompt_hash"], b["prompt_hash"])

    def test_swarm_lifecycle_events_are_recorded(self):
        run = self._run("swarm")
        AL.record_swarm_event(run, role="orchestrator", phase="spawn")
        AL.record_swarm_event(run, role="scorer", phase="handoff")
        AL.record_swarm_event(run, role="scorer", phase="complete")
        kinds = [e["kind"] for e in AL._load_events(run)]
        self.assertIn("assurance.swarm_spawn", kinds)
        self.assertIn("assurance.swarm_handoff", kinds)
        self.assertIn("assurance.swarm_complete", kinds)

    def test_a_swarm_failure_is_a_blocking_event(self):
        run = self._run("swarm-fail")
        AL.record_swarm_event(run, role="scorer", phase="failure",
                              error="policy gate closed")
        ev = AL._load_events(run)[0]
        self.assertEqual(ev["kind"], "assurance.swarm_failure")
        self.assertEqual(ev["severity"], "block")
        self.assertEqual(ev["verdict"], "deny")

    def test_recording_survives_a_missing_ledger(self):
        # An assurance view that must render without a database is still worth
        # computing; the missing events are what integrity_report looks for.
        out = AL.record_assurance("akm-run-nonexistent-db", ASSURANCE)
        self.assertIsInstance(out, dict)


class TestDecisionSeverity(unittest.TestCase):
    def test_a_rejection_is_a_blocking_event(self):
        # Regression: the severity used to compare against a string literal,
        # so a rejection logged severity=info beside verdict=block -- the one
        # event a monitoring query must not miss.
        from app import assurance as A
        run = "akm-run-al-severity"
        AL.record_assurance(run, {
            "assessed": True, "evidence_confidence": 0.2,
            "control_attestation": {},
            "architecture_gate": {"complete": True, "open_items": [], "items": []},
            "evidence_gate": {"gated_threats": []},
            "forensics": {}, "blast_radius": {},
            "decision": {"decision": A.DECISION_REJECT}}, assessment_id=7)
        ev = [e for e in AL._load_events(run)
              if e["kind"] == "assurance.decision"][0]
        self.assertEqual(ev["severity"], "block")
        self.assertEqual(ev["verdict"], "block")

    def test_an_acceptance_is_informational(self):
        from app import assurance as A
        run = "akm-run-al-severity-ok"
        AL.record_assurance(run, {
            "assessed": True, "evidence_confidence": 0.9,
            "control_attestation": {},
            "architecture_gate": {"complete": True, "open_items": [], "items": []},
            "evidence_gate": {"gated_threats": []},
            "forensics": {}, "blast_radius": {},
            "decision": {"decision": A.DECISION_ACCEPT}}, assessment_id=8)
        ev = [e for e in AL._load_events(run)
              if e["kind"] == "assurance.decision"][0]
        self.assertEqual(ev["severity"], "info")
        self.assertEqual(ev["verdict"], "allow")


class TestCompleteness(unittest.TestCase):
    def test_coverage_reports_recorded_and_missing_classes(self):
        cov = AL.class_coverage([
            {"kind": "assurance.score", "actor": "a", "data": {}, "seq": 0},
            {"kind": "assurance.architecture_gate", "actor": "a", "data": {},
             "seq": 1},
        ])
        self.assertTrue(cov["classes"]["architecture_gate"]["recorded"])
        self.assertEqual(cov["classes"]["architecture_gate"]["count"], 1)
        self.assertFalse(cov["classes"]["human_decision"]["recorded"])
        self.assertIn("human_decision", cov["missing"])
        self.assertEqual(cov["recorded"], 2)
        self.assertFalse(cov["complete"])
        # The question each class answers travels with the gap, so a reader can
        # see what the run never claimed.
        self.assertTrue(cov["classes"]["human_decision"]["question"])

    def test_coverage_lists_every_mandatory_class(self):
        cov = AL.class_coverage([])
        self.assertEqual(set(cov["classes"]), set(AL.MANDATORY_EVENT_CLASSES))
        self.assertEqual(cov["completeness_pct"], 0)

    def test_absent_classes_raise_an_absence_alert(self):
        alerts = AL.absence_alerts([{"kind": "assurance.score", "actor": "a",
                                      "data": {}, "seq": 0}])
        self.assertTrue(alerts)
        self.assertTrue(all("why_it_matters" in a for a in alerts))

    def test_a_scored_run_with_no_gate_is_flagged(self):
        alerts = AL.absence_alerts([{"kind": "assurance.score", "actor": "a",
                                      "data": {}, "seq": 0}])
        blocking = [a for a in alerts if a.get("severity") == "block"]
        self.assertTrue(blocking)
        # The most consequential absence: a score nobody gated.
        self.assertTrue(any("gate" in a["condition"].lower()
                            for a in blocking))

    def test_a_run_with_every_role_recorded_raises_no_swarm_alert(self):
        from app import swarm as SW
        run = "akm-run-al-complete"
        AL.record_assurance(run, ASSURANCE, assessment_id=4)
        # Every contracted role has to appear: a dropped hop is a finding even
        # when the score and the gates look perfect.
        for role in SW.ROLE_CONTRACTS:
            AL.record_swarm_event(run, role=role, phase="spawn")
            AL.record_swarm_event(run, role=role, phase="complete")
        AL.record_human_decision(run, actor="ciso", decision="accept",
                                 assessment_id=4)
        AL.record_prompt_fingerprint(run, actor="report-writer", model="m",
                                     prompt="p")
        alerts = AL.absence_alerts(AL._load_events(run))
        self.assertEqual([a for a in alerts
                          if a.get("id") == "SWARM-HOP-DROPPED"], [])


class TestIntegrityReport(unittest.TestCase):
    def test_report_states_integrity_and_completeness_separately(self):
        run = "akm-run-al-report"
        AL.record_assurance(run, ASSURANCE, assessment_id=5)
        rep = AL.integrity_report(run)
        self.assertIn("chain_intact", rep)
        self.assertIn("class_coverage", rep)
        self.assertIn("absence_alerts", rep)
        self.assertIn("note", rep)

    def test_report_for_an_unknown_run_is_empty_not_an_error(self):
        rep = AL.integrity_report("akm-run-never-happened")
        self.assertEqual(rep["events"], 0)

    def test_evidence_pack_is_self_verifying(self):
        run = "akm-run-al-pack"
        AL.record_assurance(run, ASSURANCE, assessment_id=6)
        pack = AL.evidence_pack(run, requester="legal@example.com")
        self.assertEqual(pack["run_id"], run)
        self.assertEqual(pack["requested_by"], "legal@example.com")
        self.assertTrue(pack["events_by_kind"])
        # A pack a reader can verify without trusting this service.
        self.assertIn("verification", pack)
        self.assertIn("chain", pack)
        self.assertIn("minimisation", pack)


class TestAuthorisation(unittest.TestCase):
    def test_known_roles_are_allowlisted(self):
        for role in ("ciso", "security", "audit", "legal", "dpo"):
            self.assertTrue(AL.authorize_read(role)["allowed"], role)

    def test_an_unknown_role_is_refused(self):
        self.assertFalse(AL.authorize_read("nobody")["allowed"])

    def test_anonymous_is_refused_and_named_as_such(self):
        out = AL.authorize_read("")
        self.assertFalse(out["allowed"])
        self.assertEqual(out["role"], "anonymous")

    def test_a_blocked_gate_is_not_reported_as_a_fabric_failure(self):
        # The architecture gate returns severity "block" when it refuses. That
        # is the system working; reporting it as an integrity failure told
        # leadership to distrust the most trustworthy run in the set.
        run = "akm-run-al-gate-not-fabric"
        AL.record_assurance(run, ASSURANCE, assessment_id=21)
        ids = [a["id"] for a in AL.absence_alerts(AL._load_events(run))]
        self.assertNotIn("FABRIC-INTEGRITY-EVENT", ids)

    def test_a_dropped_ledger_write_is_reported_as_a_fabric_failure(self):
        run = "akm-run-al-fabric"
        AL.record_assurance(run, ASSURANCE, assessment_id=22)
        db = SessionLocal()
        try:
            row = db.query(lg.LedgerEvent).filter(
                lg.LedgerEvent.run_id == run,
                lg.LedgerEvent.kind == "assurance.decision").first()
            row.kind = "audit.dropped"
            db.commit()
        finally:
            db.close()
        ids = [a["id"] for a in AL.absence_alerts(AL._load_events(run))]
        self.assertIn("FABRIC-INTEGRITY-EVENT", ids)

    def test_authorisation_names_the_permitted_roles(self):
        self.assertIn("ciso", AL.authorize_read("nobody")["permitted_roles"])


class TestRuntimeWiring(unittest.TestCase):
    """The run must actually write the ledger the views read.

    Every other test in this file calls the recorders directly. That leaves the
    whole governance layer untested against the thing that matters: whether an
    assessment run leaves evidence behind. These tests drive the same entry
    point :mod:`app.security_agent` uses.
    """

    TRACE = [
        {"agent": "security-orchestrator", "intent": "plan"},
        {"agent": "control-analyst", "intent": "control_plan"},
        {"agent": "research-collector", "intent": "collect_research"},
        {"agent": "threat-intel", "intent": "map_attacks"},
        {"agent": "report-writer", "intent": "write_report"},
    ]

    def _run(self, name, **over):
        return type("R", (), {"id": over.pop("run_id", abs(hash(name)) % 90000
                                            + 1000)})()

    def _result(self, **over):
        r = {"product_name": "acme-cloud", "exposure": "confidential_data",
             "assurance": ASSURANCE, "a2a_trace": list(self.TRACE)}
        r.update(over)
        return r

    def test_a_completed_run_leaves_a_readable_integrity_report(self):
        from app import security_agent as SA
        run = self._run("wire-ok")
        out = SA.record_assurance_ledger(run, {}, self._result())
        rep = AL.integrity_report(out["run_id"])
        self.assertTrue(rep["chain_intact"], rep["chain"].get("findings"))
        self.assertGreater(rep["events"], 0)
        self.assertEqual(rep["verdict"], "clean", rep["absence_alerts"])

    def test_the_roles_recorded_are_the_ones_that_actually_ran(self):
        from app import security_agent as SA
        run = self._run("wire-roles")
        out = SA.record_assurance_ledger(run, {}, self._result())
        from app import swarm as SW
        topo = SW.topology(AL._load_events(out["run_id"]))
        # Suffix matching maps "security-orchestrator" onto the orchestrator
        # contract rather than inventing an uncontracted role for it.
        self.assertEqual(topo["uncontracted"], [])
        self.assertIn("control-analyst", topo["complete"])
        self.assertIn("threat-intel", topo["complete"])
        self.assertIn("report-writer", topo["complete"])

    def test_the_policy_point_decision_travels_with_the_scorer(self):
        from app import security_agent as SA
        run = self._run("wire-policy")
        out = SA.record_assurance_ledger(run, {}, self._result())
        # The fixture's architecture gate is blocked, so the run must say so.
        self.assertFalse(out["policy"]["allowed"])
        kinds = [(e["kind"], e["data"]) for e in AL._load_events(out["run_id"])]
        scorers = [d for k, d in kinds
                   if k == "assurance.swarm_complete"
                   and d.get("role") == "scorer"]
        self.assertEqual(len(scorers), 1)
        self.assertEqual(scorers[0]["policy"]["decision"], "scorer_blocked")

    def test_a_clean_run_records_an_allowed_policy(self):
        from app import security_agent as SA
        clean = dict(ASSURANCE)
        clean["architecture_gate"] = {"gate_blocked_applied": False,
                                      "open_items": [], "items": []}
        run = self._run("wire-clean")
        out = SA.record_assurance_ledger(run, {}, self._result(assurance=clean))
        self.assertTrue(out["policy"]["allowed"])

    def test_a_role_that_failed_is_recorded_as_failed_not_complete(self):
        from app import security_agent as SA
        trace = list(self.TRACE) + [
            {"agent": "report-writer", "intent": "workflow_error"}]
        run = self._run("wire-failed")
        out = SA.record_assurance_ledger(run, {}, self._result(a2a_trace=trace))
        from app import swarm as SW
        topo = SW.topology(AL._load_events(out["run_id"]))
        self.assertIn("report-writer", topo["failed"])
        self.assertNotIn("report-writer", topo["complete"])

    def test_an_agent_with_no_contract_is_surfaced_not_hidden(self):
        from app import security_agent as SA
        trace = list(self.TRACE) + [{"agent": "mystery-agent",
                                     "intent": "do_something"}]
        run = self._run("wire-uncontracted")
        out = SA.record_assurance_ledger(run, {}, self._result(a2a_trace=trace))
        from app import swarm as SW
        self.assertIn("mystery-agent",
                      SW.topology(AL._load_events(out["run_id"]))["uncontracted"])

    def test_a_path_that_does_not_assess_records_no_assurance_events(self):
        from app import security_agent as SA
        run = self._run("wire-not-assessed")
        out = SA.record_assurance_ledger(
            run, {}, self._result(assurance={"assessed": False}))
        self.assertFalse(out["assurance"]["recorded"])
        kinds = [e["kind"] for e in AL._load_events(out["run_id"])]
        self.assertNotIn("assurance.decision", kinds)

    def test_the_critic_is_a_first_class_swarm_role(self):
        from app import security_agent as SA
        run = self._run("wire-critic")
        out = SA.record_assurance_ledger(run, {}, self._result())
        from app import swarm as SW
        topo = SW.topology(AL._load_events(out["run_id"]))
        # The critic runs after the swarm closes, so it belongs in the topology
        # as a settled role with its findings attached.
        self.assertIn("critic", topo["complete"])
        critics = [e for e in AL._load_events(out["run_id"])
                   if e["kind"] == "assurance.swarm_complete"
                   and (e["data"] or {}).get("role") == "critic"]
        self.assertEqual(len(critics), 1)
        self.assertIn("findings", critics[0]["data"]["detail"])

    def test_ledger_tracing_never_blocks_the_assessment(self):
        from app import security_agent as SA
        run = self._run("wire-robust")
        # A result with nothing usable in it must still return, because the
        # alternative is losing a sound assessment over a missing audit trail.
        out = SA.record_assurance_ledger(run, {}, {})
        self.assertIn("policy", out)


class TestMandatoryEventRecorders(unittest.TestCase):
    """The §8.3 event classes that were not previously recorded: lifecycle,
    artifact, tool and publication. Each recorder must write its kind, carry
    attribution, and reject an unknown phase/action rather than invent one."""

    def _events(self, run):
        return {e["kind"]: e for e in AL._load_events(run)}

    def test_lifecycle_events_cover_creation_to_completion(self):
        run = "akm-run-al-lifecycle"
        for phase in ("create", "plan", "pause", "resume", "complete"):
            h = AL.record_lifecycle(run, phase=phase, actor="orchestrator",
                                    assessment_id=5)
            self.assertIsNotNone(h, phase)
        kinds = self._events(run)
        self.assertIn("assurance.lifecycle.create", kinds)
        self.assertIn("assurance.lifecycle.complete", kinds)
        self.assertEqual(kinds["assurance.lifecycle.complete"]
                         ["data"]["assessment_id"], 5)
        self.assertEqual(kinds["assurance.lifecycle.complete"]["verdict"],
                         "allow")

    def test_an_abort_is_recorded_as_a_blocking_deny(self):
        run = "akm-run-al-abort"
        AL.record_lifecycle(run, phase="abort", error="interrupted")
        ev = self._events(run)["assurance.lifecycle.abort"]
        self.assertEqual(ev["verdict"], "deny")
        self.assertEqual(ev["severity"], "block")
        self.assertIn("interrupted", ev["data"]["error"])

    def test_an_unknown_lifecycle_phase_raises(self):
        with self.assertRaises(ValueError):
            AL.record_lifecycle("akm-run-al-x", phase="explode")

    def test_artifact_events_record_the_evidence_decision(self):
        run = "akm-run-al-art"
        for action in ("fetch", "ingest", "review", "accept", "reject", "drift"):
            h = AL.record_artifact(run, artifact_id="ART-1", action=action,
                                   title="vendor doc", relevance=0.7,
                                   review="accepted")
            self.assertIsNotNone(h, action)
        kinds = self._events(run)
        self.assertEqual(kinds["assurance.artifact.accept"]["verdict"], "allow")
        self.assertEqual(kinds["assurance.artifact.reject"]["verdict"], "deny")
        self.assertEqual(kinds["assurance.artifact.drift"]["severity"], "warn")

    def test_an_unknown_artifact_action_raises(self):
        with self.assertRaises(ValueError):
            AL.record_artifact("akm-run-al-y", artifact_id="A", action="burn")

    def test_tool_events_are_redacted_by_default_and_carry_status(self):
        run = "akm-run-al-tool"
        AL.record_tool(run, tool="mcp-search", intent="collect_research",
                       args={"query": "retention policy"}, latency_ms=12)
        ev = self._events(run)["assurance.tool.call"]
        self.assertEqual(ev["data"]["tool"], "mcp-search")
        self.assertTrue(ev["data"]["redacted"])
        self.assertEqual(ev["data"]["latency_ms"], 12)

    def test_a_failed_tool_call_is_a_blocking_event(self):
        run = "akm-run-al-toolerr"
        AL.record_tool(run, tool="mcp-search", intent="collect_research",
                       status="error", error="timeout")
        ev = self._events(run)["assurance.tool.call"]
        self.assertEqual(ev["verdict"], "deny")
        self.assertEqual(ev["severity"], "block")

    def test_publication_records_audience_and_supersession(self):
        run = "akm-run-al-pub"
        AL.record_publication(run, doc_id="assessment-9", version="2.1",
                              audience=["leadership", "audit"],
                              supersedes="assessment-8")
        ev = self._events(run)["assurance.publish"]
        self.assertIn("leadership", ev["data"]["audience"])
        self.assertEqual(ev["data"]["supersedes"], "assessment-8")

    def test_integrity_checks_are_recorded_as_checks_performed(self):
        run = "akm-run-al-ic"
        AL.record_integrity_check(run, check="chain_continuity", passed=True)
        AL.record_integrity_check(run, check="clock_skew", passed=False)
        checks = [e for e in AL._load_events(run) if e["kind"] == "drift.detect"]
        self.assertEqual(len(checks), 2)
        ok, bad = checks[0], checks[1]
        self.assertEqual(ok["data"]["check"], "chain_continuity")
        self.assertEqual(ok["verdict"], "pass")
        self.assertEqual(ok["severity"], "info")
        self.assertEqual(bad["verdict"], "flag")
        self.assertEqual(bad["severity"], "warn")

    def test_new_kinds_are_known_and_never_gated(self):
        for kind in ("assurance.lifecycle.create", "assurance.artifact.ingest",
                     "assurance.tool.call", "assurance.publish"):
            self.assertIn(kind, AL.ASSURANCE_KINDS, kind)
            self.assertIn(kind, lg.INTERNAL_KINDS, kind)
        # drift.detect is a base-ledger fabric kind, not an assurance kind.
        self.assertIn("drift.detect", lg.INTERNAL_KINDS)

    def test_a_full_run_records_all_mandatory_event_classes(self):
        from app import security_agent as SA
        A = dict(ASSURANCE)
        A["architecture_gate"] = {"gate_blocked_applied": False,
                                  "complete": True, "items": [], "open_items": []}
        A["evidence_gate"] = {"gated_threats": [], "per_threat": [],
                              "min_accepted_per_threat": 3}
        A["forensics"] = {"reconstructable": True, "score": 90.0, "band": "high"}
        A["blast_radius"] = {"quantified": True}
        A["decision"] = {"decision": "accept"}
        A["gates_open"] = []
        result = {
            "product_name": "acme-cloud", "exposure": "confidential_data",
            "assurance": A, "threat_pack_version": "2.1", "posture": "LOW",
            "a2a_trace": [
                {"agent": "security-orchestrator", "intent": "plan"},
                {"agent": "control-analyst", "intent": "control_plan"},
                {"agent": "research-collector", "intent": "collect_research"},
                {"agent": "threat-intel", "intent": "map_attacks"},
                {"agent": "report-writer", "intent": "write_report"}],
            "evidence": [{"url": "https://x/a", "title": "vendor doc",
                          "source": "vendor", "relevance": 0.9,
                          "review": "accepted"}],
            "queries_run": ["retention policy"],
        }
        run = type("R", (), {"id": 777})()
        out = SA.record_assurance_ledger(run, {}, result)
        rep = AL.integrity_report(out["run_id"])
        self.assertEqual(rep["class_coverage"]["missing"], [],
                         rep["class_coverage"]["missing"])
        self.assertEqual(rep["class_coverage"]["recorded"],
                         rep["class_coverage"]["total"])


class TestIntegrityMonitoring(unittest.TestCase):
    """§8.4: continuous chain verification across runs, not one snapshot."""

    def _run_with_events(self, name, assessment_id, tamper=False):
        run = f"akm-run-mon-{name}"
        AL.record_assurance(run, ASSURANCE, assessment_id=assessment_id)
        if tamper:
            db = SessionLocal()
            try:
                row = (db.query(lg.LedgerEvent)
                       .filter(lg.LedgerEvent.run_id == run)
                       .order_by(lg.LedgerEvent.seq.desc()).first())
                import json as _json
                row.data_json = _json.dumps({"injected": True})
                db.commit()
            finally:
                db.close()
        return run

    def test_monitor_reports_intact_and_broken_runs(self):
        good = self._run_with_events("good", 41)
        bad = self._run_with_events("bad", 42, tamper=True)
        out = AL.monitor_integrity(run_ids=[good, bad])
        self.assertIn(good, out["verified"])
        self.assertEqual(len(out["broken"]), 1)
        self.assertEqual(out["broken"][0]["run_id"], bad)
        self.assertFalse(out["broken"][0]["chain_intact"])

    def test_monitor_can_scan_recent_runs_without_explicit_ids(self):
        self._run_with_events("scan", 43)
        out = AL.monitor_integrity(limit=5)
        self.assertGreaterEqual(out["runs_checked"], 1)


class TestSiemExport(unittest.TestCase):
    """§8.4: streaming the ledger out as JSON lines for a SIEM / SOAR."""

    def test_export_emits_one_minimised_json_line_per_event(self):
        run = "akm-run-siem"
        AL.record_assurance(run, ASSURANCE, assessment_id=51)
        lines: list[str] = []
        out = AL.export_siem_events(run_ids=[run], sink=lines.append)
        self.assertEqual(out["exported"], len(lines))
        self.assertGreater(out["exported"], 0)
        first = json.loads(lines[0])
        self.assertIn("@timestamp", first)
        self.assertIn("event", first)
        self.assertEqual(first["run_id"], run)
        # Content is minimised: the payload carries hashes, not prompts.
        self.assertNotIn("prompt", str(first["assurance"]))

    def test_export_carries_attribution_and_chain_links(self):
        run = "akm-run-siem2"
        AL.record_human_decision(run, actor="ciso@x", decision="exception",
                                 rationale="because", expires_at="2030-01-01")
        lines: list[str] = []
        AL.export_siem_events(run_ids=[run], sink=lines.append)
        blob = json.loads(lines[-1])
        self.assertEqual(blob["actor"]["name"], "ciso@x")
        self.assertTrue(blob["chain"]["hash"])
        self.assertIsNotNone(blob["chain"]["prev_hash"])


if __name__ == "__main__":
    unittest.main()