"""Tests for the audit ledger.

Run with:  python3 -m unittest discover -s tests -v

The database URL is redirected to a scratch file before any app module is
imported, so these tests never touch ``data/akm.db``.
"""
import os
import tempfile
import unittest

os.environ["AKM_DATABASE_URL"] = "sqlite:///" + os.path.join(
    tempfile.mkdtemp(prefix="akm-ledger-test-"), "test.db")

from app import database  # noqa: E402
from app import ledger as L  # noqa: E402

database.init_db()


_counter = {"n": 0}


def fresh(run_id: str = None, mandate: L.Mandate = None):
    """A closed, empty run with a unique id.

    Uniqueness matters: several tests deliberately corrupt a run, and a shared id
    would leak that damage into whichever test ran next.
    """
    _counter["n"] += 1
    run_id = f"{run_id or 'run'}-{_counter['n']}"
    with L.run(run_id, mandate) as ctx:
        ctx.close()
    return run_id


def seq_of(run_id: str, event_hash: str) -> int:
    """Look up an event's position by its hash. Hardcoding seq numbers makes
    tests silently wrong the moment an event is added anywhere earlier."""
    for e in L.timeline(run_id, limit=2000, include_data=False)["events"]:
        if e["hash"] == event_hash:
            return e["seq"]
    raise AssertionError(f"event {event_hash[:12]} not found in {run_id}")


class TestCanonicalHashing(unittest.TestCase):
    def test_key_order_does_not_change_the_digest(self):
        self.assertEqual(L.digest({"a": 1, "b": 2}), L.digest({"b": 2, "a": 1}))

    def test_value_change_does_change_the_digest(self):
        self.assertNotEqual(L.digest({"a": 1}), L.digest({"a": 2}))

    def test_nested_structures_are_canonical(self):
        self.assertEqual(L.digest({"x": [{"p": 1, "q": 2}]}),
                         L.digest({"x": [{"q": 2, "p": 1}]}))

    def test_is_hash_rejects_non_digests(self):
        self.assertTrue(L.is_hash("a" * 64))
        self.assertFalse(L.is_hash("a" * 63))
        self.assertFalse(L.is_hash("Z" * 64))
        self.assertFalse(L.is_hash(None))


class TestChainIntegrity(unittest.TestCase):
    def setUp(self):
        self.run_id = fresh("chain-ok")
        for i in range(4):
            L.append(self.run_id, "source.fetch", f"agent-{i}",
                     actor_type="agent", data={"i": i}, checked=False)

    def test_clean_chain_verifies(self):
        rep = L.verify_chain(self.run_id)
        self.assertTrue(rep["ok"], rep["findings"])
        self.assertEqual(rep["events"], 6)  # start + 4 appends + end
        self.assertEqual(rep["head_hash"], L.summary(self.run_id)["head_hash"])

    def test_edited_payload_is_detected(self):
        """The whole point: a post-hoc edit to the record must not verify."""
        from app.database import SessionLocal
        from app.ledger_models import LedgerEvent
        db = SessionLocal()
        try:
            ev = (db.query(LedgerEvent)
                  .filter(LedgerEvent.run_id == self.run_id,
                          LedgerEvent.kind == "source.fetch").first())
            ev.data_json = L.canon({"i": 999, "tampered": True})
            db.commit()
        finally:
            db.close()
        rep = L.verify_chain(self.run_id)
        self.assertFalse(rep["ok"])
        self.assertIn("content_tampered", [f["issue"] for f in rep["findings"]])

    def test_deleted_event_is_detected(self):
        from app.database import SessionLocal
        from app.ledger_models import LedgerEvent
        db = SessionLocal()
        try:
            ev = (db.query(LedgerEvent)
                  .filter(LedgerEvent.run_id == self.run_id,
                          LedgerEvent.kind == "source.fetch",
                          LedgerEvent.seq == 2).first())
            db.delete(ev)
            db.commit()
        finally:
            db.close()
        rep = L.verify_chain(self.run_id)
        self.assertFalse(rep["ok"])
        issues = {f["issue"] for f in rep["findings"]}
        self.assertTrue(issues & {"sequence_gap", "broken_link"}, issues)

    def test_forged_head_is_detected(self):
        from app.database import SessionLocal
        from app.ledger_models import LedgerRun
        db = SessionLocal()
        try:
            row = db.get(LedgerRun, self.run_id)
            row.head_hash = "f" * 64
            db.commit()
        finally:
            db.close()
        rep = L.verify_chain(self.run_id)
        self.assertFalse(rep["ok"])
        self.assertIn("head_mismatch", [f["issue"] for f in rep["findings"]])

    def test_appended_event_without_relinking_breaks(self):
        """Appending directly to the table is the classic audit-log attack."""
        from app.database import SessionLocal
        from app.ledger_models import LedgerEvent
        db = SessionLocal()
        try:
            last = (db.query(LedgerEvent)
                    .filter(LedgerEvent.run_id == self.run_id)
                    .order_by(LedgerEvent.seq.desc()).first())
            forged = L.event_core(
                run_id=self.run_id, seq=last.seq + 1, ts=L._now(),
                actor_type="agent", actor="ghost", kind="source.fetch",
                intent=None, verdict="allow", severity="info",
                data={"i": "forged"}, prev_hash="0" * 64)  # not the real head
            db.add(LedgerEvent(
                run_id=self.run_id, seq=last.seq + 1, ts=forged["ts"],
                actor_type="agent", actor="ghost", kind="source.fetch",
                intent=None, verdict="allow", severity="info",
                data_json=L.canon(forged["data"]), prev_hash="0" * 64,
                hash=L.chain_hash(forged)))
            db.commit()
        finally:
            db.close()
        rep = L.verify_chain(self.run_id)
        self.assertFalse(rep["ok"])
        self.assertIn("broken_link", [f["issue"] for f in rep["findings"]])

    def test_genesis_is_the_first_prev_hash(self):
        tl = L.timeline(self.run_id)
        self.assertEqual(tl["events"][0]["prev_hash"], L.GENESIS)

    def test_seq_values_are_dense_and_ordered(self):
        seqs = [e["seq"] for e in L.timeline(self.run_id, limit=100)["events"]]
        self.assertEqual(seqs, list(range(len(seqs))))


class TestProofOfWork(unittest.TestCase):
    def setUp(self):
        self.run_id = fresh("proof-run")
        with L.scope(self.run_id) as ctx:
            self.h = ctx.llm("test-model", "the prompt", "the generated answer",
                             intent="write", latency_ms=42, tokens_in=11,
                             tokens_out=5)

    def test_llm_call_carries_a_proof(self):
        proof = L.verify_proof(self.run_id, seq_of(self.run_id, self.h))
        self.assertTrue(proof["ok"], proof["checks"])
        p = proof["proof"]
        self.assertEqual(p["method"]["type"], "llm")
        self.assertEqual(p["method"]["model"], "test-model")
        self.assertEqual(p["chain"]["hash"], self.h)
        self.assertIsNotNone(p["output_hash"])

    def test_proof_is_reproducible_offline(self):
        """Same inputs, same digest -- the proof is checkable by a third party."""
        again = L.digest(L.canon({"model": "test-model",
                                  "prompt_hash": L.text_digest("the prompt")}))
        stored = L.verify_proof(self.run_id, seq_of(self.run_id, self.h))["proof"]
        self.assertEqual(stored["method"]["prompt_hash"],
                         L.text_digest("the prompt"))
        self.assertTrue(again)

    def test_tampered_output_breaks_the_proof(self):
        from app.database import SessionLocal
        from app.ledger_models import LedgerEvent
        db = SessionLocal()
        try:
            ev = (db.query(LedgerEvent)
                  .filter(LedgerEvent.run_id == self.run_id,
                          LedgerEvent.seq == seq_of(self.run_id, self.h)).first())
            import json as _json
            data = _json.loads(ev.data_json)
            data["output"] = "a completely different answer"
            ev.data_json = L.canon(data)
            db.commit()
        finally:
            db.close()
        # The event hash catches it first, and the proof independently disagrees.
        self.assertFalse(L.verify_chain(self.run_id)["ok"])
        self.assertFalse(L.verify_proof(self.run_id, seq_of(self.run_id, self.h))["ok"])

    def test_stored_proof_drift_is_reported_separately(self):
        """A proof is derived state, so editing it alone must be reported as
        drift rather than silently passing."""
        from app.database import SessionLocal
        from app.ledger_models import LedgerEvent
        db = SessionLocal()
        try:
            ev = (db.query(LedgerEvent)
                  .filter(LedgerEvent.run_id == self.run_id,
                          LedgerEvent.seq == seq_of(self.run_id, self.h)).first())
            ev.proof_json = L.canon({"chain": {"hash": "0" * 64},
                                     "verification": {"verdict": "supported"}})
            db.commit()
        finally:
            db.close()
        rep = L.verify_chain(self.run_id)
        self.assertFalse(rep["ok"])
        self.assertIn("proof_drift", [f["issue"] for f in rep["findings"]])

    def test_missing_event_reports_not_found(self):
        self.assertFalse(L.verify_proof(self.run_id, 999)["ok"])

    def test_claim_proof_attaches_grounding_verdict(self):
        with L.scope(self.run_id) as ctx:
            res = ctx.claim("a claim", [], {}, actor="tester")
        proof = L.verify_proof(self.run_id, res["seq"] if "seq" in res else 2)
        self.assertIsNotNone(proof["proof"])


class TestMandate(unittest.TestCase):
    def setUp(self):
        self.m = L.Mandate(
            objective="scoped work",
            allowed_actors=["orchestrator", "collector"],
            allowed_intents=["collect", "summarise"],
            planned_intents=["collect"],
            allowed_tools=["search.index"],
            allowed_domains=["example.com"],
            max_llm_calls=2,
            human_gates=["deploy"],
            loop_threshold=3,
        )

    def check(self, **kw):
        return self.m.check(**kw)

    def test_in_scope_action_is_allowed(self):
        v = self.check(kind="agent.hop", actor="collector", intent="collect")
        self.assertEqual(v.decision, "allow")

    def test_unknown_actor_is_denied(self):
        v = self.check(kind="agent.hop", actor="intruder", intent="collect")
        self.assertEqual(v.decision, "deny")
        self.assertEqual(v.rule, "actor_not_in_mandate")
        self.assertEqual(v.severity, "block")

    def test_intent_outside_boundary_is_denied(self):
        v = self.check(kind="agent.hop", actor="collector", intent="exfiltrate")
        self.assertEqual(v.decision, "deny")
        self.assertEqual(v.rule, "intent_not_in_mandate")

    def test_tool_outside_boundary_is_denied(self):
        v = self.check(kind="mcp.call", actor="collector", tool="fs.write")
        self.assertEqual(v.decision, "deny")
        self.assertEqual(v.rule, "tool_not_in_mandate")

    def test_tool_prefix_match_is_allowed(self):
        v = self.check(kind="mcp.call", actor="collector", tool="search.index.v2")
        self.assertEqual(v.decision, "allow")

    def test_unplanned_intent_is_flagged_not_denied(self):
        """Soft boundary: allowed, but recorded as drift."""
        v = self.check(kind="agent.hop", actor="collector", intent="summarise")
        self.assertEqual(v.decision, "flag")
        self.assertEqual(v.rule, "unplanned_intent")

    def test_out_of_scope_domain_is_flagged(self):
        v = self.check(kind="source.fetch", actor="collector",
                       intent="collect", domain="pastebin.com")
        self.assertEqual(v.decision, "flag")
        self.assertEqual(v.rule, "scope_creep")

    def test_subdomain_of_allowed_domain_passes(self):
        v = self.check(kind="source.fetch", actor="collector", intent="collect",
                       domain="docs.example.com")
        self.assertEqual(v.decision, "allow")

    def test_human_gate_holds(self):
        # Intent is inside the hard boundary; the *kind* is what needs sign-off.
        v = self.check(kind="deploy", actor="collector", intent="summarise")
        self.assertEqual(v.decision, "hold")
        self.assertEqual(v.rule, "awaiting_approval")

    def test_budget_exceeded_is_denied(self):
        v = self.check(kind="llm.call", actor="collector",
                       counts={"llm.call": 99})
        self.assertEqual(v.decision, "deny")
        self.assertEqual(v.rule, "budget_exceeded")

    def test_internal_kinds_are_never_gated(self):
        v = self.check(kind="claim.emit", actor="intruder", intent="nonsense")
        self.assertEqual(v.decision, "pass")
        self.assertEqual(v.rule, "internal")

    def test_mandate_hash_is_stable_and_content_bound(self):
        self.assertEqual(self.m.hash, L.Mandate.from_dict(self.m.as_dict()).hash)
        other = L.Mandate(objective="scoped work", allowed_actors=["orchestrator"],
                          allowed_intents=["collect"], planned_intents=["collect"],
                          allowed_tools=["search.index"], allowed_domains=["example.com"],
                          max_llm_calls=2, human_gates=["deploy"], loop_threshold=3)
        self.assertNotEqual(self.m.hash, other.hash)

    def test_from_dict_ignores_unknown_keys(self):
        m = L.Mandate.from_dict({"objective": "x", "not_a_field": 1})
        self.assertEqual(m.objective, "x")

    def test_denied_action_lands_on_the_event(self):
        run_id = fresh("mandate-denied", self.m)
        h = L.append(run_id, "agent.hop", "intruder", actor_type="a2a",
                     intent="collect", data={})
        ev = next(e for e in L.timeline(run_id, limit=100)["events"] if e["hash"] == h)
        self.assertEqual(ev["verdict"], "deny")
        self.assertEqual(ev["severity"], "block")
        self.assertEqual(ev["data"]["gate"]["rule"], "actor_not_in_mandate")

    def test_role_allowed_actor_passes_with_unlisted_name(self):
        """Regression: llm.call events carry the model name as actor with
        actor_type 'llm'. A mandate allowing the 'llm' role must let them
        through -- otherwise every model call in every agent run denies."""
        m = L.Mandate(objective="map",
                      allowed_actors=["agent", "llm", "user", "system",
                                      "mcp", "human", "planner", "analyzer"],
                      allowed_intents=["plan"])
        v = m.check(kind="llm.call", actor="qwen3.8:latest",
                    actor_type="llm", intent="plan")
        self.assertEqual(v.decision, "allow")

    def test_model_call_under_role_mandate_records_allow(self):
        m = L.Mandate(objective="map",
                      allowed_actors=["agent", "llm", "user", "system",
                                      "mcp", "human", "planner", "analyzer"],
                      allowed_intents=["plan"])
        run_id = fresh("mandate-llm-role", m)
        h = L.RunCtx(run_id, m).llm("qwen3.8:latest", "prompt", "output",
                                    intent="plan")
        ev = next(e for e in L.timeline(run_id, limit=100)["events"] if e["hash"] == h)
        self.assertEqual(ev["verdict"], "allow")
        self.assertEqual(ev["actor"], "qwen3.8:latest")


class TestGroundingGate(unittest.TestCase):
    SOURCE = ("The committee reported that TLS 1.0 was formally deprecated by "
              "the IETF in 2021 and must not be used for new deployments.")

    def test_verbatim_quote_is_kept(self):
        r = L.verify_grounding(
            "TLS 1.0 is deprecated.",
            [{"source": "s1", "quote": "TLS 1.0 was formally deprecated by the IETF in 2021"}],
            {"s1": self.SOURCE})
        self.assertFalse(r["violation"])
        self.assertEqual(r["n_sources"], 1)
        self.assertEqual(r["kept"][0]["verified"], True)

    def test_invented_quote_is_dropped(self):
        r = L.verify_grounding(
            "TLS 1.0 is deprecated.",
            [{"source": "s1", "quote": "TLS 1.0 was removed by NIST in 1999"}],
            {"s1": self.SOURCE})
        self.assertTrue(r["violation"])
        self.assertEqual(r["n_sources"], 0)
        self.assertEqual(len(r["dropped"]), 1)
        self.assertEqual(r["confidence"], "none")

    def test_corroboration_needs_distinct_sources(self):
        quotes = [{"source": "s1", "quote": "must not be used for new deployments"}]
        one = L.verify_grounding("c", quotes, {"s1": self.SOURCE})
        self.assertEqual(one["n_sources"], 1)
        self.assertEqual(one["confidence"], "low")
        three = L.verify_grounding(
            "c",
            quotes * 1 + [{"source": "s2", "quote": "TLS 1.0 was formally deprecated by the IETF in 2021"},
                          {"source": "s3", "quote": "must not be used for new deployments"}],
            {"s1": self.SOURCE, "s2": self.SOURCE, "s3": self.SOURCE})
        self.assertEqual(three["n_sources"], 3)
        self.assertEqual(three["confidence"], "high")

    def test_short_quote_never_verifies(self):
        """A two-word quote matches nearly any source and proves nothing."""
        self.assertFalse(L.quote_is_verbatim(self.SOURCE, "the IETF"))
        self.assertFalse(L.quote_is_verbatim(self.SOURCE, "TLS"))

    def test_whitespace_and_case_are_normalised(self):
        self.assertTrue(L.quote_is_verbatim(
            self.SOURCE,
            "tls 1.0 was formally   deprecated BY the ietf in 2021"))

    def test_citation_to_unknown_source_is_dropped(self):
        r = L.verify_grounding("c", [{"source": "ghost", "quote": "anything long enough here"}],
                               {"s1": self.SOURCE})
        self.assertTrue(r["violation"])

    def test_require_grounding_raises_a_block_event(self):
        m = L.Mandate(objective="strict", require_grounding=True)
        run_id = fresh("ground-strict", m)
        with L.scope(run_id) as ctx:
            ctx.claim("fabricated", [{"source": "s1", "quote": "not in the source at all"}],
                      {"s1": self.SOURCE}, actor="collector")
        blocks = L.timeline(run_id, verdict="block", limit=100)["events"]
        self.assertTrue(any(e["kind"] == "gate.check" for e in blocks))

    def test_emit_without_strict_mode_still_records_the_violation(self):
        run_id = fresh("ground-lenient")
        with L.scope(run_id) as ctx:
            res = ctx.claim("fabricated",
                            [{"source": "s1", "quote": "not in the source at all"}],
                            {"s1": self.SOURCE}, actor="collector")
        self.assertTrue(res["violation"])
        self.assertEqual(res["confidence"], "none")


class TestClaimAddressing(unittest.TestCase):
    def test_identical_claims_share_a_hash(self):
        a = L.claim_hash("ACME uses TLS 1.0", [{"source": "s", "quote": "q"}])
        b = L.claim_hash("ACME uses TLS 1.0", [{"source": "s", "quote": "q"}])
        self.assertEqual(a, b)

    def test_different_claims_differ(self):
        self.assertNotEqual(L.claim_hash("a", []), L.claim_hash("b", []))

    def test_edited_claim_text_is_detected(self):
        run_id = fresh("claim-tamper")
        with L.scope(run_id) as ctx:
            res = ctx.claim("the original assertion", [], {}, actor="agent")
        from app.database import SessionLocal
        from app.ledger_models import LedgerClaim
        db = SessionLocal()
        try:
            row = (db.query(LedgerClaim)
                   .filter(LedgerClaim.run_id == run_id).first())
            row.text = "something else entirely"
            db.commit()
        finally:
            db.close()
        rep = L.verify_chain(run_id)
        self.assertFalse(rep["ok"])
        self.assertIn("claim_tampered", [f["issue"] for f in rep["findings"]])

    def test_verification_updates_the_verdict(self):
        run_id = fresh("claim-verify")
        with L.scope(run_id) as ctx:
            res = ctx.claim("a claim", [], {}, actor="agent")
        self.assertEqual(L.summary(run_id)["claims"]["unsupported"], 0)
        L.verify_claim(run_id, res["claim_hash"], "unsupported", method="reviewer")
        self.assertEqual(L.summary(run_id)["claims"]["unsupported"], 1)
        # The verifying event now consumes the claim, so it is in the radius.
        r = L.contamination(run_id, res["claim_hash"])
        self.assertEqual(r["blast_radius"], 1)
        self.assertEqual(r["direct_consumers"][0]["kind"], "claim.verify")


class TestContaminationTracing(unittest.TestCase):
    def setUp(self):
        self.run_id = fresh("contam")
        with L.scope(self.run_id) as ctx:
            self.origin = ctx.llm("m", "p", "o", intent="collect")
            bad = ctx.claim("fabricated fact", [], {}, actor="collector")
            self.bad = bad["claim_hash"]
            mid = ctx.hop("collector", "intel", "map", {"evidence": []},
                          input_refs=[self.bad])
            self.far = ctx.llm("m", "p2", "final report", intent="write",
                               input_refs=[mid])

    def test_blast_radius_from_a_claim(self):
        r = L.contamination(self.run_id, self.bad)
        self.assertEqual(r["blast_radius"], 2)
        self.assertEqual([c["kind"] for c in r["direct_consumers"]], ["agent.hop"])

    def test_transitive_consumers_are_found(self):
        r = L.contamination(self.run_id, self.bad)
        self.assertTrue(any(t["kind"] == "llm.call" for t in r["transitive"]))

    def test_claim_and_its_event_are_interchangeable_entry_points(self):
        """Auditors think in whichever identifier they have to hand."""
        from app.ledger_models import LedgerClaim
        from app.database import SessionLocal
        db = SessionLocal()
        try:
            row = (db.query(LedgerClaim)
                   .filter(LedgerClaim.run_id == self.run_id,
                           LedgerClaim.claim_hash == self.bad).first())
            seq = row.seq
        finally:
            db.close()
        by_claim = L.contamination(self.run_id, self.bad)["blast_radius"]
        by_event = L.contamination(self.run_id, L.timeline(
            self.run_id, limit=100)["events"][seq]["hash"])["blast_radius"]
        self.assertEqual(by_claim, by_event)

    def test_unrelated_content_has_zero_radius(self):
        self.assertEqual(L.contamination(self.run_id, L.digest("unrelated"))["blast_radius"], 0)

    def test_cycle_does_not_hang(self):
        a = L.append(self.run_id, "mcp.call", "t", actor_type="mcp",
                     data={"tool": "t"}, input_refs=[self.far], checked=False)
        L.append(self.run_id, "mcp.call", "t", actor_type="mcp", data={"tool": "t"},
                 input_refs=[a], checked=False)
        self.assertIsInstance(L.contamination(self.run_id, self.far)["blast_radius"], int)


class TestDriftDetection(unittest.TestCase):
    def test_loop_is_detected(self):
        m = L.Mandate(objective="x", loop_threshold=3, allowed_intents=["retry"],
                      planned_intents=["retry"])
        run_id = fresh("drift-loop", m)
        with L.scope(run_id) as ctx:
            for _ in range(4):
                ctx.llm("m", "p", "o", intent="retry")
        signals = {f["signal"] for f in L.detect_drift(run_id)["findings"]}
        self.assertIn("loop", signals)

    def test_budget_overrun_is_detected(self):
        m = L.Mandate(objective="x", max_llm_calls=1)
        run_id = fresh("drift-budget", m)
        with L.scope(run_id) as ctx:
            for _ in range(3):
                ctx.llm("m", "p", "o")
        signals = {f["signal"] for f in L.detect_drift(run_id)["findings"]}
        self.assertIn("budget_exceeded", signals)

    def test_unplanned_intent_is_detected(self):
        m = L.Mandate(objective="x", planned_intents=["planned"],
                      allowed_intents=["planned", "surprise"])
        run_id = fresh("drift-unplanned", m)
        with L.scope(run_id) as ctx:
            ctx.hop("a", "b", "surprise", {})
        signals = {f["signal"] for f in L.detect_drift(run_id)["findings"]}
        self.assertIn("unplanned_intent", signals)

    def test_scope_creep_is_detected(self):
        m = L.Mandate(objective="x", allowed_domains=["allowed.test"],
                      planned_intents=["fetch"])
        run_id = fresh("drift-scope", m)
        with L.scope(run_id) as ctx:
            ctx.source("https://elsewhere.test/doc", title="t")
        signals = {f["signal"] for f in L.detect_drift(run_id)["findings"]}
        self.assertIn("scope_creep", signals)

    def test_work_continuing_after_a_block_is_detected(self):
        m = L.Mandate(objective="x", allowed_intents=["permitted"])
        run_id = fresh("drift-halt", m)
        with L.scope(run_id) as ctx:
            ctx.llm("m", "p", "o", intent="forbidden")
            ctx.llm("m", "p", "o", intent="permitted")
        signals = {f["signal"] for f in L.detect_drift(run_id)["findings"]}
        self.assertIn("violation_not_halted", signals)

    def test_propagating_an_unverified_claim_is_detected(self):
        run_id = fresh("drift-propagate")
        with L.scope(run_id) as ctx:
            res = ctx.claim("unverified", [], {}, actor="collector")
            ctx.hop("collector", "intel", "use_it", {}, input_refs=[res["claim_hash"]])
        signals = {f["signal"] for f in L.detect_drift(run_id)["findings"]}
        self.assertIn("unverified_claim_propagated", signals)

    def test_verifying_a_claim_is_not_flagged_as_propagation(self):
        run_id = fresh("drift-not-propagate")
        with L.scope(run_id) as ctx:
            res = ctx.claim("unverified", [], {}, actor="collector")
        L.verify_claim(run_id, res["claim_hash"], "uncertain", method="reviewer")
        signals = {f["signal"] for f in L.detect_drift(run_id)["findings"]}
        self.assertNotIn("unverified_claim_propagated", signals)

    def test_ledger_bookkeeping_is_not_reported_as_drift(self):
        """The audit trail must not accuse itself."""
        m = L.Mandate(objective="x", planned_intents=["collect"])
        run_id = fresh("drift-clean", m)
        with L.scope(run_id) as ctx:
            ctx.hop("a", "b", "collect", {})
        self.assertTrue(L.detect_drift(run_id)["clean"],
                        L.detect_drift(run_id)["findings"])

    def test_unknown_run_is_clean_not_an_error(self):
        self.assertTrue(L.detect_drift("no-such-run")["clean"])


class TestApprovals(unittest.TestCase):
    def test_request_then_grant_is_chained(self):
        run_id = fresh("approval-grant")
        with L.scope(run_id) as ctx:
            subject = ctx.claim("needs sign-off", [], {}, actor="collector")
            aid = ctx.ask("publish", subject["claim_hash"], "publish the report?")
        self.assertIsNotNone(L.pending_approval(run_id, subject["claim_hash"]))
        L.decide_approval(aid, "grant", decided_by="alice", note="looks fine")
        self.assertIsNone(L.pending_approval(run_id, subject["claim_hash"]))
        events = L.timeline(run_id, limit=100)["events"]
        kinds = [e["kind"] for e in events]
        self.assertIn("approval.request", kinds)
        self.assertIn("approval.grant", kinds)
        grant = next(e for e in events if e["kind"] == "approval.grant")
        self.assertEqual(grant["actor_type"], "human")
        self.assertEqual(grant["actor"], "alice")
        self.assertTrue(L.verify_chain(run_id)["ok"])

    def test_denial_is_recorded_with_a_warning(self):
        run_id = fresh("approval-deny")
        with L.scope(run_id) as ctx:
            aid = ctx.ask("publish", L.digest("x"), "publish?")
        L.decide_approval(aid, "deny", decided_by="bob")
        ev = next(e for e in L.timeline(run_id, limit=100)["events"]
                  if e["kind"] == "approval.deny")
        self.assertEqual(ev["verdict"], "deny")

    def test_decision_requires_a_deciding_actor(self):
        run_id = fresh("approval-actor")
        with L.scope(run_id) as ctx:
            aid = ctx.ask("publish", L.digest("x"), "publish?")
        with self.assertRaises(ValueError):
            L.decide_approval(aid, "maybe", decided_by="carol")

    def test_human_gate_kind_holds_until_approved(self):
        m = L.Mandate(objective="x", human_gates=["agent.hop"],
                      allowed_intents=["publish"], planned_intents=["publish"])
        run_id = fresh("approval-hold", m)
        with L.scope(run_id) as ctx:
            h = ctx.hop("a", "b", "publish", {})
        ev = next(e for e in L.timeline(run_id, limit=100)["events"]
                  if e["hash"] == h)
        self.assertEqual(ev["verdict"], "hold")


class TestExport(unittest.TestCase):
    def test_export_verifies_and_is_self_contained(self):
        run_id = fresh("export-run")
        with L.scope(run_id) as ctx:
            ctx.llm("m", "p", "o", intent="do")
            ctx.claim("a grounded claim",
                      [{"source": "s", "quote": "must not be used for new deployments"}],
                      {"s": TestGroundingGate.SOURCE}, actor="agent")
        doc = L.export_run(run_id)
        self.assertEqual(doc["format"], "akm.ledger/1")
        self.assertTrue(doc["verification"]["ok"])
        self.assertIn("mandate", doc["run"])
        self.assertIn("claims", doc)

    def test_offline_verification_detects_tampering(self):
        run_id = fresh("export-tamper")
        with L.scope(run_id) as ctx:
            ctx.llm("m", "p", "o", intent="do")
        doc = L.export_run(run_id)
        self.assertTrue(L.verify_export(doc)["ok"])
        doc["events"][-1]["data"] = {"i": "edited after export"}
        self.assertFalse(L.verify_export(doc)["ok"])

    def test_verify_export_rejects_rubbish(self):
        with self.assertRaises(ValueError):
            L.verify_export({"not": "a ledger"})

    def test_export_verifies_proofs_offline(self):
        """A bundle you can check with no database must check the proofs too,
        not just the chain links -- otherwise "verified" means less offline
        than it does in the app."""
        run_id = fresh("export-proofs")
        with L.scope(run_id) as ctx:
            ctx.llm("m", "p", "o", intent="do")
            ctx.claim("a grounded claim",
                      [{"source": "s", "quote": "must not be used for new deployments"}],
                      {"s": TestGroundingGate.SOURCE}, actor="agent")
        doc = L.export_run(run_id)
        self.assertEqual(doc["verification"]["proofs_checked"], 2)
        self.assertTrue(doc["verification"]["ok"])

    def test_offline_verification_catches_a_tampered_proof(self):
        run_id = fresh("export-proof-tamper")
        with L.scope(run_id) as ctx:
            ctx.llm("m", "p", "o", intent="do")
        doc = L.export_run(run_id)
        proven = [e for e in doc["events"] if e.get("proof")]
        self.assertTrue(proven)
        proven[0]["proof"]["output_hash"] = "0" * 64
        rep = L.verify_export(doc)
        self.assertFalse(rep["ok"])
        self.assertIn("proof_drift", [f["issue"] for f in rep["findings"]])
        self.assertIn("output_hash", rep["findings"][0]["failed"])

    def test_offline_verification_flags_a_ref_to_something_absent(self):
        """A proof that cites an input the bundle does not contain must not
        verify -- that is exactly the tampering a self-contained bundle is
        supposed to expose."""
        run_id = fresh("export-dangling-ref")
        with L.scope(run_id) as ctx:
            ctx.llm("m", "p", "o", intent="do")
        doc = L.export_run(run_id)
        proven = [e for e in doc["events"] if e.get("proof")][0]
        proven["proof"]["inputs"] = [{"ref": "a" * 64}]
        proven["proof"] = {k: v for k, v in proven["proof"].items() if k != "chain"}
        proven["proof"]["chain"] = {"hash": proven["hash"]}
        rep = L.verify_export(doc)
        self.assertFalse(rep["ok"])
        self.assertTrue(any("input:" in n
                            for f in rep["findings"] for n in f.get("failed", [])))

    def test_export_is_json_serialisable(self):
        import json
        run_id = fresh("export-json")
        with L.scope(run_id) as ctx:
            ctx.mcp("srv", "tool", {"a": 1}, {"b": 2})
        json.dumps(L.export_run(run_id))


class TestRedaction(unittest.TestCase):
    def test_secret_keys_are_masked(self):
        r = L._redact({"api_key": "sk-live-abcdef123456", "nested": {"password": "hunter2"}})
        self.assertEqual(r["api_key"], "[redacted]")
        self.assertEqual(r["nested"]["password"], "[redacted]")

    def test_access_token_is_masked(self):
        self.assertEqual(L._redact({"access_token": "abc123xyz"})["access_token"],
                         "[redacted]")

    def test_token_counts_survive(self):
        """Token *counts* are audit evidence, not credentials. Redacting them
        would gut the record while protecting nothing."""
        r = L._redact({"tokens_in": 42, "tokens_out": 7, "latency_ms": 120})
        self.assertEqual(r, {"tokens_in": 42, "tokens_out": 7, "latency_ms": 120})

    def test_secret_named_field_is_masked_even_if_numeric(self):
        self.assertEqual(L._redact({"client_secret": 123456789})["client_secret"],
                         "[redacted]")

    def test_secret_shaped_values_in_strings_are_masked(self):
        self.assertIn("[redacted]", L._redact("token is sk-abcdefghijklmnop here"))

    def test_ordinary_text_survives_redaction(self):
        self.assertEqual(L._redact("an ordinary sentence about TLS"), "an ordinary sentence about TLS")

    def test_redaction_applies_to_stored_events(self):
        run_id = fresh("redact-run")
        h = L.append(run_id, "mcp.call", "svc", actor_type="mcp",
                     data={"tool": "svc.t", "api_key": "sk-live-abcdef123456"},
                     checked=False)
        ev = next(e for e in L.timeline(run_id, limit=100)["events"] if e["hash"] == h)
        self.assertEqual(ev["data"]["api_key"], "[redacted]")


class TestValidation(unittest.TestCase):
    def test_unknown_actor_type_is_rejected(self):
        run_id = fresh("validate")
        with self.assertRaises(ValueError):
            L.append(run_id, "thing", "a", actor_type="robot", checked=False)

    def test_unknown_verdict_is_rejected(self):
        run_id = fresh("validate")
        with self.assertRaises(ValueError):
            L.append(run_id, "thing", "a", verdict="maybe", checked=False)

    def test_unknown_severity_is_rejected(self):
        run_id = fresh("validate")
        with self.assertRaises(ValueError):
            L.append(run_id, "thing", "a", severity="meh", checked=False)

    def test_unknown_claim_verdict_is_rejected(self):
        run_id = fresh("validate")
        with self.assertRaises(ValueError):
            L.verify_claim(run_id, L.digest("x"), "probably")

    def test_missing_core_field_is_rejected(self):
        with self.assertRaises(ValueError):
            L.chain_hash({"run_id": "r", "seq": 0})


class TestSummaryAndTimeline(unittest.TestCase):
    def setUp(self):
        self.run_id = fresh("summary-run")
        with L.scope(self.run_id) as ctx:
            ctx.llm("m", "p", "o", intent="a")
            ctx.mcp("srv", "t", {}, "result")
            ctx.human("alice", "clicked export")
            ctx.claim("grounded",
                      [{"source": "s", "quote": "must not be used for new deployments"}],
                      {"s": TestGroundingGate.SOURCE}, actor="agent")

    def test_summary_counts_by_kind_actor_and_severity(self):
        s = L.summary(self.run_id)
        self.assertEqual(s["events"], 6)  # start, llm, mcp, human, claim, end
        self.assertEqual(s["by_actor"]["alice"], 1)
        self.assertEqual(s["claims"]["total"], 1)
        self.assertEqual(s["claims"]["ungrounded"], 0)

    def test_timeline_filters_by_kind(self):
        r = L.timeline(self.run_id, kinds=["llm.call"])
        self.assertEqual(r["total"], 1)

    def test_timeline_filters_by_actor_type(self):
        r = L.timeline(self.run_id, actor_types=["human"])
        self.assertEqual(r["total"], 1)
        self.assertEqual(r["events"][0]["actor"], "alice")

    def test_timeline_severity_filter(self):
        r = L.timeline(self.run_id, min_severity="warn")
        self.assertTrue(all(e["severity"] in ("warn", "block") for e in r["events"]))

    def test_timeline_paginates(self):
        first = L.timeline(self.run_id, limit=2)
        second = L.timeline(self.run_id, limit=2, offset=2)
        self.assertEqual(first["total"], second["total"])
        self.assertNotEqual(first["events"][0]["hash"], second["events"][0]["hash"])

    def test_timeline_can_omit_payloads(self):
        r = L.timeline(self.run_id, include_data=False)
        self.assertIsNone(r["events"][0]["data"])


class TestInstrumentationIsOptional(unittest.TestCase):
    def test_recorders_no_op_without_an_open_run(self):
        self.assertIsNone(L.record_llm_call("m", "p", "o"))
        self.assertIsNone(L.record_mcp_call("s", "t", {}, "o"))
        self.assertIsNone(L.record_human_action("a", "clicked"))
        self.assertIsNone(L.record_claim("c", [], {}))

    def test_scope_resets_the_context_on_exit(self):
        with L.scope(fresh("scope-run")):
            self.assertIsNotNone(L.current_run())
        self.assertIsNone(L.current_run())

    def test_scope_does_not_duplicate_run_start(self):
        run_id = fresh("scope-twice")
        for _ in range(3):
            with L.scope(run_id):
                pass
        starts = [e for e in L.timeline(run_id, limit=100)["events"]
                  if e["kind"] == "run.start"]
        self.assertEqual(len(starts), 1)

    def test_ledger_failure_does_not_propagate(self):
        """Auditing must never be the reason work fails."""
        def explode():
            1 / 0
        self.assertIsNone(L._safe("explode", explode))

    def test_dropped_record_lands_in_the_dead_letter_table(self):
        """A lost audit record has to be visible afterwards, not just on stderr.

        The stderr line scrolls away and cannot be queried. The table can, and
        it names the recorder and the run, so "verify_chain says there is a
        gap -- what was in it?" has an answer.
        """
        before = len(L.audit_drops(limit=500))
        def explode(*a, **k):
            raise RuntimeError("disk on fire")
        self.assertIsNone(L._safe("llm", explode, "m", "p", "o"))
        drops = L.audit_drops(limit=500)
        self.assertEqual(len(drops), before + 1)
        row = drops[0]
        self.assertEqual(row["recorder"], "llm")
        self.assertIn("disk on fire", row["error"])
        # Args are summarised, not copied: a prompt can hold anything, and an
        # immutable dead letter should not become a second copy of it.
        self.assertNotIn("p", str(row["detail"].get("args")))

    def test_drop_counter_moves(self):
        before = L.dropped_audit_count()
        def explode(*a, **k):
            raise RuntimeError("nope")
        L._safe("step", explode, "stage", "msg")
        self.assertEqual(L.dropped_audit_count(), before + 1)

    def test_dead_letter_write_failure_does_not_raise(self):
        """When the database is what is broken, the dead letter cannot be stored
        either. The stderr line and the counter are the backstops for exactly
        that case, and neither may raise."""
        real = L.SessionLocal
        def no_db():
            raise RuntimeError("cannot reach database")
        L.SessionLocal = no_db
        try:
            def explode(*a, **k):
                raise RuntimeError("first failure")
            self.assertIsNone(L._safe("claim", explode))
        finally:
            L.SessionLocal = real

    def test_summary_reports_drops_for_the_run(self):
        run_id = fresh("drops-in-summary")
        self.assertEqual(L.summary(run_id)["audit_drops"], 0)
        def explode(*a, **k):
            raise RuntimeError("lost one")
        with L.run(run_id):
            L._safe("human", explode, "alice", "clicked")
        self.assertEqual(L.summary(run_id)["audit_drops"], 1)

    def test_dispatch_still_runs_the_handler_when_the_ledger_is_down(self):
        """The audit scope is opened on the product's critical path, so a broken
        ledger must degrade to an unaudited hop, not a failed assessment."""
        from app import agents

        ran = []

        def boom(*a, **k):
            raise RuntimeError("ledger database is unreachable")

        env = {"protocol": agents.PROTOCOL, "from": "orchestrator",
               "to": "threat-intel", "intent": "map_attacks",
               "task_id": fresh("ledger-down"), "payload": {}}
        original_scope, original_map = agents.ledger.scope, agents._HANDLERS.get("threat-intel", {})
        agents.ledger.scope = boom
        agents._HANDLERS["threat-intel"] = {
            "map_attacks": lambda e: ran.append(e) or {"payload": {"threats": ["T01"]}}}
        try:
            out = agents.dispatch(env)
        finally:
            agents.ledger.scope = original_scope
            agents._HANDLERS["threat-intel"] = original_map
        self.assertEqual(len(ran), 1, "handler must still run with no ledger available")
        self.assertEqual(out["payload"]["threats"], ["T01"])

    def test_dispatch_audits_the_hop_on_the_happy_path(self):
        from app import agents
        run_id = fresh("dispatch-audit")
        env = {"protocol": agents.PROTOCOL, "from": "orchestrator",
               "to": "threat-intel", "intent": "map_attacks",
               "task_id": run_id, "payload": {}}
        agents.dispatch(env)
        kinds = [e["kind"] for e in L.timeline(run_id, limit=50)["events"]]
        self.assertIn("agent.hop", kinds)


class TestRunLifecycle(unittest.TestCase):
    def test_run_error_is_recorded_and_run_aborted(self):
        run_id = "run-error-case"
        with self.assertRaises(RuntimeError):
            with L.run(run_id):
                raise RuntimeError("boom")
        events = L.timeline(run_id, limit=100)["events"]
        self.assertIn("run.error", [e["kind"] for e in events])
        self.assertEqual(L.summary(run_id)["status"], "aborted")
        self.assertTrue(L.verify_chain(run_id)["ok"])

    def test_run_context_is_visible_inside(self):
        with L.run(fresh("ctx-run")) as ctx:
            self.assertEqual(L.current_run(), ctx.run_id)

    def test_reopening_a_run_does_not_duplicate_start(self):
        run_id = fresh("reopen")
        with L.run(run_id):
            pass
        starts = [e for e in L.timeline(run_id, limit=100)["events"]
                  if e["kind"] == "run.start"]
        self.assertEqual(len(starts), 1)


class TestConcurrency(unittest.TestCase):
    def test_parallel_appends_produce_an_unbroken_chain(self):
        """Two writers racing on the same run must not fork the chain."""
        import threading
        run_id = fresh("concurrent")
        errors = []

        def worker(n):
            try:
                for i in range(5):
                    L.append(run_id, "source.fetch", f"w{n}", actor_type="agent",
                             data={"worker": n, "i": i}, checked=False)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        rep = L.verify_chain(run_id)
        self.assertTrue(rep["ok"], rep["findings"])
        self.assertEqual(rep["events"], 22)  # start + 20 + end


class TestSessionSpine(unittest.TestCase):
    """A session is a run row of kind='session' whose chain holds one
    ``run.anchor`` per adopted run. The point of the tests below is that the
    spine proves *order* while each run keeps verifying on its own."""

    def _session(self, label="sitting"):
        return L.ensure_session(f"ses-t{_counter['n']}-{label}",
                                client_key=f"key-{label}", label=label)

    def test_client_key_reuses_one_session(self):
        a = L.resolve_session("browser-1")
        b = L.resolve_session("browser-1")
        self.assertEqual(a, b)

    def test_idle_key_starts_a_new_session(self):
        a = L.resolve_session("browser-idle")
        b = L.resolve_session("browser-idle", idle_seconds=0)
        self.assertNotEqual(a, b)

    def test_no_key_means_no_session(self):
        self.assertIsNone(L.resolve_session(None))
        self.assertIsNone(L.resolve_session("  "))

    def test_runs_anchor_in_adoption_order(self):
        sid = self._session("order")
        with L.session(sid):
            with L.scope("akm-order-a", L.Mandate(objective="o")):
                pass
            with L.scope("akm-order-b", L.Mandate(objective="o")):
                pass
        tasks = L.session_tasks(sid)
        self.assertEqual([t["run_id"] for t in tasks], ["akm-order-a", "akm-order-b"])
        self.assertEqual([t["anchor_seq"] for t in tasks], [0, 1])
        self.assertTrue(all(t["genesis_ok"] for t in tasks))

    def test_reopening_a_run_does_not_re_anchor(self):
        sid = self._session("reanchor")
        with L.session(sid):
            with L.scope("akm-reanchor", L.Mandate(objective="o")):
                pass
            with L.scope("akm-reanchor", L.Mandate(objective="o")):
                pass
        self.assertEqual([t["run_id"] for t in L.session_tasks(sid)], ["akm-reanchor"])

    def test_session_scope_survives_ledger_chain_break(self):
        """A session whose task chain was tampered with must fail loudly, and
        must not drag down the runs that are still intact."""
        sid = self._session("break")
        with L.session(sid):
            with L.scope("akm-break-bad", L.Mandate(objective="o")):
                L.append("akm-break-bad", "source.fetch", "x", actor_type="agent",
                         data={"n": 1}, checked=False)
            with L.scope("akm-break-good", L.Mandate(objective="o")):
                L.append("akm-break-good", "source.fetch", "x", actor_type="agent",
                         data={"n": 1}, checked=False)
        with database.SessionLocal() as db:
            ev = (db.query(__import__("app.ledger_models", fromlist=["LedgerEvent"]).LedgerEvent)
                    .filter_by(run_id="akm-break-bad").order_by(
                        __import__("app.ledger_models", fromlist=["LedgerEvent"]).LedgerEvent.seq)
                    .all())
            ev[-1].data_json = '{"tampered": true}'
            db.commit()
        rep = L.verify_session(sid)
        self.assertFalse(rep["ok"])
        bad = [t for t in rep["tasks"] if t["run_id"] == "akm-break-bad"][0]
        good = [t for t in rep["tasks"] if t["run_id"] == "akm-break-good"][0]
        self.assertFalse(bad["ok"])
        self.assertTrue(good["ok"], good["findings"])

    def test_session_actions_land_without_a_run(self):
        sid = self._session("human")
        with L.session(sid):
            self.assertIsNotNone(L.record_session_action("fox", "opened_investigation",
                                                          {"investigation": 1}))
        acts = [e for e in L.session_timeline(sid)["events"] if e["kind"] == "human.action"]
        self.assertEqual(len(acts), 1)
        self.assertEqual(acts[0]["actor"], "fox")
        self.assertTrue(L.verify_session(sid)["ok"])

    def test_human_action_is_dropped_without_run_or_session(self):
        self.assertIsNone(L.record_session_action("fox", "noop"))
        self.assertIsNone(L.record_human_action("fox", "noop"))

    def test_timeline_interleaves_runs_in_time_order(self):
        sid = self._session("timeline")
        with L.session(sid):
            with L.scope("akm-tl-a", L.Mandate(objective="o")):
                L.append("akm-tl-a", "source.fetch", "x", actor_type="agent",
                         data={"i": 1}, checked=False)
            with L.scope("akm-tl-b", L.Mandate(objective="o")):
                L.append("akm-tl-b", "source.fetch", "x", actor_type="agent",
                         data={"i": 2}, checked=False)
        tl = L.session_timeline(sid)
        self.assertEqual(set(tl["events"][0].keys()) >= {"run_id", "seq", "kind", "hash"}, True)
        self.assertIn("akm-tl-a", tl["runs"])
        self.assertIn("akm-tl-b", tl["runs"])
        self.assertEqual(tl["total"], len(tl["events"]))

    def test_unknown_session_timeline_is_empty_not_an_error(self):
        tl = L.session_timeline("ses-does-not-exist")
        self.assertEqual(tl["total"], 0)
        self.assertEqual(tl["runs"], [])
        self.assertFalse(L.verify_session("ses-does-not-exist")["ok"])

    def test_insights_aggregate_across_runs(self):
        sid = self._session("insights")
        with L.session(sid):
            with L.scope("akm-ins", L.Mandate(objective="o")):
                L.RunCtx("akm-ins", L.Mandate()).step("plan", "planning",
                                                      {"queries": 2})
                L.record_session_action("fox", "created_investigation",
                                        {"investigation": 42, "title": "t"})
        ins = L.session_insights(sid)
        self.assertEqual(ins["investigations"], ["42"])
        self.assertEqual([h["intent"] for h in ins["human_actions"]],
                         ["created_investigation"])
        self.assertIn("agent.step", ins["by_kind"])
        self.assertIsNotNone(ins["span"])


class TestRedactionKeepsHashes(unittest.TestCase):
    """Regression: the "long opaque token" rule used to swallow every SHA-256
    digest, silently replacing hash evidence in stored payloads."""

    def test_genesis_value_survives(self):
        self.assertEqual(L._redact({"task_genesis": L.GENESIS})["task_genesis"],
                         L.GENESIS)

    def test_hex_digest_survives(self):
        digest = "a3f9c1b2" * 8
        self.assertEqual(L._redact({"payload_hash": digest})["payload_hash"], digest)

    def test_hash_inside_a_stored_event_survives(self):
        run_id = fresh("hash-keep")
        digest = L.digest({"a": 1})
        h = L.append(run_id, "mcp.call", "svc", actor_type="mcp",
                     data={"payload_hash": digest}, checked=False)
        ev = next(e for e in L.timeline(run_id, limit=100)["events"] if e["hash"] == h)
        self.assertEqual(ev["data"]["payload_hash"], digest)

    def test_long_base64_secret_still_masked(self):
        blob = "QWxhZGRpbjpvcGVuIHNlc2FtZQ" * 2
        self.assertIn("[redacted]", L._redact("value " + blob))

    def test_mixed_token_still_masked(self):
        blob = ("a3f9c1b2" * 8)[:60] + "zzQQ"
        self.assertIn("[redacted]", L._redact(blob))


class TestSessionInsightEnrichment(unittest.TestCase):
    """The aggregates a session view is actually for.

    These are cheap to compute but easy to get quietly wrong, and the failure is
    not a crash -- it is a number that looks authoritative and is not. The
    tests below pin the ones that can drift from the events they summarise.
    """

    def _mandated(self, sid, run_id, **kw):
        mandate = L.Mandate(objective="assess", **kw)
        with L.session(sid):
            with L.scope(run_id, mandate, label="ACME assess"):
                return mandate, L.RunCtx(run_id, mandate)

    def test_violation_is_reported_once_not_twice(self):
        """The ledger annotates a refused action with a second ``gate.check``
        event. Counting both would double every violation in the session."""
        sid = L.ensure_session(f"ses-t{_counter['n']}-dup", label="dup")
        mandate, ctx = self._mandated(
            sid, "sec-dup", allowed_intents=["analyse_controls"])
        ctx.llm("gpt-4o", "p", "o", intent="publish_release")
        ins = L.session_insights(sid)
        self.assertEqual(ins["violation_count"], 1)
        self.assertEqual(len(ins["violations"]), 1)
        self.assertEqual(ins["violations"][0]["verdict"], "deny")
        self.assertIn("outside the mandate", ins["violations"][0]["reason"])
        # The histogram must agree with the notice list, or one of them lies.
        self.assertEqual(ins["verdicts"].get("deny"), 1)

    def test_violation_reason_comes_from_the_mandate(self):
        sid = L.ensure_session(f"ses-t{_counter['n']}-reason", label="reason")
        mandate, ctx = self._mandated(
            sid, "sec-reason", allowed_intents=["analyse_controls"])
        ctx.llm("gpt-4o", "p", "o", intent="publish_release")
        reason = L.session_insights(sid)["violations"][0]["reason"]
        self.assertEqual(reason, "intent 'publish_release' is outside the mandate")

    def test_ungrounded_claim_is_a_grounding_finding(self):
        sid = L.ensure_session(f"ses-t{_counter['n']}-ground", label="ground")
        mandate, ctx = self._mandated(sid, "sec-ground", require_grounding=True)
        ctx.claim("ACME is fully compliant",
                  [{"source": "a1", "quote": "no such text here"}],
                  {"a1": "the ACME edge terminates TLS 1.0"}, actor="mapper")
        ins = L.session_insights(sid)
        v = ins["violations"][0]
        self.assertEqual(v["class"], "grounding")
        self.assertIn("not found in a1", v["reason"])
        self.assertEqual(ins["claims"]["ungrounded"], 1)

    def test_allowed_call_raises_no_notice(self):
        sid = L.ensure_session(f"ses-t{_counter['n']}-clean", label="clean")
        mandate, ctx = self._mandated(
            sid, "sec-clean", allowed_intents=["analyse_controls"])
        ctx.llm("gpt-4o", "p", "o", intent="analyse_controls")
        ins = L.session_insights(sid)
        self.assertEqual(ins["violation_count"], 0)
        self.assertEqual(ins["verdicts"], {})

    def test_token_totals_and_per_model_breakdown(self):
        sid = L.ensure_session(f"ses-t{_counter['n']}-tok", label="tok")
        mandate, ctx = self._mandated(sid, "sec-tok")
        ctx.llm("gpt-4o", "p", "o", latency_ms=100, tokens_in=10, tokens_out=1)
        ctx.llm("gpt-4o", "p", "o", latency_ms=200, tokens_in=20, tokens_out=2)
        ctx.llm("claude", "p", "o", latency_ms=300, tokens_in=5, tokens_out=3)
        ins = L.session_insights(sid)
        self.assertEqual(ins["llm"]["calls"], 3)
        self.assertEqual(ins["llm"]["tokens_in"], 35)
        self.assertEqual(ins["llm"]["tokens_out"], 6)
        self.assertEqual(ins["llm"]["tokens"], 41)
        self.assertEqual(ins["llm"]["models"]["gpt-4o"],
                         {"calls": 2, "tokens_in": 30, "tokens_out": 3})
        self.assertEqual(ins["llm"]["models"]["claude"],
                         {"calls": 1, "tokens_in": 5, "tokens_out": 3})
        self.assertEqual(ins["llm"]["mean_latency_ms"], 200)

    def test_missing_token_counts_do_not_crash_the_rollup(self):
        """Older events predate token accounting; a missing field must read as
        zero rather than blow up the session view."""
        sid = L.ensure_session(f"ses-t{_counter['n']}-notok", label="notok")
        with L.session(sid):
            with L.scope("sec-notok", L.Mandate(objective="o"), label="n"):
                L.append("sec-notok", "llm.call", "gpt-4o", actor_type="agent",
                         data={"model": "gpt-4o"}, checked=False)
        ins = L.session_insights(sid)
        self.assertEqual(ins["llm"]["calls"], 1)
        self.assertEqual(ins["llm"]["tokens"], 0)
        self.assertIsNone(ins["llm"]["mean_latency_ms"])

    def test_human_automated_split_and_activity(self):
        sid = L.ensure_session(f"ses-t{_counter['n']}-split", label="split")
        with L.session(sid):
            with L.scope("akm-split", L.Mandate(objective="o"), label="k"):
                L.RunCtx("akm-split", L.Mandate()).step("plan", "planning", {})
                L.record_session_action("fox", "created_investigation",
                                        {"investigation": 7})
        ins = L.session_insights(sid)
        # Human means "a person did this"; automated is everything else,
        # including the ledger's own run.start/run.end bookkeeping, so the two
        # always add back up to the event total.
        self.assertEqual(ins["split"]["human"], 1)
        self.assertEqual(sum(ins["split"].values()), ins["total_events"])
        self.assertEqual(sum(b["events"] for b in ins["activity"]),
                         ins["total_events"])
        self.assertIsNotNone(ins["span"]["duration_s"])

    def test_per_run_rollup_keeps_order_and_health(self):
        sid = L.ensure_session(f"ses-t{_counter['n']}-runs", label="runs")
        with L.session(sid):
            with L.scope("akm-a", L.Mandate(objective="o"), label="first"):
                L.RunCtx("akm-a", L.Mandate()).step("plan", "planning", {})
            with L.scope("akm-b", L.Mandate(objective="o"), label="second"):
                L.RunCtx("akm-b", L.Mandate()).step("search", "searching", {})
        # The run's own outcome is the domain's to record, the way agent.py
        # marks a run it could not finish.
        db = L.SessionLocal()
        try:
            row = db.get(L.LedgerRun, "akm-b")
            row.status = "error"
            db.commit()
        finally:
            db.close()
        ins = L.session_insights(sid)
        self.assertEqual([t["run_id"] for t in ins["tasks"]], ["akm-a", "akm-b"])
        self.assertEqual([t["anchor_seq"] for t in ins["tasks"]], [0, 1])
        self.assertEqual(ins["failed_runs"], [{"run_id": "akm-b", "label": "second"}])

    def test_per_run_counts_its_own_llm_and_claims(self):
        sid = L.ensure_session(f"ses-t{_counter['n']}-own", label="own")
        mandate, ctx = self._mandated(sid, "sec-own")
        ctx.llm("gpt-4o", "p", "o", latency_ms=10, tokens_in=7, tokens_out=3)
        ctx.claim("grounded claim text", [{"source": "a1", "quote": "grounded claim text"}],
                  {"a1": "grounded claim text"}, actor="mapper")
        run = L.session_insights(sid)["tasks"][0]
        self.assertEqual(run["llm_calls"], 1)
        self.assertEqual(run["tokens_in"], 7)
        self.assertEqual(run["tokens_out"], 3)
        self.assertEqual(run["ungrounded_claims"], 0)

    def test_empty_session_reports_nothing_rather_than_dying(self):
        """The "New session" button creates the row before any work happens, so
        an empty session is the normal first state of the UI, not an edge case."""
        sid = L.ensure_session(f"ses-t{_counter['n']}-empty", label="empty")
        ins = L.session_insights(sid)
        self.assertEqual(ins["total_events"], 0)
        self.assertEqual(ins["violation_count"], 0)
        self.assertEqual(ins["split"], {"human": 0, "automated": 0})
        self.assertEqual(ins["activity"], [])
        self.assertEqual(ins["failed_runs"], [])
        self.assertIsNone(ins["span"])
        self.assertEqual(ins["llm"]["mean_latency_ms"], None)


class TestGatewayProofLink(unittest.TestCase):
    """The ledger and the gateway corroborate each other without exchanging text.

    The request carries only a run ID and prompt digest; the response (or a
    digest-only telemetry report) carries only IDs and proof digests. Either
    side can later compare digests without ever sending prompts or completions.
    """

    def _linked_call(self, headers, report=None):
        import app.llm as llm_mod
        original_post, original_report = llm_mod._post, llm_mod._report_proof
        seen = {}
        def fake_post(base, payload, extra_headers=None):
            seen["url"] = base
            seen["headers"] = extra_headers or {}
            seen["payload"] = payload
            return ({"id": "provider-1", "model": "qwen-test",
                     "choices": [{"message": {"content": "hello"}}],
                     "usage": {"prompt_tokens": 3, "completion_tokens": 1}}, headers)
        def fake_report(payload):
            if report is not None:
                report.append(payload)
        llm_mod._post, llm_mod._report_proof = fake_post, fake_report
        _counter["n"] += 1
        run_id = f"akm-link-{_counter['n']}"
        try:
            sid = L.ensure_session(f"ses-t{_counter['n']}-link", label="link")
            with L.session(sid):
                with L.scope(run_id, L.Mandate(objective="o"), label="link"):
                    text = llm_mod.chat([{"role": "user", "content": "hello"}])
        finally:
            llm_mod._post, llm_mod._report_proof = original_post, original_report
        events = L.timeline(run_id, limit=100)["events"]
        call = next(e for e in events if e["kind"] == "llm.call")
        return text, seen, call, run_id

    def test_gateway_response_proof_lands_on_the_ledger(self):
        reports = []
        text, seen, call, run_id = self._linked_call(
            {"X-Fox-Request-Id": "fox-1", "X-Fox-Proof": "proof-1"}, reports)
        self.assertEqual(text, "hello")
        self.assertIn("X-Ledger-Run", seen["headers"])
        self.assertIn("X-Ledger-Prompt-Sha256", seen["headers"])
        self.assertEqual(call["data"]["gateway"]["request_id"], "fox-1")
        self.assertEqual(call["data"]["gateway"]["proof"], "proof-1")
        # The gateway already logged this call, so no duplicate telemetry report.
        self.assertEqual(reports, [])

    def test_direct_backend_sends_a_digest_only_report(self):
        reports = []
        text, seen, call, run_id = self._linked_call({}, reports)
        self.assertEqual(text, "hello")
        self.assertEqual(len(reports), 1)
        payload = reports[0]
        self.assertEqual(payload["ledger_run_id"], run_id)
        self.assertEqual(payload["prompt_sha256"], call["data"]["prompt_hash"])
        self.assertNotIn("prompt", payload)
        self.assertNotIn("output", payload)
        self.assertNotIn("messages", payload)


class TestSessionApi(unittest.TestCase):
    """HTTP-level coverage for the session wiring.

    Worth having at this level because the failure mode is not in the ledger: it
    is in plumbing (an unannotated ``request`` parameter in a FastAPI dependency
    silently becomes a required query parameter, and every request 422s).
    """

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        import app.main as main
        from app import agent
        # Keep the product path offline: this suite is about audit plumbing.
        agent._plan_queries = lambda inv: {"rationale": "s", "queries": []}
        agent._run_searches = lambda q, s: []
        agent._analyze_batch = lambda i, b, e: []
        agent._map_relationships = lambda *a, **k: 0
        main.launch_run = lambda *a, **k: None
        # The module-level init_db() above ran before app.models was imported,
        # so the product tables do not exist yet. Now they do.
        database.init_db()
        cls.client = TestClient(main.app)

    def _headers(self, key="browser-api", actor="fox"):
        return {"X-AKM-Session": key, "X-AKM-Actor": actor}

    def _new_session(self, key):
        h = self._headers(key)
        r = self.client.post("/api/ledger/sessions", headers=h,
                             json={"client_key": key, "label": "api sitting"})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["session_id"]

    def test_request_without_session_key_still_works(self):
        r = self.client.get("/api/investigations")
        self.assertEqual(r.status_code, 200, r.text)

    def test_session_header_creates_one_reused_session(self):
        key = "reuse-key"
        first = self._headers(key)
        self.client.get("/api/investigations", headers=first)
        sessions = self.client.get("/api/ledger/sessions").json()["sessions"]
        mine = [s for s in sessions if s["client_key"] == key]
        self.assertEqual(len(mine), 1, sessions)

    def test_human_actions_reach_the_session_timeline(self):
        key = "human-key"
        sid = self._new_session(key)
        h = self._headers(key)
        inv = self.client.post("/api/investigations", headers=h,
                               json={"title": "API session probe", "keywords": "k",
                                     "description": "d", "sources": "web"})
        self.assertEqual(inv.status_code, 200, inv.text)
        self.client.get(f"/api/investigations/{inv.json()['id']}", headers=h)
        tl = self.client.get(f"/api/ledger/sessions/{sid}/timeline").json()
        intents = [e["intent"] for e in tl["events"] if e["kind"] == "human.action"]
        self.assertIn("created_investigation", intents)
        self.assertIn("opened_investigation", intents)
        actors = {e["actor"] for e in tl["events"] if e["kind"] == "human.action"}
        self.assertEqual(actors, {"fox"})

    def test_session_endpoints_verify_and_summarise(self):
        key = "verify-key"
        sid = self._new_session(key)
        self.client.get("/api/investigations", headers=self._headers(key))
        rep = self.client.get(f"/api/ledger/sessions/{sid}/verify").json()
        self.assertTrue(rep["ok"], rep)
        ins = self.client.get(f"/api/ledger/sessions/{sid}/insights").json()
        self.assertIn("human_actions", ins)
        detail = self.client.get(f"/api/ledger/sessions/{sid}").json()
        self.assertEqual(detail["session_id"], sid)

    def test_unknown_session_is_404_not_500(self):
        for suffix in ("", "/timeline", "/verify", "/insights"):
            r = self.client.get(f"/api/ledger/sessions/ses-missing{suffix}")
            self.assertEqual(r.status_code, 404, f"{suffix}: {r.status_code} {r.text}")

    def test_global_timeline_is_newest_first_across_runs(self):
        """The ledger-wide view interleaves every chain, newest first, in the
        same event shape as a session timeline."""
        key = "timeline-key"
        sid = self._new_session(key)
        h = self._headers(key)
        inv = self.client.post("/api/investigations", headers=h,
                               json={"title": "Timeline probe", "keywords": "k",
                                     "description": "d", "sources": "web"})
        self.assertEqual(inv.status_code, 200, inv.text)
        tl = self.client.get("/api/ledger/timeline?limit=200").json()
        self.assertGreaterEqual(tl["total"], 2)
        self.assertIn(sid, tl["runs"])
        stamps = [e["ts"] for e in tl["events"]]
        self.assertEqual(stamps, sorted(stamps, reverse=True))
        kinds = {e["kind"] for e in tl["events"]}
        self.assertIn("human.action", kinds)
        self.assertIn("run_id", tl["events"][0])

    def test_audit_failure_never_breaks_the_product_call(self):
        """A ledger that cannot be written must not turn a 200 into a 500."""
        import app.ledger as ledger_mod
        original = ledger_mod.record_session_action
        ledger_mod.record_session_action = lambda *a, **k: (_ for _ in ()).throw(
            RuntimeError("ledger down"))
        # also break the session dependency's own write path
        try:
            r = self.client.post("/api/investigations", headers=self._headers("fail-key"),
                                 json={"title": "ledger down", "keywords": "k",
                                       "description": "d", "sources": "web"})
            self.assertEqual(r.status_code, 200, r.text)
        finally:
            ledger_mod.record_session_action = original

    def test_session_dependency_failure_never_breaks_a_browser_request(self):
        """A live browser always sends the session header, so dependency-level
        failure has to be fail-open too -- not just the per-action recorder."""
        import app.ledger as ledger_mod
        original = ledger_mod.resolve_session
        ledger_mod.resolve_session = lambda *a, **k: (_ for _ in ()).throw(
            RuntimeError("ledger database is unreachable"))
        try:
            r = self.client.get("/api/investigations", headers=self._headers("dead-key"))
            self.assertEqual(r.status_code, 200, r.text)
            self.assertIsInstance(r.json(), (list, dict))
        finally:
            ledger_mod.resolve_session = original


if __name__ == "__main__":
    unittest.main(verbosity=2)
