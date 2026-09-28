"""Tests for app.obs -- trace propagation and structured logging.

The point of a trace id is that one user action stays one thing across an HTTP
request, the A2A hops it triggers, the model calls inside them, and the
background thread that finishes the work. These tests pin that it reaches the
ledger without becoming part of the hash.
"""
import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr


# Pin the database before app.database is imported: a module that omits
# this can inherit data/akm.db and write test rows into the live store.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-obs-"), "test.db"))

from app import database  # noqa: E402
from app import ledger as L  # noqa: E402
from app import obs  # noqa: E402

database.init_db()

_n = {"i": 0}


def fresh(label="trace"):
    _n["i"] += 1
    rid = f"{label}-{_n['i']}"
    L.ensure_run(rid, L.Mandate(), label=rid)
    return rid


class TestTrace(unittest.TestCase):
    def test_new_trace_is_prefixed_and_unique(self):
        a, b = obs.new_trace(), obs.new_trace()
        self.assertTrue(a.startswith("t-"))
        self.assertNotEqual(a, b)

    def test_seeded_trace_is_deterministic(self):
        self.assertEqual(obs.new_trace("ses-abc"), obs.new_trace("ses-abc"))

    def test_seed_is_sanitised(self):
        # A trace id lands in a log line and a URL, so it has to survive both.
        t = obs.new_trace("a b/c?d&e")
        self.assertNotIn(" ", t)
        self.assertNotIn("/", t)
        self.assertNotIn("?", t)

    def test_current_trace_defaults_to_none(self):
        self.assertIsNone(obs.current_trace())

    def test_scope_sets_and_restores(self):
        with obs.trace_scope("t-outer"):
            self.assertEqual(obs.current_trace(), "t-outer")
            with obs.trace_scope("t-inner"):
                self.assertEqual(obs.current_trace(), "t-inner")
            # Restores rather than clears, so nesting does not lose the outer id.
            self.assertEqual(obs.current_trace(), "t-outer")
        self.assertIsNone(obs.current_trace())

    def test_scope_clears_even_on_error(self):
        with self.assertRaises(RuntimeError):
            with obs.trace_scope("t-boom"):
                raise RuntimeError("x")
        self.assertIsNone(obs.current_trace())


class TestLog(unittest.TestCase):
    def _capture(self, fn):
        buf = io.StringIO()
        with redirect_stderr(buf):
            fn()
        return buf.getvalue()

    def test_line_carries_the_trace(self):
        out = self._capture(lambda: obs.log("thing.happened", run_id="r1"))
        self.assertIn("thing.happened", out)
        self.assertIn("run_id=r1", out)

    def test_trace_appears_when_bound(self):
        def go():
            with obs.trace_scope("t-abc"):
                obs.log("scoped.event")
        out = self._capture(go)
        self.assertIn("trace=t-abc", out)

    def test_values_with_spaces_are_quoted(self):
        out = self._capture(lambda: obs.log("e", error="two words"))
        self.assertIn('error="two words"', out)

    def test_log_never_raises(self):
        class Unserialisable:
            def __str__(self):
                raise RuntimeError("cannot render")

        # A value that explodes on formatting must not take down the caller:
        # a logger that can fail the operation it describes is one nobody
        # turns on.
        out = self._capture(lambda: obs.log("e", weird=Unserialisable()))
        self.assertIsInstance(out, str)

    def test_level_filtering(self):
        original = obs._MIN_LEVEL
        obs._MIN_LEVEL = "error"
        try:
            out = self._capture(lambda: obs.log("chatty", level="info"))
            self.assertEqual(out, "")
            out = self._capture(lambda: obs.log("serious", level="error"))
            self.assertIn("serious", out)
        finally:
            obs._MIN_LEVEL = original


class TestTraceReachesTheLedger(unittest.TestCase):
    def test_event_records_the_trace(self):
        rid = fresh("traced")
        with obs.trace_scope("t-abc123"), L.run(rid):
            L.record_agent_step("plan", "doing a thing")
        events = L.timeline(rid)["events"]
        self.assertTrue(any(e["trace"] == "t-abc123" for e in events),
                        [e["trace"] for e in events])

    def test_events_without_a_trace_are_null_not_empty(self):
        rid = fresh("untraced")
        with L.run(rid):
            L.record_agent_step("plan", "no trace bound")
        self.assertTrue(all(e["trace"] is None
                            for e in L.timeline(rid)["events"]))

    def test_trace_is_not_part_of_the_hashed_core(self):
        """The trace says *when* a record was written, not what it says.

        Folding it into data_json would change every event hash and break
        verification of every run already on disk, so it must stay outside the
        hashed core. Proven rather than asserted: the stored hash is exactly
        the hash of the declared core fields, which do not mention the trace.
        """
        self.assertNotIn("trace", L.CORE_FIELDS)
        rid = fresh("core-fields")
        with obs.trace_scope("t-core"), L.run(rid):
            L.record_agent_step("plan", "same content")
        ev = [e for e in L.timeline(rid)["events"]
              if e["kind"] == "agent.step"][0]
        core = L.event_core(run_id=rid, seq=ev["seq"], ts=ev["ts"],
                            actor_type=ev["actor_type"], actor=ev["actor"],
                            kind=ev["kind"], intent=ev["intent"],
                            verdict=ev["verdict"], severity=ev["severity"],
                            data=ev["data"], prev_hash=ev["prev_hash"])
        self.assertEqual(L.chain_hash(core), ev["hash"])
        self.assertEqual(ev["trace"], "t-core")

    def test_trace_timeline_spans_runs(self):
        r1, r2 = fresh("span-a"), fresh("span-b")
        with obs.trace_scope("t-wide"), L.run(r1):
            L.record_agent_step("plan", "first hop")
        with obs.trace_scope("t-wide"), L.run(r2):
            L.record_agent_step("plan", "second hop")
        view = L.trace_timeline("t-wide")
        self.assertEqual(sorted(view["runs"]), sorted([r1, r2]))
        steps = {(e["run_id"], e["intent"]) for e in view["events"]
                 if e["kind"] == "agent.step"}
        self.assertEqual(steps, {(r1, "plan"), (r2, "plan")})
        self.assertEqual(view["by_run"][r1], view["by_run"][r2])

    def test_trace_timeline_is_ordered_across_runs(self):
        r1, r2 = fresh("order-a"), fresh("order-b")
        with obs.trace_scope("t-seq"), L.run(r1):
            L.record_agent_step("plan", "first")
        with obs.trace_scope("t-seq"), L.run(r2):
            L.record_agent_step("plan", "second")
        view = L.trace_timeline("t-seq")
        stamps = [e["ts"] for e in view["events"]]
        self.assertEqual(stamps, sorted(stamps))

    def test_unknown_trace_is_empty_not_an_error(self):
        view = L.trace_timeline("t-never-existed")
        self.assertEqual(view["events"], [])
        self.assertEqual(view["runs"], [])

    def test_chain_still_verifies_with_traces(self):
        """The real regression risk: a new column must not disturb the chain."""
        rid = fresh("verify")
        with obs.trace_scope("t-verify"), L.run(rid):
            L.record_agent_step("plan", "a step")
        report = L.verify_chain(rid)
        self.assertTrue(report["ok"], report)


class TestA2ATraceAdoption(unittest.TestCase):
    def test_envelope_trace_is_adopted(self):
        from app import agents
        seen = []
        agents._HANDLERS["trace-probe"] = {
            "ping": lambda e: seen.append(obs.current_trace()) or {"payload": {}}}
        env = {"protocol": agents.PROTOCOL, "from": "orchestrator",
               "to": "trace-probe", "intent": "ping", "task_id": "task-1",
               "trace_id": "t-from-peer", "payload": {}}
        try:
            agents.dispatch(env)
        finally:
            del agents._HANDLERS["trace-probe"]
        # A contextvar does not cross a process boundary, so the sender's id
        # has to be adopted from the envelope or both sides' events land under
        # different traces.
        self.assertEqual(seen, ["t-from-peer"])

    def test_a_hop_log_on_the_envelope_is_not_mistaken_for_a_trace_id(self):
        """``trace`` on an envelope is the list of agents, not the trace's name.

        Reading it as an id bound a list to the contextvar, and the next ledger
        write died trying to bind a list to a VARCHAR -- which took out the
        whole security assessment, silently, on any run that reached an A2A hop.
        """
        from app import agents
        seen = []
        agents._HANDLERS["trace-probe"] = {
            "ping": lambda e: seen.append(obs.current_trace()) or {"payload": {}}}
        env = agents.new_envelope("orchestrator", "trace-probe", "ping",
                                  trace_id="t-real-id")
        with obs.trace_scope("t-caller"):
            try:
                agents.dispatch(env)
            finally:
                del agents._HANDLERS["trace-probe"]
        self.assertEqual(seen, ["t-real-id"])
        self.assertIsInstance(env["trace"], list)

    def test_a_non_string_trace_never_binds(self):
        """A wrong type costs the correlation, not the ledger write."""
        with obs.trace_scope(["not", "an", "id"]):
            self.assertIsNone(obs.current_trace())
        with obs.trace_scope("   "):
            self.assertIsNone(obs.current_trace())

    def test_local_dispatch_inherits_the_caller_trace(self):
        from app import agents
        seen = []
        agents._HANDLERS["trace-probe"] = {
            "ping": lambda e: seen.append(obs.current_trace()) or {"payload": {}}}
        env = {"protocol": agents.PROTOCOL, "from": "orchestrator",
               "to": "trace-probe", "intent": "ping", "task_id": "task-2",
               "payload": {}}
        try:
            with obs.trace_scope("t-caller"):
                agents.dispatch(env)
        finally:
            del agents._HANDLERS["trace-probe"]
        self.assertEqual(seen, ["t-caller"])

    def test_dispatch_mints_a_trace_when_there_is_none(self):
        from app import agents
        seen = []
        agents._HANDLERS["trace-probe"] = {
            "ping": lambda e: seen.append(obs.current_trace()) or {"payload": {}}}
        env = {"protocol": agents.PROTOCOL, "from": "orchestrator",
               "to": "trace-probe", "intent": "ping", "task_id": "task-3",
               "payload": {}}
        try:
            agents.dispatch(env)
        finally:
            del agents._HANDLERS["trace-probe"]
        self.assertTrue(seen[0] and seen[0].startswith("t-"))

    def test_dispatch_restores_the_previous_trace(self):
        from app import agents
        agents._HANDLERS["trace-probe"] = {
            "ping": lambda e: {"payload": {}}}
        env = {"protocol": agents.PROTOCOL, "from": "orchestrator",
               "to": "trace-probe", "intent": "ping", "task_id": "task-4",
               "payload": {}}
        try:
            with obs.trace_scope("t-outer"):
                agents.dispatch(env)
                self.assertEqual(obs.current_trace(), "t-outer")
        finally:
            del agents._HANDLERS["trace-probe"]


if __name__ == "__main__":
    unittest.main()
