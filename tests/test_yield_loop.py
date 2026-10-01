"""End-to-end: the agent loop actually learns from what it kept.

``tests/test_yield_ledger.py`` pins the accounting. This pins the wiring --
that a real run records its round, re-orders its next round by that record, and
that a barren round leaves a trace instead of vanishing.

Run with: ``python3 -m unittest discover -s tests -t .``
"""
import os
import tempfile
import unittest


# Pin the database before app.database is imported: a module that omits
# this can inherit data/akm.db and write test rows into the live store.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-yield-loop-"), "test.db"))

from app import agent as agent_mod  # noqa: E402
from app import database  # noqa: E402
from app import yield_ as yld  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.models import Investigation  # noqa: E402

database.init_db()

_n = {"i": 0}


def new_inv():
    _n["i"] += 1
    db = SessionLocal()
    try:
        inv = Investigation(title=f"frontier alignment {_n['i']}",
                            keywords="interpretability,alignment",
                            description="mechanistic interpretability research",
                            sources="web")
        db.add(inv)
        db.commit()
        return inv.id
    finally:
        db.close()


def candidate(i, title="item"):
    return {"id": None, "title": f"{title} {i}", "url": f"http://x/{i}",
            "snippet": "s", "source": "web"}


class LoopHarness:
    """Drive ``run_investigation_agent`` with the network and LLM stubbed out.

    Restores every patch on exit, so a failing test cannot leak a stub into
    another one -- a leaked ``_run_searches`` would make the whole file lie.
    """

    def __init__(self, *, plan, rounds_found, keep_relevance=0.9,
                 analyze=None):
        self.plan = plan
        self.rounds_found = rounds_found
        self.keep_relevance = keep_relevance
        self.analyze = analyze
        self.searched = []
        self._saved = {}

    def __enter__(self):
        self._saved = {
            "_plan_queries": agent_mod._plan_queries,
            "_run_searches": agent_mod._run_searches,
            "_analyze_batch": agent_mod._analyze_batch,
            "_map_relationships": agent_mod._map_relationships,
            "_persist": agent_mod._persist,
        }
        n = {"round": 0}

        def searches(queries, seen):
            self.searched.append([q["text"] for q in queries])
            idx = n["round"]
            n["round"] += 1
            if idx < len(self.rounds_found):
                return list(self.rounds_found[idx])
            return []

        def analyze(inv, batch, existing, model_subject=False):
            if self.analyze is not None:
                return self.analyze(inv, batch, existing)
            return [{"index": i, "keep": self.keep_relevance > 0,
                     "relevance": self.keep_relevance}
                    for i in range(len(batch))]

        def persist(db, inv_id, kept, run_id=None):
            return [{"id": None, "title": c[0]["title"], "tags": ""}
                    for c in kept]

        agent_mod._plan_queries = lambda inv: {"rationale": "s",
                                               "queries": list(self.plan)}
        agent_mod._run_searches = searches
        agent_mod._analyze_batch = analyze
        agent_mod._map_relationships = lambda *a, **k: 0
        agent_mod._persist = persist
        return self

    def __exit__(self, *exc):
        for name, fn in self._saved.items():
            setattr(agent_mod, name, fn)
        return False


class TestLoopRecordsYield(unittest.TestCase):
    def test_a_kept_round_is_recorded(self):
        inv = new_inv()
        plan = [{"text": "alignment tax", "sources": ["web"]}]
        with LoopHarness(plan=plan, rounds_found=[[candidate(1)]]):
            agent_mod.run_investigation_agent(inv, max_items=5, max_rounds=1)
        db = SessionLocal()
        try:
            rows = yld.shape_stats(db, inv)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["attempts"], 1)
            self.assertEqual(rows[0]["kept"], 1)
            self.assertGreater(rows[0]["yield"], 0)
        finally:
            db.close()

    def test_a_barren_round_is_remembered(self):
        """Analyzed, kept nothing -- the round that used to leave no trace.

        Without this row the loop would re-propose the same dead shape forever,
        because "nothing kept" and "nothing asked" look identical without it.
        """
        inv = new_inv()
        plan = [{"text": "alignment tax", "sources": ["web"]}]
        with LoopHarness(plan=plan, rounds_found=[[candidate(1), candidate(2)]],
                         keep_relevance=0.0):
            agent_mod.run_investigation_agent(inv, max_items=5, max_rounds=1)
        db = SessionLocal()
        try:
            rows = yld.shape_stats(db, inv)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["attempts"], 1)
            self.assertEqual(rows[0]["kept"], 0)
            self.assertEqual(rows[0]["found"], 2)
            self.assertEqual(rows[0]["yield"], 0.0)
        finally:
            db.close()

    def test_llm_call_cost_is_counted(self):
        inv = new_inv()
        plan = [{"text": "alignment tax", "sources": ["web"]}]
        # 7 candidates in batches of 5 -> 2 analysis calls. Both stay under the
        # analyze_cap (max_items*3) so the prefilter does not trim them.
        with LoopHarness(plan=plan, rounds_found=[[candidate(i) for i in range(7)]]):
            agent_mod.run_investigation_agent(inv, max_items=5, max_rounds=1)
        db = SessionLocal()
        try:
            self.assertEqual(yld.shape_stats(db, inv)[0]["llm_calls"], 2)
        finally:
            db.close()

    def test_history_survives_a_later_run(self):
        inv = new_inv()
        plan = [{"text": "alignment tax", "sources": ["web"]}]
        with LoopHarness(plan=plan, rounds_found=[[candidate(1)]]):
            agent_mod.run_investigation_agent(inv, max_items=5, max_rounds=1)
        with LoopHarness(plan=plan, rounds_found=[[candidate(2)]]):
            agent_mod.run_investigation_agent(inv, max_items=5, max_rounds=1)
        db = SessionLocal()
        try:
            row = yld.shape_stats(db, inv)[0]
            self.assertEqual(row["attempts"], 2)
            self.assertEqual(row["kept"], 2)
        finally:
            db.close()

    def test_one_investigations_yield_does_not_leak_into_another(self):
        a, b = new_inv(), new_inv()
        with LoopHarness(plan=[{"text": "alignment tax", "sources": ["web"]}],
                         rounds_found=[[candidate(1)]]):
            agent_mod.run_investigation_agent(a, max_items=5, max_rounds=1)
        db = SessionLocal()
        try:
            self.assertEqual(len(yld.shape_stats(db, a)), 1)
            self.assertEqual(yld.shape_stats(db, b), [])
        finally:
            db.close()


class TestLoopUsesYield(unittest.TestCase):
    def test_a_known_productive_query_is_searched_first(self):
        """A barren history moves the productive query to position 0."""
        inv = new_inv()
        db = SessionLocal()
        try:
            yld.record_yield(db, inv, [{"text": "dead topic"}], found=10,
                             kept=0, llm_calls=2, )
        finally:
            db.close()
        with LoopHarness(plan=[{"text": "dead topic", "sources": ["web"]},
                               {"text": "good topic", "sources": ["web"]}],
                         rounds_found=[[candidate(1)]]) as h:
            agent_mod.run_investigation_agent(inv, max_items=5, max_rounds=1)
        self.assertEqual(h.searched[0], ["good topic", "dead topic"])

    def test_planner_proposals_are_reranked_not_dropped(self):
        inv = new_inv()
        plan = [{"text": "novel one", "sources": ["web"]},
                {"text": "novel two", "sources": ["web"]},
                {"text": "novel three", "sources": ["web"]}]
        with LoopHarness(plan=plan, rounds_found=[[candidate(1)]]) as h:
            agent_mod.run_investigation_agent(inv, max_items=5, max_rounds=1)
        self.assertEqual(sorted(h.searched[0]), sorted(q["text"] for q in plan))

    def test_run_stats_report_cost(self):
        inv = new_inv()
        plan = [{"text": "alignment tax", "sources": ["web"]}]
        with LoopHarness(plan=plan, rounds_found=[[candidate(1)]]):
            agent_mod.run_investigation_agent(inv, max_items=5, max_rounds=1)
        db = SessionLocal()
        try:
            from app.models import AgentRun
            import json
            run = (db.query(AgentRun)
                   .filter(AgentRun.investigation_id == inv).first())
            stats = json.loads(run.stats)
            self.assertIn("llm_calls", stats)
            self.assertIn("query_shapes", stats)
            self.assertEqual(stats["query_shapes"], 1)
        finally:
            db.close()

    def test_a_failing_loop_still_raises(self):
        """Yield recording must not swallow the run's own outcome."""
        inv = new_inv()

        def boom(inv, batch, existing):
            raise RuntimeError("gateway down")

        with LoopHarness(plan=[{"text": "alignment tax", "sources": ["web"]}],
                         rounds_found=[[candidate(1)]], analyze=boom):
            agent_mod.run_investigation_agent(inv, max_items=5, max_rounds=1)
        db = SessionLocal()
        try:
            from app.models import AgentRun
            run = (db.query(AgentRun)
                   .filter(AgentRun.investigation_id == inv).first())
            self.assertEqual(run.status, "error")
        finally:
            db.close()


class TestYieldEndpoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        from app import main as main_mod
        cls.client = TestClient(main_mod.app)
        cls.n = 0

    def _inv(self):
        type(self).n += 1
        r = self.client.post("/api/investigations",
                             json={"title": f"yield api {type(self).n}",
                                   "keywords": "alignment,interpretability",
                                   "description": "mechanistic research",
                                   "sources": "web"})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["id"]

    def test_empty_for_a_fresh_investigation(self):
        inv = self._inv()
        r = self.client.get(f"/api/investigations/{inv}/query-yields")
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["total"], 0)
        self.assertEqual(body["shapes"], [])

    def test_reports_recorded_shapes(self):
        inv = self._inv()
        db = SessionLocal()
        try:
            yld.record_yield(db, inv, [{"text": "alignment tax"}], found=6,
                             kept=3, llm_calls=2)
        finally:
            db.close()
        body = self.client.get(f"/api/investigations/{inv}/query-yields").json()
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["artifacts_kept"], 3)
        self.assertEqual(body["llm_calls"], 2)
        self.assertEqual(body["productive"], 1)
        self.assertEqual(body["barren"], 0)

    def test_counts_barren_shapes(self):
        inv = self._inv()
        db = SessionLocal()
        try:
            yld.record_yield(db, inv, [{"text": "dead topic"}], found=6,
                             kept=0, llm_calls=2)
        finally:
            db.close()
        body = self.client.get(f"/api/investigations/{inv}/query-yields").json()
        self.assertEqual(body["barren"], 1)
        self.assertEqual(body["productive"], 0)

    def test_suggests_untried_shapes(self):
        inv = self._inv()
        body = self.client.get(f"/api/investigations/{inv}/query-yields").json()
        self.assertTrue(body["suggested"])

    def test_reset_clears_history(self):
        inv = self._inv()
        db = SessionLocal()
        try:
            yld.record_yield(db, inv, [{"text": "alignment tax"}], found=6,
                             kept=3, llm_calls=2)
        finally:
            db.close()
        r = self.client.get(f"/api/investigations/{inv}/query-yields?reset=true")
        self.assertEqual(r.json()["cleared"], 1)
        self.assertEqual(r.json()["total"], 0)

    def test_unknown_investigation_is_404(self):
        self.assertEqual(
            self.client.get("/api/investigations/999999/query-yields").status_code,
            404)


if __name__ == "__main__":
    unittest.main()
