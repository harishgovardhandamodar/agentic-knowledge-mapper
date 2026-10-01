"""Tests for the Agentic Manager (app/manager.py + routes).

One command fans out to N investigations (research + security assessment
each) plus a summary investigation that compiles finished children on
demand. Launchers and the model are mocked: these tests pin planning,
creation, status derivation and compilation, never live runs.
"""
import json
import os
import tempfile
import unittest
from unittest import mock

# Pin the database before app.database is imported: a module that omits
# this can inherit data/akm.db and write test rows into the live store.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-manager-"), "test.db"))

from app import database  # noqa: E402
from app import manager as mgr  # noqa: E402
from app import agent as agent_mod  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.models import (AgentEvent, AgentRun, Artifact, Investigation,  # noqa: E402
                        ManagerRun, SecurityAssessment)

database.init_db()

COMMAND = ("Run a detailed security investigations on AI agents in finance "
           "domain, especially Agent initiated payments / trade agents / "
           "deFI agents / crypto trade")


def _plan(n=2):
    return {"domain": "finance", "exposure": "confidential_data",
            "topics": [{"title": f"Topic {i}", "description": f"About {i}",
                        "keywords": f"t{i}", "focus": []} for i in range(n)],
            "summary": {"title": "Summary", "description": "All together"},
            "parsed_by": "test"}


class TestValidatePlan(unittest.TestCase):
    def test_empty_command_is_an_error(self):
        with self.assertRaises(ValueError):
            mgr.parse_command("   ")

    def test_topics_capped_with_flag(self):
        plan = {"topics": [{"title": f"T{i}"} for i in range(9)]}
        out = mgr.validate_plan(plan)
        self.assertEqual(len(out["topics"]), mgr.MAX_TOPICS)
        self.assertTrue(out["truncated"])

    def test_dupes_dropped_and_titles_capped(self):
        plan = {"topics": [{"title": "Same"}, {"title": "same "},
                           {"title": "x" * 200}]}
        out = mgr.validate_plan(plan)
        self.assertEqual([t["title"] for t in out["topics"]],
                         ["Same", "x" * 120])

    def test_no_topics_is_an_error(self):
        with self.assertRaises(ValueError):
            mgr.validate_plan({"topics": []})

    def test_bad_exposure_falls_back(self):
        out = mgr.validate_plan({"topics": [{"title": "T"}],
                                 "exposure": "martian"})
        self.assertEqual(out["exposure"], "confidential_data")


class TestHeuristicSplit(unittest.TestCase):
    def test_example_command_yields_four_topics(self):
        plan = mgr.split_command(COMMAND)
        titles = " | ".join(t["title"] for t in plan["topics"]).lower()
        self.assertEqual(len(plan["topics"]), 4)
        for word in ("payment", "trade", "defi", "crypto"):
            self.assertIn(word, titles)
        self.assertEqual(plan["parsed_by"], "heuristic")
        self.assertIn("finance", plan["domain"].lower())

    def test_parse_prefers_llm_then_falls_back(self):
        with mock.patch.object(mgr.llm, "chat_json",
                               return_value={"domain": "d", "topics": [
                                   {"title": "T", "description": "x"}],
                                   "summary": {}}):
            plan = mgr.parse_command("anything at all")
        self.assertEqual(plan["parsed_by"], "llm")
        self.assertEqual(plan["topics"][0]["title"], "T")
        with mock.patch.object(mgr.llm, "chat_json",
                               side_effect=RuntimeError("model down")):
            plan = mgr.parse_command("Red / Blue")
        self.assertEqual(plan["parsed_by"], "heuristic")
        self.assertEqual(len(plan["topics"]), 2)

    def test_empty_llm_plan_falls_back_to_heuristic(self):
        with mock.patch.object(mgr.llm, "chat_json",
                               return_value={"domain": "d", "topics": [],
                                             "summary": {}}):
            plan = mgr.parse_command("Red / Blue")
        self.assertEqual(plan["parsed_by"], "heuristic")
        self.assertEqual(len(plan["topics"]), 2)

    def test_heuristic_derives_focus_and_domain_context(self):
        plan = mgr.split_command("Customer information / Trade logs")
        by_title = {t["title"]: t for t in plan["topics"]}
        self.assertIn("customer", by_title["Customer information"]["focus"])
        self.assertIn("trade", by_title["Trade logs"]["focus"])
        self.assertTrue(
            by_title["Customer information"]["description"].startswith(
                "Customer information"))
        self.assertIsNone(by_title["Customer information"]["exposure"])


def _db():
    return SessionLocal()


class TestRunPlan(unittest.TestCase):
    def _run(self, n=2, options=None):
        db = _db()
        try:
            with mock.patch.object(mgr, "launch_run") as lr, \
                 mock.patch.object(mgr, "launch_security_assessment") as la:
                row = mgr.run_plan(db, _plan(n), options)
            return row, lr, la
        finally:
            db.close()

    def test_creates_topics_plus_summary_and_launches_both(self):
        row, lr, la = self._run(3)
        self.assertEqual(len(row["children"]), 3)
        self.assertEqual(lr.call_count, 3)
        self.assertEqual(la.call_count, 3)
        self.assertIsNotNone(row["summary_investigation_id"])
        db = _db()
        try:
            summ = db.query(Investigation).filter(
                Investigation.id == row["summary_investigation_id"]).first()
            self.assertIsNotNone(summ)
            self.assertIn("#", summ.description)
            self.assertEqual(summ.status, "draft")
            for c in row["children"]:
                inv = db.query(Investigation).filter(
                    Investigation.id == c["investigation_id"]).first()
                self.assertIsNotNone(inv)
                self.assertIn(f"manager run #{row['id']}", inv.description)
        finally:
            db.close()

    def test_options_can_disable_a_launcher(self):
        row, lr, la = self._run(2, {"research": True, "assessment": False})
        self.assertEqual(lr.call_count, 2)
        la.assert_not_called()

    def test_assessment_params_derive_from_topic(self):
        _, _, la = self._run(1)
        inv_id, params = la.call_args[0][0], la.call_args[0][1]
        self.assertIn("Topic 0", params["product_name"])
        self.assertEqual(params["exposure"], "confidential_data")
        self.assertIn("manager run", la.call_args[1]["requested_by"])

    def test_run_records_the_command(self):
        db = _db()
        try:
            with mock.patch.object(mgr, "launch_run"), \
                 mock.patch.object(mgr, "launch_security_assessment"):
                row = mgr.run_plan(db, _plan(1), None, "Do the thing")
            self.assertEqual(row["command"], "Do the thing")
        finally:
            db.close()

    def test_per_topic_exposure_overrides_and_falls_back(self):
        db = _db()
        try:
            plan = _plan(2)
            plan["topics"][0]["exposure"] = "internal"
            plan["topics"][1]["exposure"] = "martian"
            with mock.patch.object(mgr, "launch_run"), \
                 mock.patch.object(mgr, "launch_security_assessment") as la:
                mgr.run_plan(db, plan, None)
            calls = [c[0][1]["exposure"] for c in la.call_args_list]
            self.assertEqual(calls, ["internal", "confidential_data"])
        finally:
            db.close()


class TestStatuses(unittest.TestCase):
    def _mk_run(self, n=1):
        db = _db()
        try:
            with mock.patch.object(mgr, "launch_run"), \
                 mock.patch.object(mgr, "launch_security_assessment"):
                return mgr.run_plan(db, _plan(n), None)["id"]
        finally:
            db.close()

    def test_fresh_run_is_not_done(self):
        rid = self._mk_run()
        db = _db()
        try:
            run = db.query(ManagerRun).filter(ManagerRun.id == rid).first()
            row = mgr._run_row(db, run)
        finally:
            db.close()
        self.assertFalse(row["all_done"])
        self.assertFalse(row["compiled"])
        self.assertFalse(row["children"][0]["done"])

    def test_done_children_derive_ready(self):
        rid = self._mk_run()
        db = _db()
        try:
            run = db.query(ManagerRun).filter(ManagerRun.id == rid).first()
            plan = json.loads(run.plan_json)
            inv_id = plan["topics"][0]["investigation_id"]
            inv = db.query(Investigation).filter(
                Investigation.id == inv_id).first()
            inv.status = "ready"
            db.add(SecurityAssessment(
                investigation_id=inv_id, product_name="T",
                exposure="confidential_data", overall_pct=10.0,
                markdown="# done"))
            db.commit()
            row = mgr._run_row(db, run)
        finally:
            db.close()
        self.assertTrue(row["children"][0]["done"])
        self.assertTrue(row["all_done"])

    def test_running_research_blocks(self):
        rid = self._mk_run()
        db = _db()
        try:
            run = db.query(ManagerRun).filter(ManagerRun.id == rid).first()
            plan = json.loads(run.plan_json)
            inv_id = plan["topics"][0]["investigation_id"]
            db.add(AgentRun(investigation_id=inv_id, status="running",
                            trigger="manual"))
            db.commit()
            row = mgr._run_row(db, run)
        finally:
            db.close()
        self.assertFalse(row["all_done"])


class TestCompile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        from app import main as main_mod
        cls.client = TestClient(main_mod.app)

    def _ready_run(self):
        db = _db()
        try:
            with mock.patch.object(mgr, "launch_run"), \
                 mock.patch.object(mgr, "launch_security_assessment"):
                row = mgr.run_plan(db, _plan(1), None)
            plan = json.loads(db.query(ManagerRun).filter(
                ManagerRun.id == row["id"]).first().plan_json)
            inv_id = plan["topics"][0]["investigation_id"]
            inv = db.query(Investigation).filter(
                Investigation.id == inv_id).first()
            inv.status = "ready"
            db.add(SecurityAssessment(
                investigation_id=inv_id, product_name="T",
                exposure="confidential_data", overall_pct=10.0,
                residual_pct=8.0, markdown="# topic report",
                threats_json=json.dumps([
                    {"id": "T05", "title": "Prompt injection",
                     "residual_severity": "High", "residual_score": 12.0,
                     "coverage": 20.0, "controls": ["C02"]}])))
            db.commit()
            return row["id"]
        finally:
            db.close()

    def test_pending_compile_is_409(self):
        db = _db()
        try:
            with mock.patch.object(mgr, "launch_run"), \
                 mock.patch.object(mgr, "launch_security_assessment"):
                row = mgr.run_plan(db, _plan(1), None)
            with self.assertRaises(mgr.PendingChildren) as cm:
                mgr.compile_run(db, row["id"])
            self.assertTrue(cm.exception.pending)
        finally:
            db.close()

    def test_unknown_run_is_lookup_error(self):
        db = _db()
        try:
            with self.assertRaises(LookupError):
                mgr.compile_run(db, 999999)
        finally:
            db.close()

    def test_compile_stores_artifact_and_is_idempotent(self):
        rid = self._ready_run()
        db = _db()
        try:
            with mock.patch.object(mgr.llm, "chat",
                                   return_value="# synthesis") as mc:
                first = mgr.compile_run(db, rid)
            self.assertFalse(first["existing"])
            self.assertEqual(first["markdown"].split("## Synthesis")[-1].strip(),
                             "# synthesis")
            # facts survive a terse model: tables precede the synthesis
            head, _, _ = first["markdown"].partition("## Synthesis")
            for needle in ("## Top risks by topic", "T05",
                           "## Overlaps", "## Lapses"):
                self.assertIn(needle, head)
            mc.assert_called_once()
            art = db.query(Artifact).filter(
                Artifact.id == first["artifact_id"]).first()
            self.assertIn(mgr.SYNTH_TAG, art.tags or "")
            self.assertEqual(art.source, "agentic-manager")
            run = db.query(ManagerRun).filter(ManagerRun.id == rid).first()
            self.assertEqual(run.status, "compiled")
            summ = db.query(Investigation).filter(
                Investigation.id == first["summary_investigation_id"]).first()
            self.assertEqual(summ.status, "ready")
            row = mgr._run_row(db, run)
            self.assertEqual(row["synthesis_artifact_id"], first["artifact_id"])
            # the detail endpoint must serve the content: both the View
            # summary toggle and the overlay read detail.content
            detail = self.client.get(
                f"/api/artifacts/{first['artifact_id']}")
            self.assertEqual(detail.status_code, 200, detail.text)
            self.assertIn("## Top risks by topic",
                          detail.json().get("content") or "")
            with mock.patch.object(mgr.llm, "chat") as mc2:
                second = mgr.compile_run(db, rid)
            self.assertTrue(second["existing"])
            mc2.assert_not_called()
        finally:
            db.close()


class TestSubagentMap(unittest.TestCase):
    def test_known_stages_map_to_roles(self):
        self.assertEqual(mgr.subagent("research", "search"), "research-collector")
        self.assertEqual(mgr.subagent("security", "gate"), "control-analyst")
        self.assertEqual(mgr.subagent("security", "score"), "scoring")
        self.assertEqual(mgr.subagent("manager", "compile"), "synthesizer")

    def test_unknown_stage_falls_through(self):
        self.assertEqual(mgr.subagent("research", "frobnicator"), "frobnicator")
        self.assertEqual(mgr.subagent("nope", "plan"), "plan")


def _timeline_run(db, n=1):
    with mock.patch.object(mgr, "launch_run"), \
         mock.patch.object(mgr, "launch_security_assessment"):
        row = mgr.run_plan(db, _plan(n), None)
    return row["id"]


class TestTimeline(unittest.TestCase):
    def test_empty_run_has_lanes_and_pending_flow(self):
        db = _db()
        try:
            rid = _timeline_run(db)
            tl = mgr.run_timeline(db, rid)
        finally:
            db.close()
        self.assertEqual(tl["run_id"], rid)
        ids = [l["id"] for l in tl["lanes"]]
        self.assertEqual(ids[0], "manager")
        self.assertEqual(ids[-1], "summary")
        self.assertEqual(len(ids), 3)
        self.assertTrue(ids[1].startswith("topic-"))
        self.assertTrue(any(e["stage"] == "command" for e in tl["events"]))
        flow = {f["key"]: f for f in tl["flow"]}
        self.assertEqual(flow["research"]["state"], "pending")
        self.assertEqual(flow["summary"]["state"], "pending")

    def test_events_map_to_subagents_and_flow_advances(self):
        from datetime import datetime, timedelta
        db = _db()
        try:
            rid = _timeline_run(db)
            run = db.query(ManagerRun).filter(ManagerRun.id == rid).first()
            plan = json.loads(run.plan_json)
            inv_id = plan["topics"][0]["investigation_id"]
            t0 = datetime(2026, 1, 1, 12, 0, 0)
            rr = AgentRun(investigation_id=inv_id, status="done",
                          trigger="manual", started_at=t0,
                          finished_at=t0 + timedelta(minutes=2))
            db.add(rr)
            db.commit()
            db.refresh(rr)
            db.add(AgentEvent(run_id=rr.id, stage="search",
                              message="Round 1: 5 queries",
                              created_at=t0 + timedelta(seconds=10)))
            sr = AgentRun(investigation_id=inv_id, status="running",
                          trigger="security", started_at=t0 + timedelta(minutes=3))
            db.add(sr)
            db.commit()
            db.refresh(sr)
            db.add(AgentEvent(run_id=sr.id, stage="gate",
                              message="Awaiting approval",
                              created_at=t0 + timedelta(minutes=4)))
            db.add(SecurityAssessment(
                investigation_id=inv_id, product_name="T",
                exposure="confidential_data", overall_pct=40.0,
                markdown="# r"))
            db.commit()
            tl = mgr.run_timeline(db, rid)
        finally:
            db.close()
        by_stage = {}
        for e in tl["events"]:
            by_stage.setdefault(e["stage"], []).append(e)
        search = [e for e in by_stage.get("search", [])
                  if e["lane"].startswith("topic-")]
        self.assertTrue(search)
        self.assertEqual(search[0]["agent"], "research-collector")
        gate = by_stage.get("gate", [])
        self.assertTrue(gate)
        self.assertEqual(gate[0]["agent"], "control-analyst")
        running = [e for e in tl["events"] if e["status"] == "running"]
        self.assertTrue(any("running" in e["label"] for e in running))
        score = [e for e in by_stage.get("score", [])
                 if e["agent"] == "scoring"]
        self.assertTrue(score)
        flow = {f["key"]: f for f in tl["flow"]}
        self.assertEqual(flow["research"]["state"], "done")
        times = [e["t"] for e in tl["events"] if e["t"]]
        self.assertEqual(times, sorted(times))

    def test_lane_cap_keeps_head_and_tail(self):
        from datetime import datetime, timedelta
        db = _db()
        old_cap = mgr.MAX_EVENTS_PER_LANE
        mgr.MAX_EVENTS_PER_LANE = 10
        try:
            rid = _timeline_run(db)
            run = db.query(ManagerRun).filter(ManagerRun.id == rid).first()
            plan = json.loads(run.plan_json)
            inv_id = plan["topics"][0]["investigation_id"]
            rr = AgentRun(investigation_id=inv_id, status="done",
                          trigger="manual")
            db.add(rr)
            db.commit()
            db.refresh(rr)
            t0 = datetime(2026, 1, 1, 12, 0, 0)
            for i in range(30):
                db.add(AgentEvent(run_id=rr.id, stage="search",
                                  message=f"m{i}",
                                  created_at=t0 + timedelta(seconds=i)))
            db.commit()
            tl = mgr.run_timeline(db, rid)
        finally:
            mgr.MAX_EVENTS_PER_LANE = old_cap
            db.close()
        lane_id = f"topic-{inv_id}"
        lane_events = [e for e in tl["events"] if e["lane"] == lane_id]
        self.assertEqual(len(lane_events), 10)
        # created + run-start + 30 search events in the lane, capped at 10.
        self.assertEqual(tl["truncated"].get(lane_id), 22)
        labels = [e["label"] for e in lane_events]
        self.assertIn("m0", labels)
        self.assertIn("m29", labels)

    def test_unknown_run_is_lookup_error(self):
        db = _db()
        try:
            with self.assertRaises(LookupError):
                mgr.run_timeline(db, 999999)
        finally:
            db.close()


class TestSummaryTables(unittest.TestCase):
    R1 = {"id": "T05", "title": "Injection", "residual_severity": "High",
          "residual_score": 12.0, "coverage": 20.0, "controls": ["C02"]}
    R2 = {"id": "T01", "title": "Paste", "residual_severity": "Medium",
          "residual_score": 9.0, "coverage": 80.0, "controls": []}
    R3 = {"id": "T02", "title": "Leak", "residual_severity": "Critical",
          "residual_score": 20.0, "coverage": 0.0, "controls": []}

    def test_top_risks_order_and_cap(self):
        out = mgr.topic_top_risks([self.R2, self.R1, self.R3,
                                   {"no": "id"}, {"id": "T09"}], n=2)
        self.assertEqual([r["id"] for r in out], ["T02", "T05"])
        self.assertEqual(out[0]["controls"], [])

    def test_overlaps_need_two_topics(self):
        ov = mgr.find_overlaps([("A", [self.R1, self.R2]),
                                ("B", [self.R1, self.R3])])
        self.assertEqual([o["id"] for o in ov], ["T05"])
        self.assertEqual(ov[0]["topics"], ["A", "B"])
        self.assertEqual(ov[0]["max_residual"], 12.0)
        self.assertEqual(mgr.find_overlaps([("A", [self.R1])]), [])

    def test_lapse_rule_boundaries(self):
        lapses = mgr.find_lapses([
            ("A", [self.R1, self.R2, self.R3,
                   dict(self.R1, coverage=50.0)])])
        self.assertEqual([(r["topic"], r["id"]) for r in lapses],
                         [("A", "T02"), ("A", "T05")])
        # exactly at the threshold is not a lapse; Medium never is
        self.assertEqual(mgr.find_lapses(
            [("A", [dict(self.R2, residual_severity="High", coverage=50.0),
                    dict(self.R2, coverage=10.0)])]), [])

    def test_tables_render_facts(self):
        md = mgr.render_summary_tables(
            [("A", [self.R1])],
            [{"id": "T05", "title": "Injection", "topics": ["A", "B"],
              "max_residual": 12.0}],
            [{"topic": "A", **self.R3}])
        for needle in ("## Top risks by topic", "T05 Injection",
                       "## Overlaps", "A, B", "## Lapses", "T02 Leak"):
            self.assertIn(needle, md)

    def test_tables_empty_states(self):
        md = mgr.render_summary_tables([("A", [])], [], [])
        self.assertIn("No threat id strikes", md)
        self.assertIn("No High/Critical", md)


class TestManagerLinks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        from app import main as main_mod
        cls.client = TestClient(main_mod.app)

    def test_links_shape(self):
        db = _db()
        try:
            links = mgr.manager_links(db)
        finally:
            db.close()
        self.assertIn("links", links)
        self.assertIn("summaries", links)
        for child, ref in links["links"].items():
            self.assertIn("summary_id", ref)
            self.assertIn("run_id", ref)

    def test_topics_map_to_summary_in_order(self):
        db = _db()
        try:
            with mock.patch.object(mgr, "launch_run"), \
                 mock.patch.object(mgr, "launch_security_assessment"):
                row = mgr.run_plan(db, _plan(2), None)
            links = mgr.manager_links(db)
        finally:
            db.close()
        kids = [c["investigation_id"] for c in row["children"]]
        for kid in kids:
            self.assertEqual(links["links"][str(kid)]["summary_id"],
                             row["summary_investigation_id"])
            self.assertEqual(links["links"][str(kid)]["run_id"], row["id"])
        meta = links["summaries"][str(row["summary_investigation_id"])]
        self.assertEqual(meta["topic_ids"], kids)
        self.assertEqual(meta["run_id"], row["id"])

    def test_latest_run_wins(self):
        db = _db()
        try:
            with mock.patch.object(mgr, "launch_run"), \
                 mock.patch.object(mgr, "launch_security_assessment"):
                first = mgr.run_plan(db, _plan(1), None)
                second = mgr.run_plan(db, _plan(1), None)
            # re-point the second run at the first run's child: the sidebar
            # must nest it under the newest summary
            kid = first["children"][0]["investigation_id"]
            run2 = db.query(ManagerRun).filter(
                ManagerRun.id == second["id"]).first()
            plan2 = json.loads(run2.plan_json)
            plan2["topics"][0]["investigation_id"] = kid
            run2.plan_json = json.dumps(plan2)
            db.commit()
            links = mgr.manager_links(db)
        finally:
            db.close()
        self.assertEqual(links["links"][str(kid)]["run_id"], second["id"])
        self.assertEqual(links["links"][str(kid)]["summary_id"],
                         second["summary_investigation_id"])

    def test_links_route_shape(self):
        r = self.client.get("/api/manager/links")
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertIn("links", body)
        self.assertIn("summaries", body)


class TestManagerRoutes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        from app import main as main_mod
        cls.client = TestClient(main_mod.app)

    def test_parse_empty_is_400(self):
        r = self.client.post("/api/manager/parse", json={"command": "  "})
        self.assertEqual(r.status_code, 400)

    def test_parse_uses_heuristic_when_model_down(self):
        with mock.patch.object(mgr.llm, "chat_json",
                               side_effect=RuntimeError("down")):
            r = self.client.post("/api/manager/parse",
                                 json={"command": "Red / Blue"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["parsed_by"], "heuristic")
        self.assertEqual(len(r.json()["topics"]), 2)

    def test_run_rejects_bad_plan(self):
        r = self.client.post("/api/manager/run", json={"plan": {"topics": []}})
        self.assertEqual(r.status_code, 422)

    def test_timeline_route_shape_and_404(self):
        db = _db()
        try:
            rid = _timeline_run(db)
        finally:
            db.close()
        r = self.client.get(f"/api/manager/runs/{rid}/timeline")
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        for key in ("run_id", "t0", "lanes", "events", "flow"):
            self.assertIn(key, body)
        self.assertTrue(any(l["kind"] == "topic" for l in body["lanes"]))
        r = self.client.get("/api/manager/runs/999999/timeline")
        self.assertEqual(r.status_code, 404)

    def test_run_lists_and_compiles(self):
        with mock.patch.object(mgr, "launch_run"), \
             mock.patch.object(mgr, "launch_security_assessment"):
            r = self.client.post("/api/manager/run",
                                 json={"plan": _plan(1),
                                       "command": "Do the thing"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["command"], "Do the thing")
        rid = r.json()["id"]
        r = self.client.get("/api/manager/runs")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(any(x["id"] == rid for x in r.json()["runs"]))
        r = self.client.get(f"/api/manager/runs/{rid}")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json()["all_done"])
        r = self.client.post(f"/api/manager/runs/{rid}/compile")
        self.assertEqual(r.status_code, 409, r.text)
        self.assertIn("pending", r.json()["detail"])
        r = self.client.get("/api/manager/runs/999999")
        self.assertEqual(r.status_code, 404)


TABULAR_CMD = ("Run detailed security investigations on Tabular Foundation "
               "Models. Focus on advancements on capabilities rather than "
               "performance improvement in efficacy and efficiency — Run detailed "
               "security investigations on Tabular Foundation Models. Focus on "
               "advancements on capabilities rather than performance improvement "
               "in efficacy and efficiency")


class TestManagerIntent(unittest.TestCase):
    """The manager must understand the prompt, not echo it.

    Run #7 pasted its command twice and carried the verb phrase into every
    field; the assessment then scored a command string as if it were a
    chatbot. These pin: dedupe, subject extraction, clean focus terms with
    explicit anti-focus, and product_name = subject at launch.
    """

    def test_duplicate_command_collapses(self):
        plan = mgr.split_command(TABULAR_CMD)
        self.assertEqual(len(plan["topics"]), 1)
        t = plan["topics"][0]
        self.assertEqual(t["description"].count("Tabular Foundation Models"), 1)
        self.assertNotIn("—", t["title"])

    def test_single_topic_title_is_subject_not_command(self):
        plan = mgr.split_command(TABULAR_CMD)
        t = plan["topics"][0]
        self.assertEqual(t["title"], "Tabular Foundation Models")
        self.assertEqual(t["subject"], "Tabular Foundation Models")
        for verb in ("run detailed", "investigations on"):
            self.assertNotIn(verb, t["title"].lower())

    def test_focus_terms_are_content_anti_focus_is_exclusion(self):
        plan = mgr.split_command(TABULAR_CMD)
        t = plan["topics"][0]
        for term in ("tabular", "foundation", "models", "advancements",
                     "capabilities"):
            self.assertIn(term, t["focus"])
        for junk in ("security", "investigations", "focus", "rather",
                     "than", "run", "detailed"):
            self.assertNotIn(junk, t["focus"])
        for out in ("performance", "efficacy", "efficiency"):
            self.assertIn(out, t["anti_focus"])
            self.assertNotIn(out, t["focus"])
        self.assertIn("Explicitly out of scope", t["description"])

    def test_run_plan_assesses_subject_with_directives(self):
        db = SessionLocal()
        try:
            plan = mgr.split_command(TABULAR_CMD)
            with mock.patch.object(mgr, "launch_run"), \
                 mock.patch.object(mgr, "launch_security_assessment") as la:
                mgr.run_plan(db, plan, {"research": False, "assessment": True},
                             TABULAR_CMD)
            # A model subject gets three assessments -- soundness, misuse, and
            # the hypothesis synthesis over the two -- because the questions
            # have different agents, weights and meanings. One averaged row
            # would bury all three answers. The order matters: the third
            # reads the stored rows of the first two, and the job queue claims
            # in id order, so it must be queued last.
            self.assertEqual(la.call_count, 3)
            modes = [c[0][1]["assessment_mode"] for c in la.call_args_list]
            self.assertEqual(modes, ["target", "adversarial", "hypothesis"])
            for call in la.call_args_list:
                params = call[0][1]
                self.assertEqual(params["product_name"], "Tabular Foundation Models")
                self.assertIn("Explicitly out of scope", params["use_case"])
                self.assertIn("performance", params["use_case"])
        finally:
            db.close()

    def test_run_plan_catalog_topic_launches_one_assessment(self):
        db = SessionLocal()
        try:
            plan = mgr.split_command("run security assessments on Stripe "
                                     "payment flows")
            with mock.patch.object(mgr, "launch_run"), \
                 mock.patch.object(mgr, "launch_security_assessment") as la:
                mgr.run_plan(db, plan, {"research": False, "assessment": True},
                             "run security assessments on Stripe payment flows")
            # Not a model: the misuse question does not apply, so it must not
            # be launched dressed up as if it did.
            self.assertEqual(la.call_count, 1)
            self.assertEqual(la.call_args[0][1]["assessment_mode"], "")
        finally:
            db.close()

    def test_llm_parse_asks_for_subject_and_exclusions(self):
        seen = {}

        def fake_chat(messages, **kw):
            seen["system"] = messages[0]["content"]
            return {"domain": "d", "topics": [
                {"title": "T", "description": "x", "subject": "S",
                 "anti_focus": ["z"]}], "summary": {}}

        with mock.patch.object(mgr.llm, "chat_json", side_effect=fake_chat):
            plan = mgr.parse_command("anything at all")
        self.assertIn("subject", seen["system"])
        self.assertIn("anti_focus", seen["system"])
        self.assertEqual(plan["topics"][0]["subject"], "S")
        self.assertEqual(plan["topics"][0]["anti_focus"], ["z"])

    def test_verb_lead_stripping_still_works(self):
        for cmd, want in [
                ("Run detailed security investigations on Tabular", "Tabular"),
                ("Please run research on X", "X"),
                ("Execute a security study of payments", "payments")]:
            self.assertEqual(mgr.split_command(cmd)["topics"][0]["title"], want)


class TestGapRequeue(unittest.TestCase):
    """Interrupted explainer_gap runs relaunch with their goal, not vanish."""

    def _gap_run(self, db, inv_id, goal="Investigate open questions: residency",
                 attempt=1, status="running", trigger="explainer_gap"):
        plan = {"goal": goal}
        if attempt != 1:
            plan["gap_attempt"] = attempt
        r = AgentRun(investigation_id=inv_id, status=status, trigger=trigger,
                     plan=json.dumps(plan))
        db.add(r)
        db.commit()
        return r.id

    def test_interrupted_gap_is_relaunched_with_goal(self):
        db = SessionLocal()
        try:
            inv = Investigation(title="t", keywords="k", description="d")
            db.add(inv)
            db.commit()
            calls = []

            def fake_launcher(inv_id, goal, **kw):
                calls.append((inv_id, goal, kw))
                return 777

            old_id = self._gap_run(db, inv.id)
            got = agent_mod.requeue_interrupted_gaps(db, launcher=fake_launcher)
            self.assertEqual([(inv.id,
                               "Investigate open questions: residency")],
                             [(c[0], c[1]) for c in calls])
            self.assertEqual(calls[0][2].get("plan_extra"), {"gap_attempt": 2})
            old = db.query(AgentRun).filter(AgentRun.id == old_id).first()
            self.assertEqual(old.status, "error")
            self.assertIn("re-queued as run #777", old.error)
            self.assertIn(old_id, got)
            self.assertIn(777, got)
        finally:
            db.close()

    def test_second_attempt_is_not_requeued(self):
        db = SessionLocal()
        try:
            inv = Investigation(title="t", keywords="k", description="d")
            db.add(inv)
            db.commit()
            old_id = self._gap_run(db, inv.id, attempt=2)
            got = agent_mod.requeue_interrupted_gaps(
                db, launcher=mock.Mock(side_effect=AssertionError("relaunched")))
            self.assertEqual(got, [])
            old = db.query(AgentRun).filter(AgentRun.id == old_id).first()
            self.assertEqual(old.status, "running")
        finally:
            db.close()

    def test_other_triggers_are_untouched(self):
        db = SessionLocal()
        try:
            inv = Investigation(title="t", keywords="k", description="d")
            db.add(inv)
            db.commit()
            old_id = self._gap_run(db, inv.id, trigger="manual")
            got = agent_mod.requeue_interrupted_gaps(
                db, launcher=mock.Mock(side_effect=AssertionError("relaunched")))
            self.assertEqual(got, [])
            old = db.query(AgentRun).filter(AgentRun.id == old_id).first()
            self.assertEqual(old.status, "running")
        finally:
            db.close()


class TestSecurityRunStats(unittest.TestCase):
    """Every security run leaves measurable stats, pass or fail."""

    def test_completed_stats_carry_provenance(self):
        from app import security_agent as sec_mod
        stats = sec_mod.security_run_stats(
            {"overall_pct": 24.3, "inherent_pct": 68.8, "residual_pct": 24.3,
             "delta": -44.5, "posture": "LOW RISK", "active_controls": ["C01"],
             "confidence": 0.5, "threats": [{"id": "T01"}],
             "evidence": [{}, {}], "known_exploits": []},
            assessment_id=16, duration_ms=90000)
        for key in ("assessment_id", "overall_pct", "inherent_pct",
                    "residual_pct", "posture", "pack_version",
                    "pack_fingerprint", "control_count", "threats",
                    "evidence", "duration_ms"):
            self.assertIn(key, stats)
        self.assertEqual(stats["assessment_id"], 16)
        self.assertEqual(stats["control_count"], 1)
        self.assertTrue(stats["pack_version"])
        self.assertTrue(stats["pack_fingerprint"])


class TestVendorDocQuery(unittest.TestCase):
    """A product brief always gets one official-docs query family."""

    @classmethod
    def setUpClass(cls):
        import importlib
        # Other test modules replace agent_mod._plan_queries globally at
        # import time; reload to get the real planner back for these tests,
        # then restore the replacement afterwards.
        cls._patched = agent_mod._plan_queries
        importlib.reload(agent_mod)

    @classmethod
    def tearDownClass(cls):
        agent_mod._plan_queries = cls._patched

    def _inv(self, title, keywords="", description=""):
        from types import SimpleNamespace
        return SimpleNamespace(title=title, keywords=keywords,
                               description=description, sources="rss,arxiv,web")

    def _planned(self, inv, queries):
        with mock.patch.object(
                agent_mod.llm, "chat_json",
                return_value={"rationale": "r", "queries": queries}):
            return agent_mod._plan_queries(inv)["queries"]

    def test_product_brief_gains_vendor_doc_query(self):
        inv = self._inv("Collibra AI Writing Assistant on Restricted Data",
                        keywords="Collibra AI writing assistant, LLM leakage")
        got = self._planned(inv, [
            {"text": "Collibra AI writing assistant", "sources": ["web"]},
            {"text": "LLM data leakage catalog", "sources": ["arxiv"]}])
        texts = [q["text"] for q in got]
        self.assertTrue(any("security architecture data flow" in t
                            for t in texts),
                        texts)
        self.assertLessEqual(len(got), 6)

    def test_existing_docs_query_is_not_duplicated(self):
        inv = self._inv("Collibra AI Writing Assistant on Restricted Data")
        got = self._planned(inv, [
            {"text": "Collibra admin security architecture", "sources": ["web"]}])
        self.assertEqual(len(got), 1)

    def test_generic_brief_is_untouched(self):
        inv = self._inv("payment fraud review",
                        keywords="payments, fraud")
        got = self._planned(inv, [
            {"text": "payment fraud review", "sources": ["rss"]}])
        self.assertEqual([q["text"] for q in got],
                         ["payment fraud review"])

    def test_diffusion_brief_is_a_model_brief(self):
        # Diffusion models are a first-class target family, so the
        # adversarial/model-card families apply here too.
        inv = self._inv("diffusion models capability review",
                        keywords="diffusion, capability")
        got = self._planned(inv, [
            {"text": "diffusion models capability", "sources": ["arxiv"]}])
        texts = [q["text"] for q in got]
        self.assertTrue(any("memorization" in t for t in texts), texts)


if __name__ == "__main__":
    unittest.main()
