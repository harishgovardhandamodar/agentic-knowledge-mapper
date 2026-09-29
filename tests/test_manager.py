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


if __name__ == "__main__":
    unittest.main()
