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
from app.models import (AgentRun, Artifact, Investigation, ManagerRun,  # noqa: E402
                        SecurityAssessment)

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
                residual_pct=8.0, markdown="# topic report"))
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
            self.assertEqual(first["markdown"], "# synthesis")
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
            with mock.patch.object(mgr.llm, "chat") as mc2:
                second = mgr.compile_run(db, rid)
            self.assertTrue(second["existing"])
            mc2.assert_not_called()
        finally:
            db.close()


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

    def test_run_lists_and_compiles(self):
        with mock.patch.object(mgr, "launch_run"), \
             mock.patch.object(mgr, "launch_security_assessment"):
            r = self.client.post("/api/manager/run", json={"plan": _plan(1)})
        self.assertEqual(r.status_code, 200, r.text)
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
