"""Manager plan card: plugin mix + episode depth, checked headlessly.

After parsing, the operator must see which investigation-type plugins
take part and pick a depth before running. This drives the *real*
mgrRenderPlan/mgrDepthPreset out of static/index.html in Node and the
parse/run endpoints, so a renamed key or a dropped block fails here
instead of silently in the browser.

Skipped, not failed, when Node is absent.
"""
import os
import shutil
import subprocess
import tempfile
import unittest

# Suite isolation invariant: pin the database in every test module.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-mgrplan-"),
                                "test.db"))

from app import database as _db  # noqa: E402
from app import models as _models  # noqa: E402,F401 -- registers tables

_db.init_db()

HERE = os.path.dirname(os.path.abspath(__file__))
SMOKE = os.path.join(HERE, "js", "manager_plan_smoke.js")


class ManagerPlanCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = shutil.which("node")

    def test_plan_card_shows_plugins_and_depth(self):
        if not self.node:
            self.skipTest("node is not on PATH; the plan card is unchecked")
        r = subprocess.run([self.node, SMOKE], capture_output=True,
                           text=True, timeout=120)
        self.assertEqual(
            r.returncode, 0,
            f"manager plan smoke did not pass:\n{r.stdout}\n{r.stderr}")
        self.assertIn("PASS", r.stdout)

    def test_parse_announces_plugins_and_depths(self):
        from fastapi.testclient import TestClient

        from app.main import app
        with TestClient(app) as c:
            r = c.post("/api/manager/parse",
                       json={"command": "list known CVEs affecting FooBar"})
            self.assertEqual(r.status_code, 200, r.text[:300])
            body = r.json()
            keys = [p["key"] for p in body["plugins"]]
            self.assertEqual(keys, ["adoption", "security",
                                    "vulnerability", "writeup",
                                    "hypothesis"])
            vuln = next(p for p in body["plugins"]
                        if p["key"] == "vulnerability")
            self.assertTrue(vuln["matched"])
            self.assertEqual(set(body["depths"]),
                             {"scout", "standard", "deep"})
            self.assertEqual(body["suggested_depth"], "standard")

    def test_depth_flows_into_launches(self):
        from unittest import mock

        from app import database as _db
        from app import manager as _mgr
        from app.models import Investigation
        db = _db.SessionLocal()
        try:
            plan = {"domain": "d", "exposure": "public",
                    "topics": [{"title": "Widget risks",
                                "subject": "Widget",
                                "description": "d",
                                "keywords": "Widget"}],
                    "summary": {}}
            seen = {}

            def _fake_launch(inv_id, max_items=25, max_rounds=2,
                             trigger="manual"):
                seen.update(max_items=max_items, max_rounds=max_rounds,
                            trigger=trigger)
                return None

            def _fake_assess(inv_id, params, requested_by=""):
                seen["assessed"] = True
                return 1

            with mock.patch.object(_mgr, "launch_run",
                                   side_effect=_fake_launch):
                with mock.patch.object(_mgr, "launch_security_assessment",
                                       side_effect=_fake_assess):
                    row = _mgr.run_plan(
                        db, plan,
                        {"research": True, "assessment": False,
                         "depth": "scout"}, "cmd")
            self.assertEqual(seen["max_items"], 8)
            self.assertEqual(seen["max_rounds"], 1)
            self.assertNotIn("assessed", seen)
            stored = row["children"][0]
            self.assertIsNotNone(stored["investigation_id"])
            inv = db.query(Investigation).filter(
                Investigation.id == stored["investigation_id"]).first()
            self.assertIsNotNone(inv)
            import json as _json

            from app.models import ManagerRun
            run = db.query(ManagerRun).order_by(
                ManagerRun.id.desc()).first()
            opts = _json.loads(run.plan_json).get("options", {})
            self.assertEqual(opts.get("depth"), "scout")
            self.assertEqual(opts.get("max_items"), 8)
        finally:
            db.close()

    def test_garbage_depth_falls_back_to_standard(self):
        from unittest import mock

        from app import database as _db
        from app import manager as _mgr
        db = _db.SessionLocal()
        try:
            plan = {"domain": "d", "exposure": "public",
                    "topics": [{"title": "Widget risks",
                                "subject": "Widget",
                                "description": "d",
                                "keywords": "Widget"}],
                    "summary": {}}
            seen = {}

            def _fake_launch(inv_id, max_items=25, max_rounds=2,
                             trigger="manual"):
                seen.update(max_items=max_items, max_rounds=max_rounds)
                return None

            with mock.patch.object(_mgr, "launch_run",
                                   side_effect=_fake_launch):
                with mock.patch.object(_mgr, "launch_security_assessment",
                                       return_value=1):
                    _mgr.run_plan(
                        db, plan,
                        {"research": True, "assessment": False,
                         "depth": "abyss", "max_items": 9999,
                         "max_rounds": 99}, "cmd")
            self.assertEqual(seen["max_items"], 100)
            self.assertEqual(seen["max_rounds"], 3)
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
