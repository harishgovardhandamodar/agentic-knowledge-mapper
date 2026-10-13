"""Investigation plugins: registry, routing, and read adapters.

The five types share one shape (route a command, plan topics, read an
investigation back) while launches stay in their home modules. Pin
header required suite-wide (see tests/test_db_isolation.py).
"""
import json
import os
import tempfile
import unittest

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-plugins-"),
                                "test.db"))

from app import database as _db  # noqa: E402
from app import plugins as pg  # noqa: E402
from app.models import (  # noqa: E402
    Artifact,
    Explanation,
    Investigation,
    SecurityAssessment,  # noqa: E402,F401
)

_db.init_db()


def _inv(**over):
    base = {"title": "Probe product", "keywords": "ProbeCorp",
            "description": "d", "sources": "web"}
    base.update(over)
    db = _db.SessionLocal()
    try:
        inv = Investigation(**base)
        db.add(inv)
        db.commit()
        db.refresh(inv)
        return inv.id
    finally:
        db.close()


def _db_call(fn, *args):
    db = _db.SessionLocal()
    try:
        return fn(db, *args)
    finally:
        db.close()


class RegistryCase(unittest.TestCase):
    def test_five_plugins_in_order(self):
        self.assertEqual(list(pg.PLUGINS),
                         ["adoption", "security", "vulnerability",
                          "writeup", "hypothesis"])
        for key, plugin in pg.PLUGINS.items():
            self.assertEqual(plugin.key, key)
            self.assertTrue(plugin.title)
            self.assertTrue(plugin.version)
            self.assertTrue(plugin.fingerprint())
            self.assertTrue(callable(plugin.analyze))

    def test_generic_commands_match_nothing(self):
        self.assertIsNone(pg.plan_for(
            "assess the security risk of adopting Collibra"))
        self.assertIsNone(pg.plan_for("research quantum batteries"))


class VulnerabilityTrackCase(unittest.TestCase):
    def test_cve_commands_route(self):
        plan = pg.plan_for("list known CVEs affecting FooBar 2.1")
        self.assertIsNotNone(plan)
        self.assertEqual(plan["plugin"], "vulnerability")
        self.assertEqual(len(plan["topics"]), 1)
        topic = plan["topics"][0]
        self.assertEqual(topic["task"], "vulnerability_landscape")
        self.assertIn("FooBar", topic["subject"])

    def test_manager_routing_needs_no_network(self):
        from app import manager as _mgr
        plan = _mgr.parse_command("list known CVEs affecting FooBar 2.1")
        self.assertEqual(plan.get("plugin"), "vulnerability")
        self.assertEqual(plan["parsed_by"], "vulnerability-template")

    def test_analyze_counts_findings(self):
        iid = _inv()
        db = _db.SessionLocal()
        try:
            db.add(Artifact(investigation_id=iid, title="CVE-2024-0001 X",
                            artifact_type="cve", relevance=0.9))
            db.add(Artifact(investigation_id=iid, title="notes",
                            artifact_type="news"))
            db.commit()
        finally:
            db.close()
        pack = _db_call(pg.PLUGINS["vulnerability"].analyze, iid)
        self.assertEqual(pack["cve_artifacts"], 1)
        self.assertEqual(pack["top"][0]["title"], "CVE-2024-0001 X")


class HypothesisTrackCase(unittest.TestCase):
    def test_scenario_commands_route(self):
        plan = pg.plan_for("enumerate all scenarios for FooBar rollout")
        self.assertIsNotNone(plan)
        self.assertEqual(plan["plugin"], "hypothesis")
        self.assertEqual(plan["topics"][0]["task"],
                         "hypothesis_scenarios")

    def test_manager_routing_needs_no_network(self):
        from app import manager as _mgr
        plan = _mgr.parse_command("what could happen if FooBar leaks keys")
        self.assertEqual(plan.get("plugin"), "hypothesis")


class AdapterCase(unittest.TestCase):
    def test_security_reads_latest(self):
        iid = _inv()
        db = _db.SessionLocal()
        try:
            db.add(SecurityAssessment(
                investigation_id=iid, product_name="Widget",
                exposure="public", overall_pct=10.0, inherent_pct=10.0,
                residual_pct=10.0, markdown="# stub",
                threat_pack_version="2024.1",
                threats_json=json.dumps(
                    [{"title": "T1", "severity": "high"}])))
            db.commit()
        finally:
            db.close()
        pack = _db_call(pg.PLUGINS["security"].analyze, iid)
        self.assertEqual(pack["product"], "Widget")
        self.assertEqual(pack["residual_pct"], 10.0)
        self.assertEqual(pack["top_threats"][0]["title"], "T1")

    def test_security_without_row_is_a_gap(self):
        pack = _db_call(pg.PLUGINS["security"].analyze, _inv())
        self.assertIsNone(pack["assessment"])
        self.assertTrue(pack["gap"])

    def test_writeup_reads_latest(self):
        iid = _inv()
        db = _db.SessionLocal()
        try:
            db.add(Explanation(
                investigation_id=iid, question="What is X?",
                status="done", mode="explain",
                answer=json.dumps({"summary": "X is a thing.",
                                   "diagrams": [{"k": "v"}]})))
            db.commit()
        finally:
            db.close()
        pack = _db_call(pg.PLUGINS["writeup"].analyze, iid)
        self.assertIn("X is a thing", pack["answer_head"])
        self.assertEqual(pack["diagrams"], 1)

    def test_adoption_adapter_runs(self):
        iid = _inv(title="Collibra AI Writing Assistant",
                   keywords="Collibra")
        pack = _db_call(pg.PLUGINS["adoption"].analyze, iid)
        self.assertIn("verdict", pack)
        self.assertTrue(pack["fingerprint"])


if __name__ == "__main__":
    unittest.main()
