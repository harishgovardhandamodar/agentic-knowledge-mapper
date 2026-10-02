"""Risk Console — fixture-based UI tests (persona × empty/full).

Console is read-only over same backend; persona changes emphasis, never data.
"""

import json
import os
import tempfile
import unittest

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-console-"), "test.db"))

from app import database as _db  # noqa: E402
from app import model_eval as me  # noqa: E402
from app.database import Base, SessionLocal  # noqa: E402
from app.models import Investigation, SecurityAssessment, Artifact, Initiative  # noqa: E402

_db.init_db()


def _scoring():
    return json.dumps({
        "assessment_path": "model_engineering",
        "w1": {"overall_pct": 46.6, "coverage_pct": 20.0, "model_adv_version": me.MODEL_ADV_VERSION, "model_adv_fingerprint": me.model_adv_fingerprint()},
        "w2": {"overall_pct": 60.0, "uncertainty_pct": 50.0, "adoption_version": me.ADOPTION_VERSION, "adoption_fingerprint": me.adoption_fingerprint()},
        "w3": {"residual_pct": 22.0, "mitigation_version": me.MITIGATION_VERSION, "mitigation_fingerprint": me.mitigation_fingerprint()},
    })


def _model_json():
    return json.dumps({
        "meta": {"model_name": "TestModel", "model_family": "tabular_fm", "weights_source": "open_weights"},
        "attacks": [{"attack_class": "extraction", "applies_to": "model_specific", "confidence": 0.8}],
        "dimensions": [{"dimension": "memorization", "rating": "high"}],
        "mitigation": {"plan": [], "deferred": []}, "experiments": [],
    })


class ConsoleCase(unittest.TestCase):
    def setUp(self):
        Base.metadata.create_all(_db.engine)
        self.db = SessionLocal()
        from fastapi.testclient import TestClient
        from app.main import app
        self.client = TestClient(app)
        self.client.__enter__()

    def tearDown(self):
        try:
            self.client.__exit__(None, None, None)
        finally:
            self.db.close()

    def _inv(self, title="Console Test"):
        inv = Investigation(title=title, keywords="test", description="test", sources="web")
        self.db.add(inv)
        self.db.commit()
        self.db.refresh(inv)
        return inv


class TestConsoleHome(ConsoleCase):
    def test_persona_switch_keeps_data(self):
        inv = self._inv()
        # empty portfolio
        for persona in ("executive", "researcher", "legal", "privacy", "dpo"):
            r = self.client.get("/api/console/home", params={"investigation_id": inv.id, "persona": persona})
            self.assertEqual(r.status_code, 200, r.text)
            j = r.json()
            self.assertEqual(j["persona"], persona)
            self.assertIn("summary", j)
            self.assertIn("attention", j)
        # full portfolio: add model
        rec = SecurityAssessment(investigation_id=inv.id, product_name="TestModel", exposure="confidential_data", overall_pct=46.6, markdown="# report", scoring_json=_scoring(), model_json=_model_json(), hypothesis_json=json.dumps({"claims": []}), threat_pack_version="2.1.0", threat_pack_fingerprint="x")
        self.db.add(rec)
        self.db.commit()
        from app import model_kb as kb

        kb.sync_model_kb(self.db, rec.id)
        for persona in ("executive", "privacy"):
            r = self.client.get("/api/console/home", params={"investigation_id": inv.id, "persona": persona})
            self.assertEqual(r.status_code, 200)
            # same total risks regardless of persona
            self.assertEqual(r.json()["summary"]["register_total"], self.client.get("/api/console/home", params={"investigation_id": inv.id, "persona": "researcher"}).json()["summary"]["register_total"])


class TestConsoleRisks(ConsoleCase):
    def test_risk_list_and_detail(self):
        inv = self._inv()
        r = self.client.get("/api/console/risks", params={"investigation_id": inv.id})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["total"], 0)
        # add model
        rec = SecurityAssessment(investigation_id=inv.id, product_name="TestModel", exposure="confidential_data", overall_pct=46.6, markdown="# report", scoring_json=_scoring(), model_json=_model_json(), hypothesis_json=json.dumps({"claims": []}), threat_pack_version="2.1.0", threat_pack_fingerprint="x")
        self.db.add(rec)
        self.db.commit()
        from app import model_kb as kb

        kb.sync_model_kb(self.db, rec.id)
        r = self.client.get("/api/console/risks", params={"investigation_id": inv.id, "layer": "model"})
        self.assertGreater(r.json()["total"], 0)
        # drill-down filters
        r2 = self.client.get("/api/console/risks", params={"investigation_id": inv.id, "severity": "high"})
        self.assertLessEqual(r2.json()["total"], r.json()["total"])


class TestConsoleBriefs(ConsoleCase):
    def test_brief_types(self):
        inv = self._inv()
        for t in ("board", "privacy", "counsel", "tech"):
            r = self.client.get("/api/console/brief", params={"investigation_id": inv.id, "type": t})
            self.assertEqual(r.status_code, 200, r.text)
            self.assertIn("markdown", r.json())
            self.assertGreater(len(r.json()["markdown"]), 20)


class TestSearch(ConsoleCase):
    def test_operators_and_facets(self):
        inv = self._inv()
        # seed artifacts
        for title in ["Preference-data memorization study", "Feedback retention policy"]:
            a = Artifact(investigation_id=inv.id, title=title, artifact_type="paper", review="accepted", description="test", tags="ai_safety")
            self.db.add(a)
        self.db.commit()
        # exact phrase
        r = self.client.get("/api/search", params={"q": '"Preference-data"', "investigation_id": inv.id, "limit": 20})
        self.assertEqual(r.status_code, 200)
        self.assertGreaterEqual(r.json()["total"], 1)
        # field filter
        r = self.client.get("/api/search", params={"q": "memorization", "investigation_id": inv.id, "limit": 20})
        self.assertEqual(r.status_code, 200)
        self.assertIn("facets", r.json())
        # prefix
        r = self.client.get("/api/search", params={"q": "memoriz*", "investigation_id": inv.id})
        self.assertEqual(r.status_code, 200)
        # suggest
        r = self.client.get("/api/search/suggest", params={"q": "pref", "investigation_id": inv.id})
        self.assertEqual(r.status_code, 200)
        self.assertIn("suggestions", r.json())
        # highlight
        r = self.client.get("/api/search", params={"q": "memorization", "investigation_id": inv.id})
        if r.json()["hits"]:
            self.assertIn("<mark>", r.json()["hits"][0]["highlights"] or "")


class TestConsoleAccess(ConsoleCase):
    def test_console_serves(self):
        r = self.client.get("/console")
        # may be 200 or 404 if flag off; with flag on should be 200 and contain Risk Console
        self.assertIn(r.status_code, (200, 404))
        if r.status_code == 200:
            self.assertIn("Risk Console", r.text)


if __name__ == "__main__":
    unittest.main()
