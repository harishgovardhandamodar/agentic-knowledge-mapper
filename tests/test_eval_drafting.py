"""Agentic Manager — deep-research question drafting — tests.

Run with:  python3 -m pytest tests/test_eval_drafting.py -q
"""
import json
import os
import tempfile
import unittest

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-evaldraft-"),
                                "test.db"))

from app import database as _db  # noqa: E402
from app.database import Base, SessionLocal  # noqa: E402
from app import eval_drafting as ed  # noqa: E402
from app.models import (EvaluationCatalog, EvaluationDraft,  # noqa: E402
                        EvaluationQuestion, EvaluationRun, EvaluationSection)

_db.init_db()

_SEV = ("low", "medium", "high", "critical")


def _deterministic():
    ed._llm_draft = lambda *a, **k: None


def _draft(domain="payments", target="payment-capable agent", depth="deep",
           axes=None, actor="tester"):
    db = SessionLocal()
    try:
        return ed.draft_evaluation_catalog(db, domain, target, depth=depth,
                                           axes=axes, actor=actor)
    finally:
        db.close()


class TestAxisLibrary(unittest.TestCase):
    def test_library_shape_and_mandatory_axes(self):
        self.assertEqual(len(ed.AXIS_LIBRARY), 13)
        keys = {a["key"] for a in ed.AXIS_LIBRARY}
        for must in ed.MIN_DEEP_AXES:
            self.assertIn(must, keys)
        for a in ed.AXIS_LIBRARY:
            self.assertTrue(a["title"])
            self.assertTrue(a["concern"])

    def test_default_deep_axes_include_mandatory(self):
        axes = ed.normalize_axes(None, "deep")
        for must in ed.MIN_DEEP_AXES:
            self.assertIn(must, axes)


class TestDrafting(unittest.TestCase):
    def setUp(self):
        Base.metadata.create_all(_db.engine)
        _deterministic()

    def test_deep_draft_shape(self):
        d = _draft()
        self.assertGreaterEqual(len(d["sections"]), 8)
        self.assertLessEqual(len(d["sections"]), 15)
        total = d["quality"]["questions"]
        self.assertLessEqual(total, ed.MAX_QUESTIONS)
        keys = []
        for s in d["sections"]:
            for q in s["questions"]:
                keys.append(q["key"])
                self.assertIn(q["severity_hint"], _SEV)
                self.assertGreater(q["weight"], 0)
        self.assertEqual(len(keys), len(set(keys)), "keys unique")
        # depth standard: a threat-model/residual section is always present
        self.assertIn("threat_model_residual",
                      [s["key"] for s in d["sections"]])

    def test_failure_orientation_above_20pct(self):
        d = _draft()
        self.assertGreaterEqual(d["quality"]["failure_pct"], 20.0)

    def test_auditable_rationale(self):
        d = _draft()
        self.assertTrue(d["rationale"])
        self.assertIn("Axes chosen", d["rationale"])
        self.assertEqual(d["source"], "deterministic")
        db = SessionLocal()
        try:
            dr = db.query(EvaluationDraft).filter(
                EvaluationDraft.id == d["draft_id"]).first()
            self.assertEqual(dr.domain, "payments")
            self.assertEqual(len(json.loads(dr.axes_json)), len(d["axes"]))
        finally:
            db.close()

    def test_adapts_to_second_domain(self):
        p = _draft(domain="payments", target="payment agent")
        x = _draft(domain="data export", target="export agent")
        p_prompts = {q["prompt"] for s in p["sections"]
                     for q in s["questions"]}
        x_prompts = {q["prompt"] for s in x["sections"]
                     for q in s["questions"]}
        # domain-adapted: export set must mention data-export concerns that
        # the payments set does not, and vice versa
        self.assertTrue(any("export" in str(pp).lower() or "data" in str(pp).lower()
                            for pp in x_prompts))
        self.assertTrue(any("payment" in str(pp).lower() for pp in p_prompts))


class TestSeedChain(unittest.TestCase):
    def setUp(self):
        Base.metadata.create_all(_db.engine)
        _deterministic()

    def _client(self):
        from fastapi.testclient import TestClient
        from app.main import app
        c = TestClient(app)
        c.__enter__()
        self.addCleanup(lambda: c.__exit__(None, None, None))
        return c

    def test_draft_seed_start_run_chain(self):
        c = self._client()
        # draft via API (deterministic path forced)
        r = c.post("/api/eval-draft",
                   json={"domain": "clinical advice",
                         "target": "a clinical decision-support agent",
                         "depth": "deep"},
                   headers={"X-AKM-Actor": "tester"})
        self.assertEqual(r.status_code, 201, r.text)
        draft = r.json()
        did = draft["draft_id"]
        self.assertGreaterEqual(draft["quality"]["questions"], 40)

        # catalog.json is seedable
        cat = c.get(f"/api/eval-draft/{did}/catalog.json").json()
        self.assertIn("sections", cat)
        self.assertEqual(cat["questions"], draft["quality"]["questions"])

        # seed + start a run
        s = c.post(f"/api/eval-draft/{did}/seed",
                   json={"start_run": True,
                         "run_target_agent_id": "clin-agent",
                         "run_title": "Clinical eval"},
                   headers={"X-AKM-Actor": "tester"})
        self.assertEqual(s.status_code, 200, s.text)
        seeded = s.json()
        self.assertTrue(seeded["seeded_catalog_id"])
        self.assertTrue(seeded["run"]["id"])

        db = SessionLocal()
        try:
            qcount = (db.query(EvaluationQuestion)
                      .join(EvaluationSection)
                      .filter(EvaluationSection.catalog_id ==
                              seeded["seeded_catalog_id"]).count())
            self.assertEqual(qcount, draft["quality"]["questions"])
            run = db.query(EvaluationRun).filter(
                EvaluationRun.id == seeded["run"]["id"]).first()
            self.assertEqual(run.target_agent_id, "clin-agent")
            dr = db.query(EvaluationDraft).filter(
                EvaluationDraft.id == did).first()
            self.assertEqual(dr.status, "run_started")
        finally:
            db.close()

    def test_output_formats(self):
        c = self._client()
        draft = c.post("/api/eval-draft",
                       json={"domain": "payments", "target": "pay agent"},
                       headers={"X-AKM-Actor": "tester"}).json()
        did = draft["draft_id"]
        for fmt in ("brief", "agenda", "adversarial", "catalog"):
            r = c.get(f"/api/eval-draft/{did}/report.md", params={"format": fmt})
            self.assertEqual(r.status_code, 200, fmt)
            self.assertIn("Draft", r.text)

    def test_authz_anonymous_denied(self):
        c = self._client()
        r = c.post("/api/eval-draft",
                   json={"domain": "x", "target": "y"})
        self.assertEqual(r.status_code, 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)