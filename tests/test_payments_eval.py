"""Agentic Payments Security & Privacy Evaluation — tests.

Run with:  python3 -m pytest tests/test_payments_eval.py -q
"""
import json
import os
import tempfile
import unittest

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-payeval-"),
                                "test.db"))

from app import database as _db  # noqa: E402
from app.database import Base, SessionLocal  # noqa: E402
from app.models import (EvaluationCatalog, EvaluationQuestion,  # noqa: E402
                        EvaluationSection)
from app import payments_eval as pe  # noqa: E402

_db.init_db()


def _seed():
    db = SessionLocal()
    try:
        return pe.seed_catalog_v1(db)
    finally:
        db.close()


def _make_run(client, actor="tester"):
    r = client.post("/api/payments-eval/runs",
                    json={"target_agent_id": "pay-agent-1",
                          "title": "Test payment agent"},
                    headers={"X-AKM-Actor": actor})
    assert r.status_code == 201, r.text
    return r.json()


class TestSeed(unittest.TestCase):
    def _v1_questions(self, db):
        from sqlalchemy import func
        return (db.query(EvaluationQuestion)
                .join(EvaluationSection)
                .filter(EvaluationSection.catalog_id ==
                        db.query(EvaluationCatalog.id)
                        .filter(EvaluationCatalog.version == "v1"))
                .count())

    def test_catalog_v1_shape(self):
        info = _seed()
        self.assertEqual(info["sections"], 12)
        self.assertEqual(info["questions"], 53)
        self.assertEqual(info["version"], "v1")
        db = SessionLocal()
        try:
            v1_id = db.query(EvaluationCatalog.id).filter(
                EvaluationCatalog.version == "v1").scalar()
            qkeys = [q.key for q in db.query(EvaluationQuestion)
                     .join(EvaluationSection)
                     .filter(EvaluationSection.catalog_id == v1_id).all()]
            self.assertEqual(len(qkeys), len(set(qkeys)),
                             "question keys unique within v1")
            skey = [s.key for s in db.query(EvaluationSection)
                    .filter(EvaluationSection.catalog_id == v1_id).all()]
            self.assertEqual(len(skey), len(set(skey)),
                             "section keys unique within v1")
        finally:
            db.close()

    def test_seed_is_idempotent(self):
        first = _seed()
        second = _seed()
        self.assertEqual(first["questions"], second["questions"])
        db = SessionLocal()
        try:
            v1_id = db.query(EvaluationCatalog.id).filter(
                EvaluationCatalog.version == "v1").scalar()
            qn = (db.query(EvaluationQuestion)
                  .join(EvaluationSection)
                  .filter(EvaluationSection.catalog_id == v1_id).count())
            self.assertEqual(qn, 53)
            self.assertEqual(db.query(EvaluationCatalog).filter(
                EvaluationCatalog.version == "v1").count(), 1)
        finally:
            db.close()


class PaymentsEvalCase(unittest.TestCase):
    def setUp(self):
        Base.metadata.create_all(_db.engine)
        _seed()
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

    def _catalog_sections(self):
        cats = self.client.get("/api/payments-eval/catalogs").json()["catalogs"]
        cat = self.client.get(f"/api/payments-eval/catalogs/{cats[0]['id']}").json()
        return [q["id"] for s in cat["sections"] for q in s["questions"]]

    def _answer(self, run_id, qid, rating, value=None):
        return self.client.patch(
            f"/api/payments-eval/runs/{run_id}/answers/{qid}",
            json={"risk_rating": rating, "answer_value": value or "x",
                  "evidence_url": "https://example.com/evidence",
                  "notes": "seen"}, headers={"X-AKM-Actor": "tester"})


class TestScoring(PaymentsEvalCase):
    def test_score_math(self):
        run = _make_run(self.client)
        qids = self._catalog_sections()
        # 10 pass (weight 1 each), 2 partial, 2 fail, 2 na
        plan = [("pass", 10), ("partial", 2), ("fail", 2), ("na", 2)]
        i = 0
        for rating, n in plan:
            for _ in range(n):
                self._answer(run["run"]["id"], qids[i], rating)
                i += 1
        r = self.client.post(f"/api/payments-eval/runs/{run['run']['id']}/complete",
                             headers={"X-AKM-Actor": "tester"})
        self.assertEqual(r.status_code, 200, r.text)
        d = r.json()["run"]
        # numer = 10*1 + 2*0.5 = 11 ; denom = 14 (2 na excluded from 16)
        self.assertAlmostEqual(d["overall_score"], 100.0 * 11 / 14, places=1)
        self.assertEqual(d["status"], "completed")
        self.assertIn("gaps", r.json())
        gaps = r.json()["gaps"]
        self.assertEqual(len(gaps), 4)  # fail + partial
        # fail/partial sorted by severity: fail first (both same severity -> weight)
        self.assertTrue(all(g["risk_rating"] in ("fail", "partial")
                            for g in gaps))

    def test_all_na_excluded(self):
        run = _make_run(self.client)
        for qid in self._catalog_sections():
            self._answer(run["run"]["id"], qid, "na")
        r = self.client.post(f"/api/payments-eval/runs/{run['run']['id']}/complete",
                             headers={"X-AKM-Actor": "tester"})
        d = r.json()["run"]
        self.assertEqual(d["overall_score"], None)  # no denominator
        self.assertEqual(d["status"], "completed")

    def test_report_markdown_and_json(self):
        run = _make_run(self.client)
        for qid in self._catalog_sections()[:4]:
            self._answer(run["run"]["id"], qid, "pass")
        r = self.client.get(f"/api/payments-eval/runs/{run['run']['id']}/report.md")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Agentic Payments", r.text)
        rj = self.client.get(
            f"/api/payments-eval/runs/{run['run']['id']}/report.json").json()
        self.assertEqual(rj["run"]["target_agent_id"], "pay-agent-1")
        self.assertEqual(len(rj["sections"]), 12)


class TestAuthZ(PaymentsEvalCase):
    def test_anonymous_writes_denied(self):
        r = self.client.post("/api/payments-eval/runs",
                             json={"target_agent_id": "x"})
        self.assertEqual(r.status_code, 401)
        run = _make_run(self.client)
        qid = self._catalog_sections()[0]
        r = self.client.patch(
            f"/api/payments-eval/runs/{run['run']['id']}/answers/{qid}",
            json={"risk_rating": "pass"})
        self.assertEqual(r.status_code, 401)

    def test_role_gate_when_configured(self):
        import app.payments_eval_api as api_mod
        old = api_mod._REQUIRED_ROLES
        api_mod._REQUIRED_ROLES = ["admin", "security"]
        try:
            # without role -> 403
            r = self.client.post("/api/payments-eval/runs",
                                 json={"target_agent_id": "x"},
                                 headers={"X-AKM-Actor": "alice"})
            self.assertEqual(r.status_code, 403)
            # wrong role -> 403
            r = self.client.post("/api/payments-eval/runs",
                                 json={"target_agent_id": "x"},
                                 headers={"X-AKM-Actor": "alice",
                                          "X-AKM-Role": "viewer"})
            self.assertEqual(r.status_code, 403)
            # allowed role -> 201
            r = self.client.post("/api/payments-eval/runs",
                                 json={"target_agent_id": "x"},
                                 headers={"X-AKM-Actor": "alice",
                                          "X-AKM-Role": "security"})
            self.assertEqual(r.status_code, 201, r.text)
        finally:
            api_mod._REQUIRED_ROLES = old

    def test_upsert_and_complete_are_audited(self):
        run = _make_run(self.client)
        qid = self._catalog_sections()[0]
        self._answer(run["run"]["id"], qid, "fail")
        self.client.post(f"/api/payments-eval/runs/{run['run']['id']}/complete",
                         headers={"X-AKM-Actor": "tester"})
        # the run view reflects the answer + completion; human_action records
        # each write on the caller's ledger session (audited in ledger tests)
        r = self.client.get(f"/api/payments-eval/runs/{run['run']['id']}")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["run"]["answered"], 1)
        self.assertEqual(r.json()["run"]["status"], "completed")


class TestNoCredentials(PaymentsEvalCase):
    def test_catalog_never_asks_for_raw_instrument_data(self):
        # SAN check: prompts must not ask the operator to paste raw secrets /
        # card data. Asking *whether* a control exists is fine.
        db = SessionLocal()
        try:
            prompts = [q.prompt for q in db.query(EvaluationQuestion).all()]
        finally:
            db.close()
        banned = ("paste", "enter your", "provide your", "submit your",
                  "your pan", "your card number", "your api key",
                  "your secret")
        for p in prompts:
            low = p.lower()
            self.assertFalse(any(b in low for b in banned),
                             f"prompt asks the operator to disclose raw data: {p}")


if __name__ == "__main__":
    unittest.main(verbosity=2)