"""Tests for intent-grounded follow-up suggestions (_question_suggestions).

The strip used to print model gap text unfiltered and the top-4 graph
artifacts at any overlap, so product pages and crypto bots showed up as
"next questions" for unrelated queries. Now every candidate scores
overlap against the question+answer intent, graph items must add a term
beyond the investigation's own title, and thin strips refill from the
answer's own section headings -- never invented.
"""
import json
import os
import tempfile
import unittest

# Pin the database before app.database is imported: a module that omits
# this can inherit data/akm.db and write test rows into the live store.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-suggestions-"), "test.db"))

from app import database  # noqa: E402
from app import explainer as ex  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.models import Artifact, Explanation, Investigation  # noqa: E402

database.init_db()

ANSWER = {
    "summary": "KE-02 memorization lets an attacker extract training data.",
    "sections": [
        {"heading": "Attack mechanism",
         "body": "The model regurgitates memorized samples on crafted prompts."},
        {"heading": "Mitigations",
         "body": "Deduplicate training data and filter outputs."},
    ],
    "key_points": ["deduplication helps"],
}
TRACE = {
    "followup_queries": ["What is the capital of Assyria"],
    "gaps": [],
    "hop_plan": [{"missing_topics": ["Concrete mitigation steps for KE-02"]}],
}


def _setup():
    db = SessionLocal()
    try:
        inv = Investigation(title="KE-02 memorization leak",
                            keywords="collibra, leakage, llm",
                            description="training data extraction")
        db.add(inv)
        db.commit()
        db.refresh(inv)
        exp = Explanation(
            investigation_id=inv.id, status="done",
            question="How does memorization extraction attack work",
            answer=json.dumps(ANSWER), trace=json.dumps(TRACE))
        db.add(exp)
        db.commit()
        db.refresh(exp)
        arts = [
            ("Memorization extraction attack KE-02 analysis",
             "paper", "extraction, memorization, attack"),
            ("About the writing assistant", "news", "assistant, product"),
            ("Configure the assistant for a team", "news", "assistant, team"),
        ]
        for title, typ, tags in arts:
            db.add(Artifact(investigation_id=inv.id, title=title,
                            artifact_type=typ, tags=tags))
        db.commit()
        return inv.id, exp.id
    finally:
        db.close()


class TestIntentSuggestions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inv_id, cls.exp_id = _setup()

    def _items(self):
        db = SessionLocal()
        try:
            exp = db.query(Explanation).filter(
                Explanation.id == self.exp_id).first()
            return ex._question_suggestions(exp, db=db)
        finally:
            db.close()

    def test_drifting_followup_dropped_on_topic_kept(self):
        texts = [it["text"] for it in self._items()]
        self.assertFalse(any("Assyria" in t for t in texts))
        self.assertTrue(any("mitigation" in t.lower() for t in texts))

    def test_product_echo_artifacts_dropped(self):
        texts = [it["text"] for it in self._items()]
        self.assertFalse(any("About the writing assistant" in t for t in texts))
        self.assertFalse(any("Configure the assistant" in t for t in texts))
        self.assertTrue(any("KE-02 analysis" in t for t in texts))

    def test_most_plausible_first(self):
        items = self._items()
        scores = []
        db = SessionLocal()
        try:
            exp = db.query(Explanation).filter(
                Explanation.id == self.exp_id).first()
            intent = ex._suggestion_intent(exp)
            for it in items:
                scores.append(ex._overlap(intent, ex._tok(it["text"])))
        finally:
            db.close()
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_fallback_fills_from_answer_sections(self):
        db = SessionLocal()
        try:
            inv = Investigation(title="lonely topic", keywords="",
                                description="")
            db.add(inv)
            db.commit()
            db.refresh(inv)
            exp = Explanation(
                investigation_id=inv.id, status="done",
                question="How does memorization extraction attack work",
                answer=json.dumps(ANSWER), trace=json.dumps({}))
            db.add(exp)
            db.commit()
            db.refresh(exp)
            items = ex._question_suggestions(exp, db=db)
        finally:
            db.close()
        self.assertTrue(items)
        self.assertTrue(all(it["kind"] == "deepen" for it in items))
        self.assertTrue(any("Attack mechanism" in it["text"] for it in items))

    def test_empty_everything_is_empty(self):
        db = SessionLocal()
        try:
            inv = Investigation(title="Q", keywords="", description="")
            db.add(inv)
            db.commit()
            db.refresh(inv)
            exp = Explanation(investigation_id=inv.id, status="done",
                              question="Why is the sky blue",
                              answer=json.dumps({}), trace=json.dumps({}))
            db.add(exp)
            db.commit()
            db.refresh(exp)
            items = ex._question_suggestions(exp, db=db)
        finally:
            db.close()
        self.assertEqual(items, [])

    def test_route_shape(self):
        from fastapi.testclient import TestClient
        from app import main as main_mod
        client = TestClient(main_mod.app)
        r = client.get(f"/api/explanations/{self.exp_id}/suggestions")
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertIn("items", body)
        for it in body["items"]:
            self.assertIn("text", it)
            self.assertIn("kind", it)
        r = client.get("/api/explanations/999999/suggestions")
        self.assertEqual(r.status_code, 404)


if __name__ == "__main__":
    unittest.main()
