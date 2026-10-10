"""LLM-generated follow-up questions: genuinely new, verified before offered.

Retrieval ranks what already exists; it cannot ask what nobody wrote down.
These tests pin the generation path's contract: grounded questions survive,
ungrounded ones are dropped with the count recorded, duplicates and repeats
of asked questions go, and a dead gateway degrades to retrieval instead of
failing the endpoint.
"""
import json
import os
import tempfile
import unittest
from unittest import mock

# Pin the database before app.database is imported: a module that omits
# this can inherit data/akm.db and write test rows into the live store.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-gen-suggest-"), "test.db"))

from app import database  # noqa: E402
from app import explainer as ex  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.models import Artifact, Explanation, Investigation  # noqa: E402

database.init_db()

ANSWER = {
    "summary": "The egress allowlist permits only approved hosts.",
    "sections": [
        {"heading": "DNS handling",
         "body": "DNS queries go through the broker, which logs them."},
    ],
    "key_points": ["broker logs DNS"],
}


def _exp(db, question="How is egress controlled?"):
    inv = Investigation(title="Egress review", keywords="egress, allowlist")
    db.add(inv)
    db.commit()
    e = Explanation(investigation_id=inv.id, question=question,
                    answer=json.dumps(ANSWER), trace=json.dumps({}),
                    status="done")
    db.add(e)
    db.commit()
    return inv, e


class TestGeneratedFollowups(unittest.TestCase):
    def test_grounded_question_survives(self):
        with mock.patch("app.llm.chat_json", return_value={
                "questions": ["How does the egress allowlist handle DNS?"]}):
            out = ex._generated_followups(
                "How is egress controlled?",
                "The egress allowlist permits only approved hosts.",
                context_terms=["egress", "allowlist", "dns"],
                n=4)
        self.assertTrue(out["generated"])
        self.assertEqual(len(out["items"]), 1)
        self.assertEqual(out["items"][0]["origin"], "generated")

    def test_ungrounded_question_is_dropped_with_count(self):
        with mock.patch("app.llm.chat_json", return_value={
                "questions": ["What is the capital of Mars?",
                              "How does the egress allowlist handle DNS?"]}):
            out = ex._generated_followups(
                "How is egress controlled?",
                "The egress allowlist permits only approved hosts.",
                context_terms=["egress", "allowlist", "dns"],
                n=4)
        self.assertEqual(len(out["items"]), 1)
        self.assertEqual(out["dropped"], 1)

    def test_repeat_of_asked_question_is_dropped(self):
        with mock.patch("app.llm.chat_json", return_value={
                "questions": ["What hosts are approved?"]}):
            out = ex._generated_followups(
                "How is egress controlled?", "The allowlist permits hosts.",
                context_terms=["allowlist", "hosts"],
                asked=["What hosts are approved?"], n=4)
        self.assertEqual(out["items"], [])
        self.assertEqual(out["dropped"], 1)

    def test_duplicates_count_once(self):
        q = "How does the egress allowlist handle DNS?"
        with mock.patch("app.llm.chat_json",
                        return_value={"questions": [q, q]}):
            out = ex._generated_followups(
                "How is egress controlled?",
                "The egress allowlist permits hosts. DNS via broker.",
                context_terms=["egress", "allowlist", "dns", "broker"],
                n=4)
        self.assertEqual(len(out["items"]), 1)
        self.assertEqual(out["dropped"], 1)

    def test_malformed_reply_yields_nothing(self):
        for bad in ({"nope": 1}, ["not", "a", "dict"], "a string", None):
            with mock.patch("app.llm.chat_json", return_value=bad):
                out = ex._generated_followups("q", "a", context_terms=["x"])
                self.assertEqual(out["items"], [])

    def test_dead_gateway_fails_open(self):
        with mock.patch("app.llm.chat_json",
                        side_effect=RuntimeError("gateway down")):
            out = ex._generated_followups("q", "a", context_terms=["x"])
        self.assertEqual(out, {"items": [], "dropped": 0,
                               "generated": False})


class TestSuggestionBlending(unittest.TestCase):
    def test_generated_items_lead_retrieved_ones(self):
        db = SessionLocal()
        try:
            inv, e = _exp(db)
            db.add(Artifact(investigation_id=inv.id, title="Broker DNS logs",
                            artifact_type="news"))
            db.commit()
            with mock.patch("app.llm.chat_json", return_value={
                    "questions": ["Does the broker log DNS for allowlisted hosts?"]}):
                out = ex._question_suggestions(e, db=db, generate=True)
            self.assertTrue(out)
            self.assertEqual(out[0]["origin"], "generated")
        finally:
            db.close()

    def test_failed_generation_leaves_retrieval_untouched(self):
        db = SessionLocal()
        try:
            inv, e = _exp(db)
            plain = ex._question_suggestions(e, db=db, generate=False)
            with mock.patch("app.llm.chat_json",
                            side_effect=RuntimeError("down")):
                degraded = ex._question_suggestions(e, db=db, generate=True)
            self.assertEqual(
                [i["text"] for i in degraded],
                [i["text"] for i in plain])
        finally:
            db.close()

    def test_default_path_is_unchanged(self):
        db = SessionLocal()
        try:
            inv, e = _exp(db)
            out = ex._question_suggestions(e, db=db)
            self.assertFalse(any(i.get("origin") == "generated" for i in out))
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
