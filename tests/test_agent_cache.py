"""Shared research cache: same subject + same questions reuse evidence."""
import json
import os
import tempfile
import unittest

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-cache-"), "test.db"))

from app import agents as am  # noqa: E402
from app import database  # noqa: E402
from app import models as _models  # noqa: E402,F401 -- registers tables
from app.database import SessionLocal  # noqa: E402

database.init_db()


def _payload(inv_id, titles, key="skey-1"):
    return {"product_name": "TabPFN", "use_case": "credit",
            "subject_key": key, "threat_titles": titles, "top_k": 8,
            "investigation_id": inv_id}


def _collect(db, inv_id, titles, key="skey-1"):
    env = am.new_envelope("t", "research-collector", "collect_research",
                          _payload(inv_id, titles, key))
    return am.research_collector_handle(env, db)["payload"]


class TestCollectorCache(unittest.TestCase):
    def setUp(self):
        am._COLLECTOR_CACHE.clear()
        db = SessionLocal()
        try:
            db.query(_models.Artifact).delete()
            db.query(_models.Investigation).delete()
            db.commit()
            inv = _models.Investigation(title="t", keywords="k",
                                        description="d", sources="web")
            db.add(inv)
            db.commit()
            self.inv_id = inv.id
            db.add(_models.Artifact(
                investigation_id=inv.id, title="Membership inference survey",
                artifact_type="paper", source="arxiv", relevance=0.8,
                review="accepted",
                description="membership inference extraction memorization"))
            db.commit()
        finally:
            db.close()

    def test_second_identical_call_hits_cache(self):
        db = SessionLocal()
        try:
            first = _collect(db, self.inv_id, ["membership inference"])
            self.assertFalse(first.get("cached", False))
            self.assertGreater(first["artifacts_scanned"], 0)
            second = _collect(db, self.inv_id, ["membership inference"])
            self.assertTrue(second.get("cached"))
            self.assertEqual(second["artifacts_scanned"], 0)
            self.assertEqual(second["evidence"], first["evidence"])
            self.assertEqual(second["queries_run"], first["queries_run"])
        finally:
            db.close()

    def test_different_questions_miss(self):
        db = SessionLocal()
        try:
            _collect(db, self.inv_id, ["membership inference"])
            other = _collect(db, self.inv_id, ["model watermarking"])
            self.assertFalse(other.get("cached", False))
            self.assertGreater(other["artifacts_scanned"], 0)
        finally:
            db.close()

    def test_new_artifact_invalidates(self):
        db = SessionLocal()
        try:
            _collect(db, self.inv_id, ["membership inference"])
            db.add(_models.Artifact(
                investigation_id=self.inv_id, title="Fresh extraction paper",
                artifact_type="paper", source="arxiv", relevance=0.7,
                review="pending",
                description="training data extraction memorization"))
            db.commit()
            again = _collect(db, self.inv_id, ["membership inference"])
            self.assertFalse(again.get("cached", False))
            titles = [e["title"] for e in again["evidence"]]
            self.assertIn("Fresh extraction paper", titles)
        finally:
            db.close()

    def test_no_subject_key_never_caches(self):
        db = SessionLocal()
        try:
            env = am.new_envelope("t", "research-collector", "collect_research",
                                  {"product_name": "Widget",
                                   "threat_titles": ["membership inference"],
                                   "investigation_id": self.inv_id})
            first = am.research_collector_handle(env, db)["payload"]
            second = am.research_collector_handle(env, db)["payload"]
            self.assertFalse(first.get("cached", False))
            self.assertFalse(second.get("cached", False))
        finally:
            db.close()

    def test_subject_key_is_stable_and_discriminating(self):
        a = am.collector_subject_key("model_engineering", "TabPFN", "tabular_fm")
        self.assertEqual(a, am.collector_subject_key(
            "model_engineering", "TabPFN", "tabular_fm"))
        self.assertNotEqual(a, am.collector_subject_key(
            "model_engineering", "TabPFN", "diffusion"))
        self.assertNotEqual(a, am.collector_subject_key(
            "standard", "TabPFN", "tabular_fm"))


if __name__ == "__main__":
    unittest.main()
