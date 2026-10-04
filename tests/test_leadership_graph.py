"""Global knowledge graph and its clusters (leadership sub-tab).

The portfolio-wide graph is the same data the per-investigation graph serves,
but namespaced (``a:`` / ``inv:``) so a global view cannot collide with
itself, and it carries investigation hub nodes so "what collected what" is
visible rather than implied by a foreign key.
"""
import json
import os
import tempfile
import unittest

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.gettempdir(),
                                "akm_test_leadership_graph.db"))

from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal, init_db
from app.models import Artifact, Investigation, Relationship


class GlobalGraphCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def setUp(self):
        self.db = SessionLocal()
        for m in (Artifact, Relationship, Investigation):
            self.db.query(m).delete()
        self.db.commit()
        self.inv1 = Investigation(title="One", keywords="rlhf")
        self.inv2 = Investigation(title="Two", keywords="policy")
        self.db.add_all([self.inv1, self.inv2])
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def _seed(self):
        a1 = Artifact(investigation_id=self.inv1.id, title="paper A",
                      artifact_type="paper", tags="rlhf, preference")
        a2 = Artifact(investigation_id=self.inv1.id, title="paper B",
                      artifact_type="paper", tags="rlhf, safety")
        a3 = Artifact(investigation_id=self.inv2.id, title="news C",
                      artifact_type="news", tags="policy")
        self.db.add_all([a1, a2, a3])
        self.db.commit()
        self.db.add(Relationship(investigation_id=self.inv1.id,
                                 source_id=a1.id, target_id=a2.id,
                                 relationship_type="cites"))
        self.db.commit()
        return a1, a2, a3

    def test_graph_returns_every_artifact_and_investigation_hub(self):
        self._seed()
        with TestClient(app) as c:
            g = c.get("/api/leadership/knowledge-graph").json()
        self.assertEqual(g["counts"]["artifacts"], 3)
        self.assertEqual(g["counts"]["investigations"], 2)
        self.assertEqual(g["counts"]["relationships"], 1)
        types = {n["type"] for n in g["nodes"]}
        self.assertIn("investigation", types)
        # namespacing: no bare id can collide
        self.assertTrue(all(n["id"].startswith(("a:", "inv:"))
                            for n in g["nodes"]))
        # every artifact links to its investigation hub
        collected = [e for e in g["edges"] if e["label"] == "collected_in"]
        self.assertEqual(len(collected), 3)

    def test_category_clusters_group_by_type_across_investigations(self):
        self._seed()
        with TestClient(app) as c:
            d = c.get("/api/leadership/knowledge-graph/clusters?mode=category").json()
        by = {cl["centroid"]: cl["size"] for cl in d["clusters"]}
        self.assertEqual(by.get("paper"), 2)
        self.assertEqual(by.get("news"), 1)

    def test_similarity_clusters_group_by_tag_overlap(self):
        self._seed()
        with TestClient(app) as c:
            d = c.get("/api/leadership/knowledge-graph/clusters?mode=similarity").json()
        self.assertTrue(d["clusters"], "expected at least one similarity cluster")
        biggest = d["clusters"][0]
        self.assertEqual(biggest["size"], 2)
        self.assertEqual(biggest["centroid_tags"], ["rlhf"])

    def test_empty_portfolio_graph_is_honest_not_erroring(self):
        with TestClient(app) as c:
            g = c.get("/api/leadership/knowledge-graph").json()
            cat = c.get("/api/leadership/knowledge-graph/clusters?mode=category").json()
        self.assertEqual(g["counts"]["artifacts"], 0)
        # investigation hubs still exist; artifact nodes do not
        self.assertFalse(any(n["id"].startswith("a:") for n in g["nodes"]))
        self.assertTrue(any(n["type"] == "investigation" for n in g["nodes"]))
        self.assertEqual(g["edges"], [])
        self.assertEqual(cat["clusters"], [])


if __name__ == "__main__":
    unittest.main()