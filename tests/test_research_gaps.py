"""Tests for research gaps and the investigation summary overlay.

Gaps rank open questions by how little supports them (novel first), and a
paper-first run launches on the least-covered ones. The summary overlay
combines deterministic facts (counts, top artifacts, top threats) with an
LLM executive paragraph that falls back to a factual brief.
"""
import json
import os
import tempfile
import unittest
from unittest import mock

# Pin the database before app.database is imported: a module that omits
# this can inherit data/akm.db and write test rows into the live store.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-gaps-"), "test.db"))

from app import database  # noqa: E402
from app import explainer as ex  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.models import (Artifact, CveFinding, Explanation, Investigation,  # noqa: E402
                        SecurityAssessment)

database.init_db()


def _inv(db, title="Gap country"):
    inv = Investigation(title=title, keywords="gaps, papers",
                        description="find the holes")
    db.add(inv)
    db.commit()
    db.refresh(inv)
    return inv.id


def _exp(db, inv_id, question, trace=None):
    exp = Explanation(investigation_id=inv_id, status="done",
                      question=question, answer=json.dumps({"summary": "s"}),
                      trace=json.dumps(trace or {}))
    db.add(exp)
    db.commit()
    db.refresh(exp)
    return exp.id


def _art(db, inv_id, title, tags="", typ="news", relevance=0.5,
         review="pending"):
    a = Artifact(investigation_id=inv_id, title=title, tags=tags,
                 artifact_type=typ, relevance=relevance, review=review)
    db.add(a)
    db.commit()
    db.refresh(a)
    return a.id


TRACE = {"hop_plan": [{"missing_topics": [
    "Covered gap with supporting artifact",
    "Lonely gap nobody collected",
]}]}


class TestResearchGaps(unittest.TestCase):
    def test_novel_first_then_coverage(self):
        db = SessionLocal()
        try:
            inv_id = _inv(db)
            _exp(db, inv_id, "What is missing here", TRACE)
            _art(db, inv_id, "A paper covering the covered gap",
                 tags="covered gap supporting artifact")
            out = ex.investigation_gaps(db, inv_id)
        finally:
            db.close()
        self.assertEqual([g["question"] for g in out["gaps"]],
                         ["Lonely gap nobody collected",
                          "Covered gap with supporting artifact"])
        self.assertTrue(out["gaps"][0]["novel"])
        self.assertFalse(out["gaps"][1]["novel"])
        self.assertGreaterEqual(out["gaps"][1]["supporting"], 1)

    def test_novel_areas_from_untagged_ground(self):
        db = SessionLocal()
        try:
            inv_id = _inv(db)
            _exp(db, inv_id, "What about quantum", {})
            _art(db, inv_id, "Post-quantum migration survey",
                 tags="postquantum migration lattices")
            areas = ex.investigation_gaps(db, inv_id)["novel_areas"]
        finally:
            db.close()
        topics = [a["topic"] for a in areas]
        self.assertIn("postquantum", topics)

    def test_launch_runs_on_least_covered(self):
        db = SessionLocal()
        try:
            inv_id = _inv(db)
            _exp(db, inv_id, "What is missing here", TRACE)
            _art(db, inv_id, "A paper covering the covered gap",
                 tags="covered gap supporting artifact")
            with mock.patch("app.agent.launch_run_with_goal",
                            return_value=77) as m:
                out = ex.launch_gap_research(db, inv_id, top_n=1)
        finally:
            db.close()
        self.assertEqual(out["launched"]["run_id"], 77)
        self.assertIn("Lonely gap", out["launched"]["goal"])
        self.assertIn("paper", out["launched"]["goal"].lower())
        m.assert_called_once()
        self.assertEqual(len(out["gaps"]), 1)

    def test_no_gaps_launches_nothing(self):
        db = SessionLocal()
        try:
            inv_id = _inv(db)
            with mock.patch("app.agent.launch_run_with_goal") as m:
                out = ex.launch_gap_research(db, inv_id)
        finally:
            db.close()
        self.assertEqual(out["gaps"], [])
        self.assertIsNone(out["launched"])
        m.assert_not_called()


class TestInvestigationSummary(unittest.TestCase):
    def _full(self):
        db = SessionLocal()
        try:
            inv_id = _inv(db, "Summary state")
            _art(db, inv_id, "Top paper", tags="t", typ="paper",
                 relevance=0.9, review="accepted")
            _art(db, inv_id, "Old news", tags="t", typ="news",
                 relevance=0.2, review="pending")
            db.add(SecurityAssessment(
                investigation_id=inv_id, product_name="P",
                exposure="confidential_data", overall_pct=40.0,
                residual_pct=30.0, markdown="# r",
                threats_json=json.dumps([
                    {"id": "T05", "title": "Inj", "residual_severity": "High",
                     "residual_score": 12.0},
                    {"id": "T01", "title": "Paste", "residual_severity": "Low",
                     "residual_score": 2.0}])))
            _exp(db, inv_id, "What is the risk here", {})
            db.add(CveFinding(investigation_id=inv_id,
                              cve_id="CVE-2025-0001", title="A bug"))
            db.commit()
            return inv_id
        finally:
            db.close()

    def test_deterministic_fallback_when_model_down(self):
        inv_id = self._full()
        db = SessionLocal()
        try:
            with mock.patch.object(ex.llm, "chat",
                                   side_effect=RuntimeError("down")):
                out = ex.investigation_summary(db, inv_id)
        finally:
            db.close()
        self.assertEqual(out["synthesis"], "deterministic")
        self.assertIn("2 artifacts", out["executive_summary"])
        self.assertIn("1 papers", out["executive_summary"])
        self.assertEqual(out["counts"]["cves"], 1)
        self.assertEqual(out["counts"]["threats"], 2)
        self.assertEqual(out["top_artifacts"][0]["title"], "Top paper")
        self.assertEqual(out["top_findings"]["threats"][0]["id"], "T05")
        self.assertEqual(len(out["top_findings"]["explanations"]), 1)

    def test_llm_preferred_when_up(self):
        inv_id = self._full()
        db = SessionLocal()
        try:
            with mock.patch.object(ex.llm, "chat",
                                   return_value="  Sharp paragraph.  "):
                out = ex.investigation_summary(db, inv_id)
        finally:
            db.close()
        self.assertEqual(out["synthesis"], "llm")
        self.assertEqual(out["executive_summary"], "Sharp paragraph.")

    def test_hanging_model_falls_back_fast(self):
        import time
        inv_id = self._full()
        db = SessionLocal()
        try:
            def slow(*a, **k):
                time.sleep(30)
                return "too late"
            with mock.patch.object(ex.llm, "chat", side_effect=slow):
                with mock.patch.object(ex, "SUMMARY_LLM_TIMEOUT_S", 0.2):
                    t0 = time.monotonic()
                    out = ex.investigation_summary(db, inv_id)
                    dt = time.monotonic() - t0
            self.assertEqual(out["synthesis"], "deterministic")
            self.assertLess(dt, 10)
        finally:
            db.close()

    def test_unknown_investigation_is_lookup_error(self):
        db = SessionLocal()
        try:
            with self.assertRaises(LookupError):
                ex.investigation_summary(db, 999999)
        finally:
            db.close()


class TestIntelRoutes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        from app import main as main_mod
        cls.client = TestClient(main_mod.app)

    def test_gaps_and_summary_shapes(self):
        db = SessionLocal()
        try:
            inv_id = _inv(db)
            _exp(db, inv_id, "What is missing here", TRACE)
        finally:
            db.close()
        r = self.client.get(f"/api/investigations/{inv_id}/research-gaps")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIn("gaps", r.json())
        self.assertIn("novel_areas", r.json())
        r = self.client.get(f"/api/investigations/{inv_id}/summary")
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        for key in ("executive_summary", "counts", "top_artifacts",
                    "top_findings"):
            self.assertIn(key, body)

    def test_run_launches(self):
        db = SessionLocal()
        try:
            inv_id = _inv(db)
            _exp(db, inv_id, "What is missing here", TRACE)
        finally:
            db.close()
        with mock.patch("app.agent.launch_run_with_goal",
                        return_value=78):
            r = self.client.post(
                f"/api/investigations/{inv_id}/research-gaps/run", json={})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["launched"]["run_id"], 78)

    def test_unknown_investigation_404s(self):
        for method, path, kwargs in [
                ("get", "/api/investigations/999999/research-gaps", {}),
                ("post", "/api/investigations/999999/research-gaps/run", {"json": {}}),
                ("get", "/api/investigations/999999/summary", {}),
                ("post", "/api/investigations/999999/summary/regenerate", {})]:
            r = getattr(self.client, method)(path, **kwargs)
            self.assertEqual(r.status_code, 404, path)


class TestSummarySubTab(unittest.TestCase):
    """The Summary sub-tab: query brief, flag-aware evidence, answers with
    supporting materials, a deterministic evidence diagram, and regenerate."""

    def _flagged(self):
        db = SessionLocal()
        try:
            inv_id = _inv(db, "Flagged brief")
            _art(db, inv_id, "Kept grid report about duke energy",
                 tags="duke energy grid", typ="news", relevance=0.9,
                 review="accepted")
            _art(db, inv_id, "Rejected spam post", tags="spam",
                 typ="news", relevance=0.1, review="rejected")
            _art(db, inv_id, "Pending duke storage paper",
                 tags="duke storage", typ="paper", relevance=0.7,
                 review="pending")
            db.add(Explanation(
                investigation_id=inv_id, status="done",
                question="What is duke doing on grid storage?",
                answer=json.dumps(
                    {"summary": "Duke pilots grid storage."}),
                trace="{}"))
            db.commit()
            return inv_id
        finally:
            db.close()

    def _summarize(self, inv_id):
        db = SessionLocal()
        try:
            with mock.patch.object(ex.llm, "chat",
                                   side_effect=RuntimeError("down")):
                return ex.investigation_summary(db, inv_id)
        finally:
            db.close()

    def test_query_brief_and_flag_counts(self):
        out = self._summarize(self._flagged())
        self.assertEqual(out["query"]["title"], "Flagged brief")
        self.assertIn("gaps", out["query"]["keywords"])
        self.assertEqual(out["flags"],
                         {"accepted": 1, "pending": 1, "rejected": 1,
                          "drift": 0})

    def test_rejected_artifacts_are_flagged_out(self):
        out = self._summarize(self._flagged())
        titles = [a["title"] for a in out["top_artifacts"]]
        self.assertNotIn("Rejected spam post", titles)
        self.assertEqual(titles[0], "Kept grid report about duke energy")

    def test_answers_carry_excerpts_and_supporting_materials(self):
        out = self._summarize(self._flagged())
        self.assertEqual(len(out["answers"]), 1)
        ans = out["answers"][0]
        self.assertIn("Duke pilots grid storage.", ans["excerpt"])
        self.assertTrue(ans["supporting"], "answer must name its evidence")
        for s in ans["supporting"]:
            self.assertNotEqual(s["review"], "rejected")
            self.assertIn("id", s)
        kept = {s["title"] for s in ans["supporting"]}
        self.assertIn("Kept grid report about duke energy", kept)

    def test_diagram_is_a_valid_evidence_map(self):
        out = self._summarize(self._flagged())
        self.assertTrue(out["diagram"].startswith("flowchart TB"))
        self.assertIn("Flagged brief", out["diagram"])
        self.assertIn("Kept grid report about duke energy", out["diagram"])
        self.assertNotIn("Rejected spam post", out["diagram"])

    def test_regenerate_route_recomputes(self):
        from fastapi.testclient import TestClient
        from app import main as main_mod
        client = TestClient(main_mod.app)
        inv_id = self._flagged()
        r = client.post(f"/api/investigations/{inv_id}/summary/regenerate")
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertTrue(body.get("regenerated"))
        self.assertEqual(body["flags"]["rejected"], 1)
        self.assertIn("diagram", body)
        self.assertIn("answers", body)
        r = client.post("/api/investigations/999999/summary/regenerate")
        self.assertEqual(r.status_code, 404)


if __name__ == "__main__":
    unittest.main()
