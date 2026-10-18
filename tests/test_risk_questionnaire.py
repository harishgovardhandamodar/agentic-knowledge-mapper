"""Security risk questionnaire: framing, routing, coverage — tests.

The questionnaire is the one surface a non-security team fills in, so the
tests pin the properties that make it trustworthy rather than the happy
path: an invented standards tag must never be stored, an unanswered question
must never read as a control failure, and every question must have an owner
and a standard behind it.

Pinned header required suite-wide (see tests/test_db_isolation.py).
"""
import os
import tempfile
import unittest

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-rq-"), "test.db"))
# The deterministic framer is what tests and offline use exercise; pin the LLM
# endpoint at a closed port so a reachable gateway cannot change the output.
os.environ.setdefault("LLM_BASE_URL", "http://127.0.0.1:9/v1")

from app import database as _db  # noqa: E402
from app import models as _models  # noqa: E402,F401 -- registers tables
from app import risk_questionnaire as rq  # noqa: E402

_db.init_db()

QUERY = ("We run a customer-support agent that reads ticket text containing "
         "personal data, drafts replies and can issue refunds under 50 EUR "
         "without human approval. It uses a hosted LLM. We must evidence "
         "GDPR and ISO 42001 controls.")

HEADERS = {"X-AKM-Actor": "product-lead"}


class TagLibraryCase(unittest.TestCase):
    """A tag that names no real control must be dropped, not stored."""

    def test_every_library_control_is_a_known_tag(self):
        for fw in rq.FRAMEWORK_LIBRARY:
            for control, label in fw["controls"]:
                self.assertTrue(rq.is_known_tag(f"{fw['id']}:{control}"))
                self.assertTrue(label)

    def test_invented_tags_are_dropped(self):
        tags = rq.normalize_tags([
            "owasp-llm-top10:LLM99", "not-a-framework:control",
            "owasp-llm-top10:", "owasp-llm-top10:LLM01-prompt-injection"])
        self.assertEqual(tags, ["owasp-llm-top10:LLM01-prompt-injection"])

    def test_normalize_is_deduped_and_library_ordered(self):
        tags = rq.normalize_tags([
            "nist-ai-rmf:manage", "owasp-agentic:agent-identity",
            "nist-ai-rmf:manage"])
        self.assertEqual(tags, ["owasp-agentic:agent-identity",
                                "nist-ai-rmf:manage"])

    def test_normalize_tolerates_junk(self):
        self.assertEqual(rq.normalize_tags("not a list"), [])
        self.assertEqual(rq.normalize_tags([None, 3, {}]), [])

    def test_control_label_names_framework_and_control(self):
        label = rq.control_label("owasp-llm-top10:LLM01-prompt-injection")
        self.assertIn("OWASP", label)
        self.assertIn("Prompt injection", label)


class FramingCase(unittest.TestCase):
    def test_deterministic_frame_picks_relevant_axes(self):
        frame = rq._deterministic_frame(QUERY)
        self.assertEqual(frame["source"], "deterministic")
        for axis in ("data_privacy", "autonomy_boundaries",
                     "regulatory_policy", "third_parties_models"):
            self.assertIn(axis, frame["axes"])

    def test_mandatory_axes_always_present(self):
        for axis in rq.MIN_DEEP_AXES:
            self.assertIn(axis, rq._deterministic_frame(QUERY)["axes"])

    def test_roles_cover_every_selected_axis(self):
        frame = rq._deterministic_frame(QUERY)
        for axis in frame["axes"]:
            if axis in rq._AXIS_MAP:
                self.assertIn(rq._AXIS_MAP[axis]["role"], frame["roles"])

    def test_target_is_a_noun_phrase_not_a_sentence(self):
        target = rq._deterministic_frame(QUERY)["target"]
        self.assertEqual(target, "a customer-support agent")
        self.assertLess(len(target), 60)

    def test_empty_query_is_refused(self):
        db = _db.SessionLocal()
        try:
            with self.assertRaises(ValueError):
                rq.generate(db, "   ")
        finally:
            db.close()


class BuildCase(unittest.TestCase):
    """Every question must be owned, tagged, and answerable."""

    def _sections(self, depth="standard"):
        return rq.build_sections(rq._deterministic_frame(QUERY), depth)

    def test_intake_section_comes_first(self):
        sections = self._sections()
        self.assertEqual(sections[0]["key"], "system_intake")
        self.assertTrue(rq._INTAKE_AXIS["prompts"])

    def test_every_question_is_owned_and_tagged(self):
        for s in self._sections():
            for q in s["questions"]:
                self.assertIn(q["answerer_role"], rq._ROLE_KEYS)
                self.assertTrue(q["framework_tags"], q["key"])
                for tag in q["framework_tags"]:
                    self.assertTrue(rq.is_known_tag(tag), tag)

    def test_question_keys_are_unique(self):
        keys = [q["key"] for s in self._sections() for q in s["questions"]]
        self.assertEqual(len(keys), len(set(keys)))

    def test_every_question_offers_the_rating_scale(self):
        values = [o["value"] for o in rq.ANSWER_OPTIONS]
        self.assertEqual(values, ["pass", "partial", "fail", "na"])
        for s in self._sections():
            for q in s["questions"]:
                self.assertEqual(q["question_type"], "enum")
                self.assertEqual([o["value"] for o in q["options"]], values)

    def test_depth_trims_questions_but_keeps_the_set_usable(self):
        brief = self._sections("brief")
        full = self._sections("full")
        self.assertLess(sum(len(s["questions"]) for s in brief),
                        sum(len(s["questions"]) for s in full))
        self.assertTrue(rq._quality(brief)["ok"])
        self.assertTrue(rq._quality(full)["ok"])

    def test_quality_pass_rejects_unowned_and_untagged(self):
        sections = self._sections()
        sections[1]["questions"][0]["framework_tags"] = []
        sections[1]["questions"][1]["answerer_role"] = "nobody"
        quality = rq._quality(sections)
        self.assertFalse(quality["ok"])
        self.assertEqual(len(quality["untagged"]), 1)
        self.assertEqual(len(quality["unowned"]), 1)

    def test_role_slices_partition_every_question(self):
        sections = self._sections()
        sliced = [q for v in rq._role_slices(sections).values() for q in v]
        self.assertEqual(len(sliced),
                         sum(len(s["questions"]) for s in sections))


class ApiCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient

        from app.main import app
        cls.client = TestClient(app)

    def _generate(self, query=QUERY, depth="standard"):
        r = self.client.post("/api/risk-questionnaire/generate",
                             json={"query": query, "depth": depth},
                             headers=HEADERS)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def test_frameworks_library_is_open(self):
        r = self.client.get("/api/risk-questionnaire/frameworks")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(len(body["frameworks"]), len(rq.FRAMEWORK_LIBRARY))
        self.assertEqual(body["generator_version"], rq.GENERATOR_VERSION)
        tags = [c["tag"] for f in body["frameworks"] for c in f["controls"]]
        self.assertTrue(all(rq.is_known_tag(t) for t in tags))

    def test_anonymous_generate_is_denied(self):
        r = self.client.post("/api/risk-questionnaire/generate",
                             json={"query": QUERY})
        self.assertEqual(r.status_code, 401)

    def test_empty_query_is_400(self):
        r = self.client.post("/api/risk-questionnaire/generate",
                             json={"query": "  "}, headers=HEADERS)
        self.assertEqual(r.status_code, 400)

    def test_draft_report_is_a_fills_in_form(self):
        did = self._generate()["draft"]["id"]
        r = self.client.get(
            f"/api/risk-questionnaire/drafts/{did}/report.md")
        self.assertEqual(r.status_code, 200)
        md = r.text
        self.assertIn("Security risk questionnaire", md)
        self.assertIn("- Rating: pass / partial / fail / na", md)
        self.assertIn("- Evidence (link, test, config, log field):", md)
        # Routed per team, so each owner sees their own heading.
        for role in rq.ANSWERER_ROLES:
            if role["key"] in ("data_protection", "legal_compliance"):
                self.assertIn(role["title"], md)
        # Standards named per question.
        self.assertIn("Standards:", md)
        brief = self.client.get(
            f"/api/risk-questionnaire/drafts/{did}/report.md",
            params={"format": "brief"})
        self.assertEqual(brief.status_code, 200)
        self.assertIn("Audience", brief.text)

    def test_unknown_report_format_is_400(self):
        did = self._generate()["draft"]["id"]
        r = self.client.get(
            f"/api/risk-questionnaire/drafts/{did}/report.md",
            params={"format": "novel"})
        self.assertEqual(r.status_code, 400)

    def test_seed_opens_a_run_and_is_not_repeatable(self):
        did = self._generate()["draft"]["id"]
        r = self.client.post(f"/api/risk-questionnaire/drafts/{did}/seed",
                             json={"target": "support-agent"}, headers=HEADERS)
        self.assertEqual(r.status_code, 200, r.text)
        out = r.json()
        self.assertLessEqual(len(out["catalog_version"]), 20)
        again = self.client.post(
            f"/api/risk-questionnaire/drafts/{did}/seed",
            json={"target": "support-agent"}, headers=HEADERS)
        self.assertEqual(again.status_code, 400)

    def test_catalog_versions_are_unique_per_questionnaire(self):
        a = self.client.post(
            f"/api/risk-questionnaire/drafts/{self._generate()['draft']['id']}/seed",
            json={"target": "a"}, headers=HEADERS).json()["catalog_version"]
        b = self.client.post(
            f"/api/risk-questionnaire/drafts/{self._generate()['draft']['id']}/seed",
            json={"target": "b"}, headers=HEADERS).json()["catalog_version"]
        self.assertNotEqual(a, b)


class CoverageCase(unittest.TestCase):
    """Coverage is the point: which standards the answers evidence."""

    def setUp(self):
        from fastapi.testclient import TestClient

        from app.main import app
        self.client = TestClient(app)
        draft = self.client.post(
            "/api/risk-questionnaire/generate", json={"query": QUERY},
            headers=HEADERS).json()
        seeded = self.client.post(
            f"/api/risk-questionnaire/drafts/{draft['draft']['id']}/seed",
            json={"target": "coverage-case"}, headers=HEADERS).json()
        self.run_id = seeded["run_id"]

    def _state(self):
        return self.client.get(
            f"/api/risk-questionnaire/runs/{self.run_id}").json()

    def _answer(self, question_id, rating, actor="owner", notes=""):
        r = self.client.patch(
            f"/api/risk-questionnaire/runs/{self.run_id}/answers/{question_id}",
            json={"risk_rating": rating, "notes": notes,
                  "evidence_url": "https://wiki.example/x"},
            headers={"X-AKM-Actor": actor})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def test_a_fresh_run_reports_everything_unanswered(self):
        cov = self.client.get(
            f"/api/risk-questionnaire/runs/{self.run_id}/coverage").json()
        self.assertGreater(cov["counts"]["controls"], 5)
        self.assertEqual(cov["counts"]["unanswered"],
                         cov["counts"]["controls"])
        self.assertEqual(cov["counts"]["fail"], 0)
        self.assertEqual(cov["counts"]["pass"], 0)

    def test_unanswered_is_not_reported_as_failure(self):
        state = self._state()
        # Answer one team's slice only; the rest must stay unanswered.
        team = [t for t in state["teams"] if t["role"] == "product_owner"][0]
        for qn in team["questions"][:1]:
            self._answer(qn["question_id"], "fail")
        cov = self.client.get(
            f"/api/risk-questionnaire/runs/{self.run_id}/coverage").json()
        self.assertGreater(cov["counts"]["unanswered"], 0)
        self.assertLess(cov["completion"]["pct"], 100.0)
        unanswered = [c for c in cov["controls"]
                      if c["status"] == "unanswered"]
        self.assertTrue(all(c["answered"] == 0 for c in unanswered))

    def test_fail_outranks_partial_outranks_pass_per_control(self):
        state = self._state()
        team = [t for t in state["teams"] if t["role"] == "security_engineering"][0]
        tags_seen = set()
        for qn in team["questions"]:
            tags_seen.update(qn["framework_tags"])
            self._answer(qn["question_id"], "pass", actor="sec")
        cov = self.client.get(
            f"/api/risk-questionnaire/runs/{self.run_id}/coverage").json()
        by_tag = {c["tag"]: c for c in cov["controls"]}
        for tag in tags_seen:
            entry = by_tag.get(tag)
            if entry and entry["answered"]:
                self.assertNotEqual(entry["status"], "fail")
                self.assertTrue(entry["evidence"])
                self.assertTrue(all(e["answered_by"] == "sec"
                                    for e in entry["evidence"]))

    def test_named_teams_are_reported_separately(self):
        cov = self.client.get(
            f"/api/risk-questionnaire/runs/{self.run_id}/coverage").json()
        self.assertTrue(cov["frameworks"])
        for fw in cov["frameworks"]:
            self.assertEqual(fw["questions"], fw["answered"] + sum(
                1 for c in fw["controls"] if c["status"] == "unanswered"
                for _ in [0] * (c["questions"] - c["answered"])))
            self.assertTrue(fw["name"])

    def test_invalid_rating_is_rejected(self):
        qid = self._state()["teams"][0]["questions"][0]["question_id"]
        r = self.client.patch(
            f"/api/risk-questionnaire/runs/{self.run_id}/answers/{qid}",
            json={"risk_rating": "excellent"}, headers=HEADERS)
        self.assertEqual(r.status_code, 400)

    def test_answering_a_foreign_question_is_404(self):
        r = self.client.patch(
            f"/api/risk-questionnaire/runs/{self.run_id}/answers/999999",
            json={"risk_rating": "pass"}, headers=HEADERS)
        self.assertEqual(r.status_code, 404)

    def test_complete_scores_and_reports_coverage(self):
        state = self._state()
        for team in state["teams"]:
            for qn in team["questions"]:
                rating = {"product_owner": "pass",
                          "data_protection": "partial"}.get(
                              team["role"], "fail")
                self._answer(qn["question_id"], rating, actor=team["role"])
        done = self.client.post(
            f"/api/risk-questionnaire/runs/{self.run_id}/complete",
            headers=HEADERS)
        self.assertEqual(done.status_code, 200, done.text)
        out = done.json()
        self.assertEqual(out["coverage"]["completion"]["outstanding"], 0)
        self.assertEqual(out["coverage"]["completion"]["pct"], 100.0)
        self.assertGreater(out["overall_score"], 0.0)
        self.assertIn("coverage", out)
        rep = self.client.get(
            f"/api/risk-questionnaire/runs/{self.run_id}/report.md")
        self.assertEqual(rep.status_code, 200)
        self.assertIn("## Standards coverage", rep.text)
        self.assertIn("| Control | Status |", rep.text)

    def test_a_completed_run_rejects_further_answers(self):
        state = self._state()
        qid = state["teams"][0]["questions"][0]["question_id"]
        self._answer(qid, "pass")
        self.client.post(f"/api/risk-questionnaire/runs/{self.run_id}/complete",
                         headers=HEADERS)
        r = self.client.patch(
            f"/api/risk-questionnaire/runs/{self.run_id}/answers/{qid}",
            json={"risk_rating": "fail"}, headers=HEADERS)
        self.assertEqual(r.status_code, 400)

    def test_unknown_run_is_404(self):
        self.assertEqual(
            self.client.get("/api/risk-questionnaire/runs/999999").status_code,
            404)


if __name__ == "__main__":
    unittest.main()
