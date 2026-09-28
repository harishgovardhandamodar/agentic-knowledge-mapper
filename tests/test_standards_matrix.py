"""Tests for the Standards score-matrix sub-tab backend (app/standards_matrix.py).

The sub-tab shows the dashboard's framework x 10-pillar scores, scoped to the
assessment in view by deterministic token overlap -- no model, so the ranking
is pinned here: an injection-heavy assessment with an OWASP-citing control
must rank the OWASP framework first and say which tokens matched.
"""
import json
import os
import tempfile
import unittest
from unittest import mock

# Pin the database before app.database is imported: a module that omits
# this can inherit data/akm.db and write test rows into the live store.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-standards-matrix-"), "test.db"))

from app import database  # noqa: E402
from app import standards_matrix as sm  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.models import Investigation, SecurityAssessment  # noqa: E402

database.init_db()

DIMS = ["risk_management", "data_governance", "transparency", "robustness",
        "security", "privacy", "accountability", "human_oversight",
        "incident_response", "lifecycle_eval"]


def _fw(fid, name, coverage, **kw):
    fw = {"id": fid, "name": name, "issuer": kw.get("issuer", "Test issuer"),
          "jurisdiction": kw.get("jurisdiction", "Global"),
          "kind": kw.get("kind", "framework"), "version": "1.0",
          "status": "final", "url": "https://example.invalid",
          "summary": kw.get("summary", "A test framework."),
          "controls": kw.get("controls", []),
          "scenarios": kw.get("scenarios", []),
          "riskTiers": [], "lastChecked": "2026-01-01",
          "coverage": coverage}
    return fw


OWASP = _fw("owasp-llm", "OWASP Top 10 for LLM Applications",
            {d: 2 for d in DIMS},
            issuer="OWASP", summary="Prompt injection, insecure output handling, LLM02 data leakage.",
            controls=["LLM01 Prompt Injection", "LLM02 Sensitive Information Disclosure"])
NIST = _fw("nist-aire", "NIST AI Risk Management",
           {"risk_management": 2, "security": 1, **{d: 0 for d in DIMS if d not in ("risk_management", "security")}},
           issuer="NIST", kind="framework",
           summary="Risk management framework for AI systems.")
EU = _fw("eu-act", "EU AI Act",
         {"risk_management": 2, "transparency": 2, "human_oversight": 2,
          **{d: 0 for d in DIMS if d not in ("risk_management", "transparency", "human_oversight")}},
         issuer="European Union", kind="regulation",
         summary="Risk-based regulation of AI systems.")

FIXTURE_DATA = {"generated": "2026-01-01", "frameworks": [NIST, EU, OWASP]}

ASSESSMENT_RECORD = {
    "threats": [
        {"id": "T05", "title": "Prompt injection via asset names",
         "stride": "Tampering", "owasp": "LLM01: Prompt Injection",
         "description": "Injected instructions in imported docs steer the draft.",
         "controls": ["C02"]},
    ],
    "active_controls": ["C02"],
    "known_exploits": [
        {"id": "EX-9", "title": "Indirect prompt injection via RAG",
         "attack_class": "injection", "threat_ids": ["T05"],
         "description": "Poisoned retrieval content executes instructions."},
    ],
}


class TestTaxonomyVendoring(unittest.TestCase):
    def test_vendored_taxonomy_matches_the_dashboard_source(self):
        repo = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "standards-dashboard", "data", "taxonomy.json")
        with open(repo, encoding="utf-8") as fh:
            source = json.load(fh)
        vendored = sm.load_taxonomy()
        self.assertEqual(vendored["dimensions"], source["dimensions"])
        self.assertEqual(vendored["scoreLegend"], source["scoreLegend"])


class TestCoverage(unittest.TestCase):
    def test_full_coverage_is_100(self):
        self.assertEqual(sm.coverage_pct({d: 2 for d in DIMS}, DIMS), 100.0)

    def test_no_coverage_is_0(self):
        self.assertEqual(sm.coverage_pct({d: 0 for d in DIMS}, DIMS), 0.0)

    def test_missing_pillars_count_as_zero(self):
        self.assertEqual(sm.coverage_pct({"security": 2}, DIMS), 10.0)

    def test_half_coverage(self):
        self.assertEqual(sm.coverage_pct({d: 1 for d in DIMS}, DIMS), 50.0)


class TestRelevance(unittest.TestCase):
    def test_tokenizer_matches_dashboard_semantics(self):
        self.assertEqual(sm.tokens("OWASP LLM02 mitigation"), ["owasp", "llm02", "mitigation"])
        self.assertEqual(sm.tokens("ISO 27001 A.5.12"), ["iso", "27001", "12"])

    def test_empty_query_scores_zero(self):
        self.assertEqual(sm.relevance([], OWASP), (0.0, []))

    def test_injection_assessment_ranks_owasp_first(self):
        query = ["t05", "prompt", "injection", "llm01", "tampering",
                 "c02", "owasp", "llm02", "mitigation"]
        rel_o, matched_o = sm.relevance(query, OWASP)
        rel_n, _ = sm.relevance(query, NIST)
        rel_e, _ = sm.relevance(query, EU)
        self.assertGreater(rel_o, rel_n)
        self.assertGreater(rel_o, rel_e)
        for tok in ("owasp", "injection"):
            self.assertIn(tok, matched_o)

    def test_unrelated_query_scores_zero(self):
        rel, matched = sm.relevance(["quantum", "key", "distribution"], EU)
        self.assertEqual(rel, 0.0)
        self.assertEqual(matched, [])

    def test_short_substrings_do_not_count(self):
        # "or" sits inside "for" in the NIST summary; that is not a signal.
        rel, matched = sm.relevance(["or"], NIST)
        self.assertEqual(rel, 0.0)
        self.assertEqual(matched, [])
        # ...but an exact short token still does ("ai" names the domain).
        rel, matched = sm.relevance(["ai"], NIST)
        self.assertGreater(rel, 0.0)
        self.assertIn("ai", matched)


class TestAssessmentQuery(unittest.TestCase):
    def test_query_draws_from_threats_controls_and_exploits(self):
        query, basis = sm.assessment_query(ASSESSMENT_RECORD)
        # Threat T05 title/owasp, the C02 control's cited standard, exploit class.
        for tok in ("t05", "injection", "llm01", "owasp", "llm02"):
            self.assertIn(tok, query)
        self.assertEqual(basis, {"threats": 1, "controls": 1,
                                 "exploits": 1, "query_tokens": len(query)})

    def test_missing_active_controls_falls_back_to_threat_contributors(self):
        rec = dict(ASSESSMENT_RECORD, active_controls=[])
        query, basis = sm.assessment_query(rec)
        self.assertEqual(basis["controls"], 1)
        self.assertIn("owasp", query)

    def test_query_carries_no_stopwords(self):
        query, _ = sm.assessment_query(ASSESSMENT_RECORD)
        for tok in ("the", "or", "of", "and", "to", "in", "a"):
            self.assertNotIn(tok, query)


class TestBuildMatrix(unittest.TestCase):
    def setUp(self):
        sm.reset_cache()

    def test_unscoped_matrix_sorts_by_coverage(self):
        with mock.patch.object(sm, "fetch_dashboard", return_value=FIXTURE_DATA):
            payload = sm.build_matrix(None, None)
        self.assertEqual(payload["generated"], "2026-01-01")
        self.assertEqual(len(payload["dimensions"]), 10)
        self.assertEqual([f["id"] for f in payload["frameworks"]],
                         ["owasp-llm", "eu-act", "nist-aire"])
        for f in payload["frameworks"]:
            self.assertTrue(f["relevant"])
            self.assertEqual(f["relevance"], 100.0)
            self.assertEqual(f["matched"], [])
        self.assertIsNone(payload["assessment"])

    def test_scoped_matrix_ranks_by_relevance(self):
        aid = _assessment(_investigation("scoped-rank"))
        db = SessionLocal()
        try:
            with mock.patch.object(sm, "fetch_dashboard", return_value=FIXTURE_DATA):
                payload = sm.build_matrix(db, aid)
        finally:
            db.close()
        self.assertEqual(payload["frameworks"][0]["id"], "owasp-llm")
        self.assertIn("owasp", payload["frameworks"][0]["matched"])
        self.assertEqual(payload["assessment"]["id"], aid)
        self.assertGreater(payload["assessment"]["basis"]["query_tokens"], 10)

    def test_malformed_dashboard_data_is_unavailable(self):
        with mock.patch.object(sm, "fetch_dashboard",
                               side_effect=sm.StandardsUnavailable("down")):
            with self.assertRaises(sm.StandardsUnavailable):
                sm.build_matrix(None, None)


def _investigation(title="standards-matrix-target"):
    db = SessionLocal()
    try:
        inv = Investigation(title=title)
        db.add(inv)
        db.commit()
        db.refresh(inv)
        return inv.id
    finally:
        db.close()


def _assessment(inv_id):
    db = SessionLocal()
    try:
        rec = SecurityAssessment(
            investigation_id=inv_id, product_name="WidgetGPT",
            exposure="confidential_data", overall_pct=40.0,
            inherent_pct=70.0, residual_pct=40.0,
            controls_json=json.dumps({"active_controls": ["C02"]}),
            scoring_json=json.dumps({}),
            threats_json=json.dumps(ASSESSMENT_RECORD["threats"]),
            evidence_json=json.dumps({"known_exploits": ASSESSMENT_RECORD["known_exploits"]}),
            markdown="# test",
        )
        db.add(rec)
        db.commit()
        db.refresh(rec)
        return rec.id
    finally:
        db.close()


class TestScoreMatrixRoute(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient  # noqa: E402
        from app import main as main_mod  # noqa: E402
        cls.client = TestClient(main_mod.app)

    def setUp(self):
        sm.reset_cache()

    def _get(self, aid=None):
        with mock.patch.object(sm, "fetch_dashboard", return_value=FIXTURE_DATA):
            path = "/api/standards/score-matrix"
            if aid is not None:
                path += f"?assessment_id={aid}"
            return self.client.get(path)

    def test_unscoped_matrix_shape(self):
        r = self._get()
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(len(body["dimensions"]), 10)
        self.assertIn("0", body["score_legend"])
        self.assertIsNone(body["assessment"])
        first = body["frameworks"][0]
        for key in ("id", "name", "issuer", "jurisdiction", "kind",
                    "coverage", "coverage_pct", "relevance", "matched",
                    "relevant", "controls", "summary", "url"):
            self.assertIn(key, first, key)
        self.assertEqual(len(first["coverage"]), 10)

    def test_scoped_matrix_names_the_assessment_and_matches(self):
        aid = _assessment(_investigation())
        r = self._get(aid)
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["assessment"]["id"], aid)
        self.assertEqual(body["assessment"]["basis"]["threats"], 1)
        top = body["frameworks"][0]
        self.assertEqual(top["id"], "owasp-llm")
        self.assertTrue(top["relevant"])
        self.assertIn("owasp", top["matched"])

    def test_unknown_assessment_is_404(self):
        with mock.patch.object(sm, "fetch_dashboard", return_value=FIXTURE_DATA):
            r = self.client.get("/api/standards/score-matrix?assessment_id=999999")
        self.assertEqual(r.status_code, 404)

    def test_unreachable_dashboard_is_503(self):
        with mock.patch.object(sm, "fetch_dashboard",
                               side_effect=sm.StandardsUnavailable("down")):
            r = self.client.get("/api/standards/score-matrix")
        self.assertEqual(r.status_code, 503)


if __name__ == "__main__":
    unittest.main()
