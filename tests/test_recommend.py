"""Tests for app.recommend -- proactive suggestions from data already held.

The bar for these is higher than "returns something". A recommendation the user
acts on has to be *right*, so the control-leverage figures are checked against
the scorer that produced the stored assessment, and every recommender is checked
to stay quiet when it has no evidence.
"""
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone


# Pin the database before app.database is imported: a module that omits
# this can inherit data/akm.db and write test rows into the live store.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-recommend-"), "test.db"))

from app import database  # noqa: E402
from app import recommend as R  # noqa: E402
from app import security as sec  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.models import Artifact, Investigation, SecurityAssessment  # noqa: E402

database.init_db()

_n = {"i": 0}


def new_inv(title="frontier model alignment",
            keywords="interpretability,alignment",
            description="mechanistic interpretability research"):
    _n["i"] += 1
    db = SessionLocal()
    try:
        inv = Investigation(title=f"{title} {_n['i']}", keywords=keywords,
                            description=description, sources="web")
        db.add(inv)
        db.commit()
        return inv.id
    finally:
        db.close()


def add_arts(inv_id, specs, days_ago=0):
    db = SessionLocal()
    try:
        when = datetime.now(timezone.utc) - timedelta(days=days_ago)
        for i, spec in enumerate(specs):
            title = spec.get("title", f"item {i}")
            a = Artifact(investigation_id=inv_id, title=title,
                         description=spec.get("description"),
                         tags=spec.get("tags"), url=f"http://x/{inv_id}/{i}",
                         artifact_type="article", source="web",
                         relevance=spec.get("relevance", 0.8))
            a.created_at = when
            db.add(a)
        db.commit()
    finally:
        db.close()


def make_assessment(inv_id, active=(), applicability=None, exposure="confidential_data"):
    """A real assessment, scored by the real engine, stored the real way."""
    db = SessionLocal()
    try:
        weight = float(sec.EXPOSURE_META[exposure]["weight"])
        inherent = [{"id": t[0], "title": t[1], "stride": t[2], "owasp": t[3],
                     "likelihood": float(sec._scale_likelihood(t[4], weight)),
                     "impact": float(t[5]), "description": t[6],
                     "mitigations": list(t[7])}
                    for t in sec._THREAT_CATALOG]
        scoring = sec.score_assessment(exposure, inherent,
                                       active_controls=list(active),
                                       applicability=applicability)
        rec = SecurityAssessment(
            investigation_id=inv_id,
            product_name="Test product",
            exposure=exposure,
            overall_pct=scoring["residual_pct"],
            inherent_pct=scoring["inherent_pct"],
            residual_pct=scoring["residual_pct"],
            controls_json=json.dumps({"active_controls": sorted(active)}),
            scoring_json=json.dumps(scoring),
            threats_json=json.dumps(scoring["threats"]),
            markdown="# test",
        )
        db.add(rec)
        db.commit()
        return rec.id, scoring
    finally:
        db.close()


class TestCoverageGaps(unittest.TestCase):
    def test_no_investigation_is_no_gaps(self):
        db = SessionLocal()
        try:
            self.assertEqual(R.coverage_gaps(db, 999999), [])
        finally:
            db.close()

    def test_a_thin_corpus_proves_nothing(self):
        """Two artifacts is not enough evidence to declare a research hole."""
        inv = new_inv()
        add_arts(inv, [{"title": "a"}, {"title": "b"}])
        db = SessionLocal()
        try:
            self.assertEqual(R.coverage_gaps(db, inv), [])
        finally:
            db.close()

    def test_an_uncovered_brief_term_is_reported(self):
        inv = new_inv(keywords="interpretability,alignment,distillation",
                      description="mechanistic interpretability research")
        add_arts(inv, [{"title": f"alignment paper {i}",
                        "tags": "alignment",
                        "description": "alignment and interpretability work"}
                       for i in range(4)])
        db = SessionLocal()
        try:
            terms = {g["term"] for g in R.coverage_gaps(db, inv)}
            self.assertIn("distillation", terms)
            self.assertNotIn("alignment", terms)
            self.assertNotIn("interpretability", terms)
        finally:
            db.close()

    def test_a_stem_match_counts_as_covered(self):
        """Exact-token matching called this a gap on a full corpus."""
        inv = new_inv(title="reward misspecification",
                      keywords="misspecification", description="reward modeling")
        add_arts(inv, [{"title": "reward hacking",
                        "description": "specification gaming in RL"} for _ in range(4)])
        db = SessionLocal()
        try:
            terms = {g["term"] for g in R.coverage_gaps(db, inv)}
            self.assertNotIn("misspecification", terms)
        finally:
            db.close()

    def test_gap_carries_an_actionable_suggestion(self):
        inv = new_inv(keywords="quantization")
        add_arts(inv, [{"title": f"alignment paper {i}"} for i in range(4)])
        db = SessionLocal()
        try:
            gaps = R.coverage_gaps(db, inv)
            g = [x for x in gaps if x["term"] == "quantization"]
            self.assertTrue(g)
            self.assertIn("quantization", g[0]["suggestion"])
            self.assertIn("quantization", g[0]["why"])
        finally:
            db.close()

    def test_gaps_are_bounded(self):
        inv = new_inv(title="a b c d e f g h i j k l",
                      keywords="alpha,beta,gamma,delta,epsilon,zeta,eta,theta",
                      description="iota kappa lambda mu nu xi omicron pi rho")
        add_arts(inv, [{"title": f"zzz unrelated {i}"} for i in range(5)])
        db = SessionLocal()
        try:
            self.assertLessEqual(len(R.coverage_gaps(db, inv, limit=4)), 4)
        finally:
            db.close()

    def test_a_fully_covered_brief_reports_nothing(self):
        inv = new_inv(title="alignment", keywords="interpretability",
                      description="alignment interpretability")
        add_arts(inv, [{"title": "alignment interpretability study",
                        "tags": "alignment,interpretability",
                        "description": "alignment interpretability"}
                       for _ in range(4)])
        db = SessionLocal()
        try:
            self.assertEqual(R.coverage_gaps(db, inv), [])
        finally:
            db.close()


class TestStaleBrief(unittest.TestCase):
    def _inv_with_ages(self, brief_days, art_days):
        inv = new_inv()
        db = SessionLocal()
        try:
            row = db.get(Investigation, inv)
            row.created_at = datetime.now(timezone.utc) - timedelta(days=brief_days)
            db.commit()
        finally:
            db.close()
        add_arts(inv, [{"title": f"paper {i}"} for i in range(3)],
                 days_ago=art_days)
        return inv

    def test_no_artifacts_is_nothing_to_stale(self):
        inv = new_inv()
        db = SessionLocal()
        try:
            self.assertEqual(R.stale_brief(db, inv), [])
        finally:
            db.close()

    def test_fresh_brief_is_not_stale(self):
        inv = self._inv_with_ages(brief_days=2, art_days=1)
        db = SessionLocal()
        try:
            self.assertEqual(R.stale_brief(db, inv), [])
        finally:
            db.close()

    def test_corpus_outgrowing_the_brief_is_stale(self):
        inv = self._inv_with_ages(brief_days=60, art_days=1)
        db = SessionLocal()
        try:
            out = R.stale_brief(db, inv)
            self.assertTrue(out)
            self.assertEqual(out[0]["kind"], "stale_brief")
            self.assertIn("artifacts", out[0]["why"])
        finally:
            db.close()

    def test_very_old_brief_is_high_severity(self):
        inv = self._inv_with_ages(brief_days=200, art_days=1)
        db = SessionLocal()
        try:
            self.assertEqual(R.stale_brief(db, inv)[0]["severity"], "high")
        finally:
            db.close()

    def test_naive_timestamps_do_not_crash_it(self):
        """SQLite hands back naive datetimes; comparing them to aware ones
        raises, and that must not take the whole digest down."""
        inv = new_inv()
        db = SessionLocal()
        try:
            row = db.get(Investigation, inv)
            row.created_at = datetime.now(timezone.utc) - timedelta(days=90)
            db.commit()
        finally:
            db.close()
        add_arts(inv, [{"title": f"p{i}"} for i in range(3)], days_ago=1)
        db = SessionLocal()
        try:
            db.expire_all()
            self.assertTrue(R.stale_brief(db, inv))
        finally:
            db.close()

    def test_unknown_investigation(self):
        db = SessionLocal()
        try:
            self.assertEqual(R.stale_brief(db, 999999), [])
        finally:
            db.close()


class TestApplicabilityWeighting(unittest.TestCase):
    def _inh(self, exposure="confidential_data"):
        weight = float(sec.EXPOSURE_META[exposure]["weight"])
        return [{"id": t[0], "title": t[1],
                 "likelihood": float(sec._scale_likelihood(t[4], weight)),
                 "impact": float(t[5])} for t in sec._THREAT_CATALOG]

    def _res(self, app, exposure="confidential_data", active=()):
        return sec.score_assessment(exposure, self._inh(exposure),
                                    active_controls=list(active),
                                    applicability=app)["residual_pct"]

    def test_uniform_maps_score_as_unweighted(self):
        ids = [t[0] for t in sec._THREAT_CATALOG]
        self.assertEqual(self._res(None), self._res({t: 0.45 for t in ids}))
        self.assertEqual(self._res(None), self._res({t: 1.0 for t in ids}))
        self.assertEqual(self._res(None), 68.8)

    def test_varied_map_moves_the_score(self):
        ids = [t[0] for t in sec._THREAT_CATALOG]
        base = {t: 0.45 for t in ids}
        lifted = dict(base, T02=1.0, T05=1.0)
        got = self._res(lifted)
        plain = self._res(base)
        self.assertNotEqual(got, plain)
        self.assertGreater(got, plain)
        self.assertLessEqual(got, 100.0)

    def test_all_zero_falls_back_instead_of_zeroing(self):
        ids = [t[0] for t in sec._THREAT_CATALOG]
        self.assertEqual(self._res({t: 0.0 for t in ids}), self._res(None))

    def test_single_applicable_threat_scores_alone(self):
        ids = [t[0] for t in sec._THREAT_CATALOG]
        got = self._res({"T05": 1.0, **{t: 0.0 for t in ids if t != "T05"}})
        self.assertGreater(got, 0.0)
        self.assertLess(got, self._res(None))

    def test_weights_clamp(self):
        ids = [t[0] for t in sec._THREAT_CATALOG]
        over = {"T05": 1.5, **{t: 0.45 for t in ids if t != "T05"}}
        capped = {"T05": 1.0, **{t: 0.45 for t in ids if t != "T05"}}
        self.assertEqual(self._res(over), self._res(capped))

    def test_weighting_holds_with_controls_active(self):
        ids = [t[0] for t in sec._THREAT_CATALOG]
        base = {t: 0.45 for t in ids}
        plain = sec.score_assessment("confidential_data", self._inh(),
                                     active_controls=["C02"],
                                     applicability=None)["residual_pct"]
        weighted = sec.score_assessment("confidential_data", self._inh(),
                                        active_controls=["C02"],
                                        applicability=base)["residual_pct"]
        self.assertEqual(plain, weighted)


class TestControlLeverage(unittest.TestCase):
    def test_no_assessment_is_no_recommendations(self):
        inv = new_inv()
        db = SessionLocal()
        try:
            self.assertEqual(R.control_leverage(db, inv), [])
            self.assertEqual(R.control_leverage(db, inv, assessment_id=999999), [])
        finally:
            db.close()

    def test_reported_cut_matches_the_scorer_exactly(self):
        """The number is the whole value of this recommender, so it is checked
        against a real re-score, not a plausible-looking value."""
        inv = new_inv()
        aid, scoring = make_assessment(inv, active=())
        db = SessionLocal()
        try:
            recs = R.control_leverage(db, inv, assessment_id=aid)
            self.assertTrue(recs)
            for r in recs[:5]:
                # Re-score independently, exactly as rescore_security_assessment
                # would, and compare.
                weight = float(sec.EXPOSURE_META["confidential_data"]["weight"])
                inherent = [{"id": t[0], "title": t[1], "stride": t[2],
                             "owasp": t[3],
                             "likelihood": float(sec._scale_likelihood(t[4], weight)),
                             "impact": float(t[5]), "description": t[6],
                             "mitigations": list(t[7])}
                            for t in sec._THREAT_CATALOG]
                trial = sec.score_assessment(
                    "confidential_data", inherent,
                    active_controls=[r["control_id"]])
                self.assertAlmostEqual(r["residual_after"],
                                       trial["residual_pct"], places=1)
                self.assertAlmostEqual(
                    r["residual_cut"],
                    round(scoring["residual_pct"] - trial["residual_pct"], 1),
                    places=1)
        finally:
            db.close()

    def test_ranked_by_largest_cut_first(self):
        inv = new_inv()
        aid, _ = make_assessment(inv, active=())
        db = SessionLocal()
        try:
            cuts = [r["residual_cut"] for r in R.control_leverage(db, inv,
                                                                 assessment_id=aid)]
            self.assertEqual(cuts, sorted(cuts, reverse=True))
        finally:
            db.close()

    def test_already_active_controls_are_not_recommended(self):
        inv = new_inv()
        aid, _ = make_assessment(inv, active=["C01", "C02", "C03", "C04"])
        db = SessionLocal()
        try:
            recs = R.control_leverage(db, inv, assessment_id=aid)
            self.assertTrue(recs)
            for r in recs:
                self.assertNotIn(r["control_id"], {"C01", "C02", "C03", "C04"})
        finally:
            db.close()

    def test_a_control_that_moves_nothing_is_not_recommended(self):
        """Diminishing returns: a real control that adds no coverage here."""
        inv = new_inv()
        # Enable almost everything, so the remainder cannot move the aggregate.
        every = [c["id"] for c in sec.control_catalog()][:-1]
        aid, _ = make_assessment(inv, active=every)
        db = SessionLocal()
        try:
            for r in R.control_leverage(db, inv, assessment_id=aid):
                self.assertGreater(r["residual_cut"], 0)
        finally:
            db.close()

    def test_fully_covered_assessment_recommends_nothing(self):
        inv = new_inv()
        aid, _ = make_assessment(inv,
                                 active=[c["id"] for c in sec.control_catalog()])
        db = SessionLocal()
        try:
            self.assertEqual(R.control_leverage(db, inv, assessment_id=aid), [])
        finally:
            db.close()

    def test_latest_assessment_is_used_by_default(self):
        inv = new_inv()
        first, _ = make_assessment(inv, active=())
        second, _ = make_assessment(inv, active=["C01"])
        db = SessionLocal()
        try:
            recs = R.control_leverage(db, inv)
            self.assertTrue(recs)
            self.assertNotIn("C01", {r["control_id"] for r in recs})
        finally:
            db.close()

    def test_corrupt_stored_json_is_survivable(self):
        inv = new_inv()
        db = SessionLocal()
        try:
            row = SecurityAssessment(investigation_id=inv, product_name="x",
                                     exposure="confidential_data",
                                     overall_pct=0, markdown="m",
                                     threats_json="{not json")
            db.add(row)
            db.commit()
            self.assertEqual(R.control_leverage(db, inv), [])
        finally:
            db.close()

    def test_empty_threat_rows_is_survivable(self):
        inv = new_inv()
        db = SessionLocal()
        try:
            row = SecurityAssessment(investigation_id=inv, product_name="x",
                                     exposure="confidential_data",
                                     overall_pct=0, markdown="m",
                                     threats_json="[]")
            db.add(row)
            db.commit()
            self.assertEqual(R.control_leverage(db, inv), [])
        finally:
            db.close()

    def test_severity_scales_with_the_cut(self):
        inv = new_inv()
        aid, _ = make_assessment(inv, active=())
        db = SessionLocal()
        try:
            for r in R.control_leverage(db, inv, assessment_id=aid):
                expected = ("high" if r["residual_cut"] >= 5
                            else "medium" if r["residual_cut"] >= 2 else "low")
                self.assertEqual(r["severity"], expected)
        finally:
            db.close()


class TestStaleAssessment(unittest.TestCase):
    def test_newer_artifacts_flag_the_score(self):
        inv = new_inv()
        aid, _ = make_assessment(inv)
        db = SessionLocal()
        try:
            db.add(Artifact(investigation_id=inv, title="Fresh evidence",
                            artifact_type="paper", source="arxiv",
                            relevance=0.8, review="accepted"))
            db.commit()
            recs = R.stale_assessment(db, inv)
            self.assertEqual(len(recs), 1)
            self.assertEqual(recs[0]["kind"], "stale_assessment")
            self.assertEqual(recs[0]["assessment_id"], aid)
        finally:
            db.close()

    def test_nothing_newer_is_quiet(self):
        inv = new_inv()
        make_assessment(inv)
        db = SessionLocal()
        try:
            self.assertEqual(R.stale_assessment(db, inv), [])
        finally:
            db.close()


class TestUnevidencedLeverage(unittest.TestCase):
    def test_top_control_without_evidence_is_flagged(self):
        inv = new_inv()
        aid, _ = make_assessment(inv)
        db = SessionLocal()
        try:
            recs = R.unevidenced_leverage(db, inv, assessment_id=aid)
            self.assertEqual(len(recs), 1)
            self.assertEqual(recs[0]["kind"], "unevidenced_leverage")
            top = R.control_leverage(db, inv, assessment_id=aid)[0]
            self.assertEqual(recs[0]["control_id"], top["control_id"])
        finally:
            db.close()

    def test_evidenced_control_is_quiet(self):
        inv = new_inv()
        aid, _ = make_assessment(inv)
        db = SessionLocal()
        try:
            top = R.control_leverage(db, inv, assessment_id=aid)[0]
            db.add(Artifact(investigation_id=inv,
                            title=f"Vendor doc for {top['control_id']} rollout",
                            artifact_type="paper", source="web",
                            relevance=0.9, review="accepted"))
            db.commit()
            self.assertEqual(
                R.unevidenced_leverage(db, inv, assessment_id=aid), [])
        finally:
            db.close()


class TestBarrenQueries(unittest.TestCase):
    def test_repeatedly_fruitless_shapes_are_reported(self):
        from app import yield_ as yld
        inv = new_inv()
        db = SessionLocal()
        try:
            for _ in range(3):
                yld.record_yield(db, inv, [{"text": "quantum foam"}], found=8,
                                 kept=0, llm_calls=2)
            recs = R.barren_queries(db, inv)
            self.assertTrue(recs)
            self.assertIn("0", recs[0]["why"])
            self.assertIn("model calls", recs[0]["why"])
        finally:
            db.close()

    def test_a_single_attempt_is_not_enough_to_condemn(self):
        from app import yield_ as yld
        inv = new_inv()
        db = SessionLocal()
        try:
            yld.record_yield(db, inv, [{"text": "quantum foam"}], found=8,
                             kept=0, llm_calls=2)
            self.assertEqual(R.barren_queries(db, inv), [])
        finally:
            db.close()

    def test_productive_shapes_are_not_reported(self):
        from app import yield_ as yld
        inv = new_inv()
        db = SessionLocal()
        try:
            for _ in range(3):
                yld.record_yield(db, inv, [{"text": "alignment probes"}],
                                 found=8, kept=4, llm_calls=2)
            self.assertEqual(R.barren_queries(db, inv), [])
        finally:
            db.close()


class TestDigest(unittest.TestCase):
    def test_empty_for_a_bare_investigation(self):
        inv = new_inv()
        db = SessionLocal()
        try:
            out = R.digest(db, inv)
            self.assertEqual(out["total"], 0)
            self.assertEqual(out["recommended"], [])
            self.assertEqual(out["by_kind"], {})
        finally:
            db.close()

    def test_unknown_investigation_does_not_crash(self):
        db = SessionLocal()
        try:
            self.assertEqual(R.digest(db, 999999)["total"], 0)
        finally:
            db.close()

    def test_ranked_by_severity(self):
        inv = new_inv(keywords="quantization", description="quantization")
        add_arts(inv, [{"title": f"alignment {i}"} for i in range(4)])
        make_assessment(inv, active=())
        db = SessionLocal()
        try:
            out = R.digest(db, inv)
            sev = [r["severity"] for r in out["recommended"]]
            order = ["high", "medium", "low"]
            self.assertEqual(sev, sorted(sev, key=order.index))
        finally:
            db.close()

    def test_counts_by_kind(self):
        inv = new_inv(keywords="quantization", description="quantization")
        add_arts(inv, [{"title": f"alignment {i}"} for i in range(4)])
        make_assessment(inv, active=())
        db = SessionLocal()
        try:
            out = R.digest(db, inv)
            self.assertIn("coverage", out["by_kind"])
            self.assertIn("control_leverage", out["by_kind"])
            self.assertEqual(sum(out["by_kind"].values()), out["total"])
        finally:
            db.close()

    def test_limit_truncates_and_reports_the_remainder(self):
        inv = new_inv(title="a b c d e f g h i j k l",
                      keywords="alpha,beta,gamma,delta,epsilon,zeta,eta,theta",
                      description="iota kappa lambda mu nu xi omicron pi rho")
        add_arts(inv, [{"title": f"zzz {i}"} for i in range(5)])
        make_assessment(inv, active=())
        db = SessionLocal()
        try:
            out = R.digest(db, inv, limit=3)
            self.assertLessEqual(len(out["recommended"]), 3)
            if out["truncated"]:
                self.assertGreater(out["total"], 3)
        finally:
            db.close()

    def test_every_recommendation_is_self_describing(self):
        """A user has to be able to tell what a suggestion is based on."""
        inv = new_inv(keywords="quantization")
        add_arts(inv, [{"title": f"alignment {i}"} for i in range(4)])
        make_assessment(inv, active=())
        db = SessionLocal()
        try:
            for r in R.digest(db, inv)["recommended"]:
                self.assertIn("kind", r)
                self.assertIn("severity", r)
                self.assertTrue(r["why"])
                self.assertTrue(r["suggestion"])
        finally:
            db.close()


class TestRecommendationsEndpoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        from app import main as main_mod
        cls.client = TestClient(main_mod.app)
        cls.n = 0

    def _inv(self, keywords="quantization"):
        type(self).n += 1
        r = self.client.post("/api/investigations",
                             json={"title": f"recs api {type(self).n}",
                                   "keywords": keywords,
                                   "description": "mechanistic research",
                                   "sources": "web"})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["id"]

    def test_returns_a_digest(self):
        inv = self._inv()
        r = self.client.get(f"/api/investigations/{inv}/recommendations")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIn("recommended", r.json())

    def test_unknown_investigation_is_404(self):
        self.assertEqual(
            self.client.get("/api/investigations/999999/recommendations")
            .status_code, 404)

    def test_limit_is_bounded(self):
        inv = self._inv()
        self.assertEqual(
            self.client.get(f"/api/investigations/{inv}/recommendations?limit=0")
            .status_code, 422)
        self.assertEqual(
            self.client.get(f"/api/investigations/{inv}/recommendations?limit=999")
            .status_code, 422)

    def test_assessment_id_filter_is_accepted(self):
        inv = self._inv()
        r = self.client.get(
            f"/api/investigations/{inv}/recommendations?assessment_id=999999")
        self.assertEqual(r.status_code, 200, r.text)


if __name__ == "__main__":
    unittest.main()
