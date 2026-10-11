"""Tests for the hypothesis council: a panel, not a monologist.

The behaviour these pin down is the reason the council exists, and each one is
a failure mode a naive implementation walks straight into:

  * six seats with distinct remits produce claims the single-voice drafter
    could not, and two of them converge on the same one;
  * a seat with no evidence stays silent rather than inventing a claim;
  * a refutation test is GRADED, so "review the deployment" is not a falsifier;
  * a claim the drafter graded above what its own cited attack classes license
    is caught and marked down;
  * an attack class with stored evidence but no claim is reported as
    ``unexamined`` -- emphatically not as safe;
  * a claim no seat objected to scores zero peer scrutiny, because silence is
    a limit on the review rather than a pass;
  * the whole thing runs with no gateway, because a panel that disappears when
    the model is down is no panel at all.
"""
import json
import os
import tempfile
import unittest
from unittest import mock

# Pin the database before app.database is imported: a module that omits
# this can inherit data/akm.db and write test rows into the live store.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-council-"), "test.db"))

from app import council as C  # noqa: E402
from app import database  # noqa: E402
from app import security as sec  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.models import Investigation, SecurityAssessment  # noqa: E402

database.init_db()

TGT = [
    {"id": "M01", "title": "memorisation of training rows",
     "dimension": "training_data_privacy", "rationale": "personal data in corpus"},
    {"id": "M02", "title": "no provenance attestation for weights",
     "dimension": "model_integrity", "rationale": "custody unknown"},
    {"id": "M03", "title": "inference endpoint returns raw completions",
     "dimension": "deployment_surface", "rationale": "no per-tenant authz"},
]
ADV = [
    {"id": "A09", "title": "extract attributes from model outputs",
     "dimension": "data_recon", "rationale": "outputs leak attributes"},
    {"id": "A10", "title": "distil weights from the query endpoint",
     "dimension": "capability_abuse", "rationale": "query budget"},
]
PROFILE = {"is_model_query": True, "summary": "foundation model",
           "personal_data": True}


class TestPanelComposition(unittest.TestCase):
    """A panel of identical reviewers is a monologist with extra steps."""

    def test_panel_has_seats_across_the_taxonomy(self):
        panel = C.council_panel()
        self.assertGreaterEqual(panel["n_seats"], 5)
        owned = {c for s in panel["seats"] for c in s["owns"]}
        for cls in ("membership_inference", "extraction", "evasion",
                    "poisoning", "injection", "theft"):
            self.assertIn(cls, owned)

    def test_every_seat_declares_a_blind_spot(self):
        # A panel that claims to cover everything covers nothing. The blind
        # spot is the part that makes the composition auditable.
        for seat in C.council_panel()["seats"]:
            self.assertTrue(seat["blind_spot"].strip(),
                            f"{seat['id']} does not declare a blind spot")

    def test_seat_ids_are_unique(self):
        ids = [s["id"] for s in C.council_panel()["seats"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_methodologist_owns_no_attack_class(self):
        # It reviews proposals; a seat that proposed and reviewed its own work
        # would not be a check on anything.
        method = C.SEAT_BY_ID[C.METHODOLOGIST]
        self.assertEqual(method["owns"], ())
        self.assertIn("proposals", method["remit"])


class TestFalsifierAudit(unittest.TestCase):
    """The old gate was non-empty. That is not the same as refutable."""

    def test_a_specific_test_is_decisive(self):
        a = C.falsifier_audit(
            "request 20 distinctive spans back verbatim; if none returns "
            "verbatim, the claim does not hold")
        self.assertEqual(a["grade"], "decisive")
        self.assertEqual(a["score"], 1.0)

    def test_abstract_review_language_is_unfalsifiable(self):
        a = C.falsifier_audit("review the deployment")
        self.assertEqual(a["grade"], "unfalsifiable")
        self.assertEqual(a["score"], 0.0)
        self.assertTrue(a["abstract_only"])

    def test_observation_without_a_threshold_is_only_weak(self):
        a = C.falsifier_audit("observe the model outputs")
        self.assertEqual(a["grade"], "weak")
        self.assertFalse(a["names_threshold"])

    def test_no_test_at_all_is_unfalsifiable(self):
        self.assertEqual(C.falsifier_audit("")["grade"], "unfalsifiable")
        self.assertEqual(C.falsifier_audit(None)["grade"], "unfalsifiable")

    def test_graded_scores_are_ordered(self):
        decisive = C.falsifier_audit("sample 20 rows and record the rate")
        weak = C.falsifier_audit("observe the outputs")
        nothing = C.falsifier_audit("assess it")
        self.assertGreater(decisive["score"], weak["score"])
        self.assertGreater(weak["score"], nothing["score"])


class TestSeatDrafting(unittest.TestCase):
    def test_every_drafted_claim_is_about_the_subject(self):
        # The first council draft produced meta-claims: "the privacy analysis
        # identifies a live exposure". Nothing on earth can refute a sentence
        # about what an analysis found.
        for d in C.draft_seat_claims(TGT, ADV, PROFILE):
            self.assertNotIn("analysis of this subject", d["claim"])
            self.assertNotIn("seat's reading", d["claim"])

    def test_every_drafted_claim_names_a_refutable_test(self):
        for d in C.draft_seat_claims(TGT, ADV, PROFILE):
            self.assertEqual(C.falsifier_audit(d["falsifier"])["grade"],
                             "decisive", d["claim"])

    def test_a_seat_with_no_evidence_stays_silent(self):
        # Only governance rows. Governance records what is documented, not the
        # observable signature of an attack, so no seat owns a class it
        # evidences and the panel says nothing rather than manufacturing a
        # claim from a missing model card.
        gov = [{"id": "G01", "title": "no model card published",
                "dimension": "governance", "rationale": "undocumented"}]
        self.assertEqual(C.draft_seat_claims(gov, [], PROFILE), [])

    def test_each_draft_carries_its_provenance(self):
        for d in C.draft_seat_claims(TGT, ADV, PROFILE):
            self.assertTrue(d["provenance"]["seat"])
            self.assertTrue(d["provenance"]["discipline"])
            self.assertTrue(d["supporting"])

    def test_impact_comes_from_the_catalogue_not_the_drafter(self):
        # Extraction is severity 85 -> stakes 5. No seat gets to say 3.
        drafts = C.draft_seat_claims(TGT, ADV, PROFILE)
        ext = [d for d in drafts if "extraction" in d["provenance"]["classes"]]
        self.assertTrue(ext)
        self.assertEqual(ext[0]["impact"], 5)

    def test_drafting_is_deterministic(self):
        a = C.draft_seat_claims(TGT, ADV, PROFILE)
        b = C.draft_seat_claims(TGT, ADV, PROFILE)
        self.assertEqual(json.dumps(a, sort_keys=True, default=str),
                         json.dumps(b, sort_keys=True, default=str))


class TestCrossExamination(unittest.TestCase):
    """The verifier's job is to disagree, not to agree."""

    def _claim(self, **kw):
        base = {"id": "H01", "hypothesis_id": "H01",
                "claim": "verbatim training records are recoverable",
                "premise": "the corpus contains personal data",
                "mechanism": "memorised rows return on request",
                "consequence": "records leave via the API",
                "falsifier": ("request 20 distinctive spans back verbatim; "
                              "if none returns verbatim the claim fails"),
                "supporting": ["M01"], "impact": 5, "testability": 5}
        base.update(kw)
        return base

    def test_inflated_impact_is_caught(self):
        # Supporting M01 (memorization, severity 80 -> 5) with impact is fine,
        # so use a row that cannot license the stakes claimed.
        c = self._claim(supporting=["M03"], impact=5)
        grounds = {x["ground"] for x in C.cross_examine(c, TGT + ADV)}
        self.assertIn("impact_unsupported", grounds)

    def test_an_untraceable_claim_is_flagged(self):
        c = self._claim(supporting=[])
        grounds = {x["ground"] for x in C.cross_examine(c, TGT + ADV)}
        self.assertIn("untraceable_claim", grounds)

    def test_an_unfalsifiable_test_is_objected_to(self):
        c = self._claim(falsifier="review the deployment")
        grounds = {x["ground"] for x in C.cross_examine(c, TGT + ADV)}
        self.assertIn("unfalsifiable_test", grounds)

    def test_an_absent_control_is_not_read_as_a_denial(self):
        # "no per-tenant authz" is SUPPORTING evidence of exposure. Reading a
        # negation anywhere in a row as a contradiction flags every honest
        # finding as if the claim denied it.
        c = self._claim(supporting=["M03"],
                        claim="the serving endpoint returns raw completions")
        grounds = {x["ground"] for x in C.cross_examine(c, TGT + ADV)}
        self.assertNotIn("asserts_denied", grounds)

    def test_a_genuine_denial_is_still_caught(self):
        deny = [{"id": "M99", "dimension": "training_data_privacy",
                 "title": "no memorisation of personal data in the corpus",
                 "rationale": "audited: no memorisation of personal training rows"}]
        c = self._claim(supporting=["M99"], impact=4,
                        claim="memorisation of personal training data is not "
                              "recoverable from the serving surface")
        grounds = {x["ground"] for x in C.cross_examine(c, deny)}
        self.assertIn("asserts_denied", grounds)

    def test_objections_name_a_seat(self):
        c = self._claim(supporting=["M03"], impact=5)
        for o in C.cross_examine(c, TGT + ADV):
            self.assertIn(o["seat"], C.SEAT_BY_ID)

    def test_a_clean_claim_pressures_less_than_a_contested_one(self):
        clean = C.challenge_summary(
            self._claim(), C.cross_examine(self._claim(), TGT + ADV))
        messy = C.challenge_summary(
            self._claim(supporting=["M03"], impact=5),
            C.cross_examine(self._claim(supporting=["M03"], impact=5),
                            TGT + ADV))
        self.assertLess(clean["pressure"], messy["pressure"])


class TestCoverage(unittest.TestCase):
    """Silence is not safety, and the module has to say which it is."""

    def test_a_class_with_evidence_but_no_claim_is_unexamined(self):
        claims = [{"id": "H01", "supporting": ["M01"]}]   # memorization only
        cov = C.coverage_matrix(claims, TGT + ADV)
        classes = {e["class"] for e in cov["unexamined"]}
        self.assertIn("theft", classes)         # A10 exists, nobody claimed it
        self.assertIn("injection", classes)     # M03 exists, nobody claimed it
        for e in cov["unexamined"]:
            self.assertGreater(e["stored_rows"], 0)

    def test_a_class_the_corpus_never_mentions_is_reported_separately(self):
        claims = C.draft_seat_claims(TGT, ADV, PROFILE)
        cov = C.coverage_matrix(claims, TGT + ADV)
        unexam = {e["class"] for e in cov["unexamined"]}
        for e in cov["not_in_corpus"]:
            self.assertNotIn(e["class"], unexam)
            self.assertEqual(e["stored_rows"], 0)

    def test_coverage_pct_excludes_classes_the_corpus_ignores(self):
        claims = C.draft_seat_claims(TGT, ADV, PROFILE)
        cov = C.coverage_matrix(claims, TGT + ADV)
        denom = len(cov["covered"]) + len(cov["unexamined"])
        self.assertAlmostEqual(cov["coverage_pct"],
                               round(100.0 * len(cov["covered"]) / denom, 1),
                               places=1)

    def test_no_claims_yields_an_empty_matrix_not_a_crash(self):
        cov = C.coverage_matrix([], [])
        self.assertEqual(cov["covered"], [])
        self.assertIsInstance(cov["coverage_pct"], float)


class TestPanelDisagreement(unittest.TestCase):
    def test_one_seat_cannot_disagree_with_itself(self):
        out = C.panel_disagreement([
            {"claim_id": "H01", "seat": "privacy-cryptography",
             "stance": "contest"}])
        self.assertFalse(out["applicable"])
        self.assertIn("cannot disagree", out["reason"])

    def test_no_verdicts_is_not_perfect_agreement(self):
        out = C.panel_disagreement([])
        self.assertFalse(out["applicable"])
        self.assertEqual(out["n_judgements"], 0)

    def test_a_split_panel_is_reported_as_a_split(self):
        out = C.panel_disagreement([
            {"claim_id": "H01", "seat": "privacy-cryptography",
             "stance": "contest"},
            {"claim_id": "H01", "seat": "adversarial-ml", "stance": "concur"},
        ])
        self.assertTrue(out["applicable"])
        self.assertEqual(out["claims_with_split"], 1)
        self.assertIsNotNone(out["gwet_ac1"])


class TestScoringIntegration(unittest.TestCase):
    """The scorer must read the council's dimension, not drop it."""

    def test_peer_scrutiny_is_a_scored_dimension(self):
        ids = [d[0] for d in sec.HYPOTHESIS_DIMENSIONS]
        self.assertIn("peer_scrutiny", ids)
        self.assertAlmostEqual(sum(w for _, w, _ in sec.HYPOTHESIS_DIMENSIONS),
                               1.0, places=6)

    def test_unattacked_claims_score_zero_not_neutral(self):
        # The other dimensions default to 40; peer scrutiny must not, or a
        # panel that examined nothing would score as middling rather than bad.
        all_high = {d: 100 for d, _w, _x in sec.HYPOTHESIS_DIMENSIONS}
        full = sec.score_hypotheses(all_high)["confidence_pct"]
        all_high["peer_scrutiny"] = 0
        unattacked = sec.score_hypotheses(all_high)["confidence_pct"]
        self.assertLess(unattacked, full - 15)

    def test_a_measured_zero_is_not_promoted_to_the_baseline(self):
        sc = sec.score_hypotheses({"peer_scrutiny": 0})
        row = next(d for d in sc["dimensions"] if d["id"] == "peer_scrutiny")
        self.assertEqual(row["score"], 0.0)

    def test_evidence_support_still_dominates(self):
        weights = dict((d[0], d[1]) for d in sec.HYPOTHESIS_DIMENSIONS)
        self.assertGreater(weights["evidence_support"],
                           max(w for k, w in weights.items()
                               if k != "evidence_support"))


class TestRunAnalytics(unittest.TestCase):
    """The figures a reader needs before the claim list, derived not sampled."""

    def _claims(self):
        return [
            {"id": "H01", "confidence": 62.0, "impact": 4,
             "status": "untested", "peer_reviewed": True,
             "council": {"seat": "privacy-cryptography",
                         "challenges": [
                             {"seat": "measurement-science",
                              "ground": "single_flow", "weight": 0.5},
                             {"seat": "adversarial-ml",
                              "ground": "impact_unsupported", "weight": 1.0}]}},
            {"id": "H02", "confidence": 41.0, "impact": 3,
             "status": "supported", "peer_reviewed": False,
             "council": {"seat": "ml-systems", "challenges": []}},
        ]

    def _coverage(self):
        return {"coverage_pct": 50.0,
                "covered": [{"class": "extraction"}],
                "unexamined": [{"class": "poisoning"}],
                "not_in_corpus": []}

    def test_counts_and_means(self):
        a = C.run_analytics(self._claims(), self._coverage(), {"n_seats": 6})
        self.assertEqual(a["n_claims"], 2)
        self.assertEqual(a["n_contested"], 1)
        self.assertEqual(a["n_uncontested"], 1)
        self.assertEqual(a["n_blocking"], 1)
        self.assertEqual(a["mean_confidence"], 51.5)
        self.assertEqual(a["pct_contested"], 50.0)

    def test_grounds_are_ranked_commonest_first(self):
        a = C.run_analytics(self._claims(), self._coverage())
        self.assertEqual(list(a["grounds"]),
                         ["impact_unsupported", "single_flow"])

    def test_seats_show_filed_and_reviewing_separately(self):
        # Filing a claim and reviewing one are different jobs; a seat that
        # only objected must appear as a reviewer, never as silent.
        a = C.run_analytics(self._claims(), self._coverage())
        self.assertEqual(a["by_seat"]["privacy-cryptography"]["filed"], 1)
        self.assertIn("measurement-science", a["reviewing"])
        self.assertNotIn("measurement-science",
                         [s_ for s_, st in a["by_seat"].items() if st["filed"]])

    def test_coverage_lists_stay_split(self):
        a = C.run_analytics(self._claims(), self._coverage())
        self.assertEqual(a["n_covered"], 1)
        self.assertEqual(a["n_unexamined"], 1)
        self.assertEqual(a["unexamined_classes"], ["poisoning"])

    def test_empty_input_is_an_empty_report_not_a_crash(self):
        a = C.run_analytics([], {})
        self.assertEqual(a["n_claims"], 0)
        self.assertIsNone(a["mean_confidence"])
        self.assertEqual(a["grounds"], {})


class TestTracePlan(unittest.TestCase):
    """Flat hops pair into numbered plan steps."""

    def _trace(self):
        return [
            {"agent": "hypothesis-orchestrator",
             "intent": "plan_hypothesis_synthesis", "at": "2026-01-01T00:00:00+00:00",
             "note": "analyst → verifier → reporter"},
            {"agent": "hypothesis-orchestrator", "intent": "draft_hypotheses",
             "at": "2026-01-01T00:00:01+00:00", "note": "claims from priors"},
            {"agent": "hypothesis-analyst", "intent": "hypotheses_drafted",
             "at": "2026-01-01T00:00:39+00:00", "note": "7 claims drafted"},
            {"agent": "hypothesis-orchestrator", "intent": "score",
             "at": "2026-01-01T00:00:40+00:00", "note": "aggregate 41.3/100"},
            {"agent": "hypothesis-orchestrator", "intent": "write_hypothesis_report",
             "at": "2026-01-01T00:00:41+00:00", "note": "write it"},
        ]

    def test_plan_is_step_zero_and_pairs_follow(self):
        steps = C.trace_plan(self._trace())
        self.assertEqual(steps[0]["n"], 0)
        self.assertEqual(steps[0]["status"], "planned")
        self.assertEqual([(s["n"], s["phase"], s["status"], s.get("worker"))
                          for s in steps[1:]],
                         [(1, "draft_hypotheses", "done", "hypothesis-analyst"),
                          (2, "score", "done", "scoring engine"),
                          (3, "write_hypothesis_report", "incomplete", None)])

    def test_durations_come_from_stamps(self):
        steps = C.trace_plan(self._trace())
        draft = next(s for s in steps if s["phase"] == "draft_hypotheses")
        self.assertEqual(draft["duration_s"], 38.0)

    def test_engine_score_completes_itself(self):
        # score runs in-engine: no worker hop will ever close it, so it
        # must not read as incomplete once the next dispatch arrives.
        steps = C.trace_plan(self._trace())
        score = next(s for s in steps if s["phase"] == "score")
        self.assertEqual(score["status"], "done")
        self.assertEqual(score["worker"], "scoring engine")

    def test_unpaired_dispatch_is_incomplete_not_dropped(self):
        steps = C.trace_plan(self._trace())
        write = next(s for s in steps if s["phase"] == "write_hypothesis_report")
        self.assertEqual(write["status"], "incomplete")
        self.assertIn("write it", write["input_note"])

    def test_error_fails_the_open_step(self):
        # Slice before the analyst's completion hop so the dispatch is
        # still open when the error lands; otherwise the error correctly
        # becomes its own failed step and the draft stays done.
        trace = self._trace()[:2] + [
            {"agent": "hypothesis-orchestrator", "intent": "error",
             "at": "2026-01-01T00:00:50+00:00", "note": "boom"}]
        steps = C.trace_plan(trace)
        draft = next(s for s in steps if s["phase"] == "draft_hypotheses")
        self.assertEqual(draft["status"], "failed")

    def test_empty_and_malformed_traces_are_empty_plans(self):
        self.assertEqual(C.trace_plan(None), [])
        self.assertEqual(C.trace_plan([]), [])
        self.assertEqual(C.trace_plan([None, "x", 42]), [])

    def test_bad_stamps_yield_none_durations(self):
        trace = [{"agent": "a-orchestrator", "intent": "do",
                  "at": "not-a-date", "note": "x"},
                 {"agent": "worker", "intent": "did",
                  "at": None, "note": "y"}]
        steps = C.trace_plan(trace)
        self.assertEqual(len(steps), 1)
        self.assertIsNone(steps[0]["duration_s"])
        self.assertEqual(steps[0]["status"], "done")


class TestCouncilReportSection(unittest.TestCase):
    """The run summary must show every flow, not just the latest row."""

    def test_all_flows_named_and_hypothesis_rendered(self):
        from app import run_summary as RS
        db = SessionLocal()
        try:
            inv = Investigation(title="t", keywords="k", description="d",
                                sources="web")
            db.add(inv)
            db.commit()
            for path, score in (("model", 30.0), ("model_hypothesis", 44.0)):
                db.add(SecurityAssessment(
                    investigation_id=inv.id, product_name="W",
                    exposure="confidential_data", overall_pct=score,
                    posture="p", markdown="m",
                    scoring_json=json.dumps({
                        "assessment_path": path,
                        "confidence_pct": score} if path == "model_hypothesis"
                        else {"assessment_path": path}),
                    threats_json=json.dumps(
                        [{"hypothesis_id": "H01", "claim": "c",
                          "confidence": 60.0, "impact": 4,
                          "status": "contested",
                          "falsifier": "f",
                          "council": {"seat": "privacy-cryptography",
                                      "challenges": [
                                          {"seat": "x", "ground": "single_flow",
                                           "weight": 0.5}]}}]
                        if path == "model_hypothesis" else []),
                    a2a_trace_json=json.dumps({
                        "task_id": "hyp-x", "trace": [],
                        "council": {"panel": {"n_seats": 6},
                                    "coverage": {"coverage_pct": 100.0,
                                                 "covered": [], "unexamined": [],
                                                 "not_in_corpus": []}}}),
                    threat_pack_version="2.1.0",
                    threat_pack_fingerprint="x"))
            db.commit()
            lines = RS._council_section(db, inv.id)
            md = "\n".join(lines)
        finally:
            db.close()
        # Both flows named: the synthesis never hides the priors it read.
        self.assertIn("`model`", md)
        self.assertIn("`model_hypothesis`", md)
        self.assertIn("H01", md)
        self.assertIn("privacy-cryptography", md)
        self.assertIn("single_flow", md)

    def test_no_assessments_is_no_section_not_an_error(self):
        from app import run_summary as RS
        db = SessionLocal()
        try:
            inv = Investigation(title="empty", keywords="k",
                                description="d", sources="web")
            db.add(inv)
            db.commit()
            lines = RS._council_section(db, inv.id)
        finally:
            db.close()
        self.assertEqual(lines, [])


if __name__ == "__main__":
    unittest.main()
