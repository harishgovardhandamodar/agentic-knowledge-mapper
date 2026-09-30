"""Tests for the third model assessment A2A path: hypothesis synthesis.

Flow 1 asks "is this model sound?". Flow 2 asks "what could an attacker BUILD
with it?". Flow 3 reads the stored output of both and asks a different
question again: which of these claims is actually true, and what would settle
it.

The behaviours these tests pin down are the ones that make flow 3 different
from the other two rather than a third copy of them:

  * a hypothesis is a CLAIM with a falsifier, and a claim that cannot be
    refuted is not allowed to exist;
  * the aggregate is a CONFIDENCE, and must not be readable as a risk score;
  * it reads the STORED rows of flows 1 and 2 rather than re-running their
    agents, so a claim always describes the assessment the user actually read;
  * it is scored separately, never averaged into the other two.
"""
import json
import os
import re
import tempfile
import unittest
from unittest import mock

# Pin the database before app.database is imported: a module that omits
# this can inherit data/akm.db and write test rows into the live store.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-hyp-path-"), "test.db"))

from app import agents  # noqa: E402
from app import security as sec  # noqa: E402
from app import database  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.models import Investigation, SecurityAssessment  # noqa: E402

database.init_db()


NAME = "Tabular Foundation Models"
USE = "classifies confidential customer tabular records in production"
FOCUS = ["tabular", "models"]


def _offline():
    """Force the deterministic branch: no gateway, no invented claims."""
    return mock.patch("app.llm.chat", side_effect=RuntimeError("down"))


def _offline_json():
    return mock.patch("app.llm.chat_json", side_effect=RuntimeError("down"))


def _run(mode, use_case=USE, db=None, inv_id=None, product=NAME, focus=None):
    with _offline(), _offline_json():
        return sec.build_assessment(
            product_name=product, product_url="", exposure="confidential_data",
            use_case=use_case, focus=list(focus if focus is not None else FOCUS),
            db=db, investigation_id=inv_id, declared_controls=[],
            assessment_mode=mode)


def _store(db, inv_id, out):
    rec = SecurityAssessment(
        investigation_id=inv_id, product_name=out["product_name"],
        product_url="", exposure=out["exposure"], use_case=USE,
        focus_json=json.dumps(FOCUS), overall_pct=out["overall_pct"],
        inherent_pct=out["inherent_pct"], residual_pct=out["residual_pct"],
        scoring_json=json.dumps(out["scoring"]),
        threats_json=json.dumps(out["threats"]),
        markdown=out["markdown"], diagrams_json=json.dumps(out["diagrams"]))
    db.add(rec)
    db.commit()
    db.refresh(rec)
    return rec


class _Inv:
    """An investigation to hang the stored rows off."""

    def __init__(self, title="Tabular models"):
        self.db = SessionLocal()
        inv = Investigation(title=title, keywords="tabular", description="x",
                            sources="web")
        self.db.add(inv)
        self.db.commit()
        self.db.refresh(inv)
        self.id = inv.id

    def close(self):
        self.db.close()


class TestModeResolution(unittest.TestCase):
    """The third mode is a property of the request, never of the wording."""

    def test_explicit_hypothesis_mode_is_honoured(self):
        self.assertEqual(sec.resolve_model_mode(NAME, USE, FOCUS, "hypothesis"),
                         "hypothesis")

    def test_hypothesis_is_not_inferred_from_wording(self):
        # A defensively-worded request must not silently become a hypothesis
        # run, and an offensive one must not either: which question to ask is
        # the caller's call, not the classifier's.
        for use_case in ("defend against adversarial misuse",
                         "what could an attacker build with this"):
            self.assertNotEqual(sec.resolve_model_mode(NAME, use_case, FOCUS, ""),
                                "hypothesis")

    def test_resolver_returns_path_for_each_mode(self):
        prof = sec.profile_model_subject(NAME, USE, FOCUS)
        for mode, path in (("target", "model"),
                           ("adversarial", "model_adversarial"),
                           ("hypothesis", "model_hypothesis")):
            out = _run(mode)
            self.assertEqual(out["scoring"]["assessment_path"], path,
                             f"mode {mode} took the wrong path")
            self.assertEqual(sec.resolve_model_mode(NAME, USE, FOCUS, mode), mode)
        self.assertEqual(prof["is_model_query"], True)

    def test_catalog_subject_resolves_to_no_mode_at_all(self):
        # Not "target". Filing a Stripe review under the model-internals
        # question would also make the two occupy one busy slot, since the
        # lock compares resolved modes.
        self.assertEqual(
            sec.resolve_model_mode("Stripe API", "assess the public API rate limits",
                                   ["api"], ""),
            "")

    def test_explicit_mode_wins_even_for_a_catalog_subject(self):
        # The caller asked a specific question; declining to run it would be
        # worse than running it against a subject the profiler did not expect.
        for mode in ("target", "adversarial", "hypothesis"):
            self.assertEqual(
                sec.resolve_model_mode("Support chatbot", "answer billing questions",
                                       ["chatbot"], mode), mode)

    def test_catalog_subject_keeps_standard_path_when_no_mode_given(self):
        out = _run("", use_case="answer billing questions in chat",
                   product="Support chatbot", focus=["chatbot"])
        # The standard catalog path stamps its own marker, so no reader ever
        # re-derives it from the wording -- a fresh catalog row is already
        # distinguishable from a legacy unmarked one.
        self.assertEqual(out["scoring"].get("assessment_path"), "standard")
        self.assertTrue(any(t["id"].startswith("T") for t in out["threats"]))
        self.assertTrue(out["threats"][0]["id"].startswith("T"))


class TestScoringSemantics(unittest.TestCase):
    """The number is a confidence. Every test here guards that distinction."""

    def test_method_and_meaning_are_declared(self):
        sc = sec.score_hypotheses({})
        self.assertEqual(sc["method"], "hypothesis-synthesis-v1")
        self.assertEqual(sc["assessment_path"], "model_hypothesis")
        self.assertIn("not risk", sc["score_meaning"])

    def test_confidence_is_not_written_to_a_risk_field_only(self):
        sc = sec.score_hypotheses({"evidence_support": 100})
        # It does populate overall_pct for storage/UI continuity, but the
        # meaning is declared in the same dict so no consumer has to guess.
        self.assertIn("overall_pct", sc)
        self.assertIn("confidence_pct", sc)
        self.assertIn("CONFIDENCE", sc["posture"])

    def test_weights_sum_to_one(self):
        self.assertAlmostEqual(sum(w for _, w, _ in sec.HYPOTHESIS_DIMENSIONS),
                               1.0, places=6)

    def test_evidence_dominates_the_aggregate(self):
        # A claim set with no evidence cannot be well-supported no matter how
        # high its stakes: impact is deliberately the smallest weight.
        ev = sec.score_hypotheses({"evidence_support": 100, "testability": 100,
                                  "cross_flow_corroboration": 100,
                                  "impact_if_true": 0})
        no_ev = sec.score_hypotheses({"evidence_support": 0, "testability": 100,
                                      "cross_flow_corroboration": 100,
                                      "impact_if_true": 100})
        self.assertGreater(ev["confidence_pct"], no_ev["confidence_pct"])

    def test_unmeasured_dimension_takes_the_neutral_baseline(self):
        self.assertEqual(sec.score_hypotheses({})["confidence_pct"],
                         sec.score_hypotheses(
                             {"evidence_support": 40, "cross_flow_corroboration": 40,
                              "testability": 40, "impact_if_true": 40})["confidence_pct"])


class TestHypothesisShape(unittest.TestCase):
    """A hypothesis is a falsifiable claim. The tests pin that definition."""

    def test_every_claim_carries_a_falsifier(self):
        h = agents._hypothesis("H01", "c", "p", "m", "k", "the observation")
        self.assertTrue(h["falsifier"])

    def test_drafted_claims_are_all_falsifiable(self):
        t_rows = [{"id": "M01", "title": "memorisation", "rationale":
                   "trains on personal data",
                   "dimension": "training_data_privacy"}]
        a_rows = [{"id": "A09", "title": "infer withheld attributes",
                   "rationale": "from model outputs", "dimension": "data_recon"}]
        prof = {"is_model_query": True, "summary": "tabular model"}
        out = agents._hypothesis_fallback(t_rows, a_rows, prof)
        self.assertTrue(out)
        for h in out:
            self.assertTrue(str(h.get("falsifier", "")).strip(),
                            f"{h['id']} has no falsifier")

    def test_llm_claim_without_falsifier_is_discarded(self):
        # The handler drops a claim the model proposed with no refutation
        # rather than storing an assertion as a hypothesis.
        with mock.patch("app.llm.chat", return_value=json.dumps({"hypotheses": [
                {"id": "H1", "claim": "c", "falsifier": "f", "impact": 3},
                {"id": "H2", "claim": "no refutation given"}]})):
            env = {"payload": {"product_name": NAME, "use_case": USE,
                               "profile": {"is_model_query": True},
                               "target_rows": [], "adversarial_rows": []},
                   "task_id": "t", "trace": []}
            res = agents.hypothesis_analyst_handle(env)
        ids = [h["id"] for h in res["payload"]["hypotheses"]]
        self.assertEqual(ids, ["H1"])

    def test_llm_claims_keep_their_source_rows(self):
        # An LLM-drafted claim arrives as prose with no `supporting` list. If
        # it stays empty the verifier reads every claim as uncorroborated and
        # the confidence aggregate DROPS the moment the gateway is reachable --
        # so the production path would score worse than the offline test path.
        llm_claim = ("held-out training rows are recoverable through the "
                     "serving surface via memorisation")
        with mock.patch("app.llm.chat", return_value=json.dumps({"hypotheses": [
                {"id": "H01", "claim": llm_claim, "premise": "trains on "
                 "personal data and exposes an inference API",
                 "falsifier": "request 20 training rows back verbatim"}]})):
            env = {"payload": {"product_name": NAME, "use_case": USE,
                               "profile": {"is_model_query": True},
                               "target_rows": [
                                   {"id": "M01", "title": "memorisation of "
                                    "training rows", "dimension":
                                    "training_data_privacy"}],
                               "adversarial_rows": [
                                   {"id": "A09", "title": "infer withheld "
                                    "attributes from outputs", "dimension":
                                    "data_recon"}]},
                   "task_id": "t", "trace": []}
            res = agents.hypothesis_analyst_handle(env)
        h = res["payload"]["hypotheses"][0]
        self.assertIn("supporting", h)
        self.assertIn("M01", h["supporting"])
        self.assertTrue(h["supporting"])

    def test_source_matching_is_conservative(self):
        # A claim sharing nothing distinctive with a row must not inherit it.
        h = {"claim": "the deployment schedule slipped by two quarters",
             "premise": "", "mechanism": "", "consequence": ""}
        rows = [{"id": "M01", "title": "training data memorisation",
                 "dimension": "training_data_privacy"}]
        self.assertEqual(agents._match_hyp_sources(h, rows), [])

    def test_source_matching_caps_how_much_one_claim_can_stake(self):
        rows = [{"id": f"M{i:02d}", "title": "memorisation risk",
                 "dimension": "training_data_privacy"} for i in range(1, 9)]
        h = {"claim": "memorisation makes training rows recoverable",
             "premise": "", "mechanism": "", "consequence": ""}
        self.assertLessEqual(len(agents._match_hyp_sources(h, rows)), 4)

    def test_cross_flow_claim_spans_both_flows(self):
        t_rows = [{"id": "M01", "title": "training data memorisation",
                   "rationale": "fits on personal data",
                   "dimension": "training_data_privacy"},
                  {"id": "M02", "title": "unguarded inference endpoint",
                   "rationale": "public API", "dimension": "deployment_surface"}]
        a_rows = [{"id": "A09", "title": "attribute inference",
                   "rationale": "from outputs", "dimension": "data_recon"},
                  {"id": "A10", "title": "output laundering",
                   "rationale": "uninspected outputs", "dimension": "evasion"},
                  {"id": "A11", "title": "reachable endpoint capability",
                   "rationale": "needs no model defect",
                   "dimension": "capability_abuse"}]
        prof = {"is_model_query": True, "summary": "tabular"}
        claims = agents._hypothesis_fallback(t_rows, a_rows, prof)
        by_id = {c["id"]: c for c in claims}
        # H01 draws on training-data privacy AND data recon, so its supporting
        # list has to name a row from each flow or the verifier cannot call it
        # corroborated -- which is the entire reason this flow exists.
        self.assertIn("M01", by_id["H01"]["supporting"])
        self.assertIn("A09", by_id["H01"]["supporting"])
        self.assertTrue(any(len(c["supporting"]) >= 2 for c in claims))
        # H04 comes from the misuse flow alone and must not pretend otherwise.
        self.assertTrue(all(s.startswith("A") for s in by_id["H04"]["supporting"]))

    def test_no_evidence_base_yields_an_explicit_gap_marker(self):
        # Never an empty set: an empty claim list reads as "nothing worth
        # testing" when it actually means "the two flows produced nothing".
        out = agents._hypothesis_fallback([], [], {"is_model_query": True,
                                                   "summary": "m"})
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["impact"], 1.0)
        self.assertIn("no overlapping signal", out[0]["claim"])


class TestVerifier(unittest.TestCase):
    """The verifier's job is to disagree, not to agree."""

    def _verify(self, hyps):
        env = {"payload": {"hypotheses": hyps}, "task_id": "t", "trace": []}
        res = agents.hypothesis_verifier_handle(env)["payload"]["verified"]
        return {v["id"]: v for v in res}

    def test_counter_evidence_lowers_support(self):
        clean = agents._hypothesis("H01", "c", "p", "m", "k", "f",
                                   supporting=["M01", "A09", "M02"])
        argued = dict(clean, id="H02", counter_evidence=["M01", "M02"])
        by_id = self._verify([clean, argued])
        self.assertEqual(by_id["H01"]["counter_evidence"], [])
        self.assertEqual(len(by_id["H02"]["counter_evidence"]), 2)
        self.assertLess(by_id["H02"]["support_score"], by_id["H01"]["support_score"])

    def test_missing_falsifier_collapses_testability(self):
        h = agents._hypothesis("H01", "c", "p", "m", "k", "f")
        h["falsifier"] = ""
        v = self._verify([h])["H01"]
        self.assertEqual(v["verification_dimensions"]["testability"], 20.0)

    def test_vague_falsifier_claim_outscores_a_specific_one(self):
        # The whole point of the dimension: "review the deployment" settles
        # nothing, so the claim carrying it must not outrank a testable one.
        vague = agents._hypothesis("H01", "c", "p", "m", "k", "",
                                   supporting=["M01", "A09", "M02"])
        specific = agents._hypothesis("H02", "c", "p", "m", "k",
                                     "sample 20 rows and request them back",
                                     supporting=["M01", "A09", "M02"])
        by_id = self._verify([vague, specific])
        self.assertLess(by_id["H01"]["confidence"], by_id["H02"]["confidence"])

    def test_correlation_flag_requires_both_flows(self):
        both = agents._hypothesis("H01", "c", "p", "m", "k", "f",
                                  supporting=["M01", "A09"])
        only_t = agents._hypothesis("H02", "c", "p", "m", "k", "f",
                                    supporting=["M01"])
        neither = agents._hypothesis("H03", "c", "p", "m", "k", "f", supporting=[])
        for h, t_ids, a_ids in ((both, ["M01"], ["A09"]),
                                (only_t, ["M01"], []),
                                (neither, [], [])):
            h["_target_ids"] = t_ids
            h["_adversarial_ids"] = a_ids
        by_id = self._verify([both, only_t, neither])
        self.assertTrue(by_id["H01"]["cross_flow"])
        self.assertFalse(by_id["H02"]["cross_flow"])
        self.assertFalse(by_id["H03"]["cross_flow"])

    def test_dimension_inputs_use_the_mean_not_the_max(self):
        strong = agents._hypothesis("H01", "c", "p", "m", "k", "f",
                                    supporting=["M01", "A09", "M02", "A10"])
        weak = agents._hypothesis("H02", "c", "p", "m", "k", "f", supporting=[])
        env = {"payload": {"hypotheses": [strong, weak]}, "task_id": "t",
               "trace": []}
        res = agents.hypothesis_verifier_handle(env)["payload"]
        vals = [v["verification_dimensions"]["evidence_support"]
                for v in res["verified"]]
        self.assertAlmostEqual(res["dimension_inputs"]["evidence_support"],
                               sum(vals) / len(vals), places=1)
        self.assertLess(res["dimension_inputs"]["evidence_support"], max(vals))

    def test_support_score_is_capped_not_a_count(self):
        # Six rows citing one finding are not six independent confirmations:
        # the count is capped at three so a verbose claim cannot buy confidence.
        three = agents._hypothesis("H01", "c", "p", "m", "k", "f",
                                   supporting=["M01", "A09", "M02"])
        many = agents._hypothesis("H02", "c", "p", "m", "k", "f",
                                  supporting=["M01", "A09", "M02", "A10", "M03"])
        two = agents._hypothesis("H03", "c", "p", "m", "k", "f",
                                 supporting=["M01", "A09"])
        by_id = self._verify([three, many, two])
        self.assertEqual(by_id["H01"]["support_score"], by_id["H02"]["support_score"])
        self.assertLess(by_id["H03"]["support_score"], by_id["H01"]["support_score"])


class TestContradictions(unittest.TestCase):
    """A claim that denies a flow-1 finding is arguing with its own evidence."""

    P01 = {"id": "P01", "title": "Training-data minimization unverified",
           "rationale": "no personal-data signals; minimization posture unstated",
           "dimension": "training_data_privacy"}
    M02 = {"id": "M02", "title": "Schema and distribution inference from outputs",
           "rationale": "tabular outputs reveal column semantics and distributions",
           "dimension": "model_integrity"}

    def _verify(self, hyps, rows):
        env = {"payload": {"hypotheses": hyps, "target_rows": rows},
               "task_id": "t", "trace": []}
        res = agents.hypothesis_verifier_handle(env)["payload"]["verified"]
        return {v["id"]: v for v in res}

    def test_claim_denied_by_a_finding_is_flagged(self):
        # The live H01/P01 case: the premise asserts personal training data,
        # the finding states there are no personal-data signals.
        h = agents._hypothesis(
            "H01", "held-out training rows are recoverable through the serving surface",
            "the profile says it trains on personal data",
            "memorised rows are reachable by querying the model",
            "confidential training records leave via the inference API",
            "request the rows back verbatim",
            supporting=["A01"])
        v = self._verify([h], [self.P01, self.M02])["H01"]
        self.assertEqual(v["contradicted_by"], ["P01"])

    def test_contradiction_lowers_support(self):
        h = agents._hypothesis(
            "H01", "held-out training rows are recoverable through the serving surface",
            "the profile says it trains on personal data",
            "memorised rows are reachable by querying the model",
            "confidential training records leave via the inference API",
            "request the rows back verbatim",
            supporting=["M02"])
        clean = agents._hypothesis(
            "H02", "outputs reveal column distributions",
            "the model serves confidence scores", "scores expose the schema",
            "an attacker maps the columns", "serve labels only",
            supporting=["M02"])
        by_id = self._verify([h, clean], [self.P01, self.M02])
        self.assertLess(by_id["H01"]["support_score"],
                        by_id["H02"]["support_score"])

    def test_agreeing_claim_is_not_flagged(self):
        h = agents._hypothesis(
            "H01", "tabular outputs reveal column semantics",
            "the model serves full distributions",
            "distributions expose column ranges",
            "an attacker reconstructs the schema", "serve labels only",
            supporting=["M02"])
        v = self._verify([h], [self.P01, self.M02])["H01"]
        self.assertEqual(v.get("contradicted_by"), [])

    def test_vague_claim_matches_nothing(self):
        h = agents._hypothesis("H09", "things are bad somewhere", "p", "m",
                               "k", "f", supporting=[])
        v = self._verify([h], [self.P01, self.M02])["H09"]
        self.assertEqual(v.get("contradicted_by"), [])

    def test_quoting_a_denial_is_not_flagged(self):
        # A claim that repeats the finding's own denial agrees with it: both
        # sides negated means symmetric, not contradictory.
        h = agents._hypothesis(
            "H05", "minimization cannot be verified from the outside",
            "P01 found no personal-data signals in the served outputs",
            "black-box probing cannot confirm what is minimized",
            "minimization claims stay unverified", "inspect the pipeline",
            supporting=["P01"])
        v = self._verify([h], [self.P01, self.M02])["H05"]
        self.assertEqual(v.get("contradicted_by"), [])

    def test_report_names_the_tension(self):
        h = agents._hypothesis(
            "H01", "held-out training rows are recoverable through the serving surface",
            "the profile says it trains on personal data",
            "memorised rows are reachable by querying the model",
            "confidential training records leave via the inference API",
            "request the rows back verbatim",
            supporting=["A01"])
        v = self._verify([h], [self.P01, self.M02])["H01"]
        env = {"payload": {"product_name": "M", "verified": [v], "scoring": {}},
               "task_id": "t", "trace": []}
        sections = agents.hypothesis_reporter_handle(env)["payload"]["hypothesis_sections"]
        self.assertIn("In tension with flow 1", sections)
        self.assertIn("P01", sections)


class TestReadFromStoredRows(unittest.TestCase):
    """Flow 3 reads the stored rows, not a fresh run of the other agents."""

    def test_loader_takes_most_recent_row_per_path(self):
        inv = _Inv()
        db = inv.db
        try:
            old = _run("target", db=db, inv_id=inv.id)
            _store(db, inv.id, old)
            new = _run("adversarial", db=db, inv_id=inv.id)
            _store(db, inv.id, new)
            tgt, adv = sec._load_prior_model_rows(db, inv.id)
            self.assertTrue(tgt and adv)
            self.assertEqual(tgt[0]["dimension"], old["threats"][0]["dimension"])
        finally:
            inv.close()

    def test_loader_ignores_non_model_paths(self):
        inv = _Inv()
        db = inv.db
        try:
            cat = _run("", use_case="answer billing questions in chat",
                       product="Support chatbot", focus=["chatbot"])
            _store(db, inv.id, cat)
            tgt, adv = sec._load_prior_model_rows(db, inv.id)
            self.assertEqual((tgt, adv), ([], []))
        finally:
            inv.close()

    def test_no_stored_rows_reports_the_gap_not_a_silent_zero(self):
        inv = _Inv()
        try:
            out = _run("hypothesis", db=inv.db, inv_id=inv.id)
            self.assertEqual(out["scoring"]["assessment_path"], "model_hypothesis")
            self.assertTrue(out["threats"])
            self.assertIn("no overlapping signal", out["threats"][0]["claim"])
        finally:
            inv.close()

    def test_end_to_end_synthesis_over_stored_rows(self):
        inv = _Inv()
        db = inv.db
        try:
            _store(db, inv.id, _run("target", db=db, inv_id=inv.id))
            _store(db, inv.id, _run("adversarial", db=db, inv_id=inv.id))
            out = _run("hypothesis", db=db, inv_id=inv.id)
            self.assertEqual(out["scoring"]["assessment_path"], "model_hypothesis")
            self.assertTrue(out["threats"], "synthesis drafted no claims")
            self.assertTrue(any(h.get("cross_flow") for h in out["threats"]),
                            "no claim was corroborated by both flows")
            for h in out["threats"]:
                self.assertTrue(str(h.get("falsifier", "")).strip())
        finally:
            inv.close()


class TestDiagrams(unittest.TestCase):
    def test_evidence_map_separates_corroborated_from_single_flow(self):
        d = sec.mermaid_hypothesis_map([
            {"claim": "both", "supported_by_target": True,
             "supported_by_adversarial": True},
            {"claim": "one", "supported_by_target": False,
             "supported_by_adversarial": True}])
        self.assertIn("flowchart LR", d)
        self.assertIn(":::corroborated", d)
        self.assertIn(":::single", d)

    def test_chain_diagram_includes_the_refutation(self):
        d = sec.mermaid_hypothesis_chain({
            "claim": "c", "premise": "p", "mechanism": "m",
            "consequence": "k", "falsifier": "the observation"})
        self.assertIn("refuted by", d)
        self.assertIn("the observation", d)

    def test_empty_map_still_renders(self):
        self.assertIn("flowchart", sec.mermaid_hypothesis_map([]))

    def test_labels_cut_at_word_boundaries(self):
        # A fixed slice landed mid-word ("trains o") in every rendered
        # diagram; labels must end on a whole word instead.
        self.assertEqual(
            sec._mermaid_label("the profile says it trains on personal records here", 28),
            "the profile says it trains")
        self.assertEqual(sec._mermaid_label("short", 28), "short")
        self.assertEqual(sec._mermaid_label("supercalifragilisticexpialidocious", 10),
                         "supercalif")
        d = sec.mermaid_hypothesis_chain({
            "claim": "held-out training rows are recoverable through XYZ",
            "premise": "the profile says it trains on personal records here",
            "mechanism": "memorised rows are reachable by querying",
            "consequence": "records leave", "falsifier": "ask them back"})
        self.assertIn("the profile says it trains", d)
        self.assertNotIn("trains o", d)

    def test_exec_paragraph_is_short_and_rounded(self):
        # The old template recomputed the mean inline (:g keeps six
        # significant digits, hence "83.9333/100") and crammed every claim
        # into one run-on sentence.
        env = {"payload": {
            "product_name": "M",
            "verified": [
                {"id": "H01", "claim": "rows leak", "confidence": 94.0,
                 "impact": 5, "falsifier": "ask them back"},
                {"id": "H02", "claim": "steering works", "confidence": 70.0,
                 "impact": 3, "falsifier": "try it"}],
            "scoring": {"confidence_pct": 82.0}},
            "task_id": "t", "trace": []}
        para = agents.hypothesis_reporter_handle(env)["payload"]["exec_paragraph"]
        self.assertNotIn("83.9333", para)
        self.assertIn("82/100", para)
        self.assertLess(len(para), 400)
        self.assertIn("H01", para)


class TestAgentRegistry(unittest.TestCase):
    def test_three_hypothesis_cards_are_registered(self):
        names = {c["name"] for c in agents.get_agent_cards()}
        for n in ("hypothesis-analyst", "hypothesis-verifier",
                  "hypothesis-reporter"):
            self.assertIn(n, names)

    def test_cards_are_addressable_on_the_bus(self):
        for agent, intent in (("hypothesis-analyst", "draft_hypotheses"),
                              ("hypothesis-verifier", "verify_hypotheses"),
                              ("hypothesis-reporter", "write_hypothesis_report")):
            self.assertIn(agent, agents._HANDLERS)
            self.assertIn(intent, agents._HANDLERS[agent])

    def test_workflow_drafts_verifies_and_reports(self):
        tgt = [{"id": "M01", "title": "memorisation",
                "dimension": "training_data_privacy", "rationale": "personal data"}]
        adv = [{"id": "A09", "title": "infer attributes",
                "dimension": "data_recon", "rationale": "outputs"}]
        with _offline(), _offline_json():
            res = agents.run_hypothesis_a2a_workflow(
                product_name=NAME, use_case=USE, focus=FOCUS, db=None,
                investigation_id=None, target_rows=tgt, adversarial_rows=adv)
        self.assertTrue(res["hypotheses"])
        self.assertTrue(res["hypothesis_verified"])
        self.assertIn("## Hypotheses and what would settle them",
                      res["hypothesis_sections"])
        self.assertIn("Refuted by", res["hypothesis_sections"])
        self.assertEqual(res["scoring"]["assessment_path"], "model_hypothesis")
        self.assertIn("not a risk score", res["hypothesis_sections"])
        hops = {h.get("intent") for h in res["a2a_trace"]}
        self.assertIn("draft_hypotheses", hops)
        self.assertIn("verify_hypotheses", hops)
        self.assertIn("write_hypothesis_report", hops)
        # The claims must arrive carrying their sources, or the report cannot
        # say which rows each one was read off.
        self.assertTrue(all(h.get("supporting") for h in res["hypotheses"]))
        self.assertTrue(any(v.get("cross_flow") for v in res["hypothesis_verified"]))

    def test_workflow_survives_no_prior_rows(self):
        with _offline(), _offline_json():
            res = agents.run_hypothesis_a2a_workflow(
                product_name=NAME, use_case=USE, focus=FOCUS, db=None,
                investigation_id=None, target_rows=[], adversarial_rows=[])
        self.assertIn("scoring", res)
        self.assertEqual(res["scoring"]["assessment_path"], "model_hypothesis")


class TestReport(unittest.TestCase):
    def _report(self, inv):
        db = inv.db
        _store(db, inv.id, _run("target", db=db, inv_id=inv.id))
        _store(db, inv.id, _run("adversarial", db=db, inv_id=inv.id))
        return _run("hypothesis", db=db, inv_id=inv.id)["markdown"]

    def test_report_states_it_is_not_a_risk_score(self):
        inv = _Inv()
        try:
            md = self._report(inv)
            self.assertIn("not a risk score", md)
            self.assertIn("hypothesis-synthesis-v1", md)
        finally:
            inv.close()

    def test_report_names_the_rows_it_read(self):
        inv = _Inv()
        try:
            md = self._report(inv)
            self.assertIn("Model internals (flow 1)", md)
            self.assertIn("Adversarial misuse (flow 2)", md)
        finally:
            inv.close()

    def test_report_embeds_mermaid(self):
        inv = _Inv()
        try:
            md = self._report(inv)
            self.assertIn("```mermaid", md)
        finally:
            inv.close()

    def test_report_explains_what_contradicts_a_claim(self):
        inv = _Inv()
        try:
            md = self._report(inv)
            self.assertIn("Refuted by", md)
        finally:
            inv.close()


class TestGating(unittest.TestCase):
    """The hypothesis path must be refused wherever a catalog run would be."""

    def _record(self, inv, mode):
        out = _run(mode, db=inv.db, inv_id=inv.id)
        if mode != "hypothesis":
            _store(inv.db, inv.id, out)
        return _store(inv.db, inv.id, out)

    def test_rescore_is_refused(self):
        inv = _Inv()
        try:
            _store(inv.db, inv.id, _run("target", db=inv.db, inv_id=inv.id))
            _store(inv.db, inv.id, _run("adversarial", db=inv.db, inv_id=inv.id))
            rec = self._record(inv, "hypothesis")
            from app import main as main_mod
            from fastapi.testclient import TestClient
            client = TestClient(main_mod.app)
            r = client.post(f"/api/security/assessments/{rec.id}/rescore",
                            json={"persist": False})
            self.assertEqual(r.status_code, 422)
            self.assertIn("Hypothesis", r.json()["detail"])
        finally:
            inv.close()

    def test_an_unknown_mode_is_rejected_not_treated_as_auto(self):
        """A typo'd mode must not silently run some other question and return
        a report that looks like an answer to it."""
        inv = _Inv()
        try:
            from app import main as main_mod
            from fastapi.testclient import TestClient
            client = TestClient(main_mod.app)
            with mock.patch.object(main_mod.security_agent,
                                   "launch_security_assessment") as launch:
                r = client.post(f"/api/investigations/{inv.id}/security/assess",
                                json={"product_name": "Tabular Foundation Models",
                                      "use_case": "classifies confidential "
                                                  "customer tabular records",
                                      "assessment_mode": "adversarial-"})
                self.assertEqual(r.status_code, 422)
                self.assertIn("assessment_mode", r.json()["detail"])
                launch.assert_not_called()
        finally:
            inv.close()

    def test_standards_mapping_is_skipped(self):
        inv = _Inv()
        try:
            _store(inv.db, inv.id, _run("target", db=inv.db, inv_id=inv.id))
            _store(inv.db, inv.id, _run("adversarial", db=inv.db, inv_id=inv.id))
            rec = self._record(inv, "hypothesis")
            from app import standards_matrix as sm
            with mock.patch.object(sm, "load_taxonomy",
                                   return_value={"dimensions": [],
                                                 "scoreLegend": {}}), \
                 mock.patch.object(sm, "fetch_dashboard",
                                   return_value={"generated": "x",
                                                 "frameworks": []}):
                mat = sm.build_matrix(db=inv.db, assessment_id=rec.id)
            self.assertTrue(mat["skipped"])
            self.assertIn("Hypothesis-synthesis", mat["skip_reason"])
        finally:
            inv.close()

    def test_approval_gate_is_skipped(self):
        inv = _Inv()
        try:
            _store(inv.db, inv.id, _run("target", db=inv.db, inv_id=inv.id))
            _store(inv.db, inv.id, _run("adversarial", db=inv.db, inv_id=inv.id))
            _store(inv.db, inv.id, _run("hypothesis", db=inv.db, inv_id=inv.id))
            from app import security_agent as sa
            from app.models import AgentRun
            run = AgentRun(investigation_id=inv.id, status="running",
                           trigger="security", plan=json.dumps(
                               {"product": NAME,
                                "assessment_mode": "hypothesis"}))
            inv.db.add(run)
            inv.db.commit()
            inv.db.refresh(run)
            with mock.patch.object(sa, "_ensure_worker", lambda: None):
                sa.run_security_assessment(run.id, {
                    "product_name": NAME, "use_case": USE, "focus": FOCUS,
                    "exposure": "confidential_data", "doc_urls": [],
                    "declared_controls": [], "require_approval": True,
                    "assessment_mode": "hypothesis"})
            inv.db.refresh(run)
            events = [e.message for e in run.events]
            self.assertTrue(any("gate" in m.lower() for m in events))
            self.assertTrue(any("skipped" in m.lower() for m in events))
        finally:
            inv.close()


class TestBusyCheck(unittest.TestCase):
    """Distinct modes run together; a duplicate of the same one does not."""

    def _running(self, inv, mode):
        from app.models import AgentRun
        from app import security_agent as sa
        run = AgentRun(investigation_id=inv.id, status="running",
                       trigger="security",
                       plan=json.dumps({"product": NAME, "assessment_mode": mode}))
        inv.db.add(run)
        inv.db.commit()
        return sa

    def test_same_mode_is_busy(self):
        inv = _Inv()
        try:
            sa = self._running(inv, "hypothesis")
            self.assertTrue(sa.security_run_busy(
                inv.db, inv.id, assessment_mode="hypothesis",
                product_name=NAME, use_case=USE, focus=FOCUS))
        finally:
            inv.close()

    def test_other_modes_are_not_blocked_by_it(self):
        inv = _Inv()
        try:
            sa = self._running(inv, "hypothesis")
            for mode in ("target", "adversarial"):
                self.assertFalse(sa.security_run_busy(
                    inv.db, inv.id, assessment_mode=mode,
                    product_name=NAME, use_case=USE, focus=FOCUS),
                    f"{mode} was blocked by a hypothesis run")
        finally:
            inv.close()

    def test_auto_mode_is_compared_after_resolution(self):
        # An auto request that resolves to "adversarial" must be refused when
        # an explicit adversarial run is already in flight, even though the
        # requested strings differ. Without resolution this slips through and
        # two runs write two reports of the same thing.
        inv = _Inv()
        try:
            sa = self._running(inv, "adversarial")
            offensive = ("what adversarial scenarios could an attacker "
                         "engineer with this model")
            self.assertTrue(sa.security_run_busy(
                inv.db, inv.id, assessment_mode="",
                product_name=NAME, use_case=offensive, focus=FOCUS))
        finally:
            inv.close()

    def test_run_with_unknown_mode_blocks_new_requests(self):
        # A legacy in-flight run records no mode and no subject text. There is
        # no honest way to tell whether it duplicates this request, so the old
        # blanket block applies rather than guessing it is a different mode.
        from app.models import AgentRun
        from app import security_agent as sa
        inv = _Inv()
        try:
            run = AgentRun(investigation_id=inv.id, status="running",
                           trigger="security",
                           plan=json.dumps({"product": NAME}))
            inv.db.add(run)
            inv.db.commit()
            self.assertTrue(sa.security_run_busy(
                inv.db, inv.id, assessment_mode="hypothesis",
                product_name=NAME, use_case=USE, focus=FOCUS))
        finally:
            inv.close()
