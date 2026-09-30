"""Tests for the second model assessment A2A path: adversarial misuse.

Flow 1 asks "is this model sound?" and scores it by dimension weight.
Flow 2 asks "what could an attacker BUILD with it?" and is a separate
assessment, not a section of the first: different agents, different weights,
different meaning for the number. Both are stored, neither is averaged, and
neither maps to AI-standards frameworks.
"""
import os
import tempfile
import unittest
from unittest import mock

# Pin the database before app.database is imported: a module that omits
# this can inherit data/akm.db and write test rows into the live store.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-adv-path-"), "test.db"))

from app import agents  # noqa: E402
from app import security as sec  # noqa: E402
from app import database  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.models import Investigation, SecurityAssessment  # noqa: E402

database.init_db()


TABULAR = ("Tabular Foundation Models",
           "what adversarial scenarios could an attacker engineer with this "
           "model for credit scoring of tabular records",
           ["tabular", "models", "adversarial"])
CHATBOT = ("Support chatbot", "answer billing questions in chat", ["chatbot"])


def _adv_out(mode="", product=TABULAR[0], use_case=TABULAR[1], focus=None):
    with mock.patch("app.llm.chat", side_effect=RuntimeError("down")), \
         mock.patch("app.llm.chat_json", side_effect=RuntimeError("down")):
        return sec.build_assessment(
            product_name=product, product_url="", exposure="public",
            use_case=use_case, focus=list(focus if focus is not None else TABULAR[2]),
            db=None, investigation_id=None, declared_controls=[],
            assessment_mode=mode)


def _target_out():
    with mock.patch("app.llm.chat", side_effect=RuntimeError("down")), \
         mock.patch("app.llm.chat_json", side_effect=RuntimeError("down")):
        return sec.build_assessment(
            product_name=TABULAR[0], product_url="", exposure="public",
            use_case="assess internals and privacy of this model",
            focus=list(TABULAR[2]), db=None, investigation_id=None,
            declared_controls=[], assessment_mode="target")


class TestMisuseRouting(unittest.TestCase):
    def test_attacker_wording_takes_adversarial_path(self):
        out = _adv_out()
        self.assertEqual(out["scoring"].get("assessment_path"), "model_adversarial")
        self.assertEqual(out["scoring"].get("method"), "model-misuse-v1")

    def test_plain_model_request_takes_target_path(self):
        out = _target_out()
        self.assertEqual(out["scoring"].get("assessment_path"), "model")

    def test_explicit_mode_overrides_wording(self):
        # "adversarial" in the use case, but the caller asked for soundness:
        # an explicit mode wins over the heuristic.
        out = _adv_out(mode="target")
        self.assertEqual(out["scoring"].get("assessment_path"), "model")
        out2 = _adv_out(mode="adversarial",
                        use_case="assess internals and privacy of this model")
        self.assertEqual(out2["scoring"].get("assessment_path"), "model_adversarial")

    def test_non_model_subject_never_gets_misuse_path(self):
        out = _adv_out(mode="", product=CHATBOT[0], use_case=CHATBOT[1],
                       focus=CHATBOT[2])
        self.assertNotEqual(out["scoring"].get("assessment_path"), "model_adversarial")
        self.assertTrue(any(t["id"].startswith("T") for t in out["threats"]))

    def test_asking_to_protect_a_model_is_not_a_misuse_request(self):
        # "defend" is an exclusion word: a request to harden a model is asking
        # for protection, not for an attacker's playbook.
        mi = sec.profile_misuse_intent(
            "Tabular Foundation Models",
            "how do we defend against adversarial use of this model", ["tabular"])
        self.assertFalse(mi["is_misuse_query"])

    def test_two_paths_produce_independent_numbers(self):
        t = _target_out()
        a = _adv_out()
        self.assertNotEqual(t["scoring"]["method"], a["scoring"]["method"])
        self.assertNotEqual(t["scoring"]["weights"], a["scoring"]["weights"])
        # Neither reads the other's dimensions.
        self.assertNotEqual(
            [d["id"] for d in t["scoring"]["dimensions"]],
            [d["id"] for d in a["scoring"]["dimensions"]])


class TestAdversarialScoring(unittest.TestCase):
    def test_weights_sum_to_one(self):
        total = sum(w for _, w, _ in sec.ADVERSARIAL_DIMENSIONS)
        self.assertAlmostEqual(total, 1.0)
        self.assertEqual(
            [d for d, _, _ in sec.ADVERSARIAL_DIMENSIONS],
            ["capability_abuse", "data_recon", "evasion", "manipulation",
             "abuse_persistence"])

    def test_weighting_favours_capability_over_persistence(self):
        # The weighting decision under test: what makes a model a weapon
        # outranks whether the abuse survives a restart.
        w = {d: wt for d, wt, _ in sec.ADVERSARIAL_DIMENSIONS}
        self.assertGreater(w["capability_abuse"], w["abuse_persistence"])
        self.assertGreater(w["data_recon"], w["abuse_persistence"])

    def test_aggregate_is_the_weighted_sum(self):
        out = sec.score_model_adversarial({d: 100.0 for d, _, _ in sec.ADVERSARIAL_DIMENSIONS})
        self.assertAlmostEqual(out["overall_pct"], 100.0)
        out0 = sec.score_model_adversarial({})
        self.assertAlmostEqual(out0["overall_pct"], 20.0)  # documented baseline

    def test_no_residual_is_invented(self):
        out = sec.score_model_adversarial({"capability_abuse": 80.0})
        self.assertEqual(out["residual_pct"], out["inherent_pct"])
        self.assertEqual(out["delta"], 0.0)

    def test_dimension_aggregation_is_mean_not_worst(self):
        # Breadth of reachable options is the risk here, unlike flow 1 where
        # one catastrophic finding dominates.
        def score_of(rows):
            got = {d["id"]: d["score"]
                   for d in agents._adversarial_dimension_inputs(rows)}
            return got["evasion"]
        self.assertEqual(
            score_of([{"id": "A01", "dimension": "evasion", "inherent_score": 25.0}]),
            100.0)
        self.assertEqual(
            score_of([{"id": f"A{i}", "dimension": "evasion",
                       "inherent_score": 10.0} for i in range(4)]),
            40.0)


class TestCapabilityDerivation(unittest.TestCase):
    def test_tabular_model_gets_scoring_and_membership_oracles(self):
        prof = sec.profile_model_subject(TABULAR[0], "scoring tabular records", ["tabular"])
        caps, _ = agents._model_capability_fallback(prof)
        names = {c["capability"] for c in caps}
        self.assertIn("batch scoring oracle", names)
        self.assertIn("membership oracle", names)
        self.assertIn("schema and distribution oracle", names)

    def test_non_conversational_model_has_no_prompt_injection_capability(self):
        prof = sec.profile_model_subject(TABULAR[0], "batch scoring", ["tabular"])
        caps, unexploitable = agents._model_capability_fallback(prof)
        self.assertNotIn(
            "instruction-hijacked output", {c["capability"] for c in caps})
        self.assertTrue(any("prompt injection" in u for u in unexploitable))

    def test_chat_model_does_get_prompt_injection(self):
        prof = sec.profile_model_subject("Llama 3 assistant",
                                         "chat with customers about billing",
                                         ["llm", "chat"])
        caps, _ = agents._model_capability_fallback(prof)
        self.assertIn("instruction-hijacked output", {c["capability"] for c in caps})

    def test_deanonymization_needs_structured_data(self):
        # Quasi-identifier re-identification is a tabular phenomenon; an audio
        # or image model does not inherit it just by being a model.
        prof = sec.profile_model_subject("Whisper", "transcribe customer audio",
                                         ["audio", "customer"])
        caps, _ = agents._model_capability_fallback(prof)
        self.assertNotIn("record deanonymization", {c["capability"] for c in caps})
        self.assertIn("voice synthesis and speaker ID", {c["capability"] for c in caps})

    def test_vague_brief_asserts_nothing(self):
        prof = sec.profile_model_subject("", "", [])
        caps, _ = agents._model_capability_fallback(prof)
        self.assertEqual(caps[0]["id"], "C00")
        self.assertEqual(caps[0]["strength"], 1)

    def test_never_zero_capabilities(self):
        # Zero would read to a user as "this model is useless to an attacker",
        # which is a safety-relevant lie.
        for name, uc, focus in [("Tabular Foundation Models", "tabular", ["tabular"]),
                                ("Whisper", "audio", ["audio"]),
                                ("BERT", "text", ["text"]),
                                ("", "", [])]:
            prof = sec.profile_model_subject(name, uc, focus)
            caps, _ = agents._model_capability_fallback(prof)
            self.assertTrue(caps, f"no capabilities derived for {name!r}")


class TestScenarioEngineering(unittest.TestCase):
    def test_scenarios_carry_chain_and_prerequisites(self):
        out = _adv_out()
        self.assertTrue(out["threats"])
        for s in out["threats"]:
            self.assertTrue(s["id"].startswith("A"))
            self.assertTrue(s["chain"], f"{s['id']} has no chain")
            self.assertTrue(s["prerequisites"], f"{s['id']} has no prerequisites")
            self.assertTrue(s["achieves"])
            # A scenario with no detection signal is an incident waiting to
            # be discovered by the attacker instead of by the team.
            self.assertTrue(s["detections"], f"{s['id']} undetectable")
            self.assertTrue(s["mitigations"])

    def test_scenario_scores_are_reachability_times_impact(self):
        out = _adv_out()
        for s in out["threats"]:
            self.assertAlmostEqual(s["inherent_score"],
                                   s["feasibility"] * s["impact"])

    def test_scenarios_sorted_by_attacker_value(self):
        out = _adv_out()
        scores = [s["inherent_score"] for s in out["threats"]]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_catalog_threat_ids_never_appear(self):
        out = _adv_out()
        self.assertFalse([t for t in out["threats"] if t["id"].startswith("T")])


class TestA2AWorkflow(unittest.TestCase):
    def test_hop_sequence_is_the_misuse_path(self):
        a2a = agents.run_model_adversarial_a2a_workflow(
            product_name=TABULAR[0], use_case=TABULAR[1], focus=list(TABULAR[2]))
        agents_hops = [h["agent"] for h in a2a["a2a_trace"]
                       if h.get("agent") in ("model-profiler", "model-adversary",
                                             "misuse-scout", "research-collector",
                                             "misuse-reporter")]
        self.assertEqual(
            [a for a in agents_hops if a != "research-collector"],
            ["model-profiler", "model-adversary", "misuse-scout", "misuse-reporter"])

    def test_workflow_never_raises(self):
        a2a = agents.run_model_adversarial_a2a_workflow(
            product_name="", use_case="", focus=[])
        self.assertIn("a2a_trace", a2a)

    def test_three_new_agent_cards_are_discoverable(self):
        names = {c["name"] for c in agents.get_agent_cards()}
        for n in ("model-adversary", "misuse-scout", "misuse-reporter"):
            self.assertIn(n, names)

    def test_handlers_registered_for_each_intent(self):
        for agent, intent in (("model-adversary", "derive_capabilities"),
                              ("misuse-scout", "engineer_scenarios"),
                              ("misuse-reporter", "write_misuse_report")):
            self.assertIn(agent, agents._HANDLERS)
            self.assertIn(intent, agents._HANDLERS[agent])


class TestReport(unittest.TestCase):
    def test_report_states_the_tool_not_target_framing(self):
        md = _adv_out()["markdown"]
        self.assertIn("(adversarial misuse)", md)
        self.assertIn("tool", md.lower())
        self.assertIn("never averaged", md)
        self.assertIn("No AI-standards mapping applies", md)
        self.assertIn("## Weighting", md)
        self.assertIn("## Engineered adversarial scenarios", md)

    def test_report_is_defensive_use_only(self):
        md = _adv_out()["markdown"]
        self.assertIn("Defensive use only", md)

    def test_diagram_is_the_abuse_chain_not_the_dataflow(self):
        d = _adv_out()["diagrams"]["dataflow"]
        self.assertIn("attacker", d.lower())
        self.assertIn("objective", d.lower())
        self.assertNotIn("training data", d)

    def test_perspective_is_adversarial(self):
        p = _adv_out()["perspectives"][0]
        self.assertEqual(p["key"], "adversarial")
        self.assertTrue(any("no residual" in b["text"].lower() for b in p["bullets"]))


class TestStandardsSkip(unittest.TestCase):
    def test_adversarial_assessment_is_not_mapped_to_frameworks(self):
        db = SessionLocal()
        try:
            inv = Investigation(title="Tabular Foundation Models",
                                keywords="tabular", description="x", sources="web")
            db.add(inv)
            db.commit()
            db.refresh(inv)
            out = _adv_out()
            rec = SecurityAssessment(
                investigation_id=inv.id, product_name=out["product_name"],
                product_url="", exposure="public", use_case=TABULAR[1],
                focus_json="[]", overall_pct=out["overall_pct"],
                inherent_pct=out["inherent_pct"], residual_pct=out["residual_pct"],
                scoring_json=__import__("json").dumps(out["scoring"]),
                markdown=out["markdown"],
                threats_json=__import__("json").dumps(out["threats"]))
            db.add(rec)
            db.commit()
            db.refresh(rec)
            from app import main as main_mod
            from app import standards_matrix as sm
            with mock.patch.object(sm, "load_taxonomy",
                                   return_value={"dimensions": [],
                                                 "scoreLegend": {}}), \
                 mock.patch.object(sm, "fetch_dashboard",
                                   return_value={"generated": "x",
                                                 "frameworks": []}):
                mat = sm.build_matrix(db=db, assessment_id=rec.id)
            self.assertTrue(mat["skipped"])
            self.assertIn("Adversarial-misuse", mat["skip_reason"])
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
