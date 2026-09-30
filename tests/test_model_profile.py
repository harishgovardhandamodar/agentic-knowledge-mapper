"""Tests for model-aware assessment (security.profile_model_subject).

When the query is about a MODEL -- its nature, architecture, class, family,
data processing -- the assessment must reason from those properties, not from
the conversational-assistant frame the catalog was written in. The profiler is
deterministic and conservative: explicit evidence or unknown, never a guess.
"""
import os
import tempfile
import unittest
from unittest import mock

# Pin the database before app.database is imported: a module that omits
# this can inherit data/akm.db and write test rows into the live store.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-model-profile-"), "test.db"))

from app import agents  # noqa: E402
from app import security as sec  # noqa: E402


class TestProfileModelSubject(unittest.TestCase):
    def test_tabular_run_is_a_non_conversational_model_query(self):
        p = sec.profile_model_subject(
            "Tabular Foundation Models",
            "Focus on advancements on capabilities",
            ["tabular", "foundation", "models", "advancements", "capabilities"])
        self.assertTrue(p["is_model_query"])
        self.assertEqual(p["model_class"], "foundation")
        self.assertIn("tabular records", p["data"])
        self.assertEqual(p["interface"], "non_conversational")
        self.assertTrue(p["summary"])

    def test_named_family_resolves_class_and_architecture(self):
        p = sec.profile_model_subject("TabPFN deployment",
                                      "batch scoring of customer rows nightly",
                                      ["tabpfn", "customer"])
        self.assertTrue(p["is_model_query"])
        self.assertIn("TabPFN", p["families"])
        self.assertIn("transformer", p["architectures"])
        self.assertTrue(p["personal_data"])
        self.assertEqual(p["interface"], "non_conversational")

    def test_threat_model_phrase_is_not_a_model_query(self):
        p = sec.profile_model_subject("Payments", "threat model of the payment flow",
                                      ["payments"])
        self.assertFalse(p["is_model_query"])
        self.assertEqual(p["summary"], "")

    def test_chatbot_stays_product_shaped(self):
        p = sec.profile_model_subject("Support chatbot",
                                      "answer questions about billing",
                                      ["chatbot"])
        self.assertFalse(p["is_model_query"])

    def test_vague_brief_yields_unknowns_not_guesses(self):
        p = sec.profile_model_subject("Q3 review", "look at the numbers", [])
        self.assertFalse(p["is_model_query"])
        self.assertEqual(p["model_class"], "unknown")
        self.assertEqual(p["interface"], "unknown")

    def test_conversational_model_keeps_chat_threats(self):
        p = sec.profile_model_subject("Hiring assistant",
                                      "chat with candidates about roles",
                                      ["assistant"])
        # Even model-ish words with a chat surface stay conversational-first:
        # adjustments below only fire for non_conversational.
        self.assertNotEqual(p["interface"], "non_conversational")


class TestProfileDrivenApplicability(unittest.TestCase):
    def test_non_conversational_model_drops_chat_threats_below_floor(self):
        profile = sec.profile_model_subject(
            "Tabular Foundation Models",
            "batch scoring via api, no dialog",
            ["tabular", "models"])
        self.assertEqual(profile["interface"], "non_conversational")
        app = agents.heuristic_applicability(
            "Tabular Foundation Models", "batch scoring", [], ["tabular"],
            model_profile=profile)
        self.assertLess(app["T01"], 0.3)
        self.assertLess(app["T05"], 0.3)

    def test_no_profile_means_legacy_numbers(self):
        app = agents.heuristic_applicability("Anything", "does things", [], [])
        for tid, v in app.items():
            self.assertEqual(v, agents.APPLICABILITY_FLOOR, tid)

    def test_personal_data_training_lifts_leakage(self):
        profile = sec.profile_model_subject(
            "Churn model", "fine-tune on customer rows", ["customer"])
        base = agents.heuristic_applicability(
            "Churn model", "fine-tune on customer rows", [], ["customer"])
        lifted = agents.heuristic_applicability(
            "Churn model", "fine-tune on customer rows", [], ["customer"],
            model_profile=profile)
        self.assertGreater(lifted["T02"], base["T02"])

    def test_tabular_bridges_lift_schema_threats(self):
        app = agents.heuristic_applicability(
            "TabPFN", "score tabular rows from csv", [], [])
        self.assertGreater(app["T04"], agents.APPLICABILITY_FLOOR)


class TestControlAnalystFraming(unittest.TestCase):
    def _envelope(self, product, use_case, focus):
        return agents.new_envelope(
            "security-orchestrator", "control-analyst", "analyse_controls",
            {"product_name": product, "use_case": use_case,
             "exposure": "public", "declared_controls": [], "focus": focus})

    def test_prompt_names_product_not_assistant(self):
        seen = {}

        def fake_chat(messages, **kw):
            seen["system"] = messages[0]["content"]
            seen["user"] = messages[1]["content"]
            return ('{"applicability": {}, "extra_controls": [], '
                    '"confidence": 0.5, "rationale": "ok"}')

        env = self._envelope("Tabular Foundation Models",
                             "capability advancements, batch scored",
                             ["tabular", "models"])
        with mock.patch("app.llm.chat", side_effect=fake_chat):
            out = agents.control_analyst_handle(env)
        self.assertNotIn("writing-assistant", seen["system"])
        self.assertIn("Tabular Foundation Models",
                      seen["system"] + seen["user"])
        self.assertIn("tabular", seen["user"].lower())
        self.assertLess(out["payload"]["applicability"]["T01"], 0.3)
        self.assertLess(out["payload"]["applicability"]["T05"], 0.3)

    def test_chatbot_keeps_chat_threats(self):
        env = self._envelope("Support chatbot", "answer billing questions",
                             ["chatbot"])
        with mock.patch("app.llm.chat",
                         side_effect=RuntimeError("model down")):
            out = agents.control_analyst_handle(env)
        self.assertGreaterEqual(out["payload"]["applicability"]["T01"],
                                agents.APPLICABILITY_FLOOR)


if __name__ == "__main__":
    unittest.main()
