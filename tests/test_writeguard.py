"""Tests for the in-the-loop write guard (app.writeguard).

The guard sits between the writer and the answer, so its failure modes matter
more than its hit rate: it must never *add* text, it must not remove framing
prose that merely looks unsupported, it must refuse to gut an answer when the
judge is trigger-happy or unreachable, and it must report honestly -- a report
claiming a clean answer when sentences were removed is worse than no report.
"""
import os
import tempfile
import unittest
from unittest import mock

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-writeguard-"), "test.db"))

from app import writeguard as W  # noqa: E402

PAGES = [
    {"title": "Copilot retention",
     "text": ("Microsoft does not train foundation models on customer prompts by default "
              "and telemetry is stored for 30 days in the EU region. The Data Protection "
              "Addendum lists every sub-processor that may touch customer data. "
              "CVE-2026-42824 affects Microsoft 365 Copilot and the fix ships in the "
              "September 2026 update.")},
    {"title": "SearchLeak advisory",
     "text": ("An attacker-controlled link makes the victim browser request the Bing "
              "content service, and the Copilot answer is rendered as markdown "
              "containing an image tag pointing at an attacker URL.")},
]


def _answer(*bodies):
    return {"sections": [{"heading": f"H{i}", "body": b} for i, b in enumerate(bodies)]}


def _sections(*pairs):
    """An answer from (heading, body) pairs, so reports can be checked by name."""
    return {"sections": [{"heading": h, "body": b} for h, b in pairs]}


def _no_llm(*a, **k):
    raise AssertionError("the model must not be called in this test")


class TestSentenceSplitting(unittest.TestCase):
    def test_bullet_that_wraps_stays_one_sentence(self):
        body = ("- The first point runs on and says something useful here.\n"
                "  It continues onto a second line.\n\n"
                "A second paragraph with its own sentence.")
        sents = W._sentences(body)
        self.assertEqual(len(sents), 2)
        self.assertIn("continues onto a second line", sents[0])

    def test_plain_prose_splits_on_sentence_end(self):
        self.assertEqual(len(W._sentences("One thing here. Two things there! Three?")), 3)

    def test_empty_body(self):
        self.assertEqual(W._sentences(""), [])
        self.assertEqual(W._sentences(None), [])


class TestSpecifics(unittest.TestCase):
    def test_recognises_checkable_claims(self):
        kinds = {k for _, k in W._specifics(
            "CVE-2026-42824 shipped in 3.4 versions on 2026-09-28 at $12.99 for 1998 users.")}
        self.assertLessEqual({"identifier", "version", "date", "money", "year"}, kinds)

    def test_a_claim_with_no_numbers_is_not_specific(self):
        self.assertEqual(W._specifics("This mostly affects enterprise tenants."), [])


class TestAuditSection(unittest.TestCase):
    def _audit(self, body):
        norms = [W._canon(p["text"]) for p in PAGES]
        toks = [W._tokens(p["text"]) for p in PAGES]
        return W.audit_section({"body": body}, norms, toks)

    def test_framing_prose_is_left_alone(self):
        a = self._audit("This matters because the two behaviours differ in practice.")
        self.assertEqual(a["unsupported"], [])
        self.assertEqual(a["framing"], 1)

    def test_specific_found_in_a_source_passes(self):
        a = self._audit("The fix ships in the September 2026 update for Copilot.")
        self.assertEqual(a["unsupported"], [])

    def test_unsourced_specific_with_no_overlap_is_flagged(self):
        a = self._audit("Jupiter orbits the sun once every 11.86 years.")
        self.assertEqual(len(a["unsupported"]), 1)
        self.assertEqual(a["unsupported"][0]["reason"], "no_evidence_for")

    def test_two_shared_tokens_rescue_a_sentence(self):
        # The escape hatch floor is deliberately low. Raising it to a share of
        # the sentence's vocabulary was tried and measured against the stored
        # explanations: it flags 8.3% of real sentences instead of 0.58%, mostly
        # grounded technical prose, which would gut good answers. The
        # consequence is that this sentence passes -- accepted, and the reason
        # the grounding pass still has to exist.
        pages = [{"title": "Tulips", "text": "Bulbs are planted in autumn and flower in spring."}]
        a = W.audit_section(
            {"body": "A zeppelin crossed Novosibirsk in winter carrying 1846 kilograms "
                     "of bulbs for the mayor's garden in spring."},
            [W._canon(p["text"]) for p in pages], [W._tokens(p["text"]) for p in pages])
        self.assertEqual(a["unsupported"], [])

    def test_a_mostly_grounded_sentence_with_an_odd_value_is_left_to_grounding(self):
        # A deliberate boundary, pinned so it stays deliberate. Every word here
        # is in the source and only the figure differs, so this reads as a close
        # paraphrase. Distinguishing "90,000" as a corruption of "70,000" from a
        # genuine paraphrase needs claim-level comparison, which is the grounding
        # pass's job -- the guard removes off-source content, not second-guesses
        # values inside otherwise-sourced prose. See MIN_SHARED_RATIO.
        pages = [{"title": "Study", "text": ("Neptune completed 70,000 orbits around the "
                                            "Sun since it was discovered in 1846 by a "
                                            "mathematician in Paris.")}]
        a = W.audit_section(
            {"body": "Neptune completed 90,000 orbits around the Sun since it was "
                     "discovered in 1846 by a mathematician in Paris."},
            [W._canon(p["text"]) for p in pages], [W._tokens(p["text"]) for p in pages])
        self.assertEqual(a["unsupported"], [])
        self.assertEqual(a["supported"], 1)

    def test_a_bare_fragment_is_not_a_claim(self):
        self.assertEqual(self._audit("Key points:")["checked"], 0)


class TestSourceTypography(unittest.TestCase):
    """Sources and prose spell the same number differently.

    Every one of these is a real formatting difference observed in the corpus. A
    guard that treats them as different facts deletes correct figures, so they
    are pinned here rather than left to chance.
    """

    def _flagged(self, body, src):
        return bool(W.audit_section({"body": body}, [W._canon(src)], [W._tokens(src)]
                                    )["unsupported"])

    def test_a_space_before_the_percent_sign_is_the_same_number(self):
        self.assertFalse(self._flagged(
            "The case-fatality rate can reach 30 % in the worst cases seen.",
            "The case fatality rate can reach 30% in the worst cases seen."))

    def test_thousands_separators_do_not_matter(self):
        for written in ("Globally an estimated 100,000 clinical cases occur each year.",
                        "Globally an estimated 100 000 clinical cases occur each year.",
                        "Globally an estimated 100000 clinical cases occur each year."):
            self.assertFalse(self._flagged(
                written, "An estimated 100,000 clinical cases occur each year globally."))

    def test_an_en_dash_matches_a_hyphen(self):
        self.assertFalse(self._flagged(
            "Roughly 70,000 cases occur annually in Asia.",
            "Roughly 70\u2013000 cases occur annually in Asia."))

    def test_normalisation_never_invents_a_match(self):
        # Canonicalisation widens *formatting* differences only. Two different
        # numbers must stay different, or the guard would "find" evidence for
        # figures the source never states.
        src = W._canon("Neptune completed 70,000 orbits around the Sun.")
        self.assertIn(W._canon("70,000"), src)
        self.assertIn(W._canon("70 000"), src)
        self.assertNotIn(W._canon("90,000"), src)

    def test_a_decimal_point_survives_canonicalisation(self):
        self.assertEqual(W._canon("version 3.14 shipped"),
                         "version 3.14 shipped")
        self.assertEqual(W._canon("1.000.000 users"), "1000000 users")


class TestAuditAnswerDeterministic(unittest.TestCase):
    def setUp(self):
        self._env = {k: os.environ.get(k) for k in
                     ("AKM_WRITEGUARD", "AKM_WRITEGUARD_REPAIRS", "AKM_WRITEGUARD_JUDGE")}
        os.environ["AKM_WRITEGUARD_REPAIRS"] = "0"
        os.environ["AKM_WRITEGUARD_JUDGE"] = "0"

    def tearDown(self):
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_removes_only_the_unsupported_sentence(self):
        a = _answer("CVE-2026-42824 affects Microsoft 365 Copilot. "
                    "Jupiter orbits the sun once every 11.86 years. "
                    "Telemetry is stored for 30 days in the EU region.")
        rep = W.audit_answer("What does the CVE do?", a, PAGES)
        body = a["sections"][0]["body"]
        self.assertNotIn("Jupiter", body)
        self.assertIn("CVE-2026-42824", body)
        self.assertIn("30 days", body)
        self.assertEqual(rep["unsupported"], 1)
        self.assertEqual(rep["removed"], 1)
        self.assertEqual(rep["unsupported_remaining"], 0)
        self.assertEqual(rep["by_reason"]["no_evidence_for"], 1)

    def test_a_section_left_empty_is_dropped(self):
        a = _answer("Jupiter orbits the sun once every 11.86 years. "
                    "Neptune was found in 1846 by a mathematician.")
        rep = W.audit_answer("What does the CVE do?", a, PAGES)
        self.assertEqual(a["sections"], [])
        self.assertEqual(rep["sections_emptied"], 1)
        self.assertEqual(rep["removed"], 2)

    def test_removing_one_bullet_keeps_the_list_shape(self):
        a = _answer("A short note that carries no specifics at all here.\n\n"
                    "- CVE-2026-42824 affects Microsoft 365 Copilot.\n"
                    "- Jupiter orbits the sun once every 11.86 years.\n"
                    "- Telemetry is stored for 30 days in the EU region.")
        W.audit_answer("What does the CVE do?", a, PAGES)
        # Exactly the original text minus the failing item: the blank line before
        # the list and the tight list itself both survive.
        self.assertEqual(a["sections"][0]["body"],
                         "A short note that carries no specifics at all here.\n\n"
                         "- CVE-2026-42824 affects Microsoft 365 Copilot.\n"
                         "- Telemetry is stored for 30 days in the EU region.")

    def test_a_wrapped_bullet_is_judged_and_removed_whole(self):
        a = _answer("- The zeppelin flight over Novosibirsk lasted 1846 hours while the\n"
                    "  pilot, a gardener by trade, walked the whole way home.\n"
                    "- CVE-2026-42824 affects Microsoft 365 Copilot.")
        rep = W.audit_answer("What does the CVE do?", a, PAGES)
        self.assertEqual(rep["removed"], 1)
        self.assertEqual(a["sections"][0]["body"],
                         "- CVE-2026-42824 affects Microsoft 365 Copilot.")

    def test_an_on_topic_partly_sourced_specific_survives(self):
        # The escape hatch covers a sentence where one value is in the evidence
        # and another is a paraphrase of it: it is on-topic material, and
        # deleting every such sentence would gut a good answer. The grounding
        # pass downstream is what decides whether the surviving number is right.
        a = _answer("The attacker link makes the victim browser request the Bing content "
                    "service, and the answer is rendered as markdown with an image tag "
                    "pointing at an attacker URL for 12 milliseconds within 30 days.")
        W.audit_answer("What does the CVE do?", a, PAGES)
        self.assertIn("12 milliseconds", a["sections"][0]["body"])

    def test_the_guard_never_adds_text(self):
        body = ("CVE-2026-42824 affects Microsoft 365 Copilot. "
                "Jupiter orbits the sun once every 11.86 years.")
        a = _answer(body)
        before = set(W._sentences(body))
        W.audit_answer("What does the CVE do?", a, PAGES)
        after = set(W._sentences(a["sections"][0]["body"]))
        self.assertTrue(after.issubset(before))

    def test_a_clean_answer_is_untouched(self):
        body = ("Microsoft does not train foundation models on customer prompts by "
                "default, and telemetry is stored for 30 days in the EU region.")
        a = _answer(body)
        rep = W.audit_answer("What is retained?", a, PAGES)
        self.assertEqual(a["sections"][0]["body"], body)
        self.assertEqual(rep["unsupported"], 0)
        self.assertEqual(rep["removed"], 0)
        self.assertEqual(rep["sentences_checked"], 1)

    def test_no_sections_is_not_an_error(self):
        rep = W.audit_answer("q", {"sections": []}, PAGES)
        self.assertEqual(rep["sections_total"], 0)
        self.assertTrue(rep["enabled"])


class TestRepairs(unittest.TestCase):
    def setUp(self):
        self._env = {k: os.environ.get(k) for k in
                     ("AKM_WRITEGUARD", "AKM_WRITEGUARD_REPAIRS", "AKM_WRITEGUARD_JUDGE")}
        os.environ["AKM_WRITEGUARD_JUDGE"] = "0"

    def tearDown(self):
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_a_rewrite_that_fixes_the_section_is_kept(self):
        a = _answer("CVE-2026-42824 affects Microsoft 365 Copilot. "
                    "Jupiter orbits the sun once every 11.86 years.")
        with mock.patch.object(W, "_rewrite_section", return_value={
                "body": "CVE-2026-42824 affects Microsoft 365 Copilot.",
                "removed": ["Jupiter orbits the sun once every 11.86 years."]}) as rw:
            rep = W.audit_answer("What does the CVE do?", a, PAGES)
        rw.assert_called_once()
        self.assertEqual(rep["repairs"], 1)
        self.assertEqual(rep["repairs_held"], 1)
        self.assertEqual(rep["removed"], 0)
        self.assertNotIn("Jupiter", a["sections"][0]["body"])
        self.assertEqual(a["sections"][0]["rewrite_removed"],
                         ["Jupiter orbits the sun once every 11.86 years."])

    def test_a_rewrite_that_does_not_help_is_discarded_then_stripped(self):
        a = _answer("Jupiter orbits the sun once every 11.86 years and Mars takes 687 days.")
        with mock.patch.object(W, "_rewrite_section", return_value={
                "body": "Jupiter orbits once every 11.86 years while Mars takes 687 days.",
                "removed": []}):
            rep = W.audit_answer("What does the CVE do?", a, PAGES)
        self.assertEqual(rep["repairs"], 1)
        self.assertEqual(rep["repairs_held"], 0)
        self.assertEqual(a["sections"], [])

    def test_a_rewrite_that_fails_is_fail_open_to_stripping(self):
        a = _answer("CVE-2026-42824 affects Copilot. Neptune was found in 1846 by a mathematician.")
        with mock.patch.object(W, "_rewrite_section", return_value=None):
            rep = W.audit_answer("What does the CVE do?", a, PAGES)
        self.assertEqual(rep["repairs"], 1)
        self.assertEqual(rep["repairs_held"], 0)
        self.assertIn("CVE-2026-42824", a["sections"][0]["body"])
        self.assertNotIn("Neptune", a["sections"][0]["body"])

    def test_a_raising_rewrite_is_fail_open(self):
        a = _answer("Neptune was found in 1846 by a mathematician.")
        with mock.patch.object(W, "llm", mock.Mock(chat_json=_no_llm)):
            rep = W.audit_answer("What does the CVE do?", a, PAGES)
        self.assertEqual(rep["removed"], 1)
        self.assertEqual(a["sections"], [])

    def test_repairs_are_capped(self):
        bodies = [f"Section {i}: Neptune was found in 184{i} by a mathematician." for i in range(5)]
        a = _answer(*bodies)
        with mock.patch.object(W, "_rewrite_section", return_value=None) as rw:
            W.audit_answer("What does the CVE do?", a, PAGES, max_repairs=2)
        self.assertEqual(rw.call_count, 2)

    def test_repair_disabled_never_calls_the_model(self):
        os.environ["AKM_WRITEGUARD_REPAIRS"] = "0"
        a = _answer("Neptune was found in 1846 by a mathematician.")
        with mock.patch.object(W, "llm", mock.Mock(chat_json=_no_llm)):
            W.audit_answer("What does the CVE do?", a, PAGES)
        self.assertEqual(a["sections"], [])


class TestDriftGate(unittest.TestCase):
    BRIEF = "Microsoft 365 Copilot adoption and usage in enterprise financial institutions"

    def _on(self):
        os.environ["AKM_WRITEGUARD_REPAIRS"] = "0"
        os.environ["AKM_WRITEGUARD_JUDGE"] = "1"

    def setUp(self):
        self._env = {k: os.environ.get(k) for k in
                     ("AKM_WRITEGUARD", "AKM_WRITEGUARD_REPAIRS", "AKM_WRITEGUARD_JUDGE")}
        self._on()

    def tearDown(self):
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _mixed(self):
        return _sections(
            ("Training", "Microsoft does not train foundation models on customer prompts "
                         "by default, which is the part that matters here."),
            ("The CVE", "CVE-2026-42824 affects Microsoft 365 Copilot and the attacker link "
                        "leaks data through the Bing content service."),
            ("Sourdough", "Baking sourdough at home needs a starter culture kept warm "
                          "overnight in a cool kitchen."))

    def test_an_on_brief_section_is_not_a_candidate(self):
        tok = W._tokens(self.BRIEF)
        self.assertFalse(W._drift_candidate(
            {"heading": "Training", "body": "Microsoft does not train on customer prompts."},
            tok))

    def test_a_section_matching_its_own_plan_is_exempt(self):
        tok = W._tokens("What does Copilot retain?")
        sec = {"heading": "Baking", "body": "Sourdough needs a starter culture kept warm."}
        self.assertTrue(W._drift_candidate(sec, tok))
        plan = W._tokens("baking sourdough starter overnight")
        self.assertFalse(W._drift_candidate(sec, tok, plan))

    def test_confirmed_off_brief_section_is_removed_and_reported(self):
        a = self._mixed()
        with mock.patch.object(W, "_judge_drift", return_value={2: True}) as j:
            rep = W.audit_answer("What does Copilot retain?", a, PAGES,
                                 brief_text=self.BRIEF)
        j.assert_called_once()
        self.assertEqual(rep["drift_flagged"], 1)
        self.assertEqual(rep["sections_dropped"], 1)
        self.assertEqual(len(a["sections"]), 2)
        self.assertEqual(rep["dropped_sections"][0]["reason"], "off_brief")
        self.assertEqual(rep["dropped_sections"][0]["heading"], "Sourdough")

    def test_the_judge_can_veto_a_candidate(self):
        a = self._mixed()
        with mock.patch.object(W, "_judge_drift", return_value={}):
            rep = W.audit_answer("What does Copilot retain?", a, PAGES,
                                 brief_text=self.BRIEF)
        self.assertEqual(rep["drift_flagged"], 0)
        self.assertEqual(len(a["sections"]), 3)

    def test_a_trigger_happy_judge_cannot_gut_the_answer(self):
        a = self._mixed()
        with mock.patch.object(W, "_drift_candidate", return_value=True), \
                mock.patch.object(W, "_judge_drift", return_value={0: True, 1: True, 2: True}):
            rep = W.audit_answer("What does Copilot retain?", a, PAGES,
                                 brief_text=self.BRIEF)
        self.assertEqual(len(a["sections"]), 3)
        self.assertEqual(rep["sections_dropped"], 0)
        self.assertEqual(rep["drift_candidates"], 3)
        self.assertEqual({d["reason"] for d in rep["dropped_sections"]},
                         {"off_brief_not_removed"})

    def test_the_loss_ceiling_holds_when_half_the_answer_is_flagged(self):
        a = self._mixed()
        a["sections"].append({"heading": "Sourdough again",
                              "body": "A starter culture kept warm overnight feeds the loaf."})
        with mock.patch.object(W, "_drift_candidate", return_value=True), \
                mock.patch.object(W, "_judge_drift", return_value={2: True, 3: True}):
            rep = W.audit_answer("What does Copilot retain?", a, PAGES,
                                 brief_text=self.BRIEF)
        self.assertEqual(len(a["sections"]), 4)
        self.assertEqual(rep["sections_dropped"], 0)
        self.assertEqual([d["reason"] for d in rep["dropped_sections"]],
                         ["off_brief_not_removed"] * 2)

    def test_the_prefilter_only_asks_about_sections_sharing_nothing(self):
        # The two on-brief sections must never reach the judge: every guard call
        # costs a round trip, and a confident-looking drop is expensive to undo.
        a = self._mixed()
        with mock.patch.object(W, "_judge_drift", return_value={}) as j:
            W.audit_answer("What does Copilot retain?", a, PAGES, brief_text=self.BRIEF)
        asked = j.call_args[0][1] if j.call_args else []
        self.assertEqual([c["section"]["heading"] for c in asked], ["Sourdough"])

    def test_an_unreachable_judge_removes_nothing(self):
        a = self._mixed()
        with mock.patch.object(W.llm, "chat_json", side_effect=RuntimeError("down")):
            rep = W.audit_answer("What does Copilot retain?", a, PAGES,
                                 brief_text=self.BRIEF)
        self.assertEqual(len(a["sections"]), 3)
        self.assertEqual(rep["drift_flagged"], 0)
        self.assertEqual(rep["drift_candidates"], 1)

    def test_judge_disabled_never_calls_the_model(self):
        os.environ["AKM_WRITEGUARD_JUDGE"] = "0"
        a = self._mixed()
        with mock.patch.object(W, "llm", mock.Mock(chat_json=_no_llm)):
            W.audit_answer("What does Copilot retain?", a, PAGES, brief_text=self.BRIEF)
        self.assertEqual(len(a["sections"]), 3)


class TestKillSwitch(unittest.TestCase):
    def test_disabled_guard_leaves_the_answer_completely_alone(self):
        os.environ["AKM_WRITEGUARD"] = "0"
        try:
            a = _answer("Jupiter orbits the sun once every 11.86 years.")
            with mock.patch.object(W, "llm", mock.Mock(chat_json=_no_llm)):
                rep = W.audit_answer("q", a, PAGES)
            self.assertFalse(rep["enabled"])
            self.assertEqual(a["sections"][0]["body"],
                             "Jupiter orbits the sun once every 11.86 years.")
        finally:
            os.environ.pop("AKM_WRITEGUARD", None)

    def test_flag_helper_reads_the_env(self):
        for v, want in (("0", False), ("false", False), ("no", False),
                        ("1", True), ("", True), ("yes", True)):
            os.environ["AKM_WRITEGUARD"] = v
            self.assertEqual(W._flag("AKM_WRITEGUARD"), want, v)
        os.environ.pop("AKM_WRITEGUARD", None)


class TestSelfContradiction(unittest.TestCase):
    """An answer must not praise a control it lists as missing."""

    def setUp(self):
        self._env = {k: os.environ.get(k) for k in
                     ("AKM_WRITEGUARD_REPAIRS", "AKM_WRITEGUARD_JUDGE")}
        os.environ["AKM_WRITEGUARD_REPAIRS"] = "0"
        os.environ["AKM_WRITEGUARD_JUDGE"] = "0"

    def tearDown(self):
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_praise_the_answer_denies_is_stripped(self):
        a = {"summary": ("The platform ships with strict data residency "
                         "guardrails for regulated customers."),
             "sections": [{"heading": "Gaps",
                           "body": ("No residency control exists in the "
                                    "collected sources. Residency "
                                    "requirements remain unmet.")}]}
        rep = W.audit_answer("How is residency handled?", a, PAGES)
        self.assertNotIn("strict data residency guardrails", a["summary"])
        self.assertIn("No residency control exists",
                      a["sections"][0]["body"])
        self.assertEqual(rep["contradictions"], 1)
        self.assertEqual(rep["by_reason"].get("self_contradiction"), 1)

    def test_attributed_vendor_claim_survives(self):
        # "According to the docs, X is enforced" next to "no X found" is the
        # labelled vendor-claims-vs-verified voice the report wants: kept.
        a = {"sections": [{"heading": "Findings",
                           "body": ("According to the vendor docs, zero data "
                                    "retention is enforced. Handling is "
                                    "described there. No retention guarantee "
                                    "was found in any collected source.")}]}
        rep = W.audit_answer("How is retention handled?", a, PAGES)
        self.assertIn("zero data retention is enforced",
                      a["sections"][0]["body"])
        self.assertEqual(rep["contradictions"], 0)

    def test_praise_without_denial_is_untouched(self):
        a = {"sections": [{"heading": "Findings",
                           "body": ("The platform ships with strict data "
                                    "residency guardrails. Latency is fine.")}]}
        rep = W.audit_answer("How is residency handled?", a, PAGES)
        self.assertIn("strict data residency guardrails",
                      a["sections"][0]["body"])
        self.assertEqual(rep["contradictions"], 0)


if __name__ == "__main__":
    unittest.main()
