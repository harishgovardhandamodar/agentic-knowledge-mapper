"""Tests for the proactive, per-investigation suggestion panel.

The properties that matter: a suggestion is only ever offered when the
investigation holds the evidence for it (a CVE row, a threat-assessment row, an
artefact that really mentions liability or an attack class); the security lenses
outrank the general ones, because the point of the panel is to lead with what
can be attacked; and the matching is on word boundaries, so "e-comme*rce*" or
"ty*pical*" cannot turn a paper on reinforcement learning into a prompt about
remote code execution.
"""
import json
import os
import tempfile
import unittest

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-invsugg-"), "test.db"))

from app import database  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.explainer import investigation_suggestions, _lex_hits  # noqa: E402
from app.models import (Artifact, CveFinding, Explanation,  # noqa: E402
                        Investigation, SecurityAssessment)

database.init_db()


def _threat(tid, title, score, stride="Information Disclosure"):
    return {"id": tid, "title": title, "stride": stride,
            "residual_score": score, "mitigations": ["do the thing"]}


def _exploit(kid, title, attack_class):
    return {"id": kid, "title": title, "attack_class": attack_class,
            "threat_ids": ["T01"], "description": "d", "relevance": "r",
            "mitigation": "patch"}


class TestLexiconBoundaries(unittest.TestCase):
    def test_rce_inside_a_word_is_not_remote_code_execution(self):
        for text in ("Why I'm scared of reinforcement learning",
                     "the e-commerce checkout flow", "we enforce quotas",
                     "a forced update"):
            self.assertNotIn("remote code execution",
                             _lex_hits(text, {"rce": "remote code execution"}))

    def test_rce_as_a_token_is(self):
        self.assertIn("remote code execution",
                      _lex_hits("an RCE in the parser", {"rce": "remote code execution"}))

    def test_sla_inside_display_is_not_service_levels(self):
        self.assertNotIn("service levels", _lex_hits("we display the table",
                                                     {"sla": "service levels"}))
        self.assertIn("service levels", _lex_hits("the SLA is breached",
                                                  {"sla": "service levels"}))

    def test_labels_are_deduplicated(self):
        hits = _lex_hits("GDPR and gdpr and GDPR again", {"gdpr": "GDPR"})
        self.assertEqual(hits, ["GDPR"])


class TestInvestigationSuggestions(unittest.TestCase):
    def setUp(self):
        self.db = SessionLocal()
        self.inv = Investigation(title="Copilot on confidential data",
                                 keywords="copilot, leakage", description="")
        self.db.add(self.inv)
        self.db.commit()
        self.inv_id = self.inv.id

    def tearDown(self):
        for model in (CveFinding, SecurityAssessment, Explanation, Artifact):
            self.db.query(model).filter(
                model.investigation_id == self.inv_id).delete()
        self.db.query(Investigation).filter(Investigation.id == self.inv_id).delete()
        self.db.commit()
        self.db.close()

    def _add(self, model, **kw):
        row = model(investigation_id=self.inv_id, **kw)
        self.db.add(row)
        self.db.commit()
        return row

    def _lenses(self):
        return [(it["lens"], it["weight"]) for it in
                investigation_suggestions(self.db, self.inv_id)]

    def test_empty_investigation_still_gets_security_questions(self):
        items = investigation_suggestions(self.db, self.inv_id)
        self.assertGreaterEqual(len(items), 3)
        lenses = {it["lens"] for it in items}
        self.assertIn("surface", lenses)
        self.assertIn("control", lenses)
        # nothing is stored yet, so nothing may claim to be grounded in evidence
        for it in items:
            self.assertEqual(it["why"], "no threat assessment yet")

    def test_unknown_investigation_returns_nothing(self):
        self.assertEqual(investigation_suggestions(self.db, 999999), [])

    def test_cve_becomes_a_prompt_naming_the_identifier(self):
        self._add(CveFinding, cve_id="CVE-2026-42824", title="SearchLeak",
                  severity="critical", status="Analyzed", cvss=9.1)
        items = investigation_suggestions(self.db, self.inv_id)
        cve = [it for it in items if it["lens"] == "cve"]
        self.assertEqual(len(cve), 1)
        self.assertIn("CVE-2026-42824", cve[0]["text"])
        self.assertIn("critical", cve[0]["why"])

    def test_exploit_outranks_threat_and_artifact_prompts(self):
        self._add(SecurityAssessment, product_name="Microsoft 365 Copilot",
                  exposure="confidential_data", residual_pct=51.5,
                  threats_json=json.dumps([_threat("T01", "Data leakage", 20.0)]),
                  evidence_json=json.dumps({"known_exploits": [
                      _exploit("KE-01", "Prompt injection", "prompt injection")]}),
                  controls_json="{}", markdown="")
        self._add(Artifact, title="an article", artifact_type="article",
                  description="", content="a discussion of encryption and access control")
        lenses = [l for l, _ in self._lenses()]
        self.assertEqual(lenses[0], "exploit")
        self.assertLess(lenses.index("exploit"), lenses.index("threat"))
        self.assertLess(lenses.index("threat"), lenses.index("mechanism"))

    def test_top_threat_by_residual_score_is_asked_about_first(self):
        self._add(SecurityAssessment, product_name="Copilot",
                  exposure="internal", residual_pct=10.0, markdown="",
                  controls_json="{}",
                  threats_json=json.dumps([_threat("T01", "Minor thing", 1.0),
                                           _threat("T09", "Cross tenant read", 19.0)]),
                  evidence_json="{}")
        threats = [it for it in investigation_suggestions(self.db, self.inv_id)
                   if it["lens"] == "threat"]
        self.assertTrue(threats)
        self.assertIn("cross tenant read", threats[0]["text"].lower())
        # lower-residual threats may follow, but never outrank the top one
        weights = [it["weight"] for it in threats]
        self.assertEqual(weights, sorted(weights, reverse=True))

    def test_control_prompt_uses_the_stored_residual_score(self):
        self._add(SecurityAssessment, product_name="Copilot", exposure="internal",
                  residual_pct=68.8, overall_pct=68.8, markdown="",
                  threats_json="[]", evidence_json="{}",
                  controls_json=json.dumps({"control_plan": {
                      "declared_controls": [], "proposed_controls": []}}))
        ctl = [it for it in investigation_suggestions(self.db, self.inv_id)
               if it["lens"] == "control"]
        self.assertTrue(ctl)
        self.assertIn("68.8%", ctl[0]["text"])

    def test_declared_controls_are_not_offered_back(self):
        from app.security import _CONTROL_CATALOG
        declared = [c["id"] for c in _CONTROL_CATALOG[:3]]
        self._add(SecurityAssessment, product_name="Copilot", exposure="internal",
                  residual_pct=20.0, markdown="", threats_json="[]",
                  evidence_json="{}",
                  controls_json=json.dumps({"control_plan": {
                      "declared_controls": declared}}))
        ctl = [it for it in investigation_suggestions(self.db, self.inv_id)
               if it["lens"] == "control"]
        for c in _CONTROL_CATALOG[:3]:
            self.assertNotIn(c["name"], " ".join(x["text"] for x in ctl))

    def test_regulatory_signal_names_the_regulation(self):
        self._add(Artifact, title="Vendor terms", artifact_type="article",
                  description="Liability cap and GDPR obligations, data residency",
                  content="")
        items = investigation_suggestions(self.db, self.inv_id)
        comp = [it for it in items if it["lens"] == "compliance"]
        self.assertTrue(comp)
        self.assertIn("GDPR", comp[0]["text"])

    def test_plain_article_gets_no_liability_prompt(self):
        self._add(Artifact, title="A post about caching", artifact_type="article",
                  description="Fast caches and how they work", content="")
        self.assertNotIn("liability",
                         {it["lens"] for it in
                          investigation_suggestions(self.db, self.inv_id)})

    def test_questions_already_asked_are_not_re_offered(self):
        self._add(Explanation, question="What is the attack surface of Copilot?",
                  status="done", answer="{}", trace="{}")
        texts = " ".join(it["text"] for it in
                         investigation_suggestions(self.db, self.inv_id))
        self.assertNotIn("attack surface", texts.lower())

    def test_fixture_product_name_is_not_used_as_the_subject(self):
        self._add(SecurityAssessment, product_name="Gate Override Test",
                  exposure="internal", residual_pct=5.0, markdown="",
                  threats_json=json.dumps([_threat("T01", "Leak", 2.0)]),
                  evidence_json="{}", controls_json="{}")
        text = " ".join(it["text"] for it in
                        investigation_suggestions(self.db, self.inv_id))
        self.assertNotIn("Gate Override", text)

    def test_numeric_product_name_is_not_used_as_the_subject(self):
        self._add(SecurityAssessment, product_name="0", exposure="internal",
                  residual_pct=5.0, markdown="", threats_json="[]",
                  evidence_json="{}", controls_json="{}")
        text = " ".join(it["text"] for it in
                        investigation_suggestions(self.db, self.inv_id))
        self.assertNotIn(" of 0 ", text)
        self.assertNotIn("does 0 ", text)

    def test_gaps_from_past_runs_are_surfaced(self):
        self._add(Explanation, question="Explain the threat model",
                  status="done", answer="{}",
                  trace=json.dumps({"gaps": ["No retention policy is documented"],
                                    "hop_plan": [{"missing_topics": ["subprocessor list"]}]}))
        lenses = [it["lens"] for it in investigation_suggestions(self.db, self.inv_id)]
        self.assertIn("gap", lenses)
        self.assertIn("deepen", lenses)

    def test_suggestions_are_deduplicated_and_ordered(self):
        self._add(CveFinding, cve_id="CVE-1", title="a", severity="low", status="x")
        self._add(CveFinding, cve_id="CVE-2", title="b", severity="low", status="x")
        items = investigation_suggestions(self.db, self.inv_id)
        texts = [it["text"] for it in items]
        self.assertEqual(len(texts), len(set(texts)))
        weights = [it["weight"] for it in items]
        self.assertEqual(weights, sorted(weights, reverse=True))

    def test_limit_is_respected(self):
        self._add(SecurityAssessment, product_name="Copilot", exposure="internal",
                  residual_pct=40.0, markdown="", controls_json="{}",
                  evidence_json=json.dumps({"known_exploits": [
                      _exploit("KE-01", "a", "injection"),
                      _exploit("KE-02", "b", "exfiltration")]}),
                  threats_json=json.dumps([_threat("T%02d" % i, "Threat %d" % i, i * 1.0)
                                           for i in range(1, 8)]))
        self.assertLessEqual(len(investigation_suggestions(self.db, self.inv_id, limit=4)), 4)


if __name__ == "__main__":
    unittest.main()
