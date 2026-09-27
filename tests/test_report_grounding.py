"""Tests for the report-writer's post-hoc grounding of drafted prose.

The executive paragraph is the one piece of the security report a model writes
in free prose, so it has no quotes to verify. What it can do is cite evidence
by ``#id`` -- and an id that matches nothing in the evidence list is a
hallucinated citation that reads exactly like real support.

These tests pin the behaviour: a draft that invents an id is rejected in favour
of the deterministic paragraph, and the verdict is reported either way.
"""
import unittest
from unittest import mock

from app import agents


PAYLOAD = {
    "product_name": "WidgetGPT",
    "exposure_label": "Confidential data",
    "residual_pct": 42.0,
    "inherent_pct": 71.0,
    "declared_controls": ["C01"],
    "known_exploits": [
        {"id": "EX-1", "title": "Prompt injection via catalog", "threat_ids": ["T05"],
         "attack_class": "injection", "description": "d", "relevance": "r",
         "mitigation": "m", "local_refs": [{"title": "p", "artifact_id": 1}]},
    ],
    "evidence": [
        {"artifact_id": 1, "title": "Grounding paper", "relevance": 0.9},
        {"artifact_id": 2, "title": "Leakage survey", "relevance": 0.7},
    ],
    "control_plan": {"declared_controls": ["C01"]},
}


def _env(payload=None):
    return {
        "protocol": agents.PROTOCOL, "from": "threat-intel", "to": "report-writer",
        "intent": "write_section", "task_id": "t-1",
        "payload": payload if payload is not None else PAYLOAD,
    }


class TestExecParagraphGrounding(unittest.TestCase):
    def _run(self, llm_text):
        with mock.patch("app.llm.chat", return_value=llm_text):
            return agents.report_writer_handle(_env())

    def test_draft_with_real_ids_is_used(self):
        out = self._run("Residual risk is 42/100, confirmed by #1 and #2.")
        p = out["payload"]
        self.assertEqual(p["exec_paragraph"],
                         "Residual risk is 42/100, confirmed by #1 and #2.")
        g = p["exec_paragraph_grounding"]
        self.assertEqual(g["verdict"], "supported")
        self.assertEqual(g["cited"], [1, 2])
        self.assertEqual(g["invented"], [])
        self.assertTrue(g["draft_accepted"])

    def test_draft_inventing_an_id_is_rejected(self):
        out = self._run("Confirmed by #1 and #99.")
        p = out["payload"]
        g = p["exec_paragraph_grounding"]
        # The shipped paragraph is the deterministic one, so it is clean; the
        # draft's invention is what a reviewer needs to see. "cited" is every
        # id the draft referenced; "kept"/"invented" split it.
        self.assertEqual(g["draft"]["cited"], [1, 99])
        self.assertEqual(g["draft"]["invented"], [99])
        self.assertFalse(g["draft_accepted"])
        self.assertEqual(g["invented"], [])
        # The deterministic paragraph names only artifacts that exist.
        self.assertIn("Residual risk is 42/100 for WidgetGPT", p["exec_paragraph"])
        self.assertNotIn("#99", p["exec_paragraph"])
        self.assertIn("rejected", g["note"])

    def test_draft_citing_nothing_is_rejected(self):
        out = self._run("Risk remains elevated for a number of reasons.")
        p = out["payload"]
        g = p["exec_paragraph_grounding"]
        self.assertFalse(g["draft_accepted"])
        self.assertIn("cited no evidence", g["note"])
        self.assertIn("Residual risk is 42/100 for WidgetGPT", p["exec_paragraph"])

    def test_no_evidence_supplied_rejects_any_citation(self):
        payload = dict(PAYLOAD, evidence=[])
        with mock.patch("app.llm.chat", return_value="Confirmed by #1."):
            out = agents.report_writer_handle(_env(payload))
        p = out["payload"]
        self.assertEqual(p["exec_paragraph_grounding"]["draft"]["invented"], [1])
        self.assertIn("Residual risk is 42/100 for WidgetGPT", p["exec_paragraph"])

    def test_llm_failure_still_yields_grounded_text(self):
        with mock.patch("app.llm.chat", side_effect=RuntimeError("gateway down")):
            out = agents.report_writer_handle(_env())
        p = out["payload"]
        self.assertIn("Residual risk is 42/100 for WidgetGPT", p["exec_paragraph"])
        self.assertIn("LLM unavailable", p["exec_paragraph_grounding"]["note"])

    def test_exploits_section_still_written_on_rejection(self):
        out = self._run("Confirmed by #404.")
        self.assertIn("EX-1", out["payload"]["exploits_markdown"])
        self.assertTrue(out["payload"]["exec_evidence_lines"])


if __name__ == "__main__":
    unittest.main()
