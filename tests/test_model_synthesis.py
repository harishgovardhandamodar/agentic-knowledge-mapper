"""Tests for the model security synthesis in the executive summary.

When an investigation assessed a model subject, GET /summary must stand on
all three workflows -- not just the latest stored row:

  * workflow 1 (target/internals): is the model sound;
  * workflow 2 (adversarial/misuse): what could be built with it;
  * the hypothesis flow, but only when it has actually run.

Each flow keeps its own headline number with its own meaning, its top items,
its exec paragraph, and its mermaid diagram. Nothing is merged and nothing is
ranked across flows. Catalog investigations keep exactly the summary they
always had.
"""
import json
import os
import tempfile
import unittest
from unittest import mock

# Pin the database before app.database is imported: a module that omits
# this can inherit data/akm.db and write test rows into the live store.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-model-syn-"), "test.db"))

from app import security as sec  # noqa: E402
from app import database  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.explainer import investigation_summary  # noqa: E402
from app.models import Investigation, SecurityAssessment  # noqa: E402

database.init_db()


NAME = "Tabular Foundation Models"
USE = "classifies confidential customer tabular records in production"
FOCUS = ["tabular", "models"]


def _offline():
    return mock.patch("app.llm.chat", side_effect=RuntimeError("down"))


def _offline_json():
    return mock.patch("app.llm.chat_json", side_effect=RuntimeError("down"))


class _Inv:
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


def _run(mode, db, inv_id, product=NAME, focus=None):
    with _offline(), _offline_json():
        return sec.build_assessment(
            product_name=product, product_url="", exposure="confidential_data",
            use_case=USE, focus=list(focus if focus is not None else FOCUS),
            db=db, investigation_id=inv_id,
            declared_controls=[], assessment_mode=mode)


def _store(db, inv_id, out, with_evidence=True, focus=None):
    rec = SecurityAssessment(
        investigation_id=inv_id, product_name=out["product_name"],
        product_url="", exposure=out["exposure"], use_case=USE,
        focus_json=json.dumps(focus if focus is not None else FOCUS),
        overall_pct=out["overall_pct"],
        inherent_pct=out["inherent_pct"], residual_pct=out["residual_pct"],
        scoring_json=json.dumps(out["scoring"]),
        threats_json=json.dumps(out["threats"]),
        markdown=out["markdown"], diagrams_json=json.dumps(out["diagrams"]),
        evidence_json=json.dumps(
            {"exec_paragraph": out.get("exec_paragraph", "")})
        if with_evidence else None)
    db.add(rec)
    db.commit()
    db.refresh(rec)
    return rec


def _summarise(inv, modes):
    for m in modes:
        _store(inv.db, inv.id, _run(m, inv.db, inv.id))
    with _offline():
        return investigation_summary(inv.db, inv.id)


class TestModelSynthesis(unittest.TestCase):
    def test_catalog_investigation_has_no_synthesis(self):
        inv = _Inv(title="Stripe payments")
        try:
            with _offline(), _offline_json():
                out = sec.build_assessment(
                    product_name="Stripe payments", product_url="",
                    exposure="confidential_data", use_case="charge cards",
                    focus=["payments"], db=inv.db, investigation_id=inv.id,
                    declared_controls=[], assessment_mode="")
            _store(inv.db, inv.id, out, focus=["payments"])
            with _offline():
                d = investigation_summary(inv.db, inv.id)
            self.assertIsNone(d["model_synthesis"])
            self.assertTrue(d["top_findings"]["threats"])
            self.assertNotIn("model security synthesis",
                             d["executive_summary"])
        finally:
            inv.close()

    def test_two_flows_synthesised_without_hypothesis(self):
        inv = _Inv()
        try:
            d = _summarise(inv, ("target", "adversarial"))
            ms = d["model_synthesis"]
            self.assertIsNotNone(ms)
            self.assertEqual([f["path"] for f in ms["flows"]],
                             ["model", "model_adversarial"])
            labels = [f["label"] for f in ms["flows"]]
            self.assertTrue(any("Workflow 1" in l for l in labels))
            self.assertTrue(any("Workflow 2" in l for l in labels))
            # Each flow keeps its own number with its own meaning.
            meanings = {f["path"]: f["score_meaning"] for f in ms["flows"]}
            self.assertEqual(meanings["model"], "model risk")
            self.assertEqual(meanings["model_adversarial"], "misuse potential")
            for f in ms["flows"]:
                self.assertTrue(f["top_items"])
                self.assertTrue(f["exec_paragraph"])
                self.assertGreater(f["item_count"], 0)
            # One diagram per flow that drew one.
            self.assertEqual(len(ms["diagrams"]), 2)
            for g in ms["diagrams"]:
                self.assertTrue(g["mermaid"].strip())
        finally:
            inv.close()

    def test_hypothesis_included_only_when_it_ran(self):
        inv = _Inv()
        try:
            d = _summarise(inv, ("target", "adversarial", "hypothesis"))
            ms = d["model_synthesis"]
            self.assertEqual([f["path"] for f in ms["flows"]],
                             ["model", "model_adversarial", "model_hypothesis"])
            hyp = ms["flows"][2]
            self.assertEqual(hyp["score_meaning"], "mean confidence")
            for item in hyp["top_items"]:
                self.assertIn("confidence", item["score_label"])
                self.assertIn("Refuted by", item["detail"])
            self.assertEqual(len(ms["diagrams"]), 3)
        finally:
            inv.close()

    def test_top_findings_are_labeled_per_flow_not_ranked(self):
        inv = _Inv()
        try:
            d = _summarise(inv, ("target", "adversarial", "hypothesis"))
            threats = d["top_findings"]["threats"]
            # Three per flow, grouped in workflow order -- a confidence must
            # never sort above or below a risk as if they were the same unit.
            self.assertEqual(len(threats), 9)
            flows = [t["flow"] for t in threats]
            self.assertEqual(flows, [flows[0]] * 3 + [flows[3]] * 3
                             + [flows[6]] * 3)
            self.assertEqual(len(set(flows)), 3)
        finally:
            inv.close()

    def test_brief_names_every_workflow_with_its_meaning(self):
        inv = _Inv()
        try:
            d = _summarise(inv, ("target", "adversarial", "hypothesis"))
            brief = d["executive_summary"]
            # One sentence per workflow, each with its own number and meaning.
            for label, meaning in (("Workflow 1", "model risk"),
                                   ("Workflow 2", "misuse potential"),
                                   ("Hypothesis synthesis", "mean confidence")):
                self.assertIn(label, brief)
                self.assertIn(meaning, brief)
            self.assertEqual(d["counts"]["assessments"], 3)
        finally:
            inv.close()

    def test_latest_row_per_path_wins(self):
        inv = _Inv()
        try:
            first = _store(inv.db, inv.id, _run("target", inv.db, inv.id))
            second = _store(inv.db, inv.id, _run("target", inv.db, inv.id))
            _store(inv.db, inv.id, _run("adversarial", inv.db, inv.id))
            with _offline():
                d = investigation_summary(inv.db, inv.id)
            target = d["model_synthesis"]["flows"][0]
            self.assertEqual(target["assessment_id"], second.id)
            self.assertNotEqual(first.id, second.id)
        finally:
            inv.close()

    def test_unmarked_legacy_model_row_counts_as_workflow_1(self):
        inv = _Inv()
        try:
            out = _run("target", inv.db, inv.id)
            scoring = dict(out["scoring"])
            scoring.pop("assessment_path", None)
            rec = SecurityAssessment(
                investigation_id=inv.id, product_name=out["product_name"],
                product_url="", exposure=out["exposure"], use_case=USE,
                focus_json=json.dumps(FOCUS), overall_pct=out["overall_pct"],
                inherent_pct=out["inherent_pct"],
                residual_pct=out["residual_pct"],
                scoring_json=json.dumps(scoring),
                threats_json=json.dumps(out["threats"]),
                markdown=out["markdown"],
                diagrams_json=json.dumps(out["diagrams"]))
            inv.db.add(rec)
            inv.db.commit()
            with _offline():
                d = investigation_summary(inv.db, inv.id)
            ms = d["model_synthesis"]
            self.assertIsNotNone(ms)
            self.assertEqual(ms["flows"][0]["path"], "model")
        finally:
            inv.close()

    def test_empty_diagram_is_not_listed(self):
        inv = _Inv()
        try:
            out = _run("target", inv.db, inv.id)
            dg = dict(out["diagrams"])
            dg["dataflow"] = "   "
            rec = _store(inv.db, inv.id, out)
            rec.diagrams_json = json.dumps(dg)
            inv.db.commit()
            _store(inv.db, inv.id, _run("adversarial", inv.db, inv.id))
            with _offline():
                d = investigation_summary(inv.db, inv.id)
            ms = d["model_synthesis"]
            self.assertEqual(len(ms["diagrams"]), 1)
            self.assertEqual(ms["diagrams"][0]["path"], "model_adversarial")
            # The flow itself is still reported -- only its picture is missing.
            self.assertEqual(len(ms["flows"]), 2)
        finally:
            inv.close()

    def test_rows_without_evidence_still_synthesise(self):
        inv = _Inv()
        try:
            _store(inv.db, inv.id, _run("target", inv.db, inv.id),
                   with_evidence=False)
            _store(inv.db, inv.id, _run("adversarial", inv.db, inv.id),
                   with_evidence=False)
            with _offline():
                d = investigation_summary(inv.db, inv.id)
            ms = d["model_synthesis"]
            self.assertIsNotNone(ms)
            self.assertEqual([f["exec_paragraph"] for f in ms["flows"]],
                             ["", ""])
        finally:
            inv.close()


if __name__ == "__main__":
    unittest.main()
