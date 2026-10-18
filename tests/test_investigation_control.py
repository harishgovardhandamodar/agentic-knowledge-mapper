"""Investigation control: what can run, what is running, rerun all or parts.

The control surface fans out to parts that each own their own guards, so
these tests pin the properties of the *orchestrator* rather than the parts:
availability is reported honestly, a refusal is not dressed as a failure, one
part breaking does not abandon the rest, and the launch order puts a part
after whatever it reads.

Launchers are mocked: nothing here starts a thread or calls a network.

Pinned header required suite-wide (see tests/test_db_isolation.py).
"""
import contextlib
import os
import tempfile
import unittest
from unittest import mock

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-ctl-"), "test.db"))
os.environ.setdefault("LLM_BASE_URL", "http://127.0.0.1:9/v1")

from app import database as _db  # noqa: E402
from app import models as _models  # noqa: E402,F401 -- registers tables

_db.init_db()

HEADERS = {"X-AKM-Actor": "ops"}


@contextlib.contextmanager
def _launchers():
    """Every part's launcher stubbed, so a trigger costs nothing.

    Yields the mocks by name, because the assertion under test is usually
    "did this part get called with these bounds" and not "did the fan-out
    reach the end".
    """
    with contextlib.ExitStack() as stack:
        m = {
            "launch_run": stack.enter_context(
                mock.patch("app.main.launch_run")),
            "collect_cves": stack.enter_context(
                mock.patch("app.main.collect_cves")),
            "detect_drift": stack.enter_context(
                mock.patch("app.main.detect_investigation_drift")),
            "regenerate_summary": stack.enter_context(
                mock.patch("app.main.regenerate_summary")),
            # app.main binds launch_explanation by name at import, so the
            # patch has to target it there: patching app.explainer would leave
            # main's reference live and let a real thread start.
            "launch_explanation": stack.enter_context(
                mock.patch("app.main.launch_explanation")),
            "investigation_summary": stack.enter_context(
                mock.patch("app.explainer.investigation_summary")),
            "launch_gap_research": stack.enter_context(
                mock.patch("app.explainer.launch_gap_research")),
            "launch_assess": stack.enter_context(
                mock.patch("app.security_agent.launch_security_assessment")),
        }
        m["collect_cves"].return_value = {"findings": [], "artifacts": 0}
        m["detect_drift"].return_value = {"checked": 0}
        m["regenerate_summary"].return_value = {"synthesis": "s", "flags": {}}
        m["launch_gap_research"].return_value = {
            "launched": {"run_id": 5, "goal": "g"}, "gaps": ["q"],
            "message": "Research launched on 1 open gaps."}
        yield m


class CatalogCase(unittest.TestCase):
    def test_every_part_names_its_endpoint(self):
        from app import investigation_control as ic
        for part in ic.PARTS:
            self.assertTrue(part["key"])
            self.assertTrue(part["label"])
            self.assertTrue(part["blurb"])
            self.assertIn("/api/", part["endpoint"])

    def test_requirements_resolve_to_real_parts(self):
        from app import investigation_control as ic
        for part in ic.PARTS:
            if part["requires"]:
                self.assertIn(part["requires"], ic.PART_BY_KEY,
                              f"{part['key']} requires a part that is not in "
                              f"the catalog")

    def test_launch_order_puts_readers_after_what_they_read(self):
        from app import investigation_control as ic
        order = ic._ORDER
        self.assertLess(order.index("research"), order.index("gaps"))
        self.assertLess(order.index("assess"), order.index("hypotheses"))
        self.assertEqual(sorted(order), sorted(ic.PART_BY_KEY))


class StateCase(unittest.TestCase):
    def setUp(self):
        from fastapi.testclient import TestClient

        from app.main import app
        self.client = TestClient(app)
        self.db = _db.SessionLocal()
        try:
            inv = _models.Investigation(
                title="Acme support agent", keywords="acme, agent",
                description="d", status="draft")
            self.db.add(inv)
            self.db.commit()
            self.inv_id = inv.id
        finally:
            self.db.close()

    def _state(self):
        r = self.client.get(
            f"/api/investigations/{self.inv_id}/control")
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def test_fresh_investigation_has_counts_and_parts(self):
        state = self._state()
        self.assertEqual(state["investigation_id"], self.inv_id)
        self.assertEqual(state["counts"]["artifacts"], 0)
        self.assertEqual(len(state["parts"]), 8)

    def test_parts_with_nothing_to_read_are_unavailable_with_a_reason(self):
        state = {p["key"]: p for p in self._state()["parts"]}
        self.assertFalse(state["gaps"]["available"])
        self.assertIn("run research first", state["gaps"]["blocked_reason"])
        self.assertFalse(state["hypotheses"]["available"])
        self.assertIn("security assessment", state["hypotheses"]["blocked_reason"])

    def test_available_parts_carry_no_blocked_reason(self):
        # A reason next to a runnable part reads as "something is wrong".
        for part in self._state()["parts"]:
            if part["available"]:
                self.assertIsNone(part["blocked_reason"], part["key"])

    def test_full_set_excludes_unavailable_parts(self):
        state = self._state()
        self.assertNotIn("gaps", state["full_set"])
        self.assertNotIn("hypotheses", state["full_set"])
        self.assertIn("research", state["full_set"])

    def test_a_live_run_makes_the_run_parts_unavailable(self):
        db = _db.SessionLocal()
        try:
            db.add(_models.AgentRun(investigation_id=self.inv_id,
                                    status="running", trigger="manual"))
            db.commit()
        finally:
            db.close()
        state = {p["key"]: p for p in self._state()["parts"]}
        self.assertFalse(state["research"]["available"])
        self.assertIn("in progress", state["research"]["blocked_reason"])
        self.assertFalse(state["gaps"]["available"])

    def test_artifacts_unlock_gap_research(self):
        db = _db.SessionLocal()
        try:
            db.add(_models.Artifact(investigation_id=self.inv_id,
                                    title="a", artifact_type="web",
                                    content="x"))
            db.commit()
        finally:
            db.close()
        state = {p["key"]: p for p in self._state()["parts"]}
        self.assertTrue(state["gaps"]["available"])

    def test_an_assessment_unlocks_hypotheses(self):
        db = _db.SessionLocal()
        try:
            db.add(_models.SecurityAssessment(
                investigation_id=self.inv_id, product_name="p",
                exposure="public", overall_pct=50.0, residual_pct=20.0,
                markdown="# report"))
            db.commit()
        finally:
            db.close()
        state = {p["key"]: p for p in self._state()["parts"]}
        self.assertTrue(state["hypotheses"]["available"])

    def test_unknown_investigation_is_404(self):
        self.assertEqual(
            self.client.get("/api/investigations/999999/control").status_code,
            404)


class LaunchCase(StateCase):
    def _post(self, body):
        r = self.client.post(
            f"/api/investigations/{self.inv_id}/control",
            json=body, headers=HEADERS)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def test_rerun_everything_covers_every_available_part(self):
        with _launchers() as m:
            m["collect_cves"].return_value = {"findings": [1],
                                              "artifacts": 1}
            m["detect_drift"].return_value = {"checked": 2}
            out = self._post({"product_name": "p"})
        self.assertEqual(out["counts"]["failed"], 0, out["outcomes"])
        self.assertEqual(out["counts"]["launched"], 6)
        # The parts with nothing to read yet were skipped, not attempted.
        self.assertNotIn("gaps", out["requested"])
        self.assertNotIn("hypotheses", out["requested"])

    def test_selected_parts_run_in_dependency_order(self):
        with _launchers():
            out = self._post({"parts": ["hypotheses", "research", "assess"]})
        order = [o["part"] for o in out["outcomes"]]
        self.assertEqual(order, ["research", "assess", "hypotheses"])

    def test_a_refusal_is_reported_not_hidden(self):
        from fastapi import HTTPException
        with _launchers() as m:
            m["launch_assess"].side_effect = HTTPException(
                429, "A security assessment of this kind is already running here")
            out = self._post({"parts": ["assess", "summary"]})
        assess = next(o for o in out["outcomes"] if o["part"] == "assess")
        summary = next(o for o in out["outcomes"] if o["part"] == "summary")
        self.assertEqual(assess["status"], "failed")
        self.assertTrue(assess["refused"])
        self.assertEqual(assess["http_status"], 429)
        # ...and the next part still ran.
        self.assertEqual(summary["status"], "computed")

    def test_one_part_failing_does_not_abandon_the_rest(self):
        from fastapi import HTTPException
        with _launchers() as m:
            m["collect_cves"].side_effect = HTTPException(
                502, "CVE collection failed: boom")
            out = self._post({"parts": ["research", "cves", "assess"]})
        statuses = {o["part"]: o["status"] for o in out["outcomes"]}
        self.assertEqual(statuses["research"], "launched")
        self.assertEqual(statuses["cves"], "failed")
        self.assertEqual(statuses["assess"], "launched")
        self.assertEqual(out["counts"]["failed"], 1)
        self.assertEqual(out["counts"]["launched"], 2)

    def test_no_open_gaps_is_an_answer_not_a_failure(self):
        db = _db.SessionLocal()
        try:
            db.add(_models.Artifact(investigation_id=self.inv_id, title="a",
                                    artifact_type="web", content="x"))
            db.commit()
        finally:
            db.close()
        with _launchers() as m:
            m["launch_gap_research"].return_value = {
                "launched": None, "gaps": [],
                "message": "No open gaps -- run the agent first."}
            out = self._post({"parts": ["gaps"]})
        gap = out["outcomes"][0]
        self.assertEqual(gap["status"], "nothing_to_do")
        self.assertEqual(out["counts"]["failed"], 0)

    def test_gap_research_launches_when_there_are_open_gaps(self):
        db = _db.SessionLocal()
        try:
            db.add(_models.Artifact(investigation_id=self.inv_id, title="a",
                                    artifact_type="web", content="x"))
            db.commit()
        finally:
            db.close()
        with _launchers() as m:
            out = self._post({"parts": ["gaps"]})
            called = m["launch_gap_research"].called
        self.assertEqual(out["outcomes"][0]["status"], "launched")
        self.assertTrue(called)

    def test_unavailable_part_is_skipped_with_its_reason(self):
        out = self._post({"parts": ["gaps"]})
        gap = out["outcomes"][0]
        self.assertEqual(gap["status"], "skipped")
        self.assertIn("run research first", gap["detail"])
        self.assertEqual(out["counts"]["launched"], 0)

    def test_explicit_wildcard_is_the_full_set(self):
        state = self.client.get(
            f"/api/investigations/{self.inv_id}/control").json()
        with _launchers():
            out = self._post({"parts": ["*"]})
        # The wildcard is exactly the set the state read called available --
        # not a hardcoded list, which would drift the moment a part is added.
        self.assertEqual(sorted(out["requested"]), sorted(state["full_set"]))
        self.assertNotIn("gaps", out["requested"])

    def test_a_part_busy_after_a_trigger_is_skipped_next_time(self):
        # Launching the explainer parks an Explanation at "running", so the
        # second full re-run must skip it. Two calls in a row are the real
        # way an operator hits this.
        with _launchers():
            first = self._post({"parts": ["explain"]})
            second = self._post({"parts": ["*"]})
        self.assertEqual(first["outcomes"][0]["status"], "launched")
        self.assertNotIn("explain", second["requested"])
        self.assertIn("explanation is already in progress",
                      second["state"]["parts"][4]["blocked_reason"] or
                      " ".join(p["blocked_reason"] or ""
                               for p in second["state"]["parts"]))

    def test_unknown_part_is_400(self):
        r = self.client.post(
            f"/api/investigations/{self.inv_id}/control",
            json={"parts": ["nope"]}, headers=HEADERS)
        self.assertEqual(r.status_code, 400)
        self.assertIn("unknown part", r.json()["detail"])

    def test_unknown_investigation_is_404(self):
        r = self.client.post("/api/investigations/999999/control",
                             json={}, headers=HEADERS)
        self.assertEqual(r.status_code, 404)

    def test_launched_research_uses_the_caller_bounds(self):
        with _launchers() as m:
            self._post({"parts": ["research"], "max_items": 7,
                        "max_rounds": 3})
            kwargs = m["launch_run"].call_args.kwargs
        self.assertEqual(kwargs["max_items"], 7)
        self.assertEqual(kwargs["max_rounds"], 3)

    def test_explainer_defaults_to_a_question_about_this_investigation(self):
        with _launchers() as m:
            out = self._post({"parts": ["explain"]})
            payload = m["launch_explanation"].call_args
        self.assertEqual(out["outcomes"][0]["status"], "launched")
        self.assertTrue(payload)

    def test_response_carries_the_refreshed_state(self):
        out = self._post({"parts": ["summary"]})
        self.assertIn("state", out)
        self.assertIn("parts", out["state"])


if __name__ == "__main__":
    unittest.main()
