"""CLI client + dashboard behaviour, headless.

httpx is mocked at the ``cli.client`` boundary; the dashboard is driven
with a stub client and a stub Live object, so no TTY or server is needed.
Pin header required suite-wide (see tests/test_db_isolation.py).
"""
import os
import tempfile
import unittest
from unittest import mock

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-cli-cl-"),
                                "test.db"))

from cli.client import AkMClient, ApiError  # noqa: E402
from cli.tui import Dashboard  # noqa: E402


class _Resp:
    def __init__(self, status=200, payload=None, text=""):
        self.status_code = status
        self._payload = payload
        self.text = text or ""
        self.content = b"{}" if payload is None else b'{"x": 1}'

    def json(self):
        return self._payload


class _ClientCtx:
    """Stands in for httpx.Client as a context manager."""

    def __init__(self, resp, seen):
        self.resp = resp
        self.seen = seen

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get(self, url, params=None, headers=None):
        self.seen.append(("GET", url, params, headers))
        return self.resp

    def post(self, url, json=None, headers=None):
        self.seen.append(("POST", url, json, headers))
        return self.resp


def _patch(resp):
    seen: list = []
    cm = _ClientCtx(resp, seen)
    p = mock.patch("cli.client.httpx.Client", return_value=cm)
    p.start()
    return seen, p


class ClientCase(unittest.TestCase):
    def tearDown(self):
        mock.patch.stopall()

    def test_get_list_accepts_bare_and_wrapped(self):
        seen, p = _patch(_Resp(payload=[{"id": 1}]))
        try:
            self.assertEqual(AkMClient("http://x").list_runs(),
                             [{"id": 1}])
        finally:
            p.stop()
        seen2, p2 = _patch(_Resp(payload={"items": [{"id": 2}]}))
        try:
            self.assertEqual(AkMClient("http://x").list_runs(),
                             [{"id": 2}])
        finally:
            p2.stop()
        self.assertTrue(seen[0][1].endswith("/api/runs"))

    def test_api_error_carries_status(self):
        _, p = _patch(_Resp(status=409, text="busy"))
        try:
            with self.assertRaises(ApiError) as ctx:
                AkMClient("http://x").launch_run(3)
            self.assertEqual(ctx.exception.status, 409)
        finally:
            p.stop()

    def test_manager_compile_uses_long_timeout(self):
        seen_client = {}

        class C:
            def __init__(self, timeout=None):
                seen_client["timeout"] = timeout

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def post(self, url, json=None, headers=None):
                return _Resp(payload={"artifact_id": 9})

        with mock.patch("cli.client.httpx.Client",
                        side_effect=lambda timeout=None: C(timeout)):
            res = AkMClient("http://x").manager_compile(4)
        self.assertEqual(res["artifact_id"], 9)
        self.assertGreaterEqual(seen_client["timeout"], 600)

    def test_llm_info_reads_health(self):
        _, p = _patch(_Resp(payload={"llm": {"served_by": "axiom"}}))
        try:
            self.assertEqual(AkMClient("http://x").llm_info(),
                             {"served_by": "axiom"})
        finally:
            p.stop()

    def test_every_request_carries_the_tui_frontend_label(self):
        from cli.client import TUI_HEADERS
        seen, p = _patch(_Resp(payload=[{"id": 1}]))
        try:
            AkMClient("http://x").list_runs()
            AkMClient("http://x").launch_run(3)
        finally:
            p.stop()
        self.assertEqual(len(seen), 2)
        for entry in seen:
            self.assertEqual(entry[3], TUI_HEADERS)
            self.assertEqual(entry[3].get("X-AKM-Client"), "tui")


class _StubLive:
    def __init__(self):
        self.frames = []
        self.running = True

    def update(self, frame):
        self.frames.append(frame)

    def stop(self):
        self.running = False

    def start(self):
        self.running = True


class StubClient:
    """Canned backend for dashboard tests."""

    def __init__(self):
        self.base_url = "http://stub"
        self.launched = []

    def health(self):
        return {"status": "ok",
                "llm": {"preferred_url": "http://axiom:8210/v1",
                        "served_by": "http://axiom:8210/v1",
                        "preferred_reachable": True,
                        "fallback_active": False}}

    def list_investigations(self):
        return [{"id": 1, "title": "Alpha", "status": "ready"},
                {"id": 2, "title": "Beta", "status": "draft"}]

    def list_runs(self):
        return [{"id": 7, "investigation_id": 1, "trigger": "manual",
                 "status": "done", "started_at": "t",
                 "finished_at": "t"}]

    def manager_runs(self, limit=20):
        return [{"id": 3, "status": "compiled", "compiled": True,
                 "command": "assess x"}]

    def ledger_timeline(self, limit=50):
        return [{"ts": "2026-01-01T00:00:00", "actor_type": "agent",
                 "actor": "r", "kind": "agent.hop", "verdict": "pass",
                 "intent": "plan"}]

    def ledger_audit_drops(self):
        return []

    def approvals_pending(self):
        return []

    def investigation_summary(self, iid):
        return {"summary": "stub summary"}

    def query_yields(self, iid):
        return {"shapes": [{"shape": "vendor docs", "attempts": 2,
                            "found": 5, "kept": 3}]}

    def list_assessments(self, iid):
        return [{"id": 11, "product_name": "Widget",
                 "residual_pct": 42.0,
                 "diagrams": {"dataflow": "graph TD\n A[x]-->B[y]"},
                 "markdown": ""}]

    def manager_get(self, run_id):
        return {"id": run_id, "status": "compiled",
                "compiled": True}

    def manager_timeline(self, run_id):
        return {"flow": ["command", "plan"], "events": []}

    def launch_run(self, iid):
        self.launched.append(iid)
        return {"run_id": 9}

    def create_investigation(self, title, desc, kw):
        return {"id": 5, "title": title}

    def manager_compile(self, run_id):
        return {"artifact_id": 12}


class DashboardCase(unittest.TestCase):
    def setUp(self):
        from rich.console import Console
        self.dash = Dashboard(StubClient())  # type: ignore[arg-type]
        # Tall console: the ops tab pages to terminal height, and the
        # default 25-line fallback would cut later sections off.
        self.dash.console = Console(width=100, height=200)
        self.dash.refresh(force=True)
        self.live = _StubLive()

    def _text(self):
        with self.dash.console.capture() as cap:
            self.dash.console.print(self.dash.frame())
        return cap.get()

    def test_research_frame_lists_shared_rows(self):
        text = self._text()
        self.assertIn("Alpha", text)
        self.assertIn("Widget", text)
        self.assertIn("dataflow", text)
        self.assertIn("axiom:8210", text)

    def test_tab_switch_and_selection(self):
        self.assertTrue(self.dash.act(self.live, "2"))
        self.assertEqual(self.dash.tab, "ops")
        text = self._text()
        self.assertIn("agent swarm", text)
        self.assertIn("vendor docs", text)
        self.assertTrue(self.dash.act(self.live, "1"))
        self.assertEqual(self.dash.tab, "research")
        self.assertTrue(self.dash.act(self.live, "down"))
        self.assertEqual(self.dash.inv_idx, 1)

    def test_launch_uses_selected_investigation(self):
        self.dash.act(self.live, "down")
        self.dash.act(self.live, "l")
        self.assertEqual(self.dash.client.launched, [2])

    def test_quit_returns_false(self):
        self.assertFalse(self.dash.act(self.live, "q"))

    def test_compile_records_note(self):
        self.dash.act(self.live, "2")
        self.dash.mgr_id = 3
        self.dash.refresh(force=True)
        self.dash.act(self.live, "c")
        self.assertIn("#12", self.dash.note)


if __name__ == "__main__":
    unittest.main()
