"""Gateway service identity: web vs TUI traffic.

The backend labels LLM calls ``agentic-knowledge-mapper`` by default and
``agentic-knowledge-mapper-tui`` when the operator drives from the terminal
CLI (``X-AKM-Client: tui`` header -> contextvar -> X-Service-Name, inherited
by research threads via copy_context and re-bound from the job payload by
queued security workers). Pin header required suite-wide (db isolation).
"""
import os
import tempfile
import unittest
from unittest import mock

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-svc-label-"),
                                "test.db"))

import app.llm as llm  # noqa: E402


class ResolverCase(unittest.TestCase):
    def tearDown(self):
        llm.reset_client_label(llm.set_client_label(None))

    def test_default_is_the_app_name(self):
        self.assertEqual(llm.service_name(), llm.SERVICE_NAME)

    def test_tui_label_switches_identity(self):
        token = llm.set_client_label("tui")
        try:
            self.assertEqual(llm.service_name(), llm.SERVICE_NAME_TUI)
            self.assertEqual(llm.current_client_label(), "tui")
        finally:
            llm.reset_client_label(token)
        self.assertEqual(llm.service_name(), llm.SERVICE_NAME)

    def test_unknown_labels_clear(self):
        token = llm.set_client_label("web")
        try:
            self.assertEqual(llm.service_name(), llm.SERVICE_NAME)
            self.assertIsNone(llm.current_client_label())
        finally:
            llm.reset_client_label(token)

    def test_chat_post_carries_the_label(self):
        resp = mock.Mock(status_code=200)
        resp.headers = {}
        resp.json.return_value = {"choices": [{"message": {"content": "x"}}]}
        client = mock.MagicMock()
        client.__enter__.return_value.post.return_value = resp
        token = llm.set_client_label("tui")
        try:
            with mock.patch("app.llm.httpx.Client",
                            return_value=client):
                llm._post("http://gw:8210/v1", {"model": "x"})
        finally:
            llm.reset_client_label(token)
        headers = client.__enter__.return_value.post.call_args.kwargs[
            "headers"]
        self.assertEqual(headers["X-Service-Name"], llm.SERVICE_NAME_TUI)


class _ProbeResp:
    status_code = 200

    def json(self):
        return {"data": [{"id": "qwen3.8:27b"}]}


class _ProbeClient:
    """Captures the models-probe request headers for health()."""

    seen: list = []

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get(self, url, headers=None):
        _ProbeClient.seen.append((url, headers or {}))
        return _ProbeResp()


class MiddlewareCase(unittest.TestCase):
    def test_tui_header_relabels_the_live_probe(self):
        from fastapi.testclient import TestClient

        from app.main import app
        _ProbeClient.seen = []
        with mock.patch("app.llm.httpx.Client", _ProbeClient):
            with TestClient(app) as c:
                r = c.get("/api/health",
                          headers={"X-AKM-Client": "tui"})
                self.assertEqual(r.status_code, 200)
                body = r.json()
        self.assertEqual(body["llm"]["service"], llm.SERVICE_NAME_TUI)
        probe = [h for _, h in _ProbeClient.seen]
        self.assertTrue(probe)
        self.assertEqual(probe[0]["X-Service-Name"],
                         llm.SERVICE_NAME_TUI)

    def test_no_header_keeps_the_app_name(self):
        from fastapi.testclient import TestClient

        from app.main import app
        _ProbeClient.seen = []
        with mock.patch("app.llm.httpx.Client", _ProbeClient):
            with TestClient(app) as c:
                body = c.get("/api/health").json()
        self.assertEqual(body["llm"]["service"], llm.SERVICE_NAME)

    def test_label_does_not_leak_between_requests(self):
        self.assertIsNone(llm.current_client_label())


class SecurityPayloadCase(unittest.TestCase):
    def test_enqueue_stashes_the_label(self):
        from app import database as _db
        from app import security_agent as _sa
        from app.models import Investigation
        _db.init_db()
        db = _db.SessionLocal()
        try:
            inv = Investigation(title="label probe", keywords="k",
                                description="d", sources="web")
            db.add(inv)
            db.commit()
            seen = {}

            def _capture(db_arg, kind, payload, **kwargs):
                seen.update(payload)
                return 1

            token = llm.set_client_label("tui")
            try:
                with mock.patch.object(_sa.jobqueue, "enqueue",
                                       side_effect=_capture):
                    _sa.launch_security_assessment(
                        inv.id, {"product_name": "Widget"}, requested_by="t")
            finally:
                llm.reset_client_label(token)
            self.assertEqual(seen.get("client"), "tui")
        finally:
            db.close()

    def test_handler_rebinds_and_resets(self):
        from app import security_agent as _sa
        observed = []

        def _fake_run(run_id, params):
            observed.append(llm.service_name())

        payload = {"run_id": 4242, "params": {}, "client": "tui"}
        with mock.patch.object(_sa, "run_security_assessment",
                               side_effect=_fake_run):
            self.assertTrue(_sa._handle_security_job(object(), payload))
        self.assertEqual(observed, [llm.SERVICE_NAME_TUI])
        self.assertEqual(llm.service_name(), llm.SERVICE_NAME)


if __name__ == "__main__":
    unittest.main()
