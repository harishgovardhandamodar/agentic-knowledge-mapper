"""Thin HTTP client for the knowledge-mapper API.

Every call goes to the running web app, so CLI-created investigations,
runs, and artifacts share the web GUI's database and are viewable there.
Only ``httpx`` is required; all payloads are plain dicts/lists and every
accessor tolerates missing keys so a newer/older server cannot crash the
CLI.
"""

from __future__ import annotations

import os

import httpx

from cli import DEFAULT_API_URL


class ApiError(RuntimeError):
    """The server answered with a non-2xx status."""

    def __init__(self, method: str, path: str, status: int, body: str):
        super().__init__(f"{method} {path} -> {status}: {body[:300]}")
        self.method = method
        self.path = path
        self.status = status
        self.body = body


# Every CLI/TUI request carries this: the backend labels the LLM traffic
# it triggers as agentic-knowledge-mapper-tui at the fox-services gateway,
# so queue slots and usage rows tell CLI-driven load apart from web load.
TUI_HEADERS = {"X-AKM-Client": "tui"}


class AkMClient:
    """Small wrapper over the endpoints the CLI/TUI needs."""

    def __init__(self, base_url: str | None = None,
                 timeout_s: float = 30.0):
        self.base_url = (base_url or os.environ.get("AKM_API_URL")
                         or DEFAULT_API_URL).rstrip("/")
        self.timeout_s = timeout_s

    # -- low level ------------------------------------------------------
    def _url(self, path: str) -> str:
        return self.base_url + path

    def _raise(self, method: str, path: str,
               resp: httpx.Response) -> None:
        if resp.status_code >= 400:
            raise ApiError(method, path, resp.status_code, resp.text)

    def get_json(self, path: str, params: dict | None = None) -> dict:
        with httpx.Client(timeout=self.timeout_s) as c:
            r = c.get(self._url(path), params=params, headers=TUI_HEADERS)
        self._raise("GET", path, r)
        data = r.json()
        return data if isinstance(data, dict) else {"items": data}

    def get_list(self, path: str, params: dict | None = None) -> list:
        with httpx.Client(timeout=self.timeout_s) as c:
            r = c.get(self._url(path), params=params, headers=TUI_HEADERS)
        self._raise("GET", path, r)
        data = r.json()
        if isinstance(data, list):
            return data
        for key in ("items", "runs", "investigations", "events",
                    "artifacts", "lanes"):
            if isinstance(data.get(key), list):
                return data[key]
        return []

    def get_text(self, path: str, params: dict | None = None) -> str:
        with httpx.Client(timeout=self.timeout_s) as c:
            r = c.get(self._url(path), params=params, headers=TUI_HEADERS)
        self._raise("GET", path, r)
        return r.text

    def post_json(self, path: str, payload: dict | None = None,
                  timeout_s: float | None = None) -> dict:
        with httpx.Client(timeout=timeout_s or self.timeout_s) as c:
            r = c.post(self._url(path), json=payload or {},
                       headers=TUI_HEADERS)
        self._raise("POST", path, r)
        if not r.content:
            return {}
        data = r.json()
        return data if isinstance(data, dict) else {"items": data}

    # -- health / LLM ----------------------------------------------------
    def health(self) -> dict:
        return self.get_json("/api/health")

    def llm_info(self) -> dict:
        return self.health().get("llm", {})

    # -- investigations + research ---------------------------------------
    def list_investigations(self) -> list:
        return self.get_list("/api/investigations")

    def create_investigation(self, title: str, description: str = "",
                             keywords: str = "",
                             sources: str = "web") -> dict:
        return self.post_json("/api/investigations", {
            "title": title, "description": description,
            "keywords": keywords, "sources": sources})

    def get_investigation(self, inv_id: int) -> dict:
        return self.get_json(f"/api/investigations/{inv_id}")

    def launch_run(self, inv_id: int) -> dict:
        return self.post_json(f"/api/investigations/{inv_id}/run")

    def investigation_summary(self, inv_id: int) -> dict:
        return self.get_json(f"/api/investigations/{inv_id}/summary")

    def artifacts_overview(self, inv_id: int) -> dict:
        return self.get_json(
            f"/api/investigations/{inv_id}/artifacts/overview")

    def list_artifacts(self, inv_id: int) -> list:
        return self.get_list(f"/api/investigations/{inv_id}/artifacts")

    def list_runs(self) -> list:
        return self.get_list("/api/runs")

    def get_run(self, run_id: int) -> dict:
        return self.get_json(f"/api/runs/{run_id}")

    def run_events(self, run_id: int) -> list:
        data = self.get_json(f"/api/runs/{run_id}/events")
        if isinstance(data, list):
            return data
        return data.get("events", [])

    def investigation_timeline(self, inv_id: int) -> dict:
        return self.get_json(f"/api/investigations/{inv_id}/timeline")

    def query_yields(self, inv_id: int) -> dict:
        """Web-search history shapes for an investigation."""
        return self.get_json(f"/api/investigations/{inv_id}/query-yields")

    def list_explanations(self, inv_id: int) -> list:
        return self.get_list(f"/api/investigations/{inv_id}/explanations")

    def get_explanation(self, exp_id: int) -> dict:
        return self.get_json(f"/api/explanations/{exp_id}")

    # -- security assessments + diagrams ----------------------------------
    def list_assessments(self, inv_id: int) -> list:
        data = self.get_json(
            f"/api/investigations/{inv_id}/security/assessments")
        if isinstance(data, list):
            return data
        for key in ("assessments", "items"):
            if isinstance(data.get(key), list):
                return data[key]
        return []

    def request_assessment(self, inv_id: int, product: str,
                           exposure: str = "restricted_data",
                           use_case: str = "") -> dict:
        return self.post_json(
            f"/api/investigations/{inv_id}/security/assess",
            {"product_name": product, "exposure": exposure,
             "use_case": use_case})

    # -- manager -----------------------------------------------------------
    def manager_parse(self, command: str) -> dict:
        return self.post_json("/api/manager/parse", {"command": command})

    def manager_run(self, plan: dict, command: str = "",
                    options: dict | None = None) -> dict:
        return self.post_json("/api/manager/run", {
            "plan": plan, "command": command,
            "options": options or {}})

    def manager_runs(self, limit: int = 20) -> list:
        return self.get_list("/api/manager/runs",
                             params={"limit": limit})

    def manager_get(self, run_id: int) -> dict:
        return self.get_json(f"/api/manager/runs/{run_id}")

    def manager_timeline(self, run_id: int) -> dict:
        return self.get_json(f"/api/manager/runs/{run_id}/timeline")

    def manager_compile(self, run_id: int,
                        timeout_s: float = 1200.0) -> dict:
        return self.post_json(f"/api/manager/runs/{run_id}/compile",
                              timeout_s=timeout_s)

    def manager_report(self, run_id: int) -> dict:
        return self.get_json(f"/api/manager/runs/{run_id}/summary-report")

    def manager_report_markdown(self, run_id: int) -> str:
        return self.get_text(
            f"/api/manager/runs/{run_id}/summary-report/markdown")

    # -- ledger / activity --------------------------------------------------
    def ledger_timeline(self, limit: int = 50) -> list:
        return self.get_list("/api/ledger/timeline",
                             params={"limit": limit})

    def ledger_runs(self) -> list:
        return self.get_list("/api/ledger/runs")

    def ledger_audit_drops(self) -> list:
        return self.get_list("/api/ledger/audit-drops")

    def approvals_pending(self) -> list:
        return self.get_list("/api/ledger/approvals/pending")
