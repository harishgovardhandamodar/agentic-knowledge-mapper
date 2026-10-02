"""mcp-search — web, arxiv, rss, fetch_page (OpenShell)."""

from __future__ import annotations

from typing import Any

from .. import search as search_providers
from .. import openshell as osh


def web_search(query: str, max_results: int = 8) -> list[dict[str, Any]]:
    return search_providers.search_web(query, max_results=max_results)


def arxiv_search(query: str, max_results: int = 5) -> list[dict[str, Any]]:
    return search_providers.search_arxiv(query, max_results=max_results)


def rss_search(query: str, max_results: int = 5) -> list[dict[str, Any]]:
    return search_providers.search_rss(query, max_results=max_results)


def fetch_page(url: str, use_sandbox: bool = True) -> dict[str, Any]:
    if use_sandbox:
        try:
            return osh.fetch_via_broker(url)
        except Exception:
            pass
    # fallback direct
    import requests

    try:
        r = requests.get(url, timeout=10, headers={"User-Agent": "AKM/1.0"})
        return {"url": url, "status": r.status_code, "content": r.text[:8000], "sandbox": False}
    except Exception as e:
        return {"url": url, "error": str(e), "sandbox": False}
