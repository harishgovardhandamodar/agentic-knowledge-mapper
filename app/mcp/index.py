"""mcp-index — search, suggest, reindex_doc."""

from __future__ import annotations

from typing import Any

from .. import kb_search as kb


def search(q: str, investigation_id: int | None = None, **kwargs) -> dict[str, Any]:
    return kb.search(q=q, investigation_id=investigation_id, **kwargs)


def suggest(q: str, investigation_id: int | None = None) -> dict[str, Any]:
    return kb.suggest(q=q, investigation_id=investigation_id)


def reindex_doc(doc_id: int) -> dict[str, Any]:
    # For small deployments, search is live (no index rebuild needed); this is a no-op that returns ok for uniform MCP surface
    return {"doc_id": doc_id, "reindexed": True}
