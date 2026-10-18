"""The Agent Patterns & Advisor knowledge base, served as a tab in this app.

The sibling ``AI-Agents-Patterns`` project is a no-backend, browser-only
catalog: 107 design patterns, 43 failure scenarios, 180 composition cascades,
39 replayable mock traces, a deployment planner, blueprint builder and a
guardrail lab. It is advice-first material -- *how to design an agent, what
goes wrong, how to protect it* -- which complements this repo's
evidence-first assessments (what this product's residual is, from stored rows).

This module does not copy that catalog and does not re-author it: it makes it
*reachable* from this app in two ways, both read-only:

* **Same-origin static mount.** ``mount_patterns()`` serves the sibling
  directory at ``/patterns/`` so the Classic GUI can iframe the full
  eleven-tab SPA without a second port or CORS. A missing sibling directory
  is a state, not a crash: the mount is skipped and the API says
  ``available: false`` with a reason, exactly like ``app/design_docs.py``.
* **A small JSON API.** ``summary()`` and ``search()`` read the sibling's
  ``data/*.json`` files (cached by mtime) so this app's own surfaces --
  the tab badge, the explainer's advice links, a future manager launcher --
  can cite catalog counts and entries without loading the whole SPA.

Two properties matter more than the feature itself:

* **The directory is a constant set, not a caller-supplied path.** The only
  input is ``AKM_PATTERNS_DIR`` (or the ``../AI-Agents-Patterns`` default);
  no request parameter ever becomes a filesystem path.
* **Missing or malformed data degrades, never 500s.** Every loader returns
  ``available: false`` with a reason when the sibling is absent, and skips a
  single unreadable file while keeping the rest.
"""

from __future__ import annotations

import json
import os
from typing import Any

#: Repository root, i.e. the parent of the ``app`` package.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def patterns_dir() -> str:
    """The sibling catalog directory, resolved per call so tests can move it."""
    return os.environ.get("AKM_PATTERNS_DIR") or os.path.join(
        os.path.dirname(REPO_ROOT), "AI-Agents-Patterns"
    )


def available(reason_dir: str | None = None) -> dict[str, Any]:
    """Availability probe: is the sibling checkout present and readable?"""
    d = reason_dir or patterns_dir()
    index = os.path.join(d, "index.html")
    if not os.path.isdir(d):
        return {"available": False, "reason": f"patterns directory not found: {d}"}
    if not os.path.isfile(index):
        return {
            "available": False,
            "reason": f"patterns directory has no index.html: {d}",
        }
    return {"available": True, "directory": d}


# ------------------------------------------------------------------ catalog --
# File layout of the sibling project (data/*.json). Each loader returns []
# when its file is absent or unreadable, so one bad file cannot take down the
# summary or the search; the summary reports which files loaded.

_CATALOG_FILES = (
    "patterns.json",
    "scenarios.json",
    "cascades.json",
    "traces.json",
    "coverage.json",
)

_cache: dict[str, Any] = {"mtime": None, "payload": None}


def _load_json(directory: str, name: str) -> tuple[Any | None, float | None]:
    path = os.path.join(directory, "data", name)
    try:
        mtime = os.path.getmtime(path)
        with open(path, encoding="utf-8") as fh:
            return json.load(fh), mtime
    except (OSError, ValueError):
        return None, None


def _catalog(directory: str) -> dict[str, Any]:
    """Load every catalog file, keyed by file name (missing -> None)."""
    out: dict[str, Any] = {}
    mtimes: list[float] = []
    for name in _CATALOG_FILES:
        payload, mtime = _load_json(directory, name)
        out[name] = payload
        if mtime is not None:
            mtimes.append(mtime)
    out["_mtime"] = max(mtimes) if mtimes else None
    return out


def _as_list(payload: Any, *keys: str) -> list[dict[str, Any]]:
    """Drill into nested dicts (e.g. {"patterns": [...]}) to reach the list."""
    node: Any = payload
    for key in keys:
        if not isinstance(node, dict):
            return []
        node = node.get(key)
    return node if isinstance(node, list) else []


def summary() -> dict[str, Any]:
    """Catalog counts for the tab badge and advice links.

    Cached by the newest data-file mtime: the sibling's JSON is versioned
    and diffable, so a changed file is a new catalog, not a stale cache.
    """
    probe = available()
    if not probe["available"]:
        return {**probe, "counts": {}, "files": {}}
    cat = _catalog(probe["directory"])
    if _cache["mtime"] == cat["_mtime"] and _cache["payload"] is not None:
        return _cache["payload"]
    patterns = _as_list(cat["patterns.json"], "patterns")
    scenarios = _as_list(cat["scenarios.json"], "scenarios")
    cascades = _as_list(cat["cascades.json"], "cascades")
    traces = _as_list(cat["traces.json"], "traces")
    severities: dict[str, int] = {}
    for s in scenarios:
        sev = str(s.get("severity") or "unknown").lower()
        severities[sev] = severities.get(sev, 0) + 1
    cascade_classes: dict[str, int] = {}
    for c in cascades:
        cls = str(c.get("cls") or "unknown").lower()
        cascade_classes[cls] = cascade_classes.get(cls, 0) + 1
    payload = {
        "available": True,
        "directory": probe["directory"],
        "counts": {
            "patterns": len(patterns),
            "scenarios": len(scenarios),
            "cascades": len(cascades),
            "traces": len(traces),
            "severities": severities,
            "cascade_classes": cascade_classes,
        },
        "files": {name: cat[name] is not None for name in _CATALOG_FILES},
    }
    _cache["mtime"] = cat["_mtime"]
    _cache["payload"] = payload
    return payload


def _hit(entry: dict[str, Any], needle: str, fields: tuple[str, ...]) -> bool:
    hay = " ".join(str(entry.get(f) or "") for f in fields).lower()
    if isinstance(entry.get("tags"), list):
        hay += " " + " ".join(str(t) for t in entry["tags"]).lower()
    return needle in hay


def search(query: str, kind: str = "all", limit: int = 20) -> dict[str, Any]:
    """Case-insensitive substring search over the catalog.

    ``kind`` is one of ``patterns`` | ``scenarios`` | ``cascades`` | ``all``.
    Matching is deliberately lexical, not ranked retrieval: the catalog is
    the authority and this endpoint is an index into it, so a hit links back
    to the SPA tab that owns the entry rather than paraphrasing it.
    """
    probe = available()
    if not probe["available"]:
        return {**probe, "query": query, "items": []}
    needle = (query or "").strip().lower()
    if not needle:
        return {
            "available": True,
            "directory": probe["directory"],
            "query": query,
            "items": [],
        }
    limit = max(1, min(limit, 50))
    cat = _catalog(probe["directory"])
    pools: dict[str, tuple[list[dict[str, Any]], tuple[str, ...]]] = {
        "patterns": (
            _as_list(cat["patterns.json"], "patterns"),
            ("id", "name", "summary", "how", "domains"),
        ),
        "scenarios": (
            _as_list(cat["scenarios.json"], "scenarios"),
            ("id", "title", "domain", "severity", "vector", "description"),
        ),
        "cascades": (
            _as_list(cat["cascades.json"], "cascades"),
            ("id", "name", "domain", "cls", "summary", "trigger"),
        ),
    }
    want = [kind] if kind in pools else list(pools)
    items: list[dict[str, Any]] = []
    for k in want:
        entries, fields = pools[k]
        for e in entries:
            if not _hit(e, needle, fields):
                continue
            title = e.get("name") or e.get("title") or e.get("id")
            items.append(
                {
                    "kind": k.rstrip("s") if k != "cascades" else "cascade",
                    "id": e.get("id"),
                    "title": title,
                    "severity": e.get("severity"),
                    "domain": e.get("domain") or e.get("domains"),
                }
            )
            if len(items) >= limit:
                break
        if len(items) >= limit:
            break
    return {
        "available": True,
        "directory": probe["directory"],
        "query": query,
        "items": items[:limit],
    }
