"""The design set, served as selectable documents to the Design tab.

The diagrams that describe this system already exist as Mermaid-in-Markdown
under ``design/``. This module does not author them and does not copy them
into the database: it makes them *selectable*. The tab lists the documents, a
click fetches one, and the browser renders the Markdown and the Mermaid.

Two properties matter more than the feature itself:

* **The index is a constant, not a directory listing.** A document is reachable
  only if its id is one of ``_DOCS`` below, and the file it resolves to is
  re-checked against the design root before it is read. A caller cannot reach a
  file by passing a path, so a traversal attempt is a 404 like any other
  unknown id -- there is no code path that turns user input into a path.
* **A missing design directory is a state, not a crash.** The docs are
  documentation; an image built without them should show an explanation, not
  a 500. ``available: false`` with a reason is the honest answer, and each
  entry is marked unavailable rather than dropped so the list keeps its shape.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Any, Optional

#: Repository root, i.e. the parent of the ``app`` package.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DESIGN_DIR = os.environ.get("AKM_DESIGN_DIR") or os.path.join(REPO_ROOT, "design")

#: Safety valve. The largest design document is ~19 kB; this is two orders of
#: magnitude above it, so hitting it means something is wrong with the file, not
#: that the tab should refuse to render. Truncation is reported, never silent.
MAX_BYTES = 1_000_000

#: id, file, title, group, diagram kind, and the one question the document
#: answers -- the same wording the design index uses, so the tab and the
#: README cannot drift apart.
_DOCS: list[dict[str, str]] = [
    {"id": "readme", "file": "README.md", "title": "The design set",
     "group": "Start here", "kind": "index · conventions · reading order",
     "answers": "How to read the set, what the arrows mean, and what keeps it honest"},
    {"id": "system-context", "file": "01-system-context.md", "title": "System context",
     "group": "Structure", "kind": "context · container · deployment · environment",
     "answers": "What is in the box, what is outside it, and what runs where"},
    {"id": "uml", "file": "02-uml.md", "title": "UML structure",
     "group": "Structure", "kind": "component · class · package",
     "answers": "Which module owns which responsibility, and how they depend"},
    {"id": "data-model", "file": "data-model.md", "title": "Data model",
     "group": "Structure", "kind": "ER · lifecycle",
     "answers": "What is stored, how it relates, and how records move through states"},
    {"id": "interaction", "file": "interaction.md", "title": "Interaction",
     "group": "Behaviour", "kind": "sequence",
     "answers": "What calls what, in what order, on every major flow"},
    {"id": "activity", "file": "activity.md", "title": "Activity",
     "group": "Behaviour", "kind": "decisions",
     "answers": "What decisions an agent makes while it works"},
    {"id": "state", "file": "state.md", "title": "State",
     "group": "Behaviour", "kind": "state machines",
     "answers": "How each long-lived object moves through its states"},
    {"id": "ui-interaction", "file": "ui-interaction.md", "title": "UI interaction",
     "group": "User-facing", "kind": "navigation · overlays · controls",
     "answers": "How a person moves through the app, and what each control does"},
    {"id": "privacy", "file": "privacy.md", "title": "Privacy",
     "group": "Privacy & assurance", "kind": "boundaries · data flow · redaction",
     "answers": "What data exists, where it can go, and what provably cannot leave"},
    {"id": "controls", "file": "controls.md", "title": "Control catalogue",
     "group": "Privacy & assurance", "kind": "catalogue · evidence",
     "answers": "Every governance, integrity and privacy control, with where it is enforced"},
    {"id": "risk-console", "file": "risk-console.md", "title": "Risk Console",
     "group": "User-facing", "kind": "alternative GUI · personas · risk-first",
     "answers": "How the parallel Risk Console presents the same backend for researchers to CISOs"},
    {"id": "risk-management", "file": "risk-management.md", "title": "Risk Management Agents",
     "group": "Behaviour", "kind": "risk lifecycle · agents · jobs",
     "answers": "How the risk family (intake → triage → treat → monitor → govern → report) manages the register"},
    {"id": "risk-scoring", "file": "risk-scoring.md", "title": "Risk Scoring",
     "group": "Structure", "kind": "scoring · bands · fingerprints",
     "answers": "How register-risk-scoring-v1 produces inherent, residual, priority and band"},
    {"id": "fox-core", "file": "fox-core.md", "title": "Fox Security Research Core",
     "group": "Structure", "kind": "switchable core · swarm · MCP",
     "answers": "How the optimized Fox core (4 swarms + MCP + deterministic core) pairs with the Risk Console"},
]

_FENCE_RE = re.compile(r"^\s*```(\w*)\s*$")
_FIRST_WORD_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*")


class UnknownDoc(KeyError):
    """Raised for an id that is not in the index -- including traversal attempts."""


def design_dir() -> str:
    """The design directory, resolved per call so tests can move it."""
    return DESIGN_DIR


def _entry(doc_id: str) -> Optional[dict[str, str]]:
    """Look an id up in the index.

    Read from ``_DOCS`` on every call rather than from a dict built at import:
    ten entries is nothing to scan, and a second copy of the index is a thing
    that can disagree with the first.
    """
    want = str(doc_id or "")
    for entry in _DOCS:
        if entry["id"] == want:
            return entry
    return None


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _resolve(doc_id: str) -> tuple[dict[str, str], str]:
    """Map an id to its file, refusing anything that leaves the design root.

    The id is the only caller-controlled input, and it is looked up in the
    index -- so the resolved path is already determined by this file. The
    ``realpath`` check is not load-bearing today; it is here so that a future
    index sourced from configuration cannot quietly turn this into a
    read-anything route.
    """
    entry = _entry(doc_id)
    if entry is None:
        raise UnknownDoc(doc_id)
    root = os.path.realpath(design_dir())
    path = os.path.realpath(os.path.join(root, entry["file"]))
    if os.path.dirname(path) != root or not path.endswith(".md"):
        raise UnknownDoc(doc_id)
    return entry, path


def _diagram_kinds(markdown: str) -> list[str]:
    """Unique Mermaid diagram kinds in a document, in first-seen order.

    A diagram is named by the first meaningful line of its block -- ``flowchart
    TB``, ``sequenceDiagram``, ``erDiagram``. Reading further would pick up
    node ids, so the scan records one kind per block and then stops until the
    fence closes.
    """
    kinds: list[str] = []
    inside = False      # inside a mermaid fence
    want_kind = False   # the next meaningful line names the diagram
    for line in markdown.splitlines():
        fence = _FENCE_RE.match(line)
        if fence:
            if inside:
                inside = False
                want_kind = False
            else:
                inside = fence.group(1).lower() == "mermaid"
                want_kind = inside
            continue
        if not inside or not want_kind:
            continue
        text = line.strip()
        if not text or text.startswith("%%"):
            continue  # leading comments do not name the diagram
        m = _FIRST_WORD_RE.match(text)
        if m and m.group(0) not in kinds:
            kinds.append(m.group(0))
        want_kind = False
    return kinds


def _count_diagrams(markdown: str) -> int:
    """Number of ```mermaid blocks.

    A block's opening fence carries the language; its closing fence does not, so
    counting the fences whose group is "mermaid" counts blocks, not lines.
    """
    total = 0
    for line in markdown.splitlines():
        fence = _FENCE_RE.match(line)
        if fence and fence.group(1).lower() == "mermaid":
            total += 1
    return total


def _stat(entry: dict[str, str]) -> dict[str, Any]:
    """The list-view row for one document, including whether it is on disk."""
    out: dict[str, Any] = {k: entry[k] for k in ("id", "file", "title", "group", "kind", "answers")}
    try:
        _, path = _resolve(entry["id"])
        st = os.stat(path)
        # Read once, for both the size-independent diagram count and the kinds:
        # a list that says "0 diagrams" for a file full of them is worse than a
        # slightly slower list endpoint.
        markdown, _ = _safe_read(path)
    except (UnknownDoc, OSError):
        out.update(available=False, diagrams=0, kinds=[], bytes=0, mtime=None)
        return out
    out.update(available=True, diagrams=_count_diagrams(markdown),
               kinds=_diagram_kinds(markdown), bytes=st.st_size, mtime=_iso(st.st_mtime))
    return out


def _safe_read(path: str) -> tuple[str, bool]:
    """Read a file, capping the size. Returns ``(text, truncated)``.

    Read in bytes, so "did the cap cut this off" is a question with an answer.
    Decoding first would make the check a guess: character counts are not byte
    counts once a file contains an em dash, and a file that simply has no
    trailing newline is complete, not truncated.
    """
    with open(path, "rb") as fh:
        raw = fh.read(MAX_BYTES)
        truncated = len(raw) == MAX_BYTES and bool(fh.read(1))
    return raw.decode("utf-8", errors="replace"), truncated


def list_docs() -> dict[str, Any]:
    """Every document in the set, in reading order, with its metadata."""
    root = design_dir()
    available = os.path.isdir(root)
    docs = [_stat(entry) for entry in _DOCS]
    groups: list[str] = []
    for d in docs:
        if d["group"] not in groups:
            groups.append(d["group"])
    out: dict[str, Any] = {
        "source": os.path.relpath(root, REPO_ROOT) if available else root,
        "available": available,
        "count": len(docs),
        "groups": groups,
        "docs": docs,
    }
    if not available:
        out["reason"] = (f"No design directory at {root}. Set AKM_DESIGN_DIR to point "
                         f"at one, or add the documents to the image.")
    return out


def get_doc(doc_id: str) -> dict[str, Any]:
    """One document, with its Markdown for the browser to render.

    Raises :class:`UnknownDoc` for an unknown id -- the same 404 a traversal
    attempt gets, because they are the same thing from the caller's side.
    """
    entry, path = _resolve(doc_id)
    meta = _stat(entry)
    if not meta.get("available"):
        raise FileNotFoundError(meta.get("file") or entry["file"])
    markdown, truncated = _safe_read(path)
    return {
        **{k: meta[k] for k in ("id", "file", "title", "group", "kind", "answers",
                                 "bytes", "mtime", "kinds")},
        "diagrams": meta["diagrams"],
        "lines": markdown.count("\n") + 1,
        "truncated": truncated,
        "markdown": markdown,
    }
