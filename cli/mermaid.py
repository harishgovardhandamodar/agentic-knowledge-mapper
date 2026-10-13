"""Mermaid handling for the terminal: fence extraction + ASCII rendering.

The server stores diagram *sources* (``SecurityAssessment.diagrams_json``,
report ```` ```mermaid ```` fences); the browser renders them natively.
Here we parse the two structural kinds the assessments emit --
``graph``/``flowchart`` and ``sequenceDiagram`` -- into plain-ASCII art so
the CLI main tab can show them. Anything else (or anything unparseable)
falls back to the highlighted source. All functions are pure.
"""

from __future__ import annotations

import re

_FENCE_RE = re.compile(r"```mermaid\s*\n(.*?)```", re.DOTALL)

_NODE_RE = re.compile(
    r"([A-Za-z0-9_]+)"
    r"(\[\[.*?\]\]|\[.*?\]|\{\{.*?\}\}|\(\(\(.*?\)\)\)"
    r"|\(.*?\)|\{.*?\}|\[/.*?/\]|\\.*?\\|>\s*.*?\])")

_EDGE_RE = re.compile(
    r"([A-Za-z0-9_]+)\s*"
    r"(-+->|---+|==+>|\.-+->|--+>)"
    r"\s*(\|[^|]*\|)?\s*"
    r"([A-Za-z0-9_]+)")

_EDGE_LABEL_RE = re.compile(
    r"([A-Za-z0-9_]+)\s*--\s*([^-\s>][^>]*?)\s*-->\s*"
    r"([A-Za-z0-9_]+)")

_MSG_RE = re.compile(
    r"([A-Za-z0-9_]+)\s*(-{1,2}>>?|-+\)|-+>)\s*"
    r"([A-Za-z0-9_]+)\s*:\s*(.*)")

_PART_RE = re.compile(
    r"(?:participant|actor|create participant)\s+"
    r"([A-Za-z0-9_]+)(?:\s+as\s+(.+))?")

_NOTE_RE = re.compile(
    r"Note\s+(left of|right of|over)\s+([^:]+):\s*(.*)")

_SKIP_LINE_RE = re.compile(
    r"^(subgraph|end|style|classDef|class\s|click|linkStyle|direction"
    r"|box\s|autonumber|activate|deactivate|destroy|title)\b")

_MAX_LABEL = 26


def extract_fences(markdown: str) -> list[tuple[str, str]]:
    """Return ``(key, source)`` for every mermaid fence in ``markdown``."""
    out = []
    for i, m in enumerate(_FENCE_RE.finditer(markdown or "")):
        src = m.group(1).strip("\n")
        first = next((ln.strip() for ln in src.splitlines()
                      if ln.strip()), "")
        key = first if first and len(first) <= 40 else f"diagram-{i + 1}"
        out.append((key, src))
    return out


def diagram_kind(source: str) -> str:
    """Classify a diagram source for the renderer dispatcher."""
    head = (source or "").strip().split("\n", 1)[0].strip().lower()
    if head.startswith("sequencediagram"):
        return "sequence"
    if head.startswith("graph") or head.startswith("flowchart"):
        return "flowchart"
    return "other"


def render_ascii(source: str, width: int = 78) -> str | None:
    """Render ``source`` as ASCII art, or None when not supported."""
    kind = diagram_kind(source)
    if kind == "flowchart":
        return _render_flowchart(source, width)
    if kind == "sequence":
        return _render_sequence(source, width)
    return None


def save_mmd(source: str, path: str) -> str:
    """Write a diagram source to ``path`` (adds ``.mmd``); returns path."""
    if not path.endswith(".mmd"):
        path += ".mmd"
    with open(path, "w") as f:
        f.write((source or "").strip() + "\n")
    return path


# -- flowchart ------------------------------------------------------------

def _clean_label(text: str) -> str:
    text = (text or "").replace("\\n", " ")
    text = re.sub(r"^[\[\(\{/\\>]+|[\]\)\}/\\<\]]+$", "", text)
    text = re.sub(r"\s+", " ", text).strip().strip('"').strip("'")
    if len(text) > _MAX_LABEL:
        text = text[:_MAX_LABEL - 1] + "…"
    return text or "?"


def _parse_flowchart(source: str) -> tuple[dict, list]:
    """Return ``(labels, edges)``; ``labels`` maps node id -> label."""
    labels: dict[str, str] = {}
    edges: list[tuple[str, str, str]] = []
    lines = (source or "").splitlines()[1:]  # drop the graph header
    for raw in lines:
        line = raw.split("%%")[0]
        for stmt in line.split(";"):
            stmt = stmt.strip()
            if not stmt or _SKIP_LINE_RE.match(stmt):
                continue
            for m in _NODE_RE.finditer(stmt):
                labels.setdefault(m.group(1),
                                  _clean_label(m.group(2)))
            # Edges parse on the skeleton: label spans (A[..]) would
            # otherwise glue the node id to the arrow apart.
            rest = _NODE_RE.sub(lambda m: m.group(1), stmt)
            # Chains (A-->B-->C) are unrolled pair by pair: after each
            # edge the remainder restarts at the destination id.
            while True:
                m = _EDGE_LABEL_RE.search(rest)
                if m:
                    edges.append((m.group(1), m.group(3),
                                  m.group(2).strip()))
                    rest = m.group(3) + rest[m.end():]
                    continue
                m = _EDGE_RE.search(rest)
                if not m:
                    break
                label = (m.group(3) or "").strip("|")
                edges.append((m.group(1), m.group(4), label))
                rest = m.group(4) + rest[m.end():]
    for a, b, _ in edges:
        labels.setdefault(a, a)
        labels.setdefault(b, b)
    return labels, edges


def _layers(labels: dict, edges: list) -> list[list[str]]:
    incoming: dict[str, int] = {n: 0 for n in labels}
    children: dict[str, list] = {n: [] for n in labels}
    for a, b, _ in edges:
        if b not in incoming:
            incoming[b] = 0
            children[b] = []
        incoming[b] += 1
        children.setdefault(a, []).append(b)
    depth: dict[str, int] = {}

    def visit(node: str, stack: tuple = ()) -> int:
        if node in depth:
            return depth[node]
        if node in stack:  # cycle: stop unrolling
            return 0
        best = 0
        for a, b, _ in edges:
            if b == node:
                best = max(best, visit(a, stack + (node,)) + 1)
        depth[node] = best
        return best

    for n in labels:
        visit(n)
    maxd = max(depth.values(), default=0)
    layers: list[list[str]] = [[] for _ in range(maxd + 1)]
    for n, d in sorted(depth.items()):
        layers[d].append(n)
    return [layer for layer in layers if layer]


class _Canvas:
    def __init__(self) -> None:
        self.rows: list[list[str]] = []

    def put(self, x: int, y: int, ch: str) -> None:
        while len(self.rows) <= y:
            self.rows.append([])
        row = self.rows[y]
        while len(row) <= x:
            row.append(" ")
        if row[x] == " " or ch != " ":
            if row[x] not in (" ",) and ch in ("|", "-", "+") \
                    and row[x] in ("|", "-", "+", "v", ">"):
                row[x] = "+"
            else:
                row[x] = ch

    def text(self, x: int, y: int, s: str) -> None:
        for i, ch in enumerate(s):
            self.put(x + i, y, ch)

    def lines(self) -> list[str]:
        return ["".join(r).rstrip() for r in self.rows]


def _render_flowchart(source: str, width: int) -> str:
    labels, edges = _parse_flowchart(source)
    if not labels:
        return "(empty diagram)"
    layers = _layers(labels, edges)
    widths = {n: len(labels[n]) + 4 for n in labels}
    pos: dict[str, tuple[int, int]] = {}
    y = 0
    for layer in layers:
        x = 0
        for n in layer:
            pos[n] = (x, y)
            x += widths[n] + 5
        y += 5
    cv = _Canvas()
    for n, (x, y0) in pos.items():
        w = widths[n]
        cv.text(x, y0, "+" + "-" * (w - 2) + "+")
        cv.text(x, y0 + 1, "| " + labels[n].ljust(w - 4) + " |")
        cv.text(x, y0 + 2, "+" + "-" * (w - 2) + "+")
    for a, b, label in edges:
        if a not in pos or b not in pos:
            continue
        ax = pos[a][0] + widths[a] // 2
        ay = pos[a][1] + 3
        bx = pos[b][0] + widths[b] // 2
        by = pos[b][1]
        if ay >= by:
            continue
        cv.put(ax, ay, "|")
        mid = ay + 1
        if ax == bx:
            for yy in range(ay + 1, by):
                cv.put(ax, yy, "|")
        else:
            cv.put(ax, mid, "+")
            step = 1 if bx > ax else -1
            for xx in range(ax + step, bx, step):
                cv.put(xx, mid, "-")
            cv.put(bx, mid, "+")
            for yy in range(mid + 1, by):
                cv.put(bx, yy, "|")
        cv.put(bx, by - 1, "v")
        if label:
            cv.text(min(ax, bx) + 1, mid, f" {label[:14]}")
    out = [ln[:width] for ln in cv.lines()]
    while out and not out[-1].strip():
        out.pop()
    return "\n".join(out) if out else "(empty diagram)"


# -- sequence diagram ------------------------------------------------------

def _parse_sequence(source: str):
    """Return ``(participants, events)`` preserving declaration order."""
    participants: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(pid: str, name: str | None = None) -> None:
        if pid not in seen:
            seen.add(pid)
            participants.append((pid, name or pid))

    events: list[tuple] = []
    for raw in (source or "").splitlines()[1:]:
        line = raw.strip()
        if not line or line.startswith("%%"):
            continue
        m = _PART_RE.match(line)
        if m:
            add(m.group(1), (m.group(2) or "").strip() or None)
            continue
        if _SKIP_LINE_RE.match(line):
            continue
        low = line.lower()
        if low.startswith(("loop ", "alt ", "opt ", "par ",
                           "rect ", "critical ", "break ")):
            events.append(("section", line))
            continue
        if low in ("end", "else"):
            events.append(("section", line))
            continue
        m = _NOTE_RE.match(line)
        if m:
            scope = [p.strip() for p in m.group(2).split(",")]
            for p in scope:
                add(p)
            events.append(("note", m.group(1), scope, m.group(3)))
            continue
        m = _MSG_RE.match(line)
        if m:
            add(m.group(1))
            add(m.group(3))
            events.append(("msg", m.group(1), m.group(2), m.group(3),
                           m.group(4)))
    return participants, events


def _render_sequence(source: str, width: int) -> str:
    participants, events = _parse_sequence(source)
    if not participants:
        return "(empty diagram)"
    col_w = max([len(name) + 4 for _, name in participants] + [14])
    total = col_w * len(participants)
    while total > width and col_w > 10:
        col_w -= 2
        total = col_w * len(participants)
    cx = {pid: i * col_w + col_w // 2 for i, (pid, _) in
          enumerate(participants)}
    out: list[str] = []
    header = "".join(
        ("[ " + name[:col_w - 4] + " ]").center(col_w)
        for _, name in participants)[:width]
    out.append(header)
    out.append("".join("|".center(col_w) for _ in participants)[:width])
    n = 0
    for ev in events:
        if ev[0] == "section":
            out.append(("-- " + ev[1] + " ").ljust(width, "-")[:width])
            out.append("".join("|".center(col_w)
                               for _ in participants)[:width])
            continue
        if ev[0] == "note":
            _, _, scope, text = ev
            idx = [i for i, (pid, _) in enumerate(participants)
                   if pid in scope]
            if not idx:
                continue
            x0 = min(idx) * col_w + 1
            note = f"Note ({'/'.join(scope)}): {text}"
            out.append((" " * x0 + note)[:width])
            out.append("".join("|".center(col_w)
                               for _ in participants)[:width])
            continue
        _, src, _arrow, dst, text = ev
        n += 1
        if src not in cx or dst not in cx:
            continue
        label = f"{n}. {text}".strip()
        x0, x1 = cx[src], cx[dst]
        if x0 == x1:
            out.append(" " * x0 + f"| {label}"[:width - x0])
        else:
            lo, hi = min(x0, x1), max(x0, x1)
            line = [" "] * (hi + 2)
            for i in range(lo + 1, hi):
                line[i] = "-"
            line[hi if x1 > x0 else lo] = ">" if x1 > x0 else "<"
            out.append(("".join(line) + f"  {label}")[:width])
        out.append("".join("|".center(col_w) for _ in participants)[:width])
    return "\n".join(out)
