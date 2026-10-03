"""Dossier Markdown -> PDF via pandoc + LaTeX, with rendered Mermaid figures.

Print contract (matches the sample ``AGI_Research_Labs_Data_Safety_Investigation.pdf``):
pandoc drives a LaTeX engine to produce an A4 report with a table of contents
and the full dossier body. Nothing here re-scores or rewrites findings — it is
a faithful print of the stored dossier Markdown (the same payload
``dossier.dossier_markdown`` serves).

Mermaid fences are rendered to PNG through the app's existing renderer
(``mermaid_png``) and rewritten to image links so the PDF shows figures, not
source text. A diagram that cannot render stays as a fenced code block, so the
export never loses content.

Failure is explicit: if ``pandoc`` or a LaTeX engine is absent, ``build_pdf``
raises ``RuntimeError`` and the API turns it into a 501 (same spirit as the
reportlab export).
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile

#: Overridable so an image can pin a specific binary/engine.
PANDOC_BIN = os.environ.get("AKM_PANDOC_BIN", "pandoc").strip() or "pandoc"
PDF_ENGINE = os.environ.get("AKM_PDF_ENGINE", "pdflatex").strip() or "pdflatex"
PANDOC_TIMEOUT_S = float(os.environ.get("AKM_PANDOC_TIMEOUT_S", "120"))
#: Second engine to try when the first fails on Unicode/symbols.
FALLBACK_ENGINE = os.environ.get("AKM_PDF_ENGINE_FALLBACK", "xelatex").strip()

# Characters pdflatex's UTF-8/T1 path does not cover; mapped to safe ASCII so a
# print never fails on a decorative glyph. Em-dash / curly quotes are left for
# pandoc (it handles them).
_SANITIZE = {
    "→": "->", "←": "<-", "⇒": "=>", "⇐": "<=", "↔": "<->",
    "≤": "<=", "≥": ">=", "≠": "!=", "×": "x", "•": "-", "·": "-",
    "⚠": "!", "✓": "[ok]", "✗": "[x]", "✔": "[ok]", "✘": "[x]",
    "⟳": "(refresh)", "█": "#", "░": "-", "…": "...", "⛁": "",
}

_MERMAID_HEAD = re.compile(
    r"^(flowchart|graph|sequenceDiagram|classDiagram|stateDiagram|erDiagram|"
    r"journey|gantt|pie|mindmap|timeline|gitGraph|quadrantChart|"
    r"C4Context|sankey|block)", re.I)


def _which(binary: str) -> str | None:
    return shutil.which(binary) if binary else None


def available() -> dict:
    """What the environment can do. Never raises."""
    pandoc = _which(PANDOC_BIN)
    engines = [e for e in (PDF_ENGINE, FALLBACK_ENGINE) if _which(e)]
    return {"pandoc": pandoc, "engines": engines,
            "ok": bool(pandoc and engines)}


def _require() -> str:
    env = available()
    if not env["pandoc"]:
        raise RuntimeError(
            "PDF export needs pandoc (apt-get install pandoc); not found on PATH")
    if not env["engines"]:
        raise RuntimeError(
            "PDF export needs a LaTeX engine (pdflatex/xelatex; apt-get install "
            "texlive-latex-base texlive-latex-recommended texlive-fonts-recommended)")
    return env["pandoc"]


# --------------------------------------------------------------------------
# Markdown normalization
# --------------------------------------------------------------------------

def preprocess_markdown(md: str) -> str:
    """Make stored dossier Markdown safe for pandoc/LaTeX.

    Removes HTML comments and raw tags pandoc rejects in LaTeX output, keeps
    ``<br>`` as a line break, strips emoji/astral-plane characters, and maps a
    few symbols pdflatex cannot print. Tables and headings are left untouched.
    """
    text = md or ""
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.I)
    # Drop remaining raw HTML tags but keep their text content.
    text = re.sub(r"</?[a-zA-Z][^>]*>", "", text)
    out: list[str] = []
    for ch in text:
        if ord(ch) > 0xFFFF:            # emoji / astral plane
            continue
        if ch in _SANITIZE:
            out.append(_SANITIZE[ch])
            continue
        out.append(ch)
    cleaned = "".join(out)
    cleaned = re.sub(r"[ \t]+\n", "\n", cleaned)
    return cleaned


def _hash(source: str) -> str:
    return hashlib.sha1(source.encode("utf-8")).hexdigest()


def _fences(md: str):
    """Yield (start, end, lang, caption, source) for every fenced block."""
    lines = (md or "").splitlines()
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        s = line.strip()
        if s.startswith("```"):
            info = s[3:].strip().split()
            lang = info[0].lower() if info else ""
            cap = " ".join(info[1:]).strip() if len(info) > 1 else ""
            start = i
            body: list[str] = []
            i += 1
            while i < n and not lines[i].strip().startswith("```"):
                body.append(lines[i])
                i += 1
            end = i                      # index of closing fence (or last)
            yield start, end, lang, cap, "\n".join(body).strip()
        i += 1


def _caption_for(md: str, start: int, fallback: str) -> str:
    """Nearest preceding heading or 'Diagram —' line, else a hash caption."""
    lines = md.splitlines()
    for j in range(start - 1, max(-1, start - 6), -1):
        t = lines[j].strip()
        if not t:
            continue
        if t.startswith("#"):
            return t.lstrip("# ").strip()[:120]
        if t.lower().startswith("diagram") or t.lower().startswith("figure"):
            return t.strip("*_ ")[:120]
        break
    return fallback


def render_mermaid_figures(md: str, workdir: str) -> tuple[str, int, int]:
    """Render every mermaid fence to ``workdir/images/<hash>.png`` and rewrite
    the fence to ``![caption](images/<hash>.png)``.

    Returns ``(rewritten_md, rendered, fallback)``. Unrenderable fences are
    left as fenced code so the PDF keeps the source instead of a blank box.
    """
    from . import mermaid_png

    lines = md.splitlines()
    sources: list[str] = []
    for start, end, lang, cap, src in _fences(md):
        if lang == "mermaid" or (not lang and _MERMAID_HEAD.match(src or "")):
            if src and src not in sources:
                sources.append(src)
    png_by_src: dict[str, bytes] = {}
    if sources:
        try:
            png_by_src = mermaid_png.render_sources(sources)
        except Exception:
            png_by_src = {}

    images_dir = os.path.join(workdir, "images")
    os.makedirs(images_dir, exist_ok=True)
    rendered = fallback = 0
    out_lines: list[str] = []
    idx = 0
    n = len(lines)
    while idx < n:
        line = lines[idx]
        s = line.strip()
        if not s.startswith("```"):
            out_lines.append(line)
            idx += 1
            continue
        info = s[3:].strip().split()
        lang = info[0].lower() if info else ""
        cap = " ".join(info[1:]).strip() if len(info) > 1 else ""
        body: list[str] = []
        j = idx + 1
        while j < n and not lines[j].strip().startswith("```"):
            body.append(lines[j])
            j += 1
        src = "\n".join(body).strip()
        is_mermaid = lang == "mermaid" or (not lang and bool(_MERMAID_HEAD.match(src or "")))
        blob = png_by_src.get(src) if is_mermaid else None
        if is_mermaid and blob:
            h = _hash(src)
            with open(os.path.join(images_dir, h + ".png"), "wb") as fh:
                fh.write(blob)
            caption = cap or _caption_for(md, idx, f"Diagram ({h[:8]})")
            out_lines.append(f"![Figure: {caption}](images/{h}.png)")
            out_lines.append("")
            rendered += 1
        else:
            if is_mermaid:
                fallback += 1
            # keep the fenced block (verbatim) so nothing is lost
            out_lines.append(line)
            out_lines.extend(body)
            out_lines.append(lines[j] if j < n else "```")
        idx = j + 1
    return "\n".join(out_lines), rendered, fallback


# --------------------------------------------------------------------------
# pandoc driver
# --------------------------------------------------------------------------

_HEADER_TEX = r"""
\usepackage{longtable}
\usepackage{booktabs}
\usepackage{graphicx}
\usepackage{url}
\setkeys{Gin}{width=\linewidth,keepaspectratio}
\setlength{\parskip}{0.4em}
"""


def _run_pandoc(pandoc: str, md_path: str, out_path: str, engine: str,
                workdir: str) -> subprocess.CompletedProcess:
    args = [
        pandoc, md_path, "-o", out_path,
        "--pdf-engine", engine,
        "--toc", "--toc-depth=2",
        "-V", "geometry:a4paper,margin=25mm",
        "-V", "fontsize=11pt",
        "-V", "colorlinks=true",
        "--from", "markdown+pipe_tables+fenced_code_blocks+raw_html",
        "--highlight-style=tango",
        "--resource-path", f"{workdir}{os.pathsep}{workdir}/images",
        "-H", os.path.join(workdir, "header.tex"),
    ]
    return subprocess.run(args, capture_output=True, text=True,
                          timeout=PANDOC_TIMEOUT_S)


def _build_with(pandoc: str, engine: str, md: str, tmp: str) -> bytes:
    rewritten, rendered, fallback = render_mermaid_figures(
        preprocess_markdown(md), tmp)
    with open(os.path.join(tmp, "header.tex"), "w", encoding="utf-8") as fh:
        fh.write(_HEADER_TEX)
    md_path = os.path.join(tmp, "dossier.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(rewritten)
    out_path = os.path.join(tmp, "dossier.pdf")
    proc = _run_pandoc(pandoc, md_path, out_path, engine, tmp)
    if proc.returncode != 0 or not os.path.isfile(out_path):
        raise RuntimeError(
            f"pandoc/{engine} failed: {(proc.stderr or '')[-600:]}")
    with open(out_path, "rb") as fh:
        return fh.read()


def build_pdf(md: str, title: str = "Investigation dossier",
              workdir: str | None = None) -> bytes:
    """Render dossier Markdown to PDF bytes via pandoc + LaTeX.

    Tries the primary engine (pdflatex, matching the sample's pdfTeX stack),
    then the fallback (xelatex/lualatex) if the first fails on Unicode or
    symbols. Raises ``RuntimeError`` when pandoc/LaTeX are missing or every
    engine fails.
    """
    pandoc = _require()
    engines = available()["engines"]
    last = None
    for engine in engines:
        try:
            if workdir:
                return _build_with(pandoc, engine, md, workdir)
            with tempfile.TemporaryDirectory(prefix="dossier_pdf_") as tmp:
                return _build_with(pandoc, engine, md, tmp)
        except Exception as exc:  # noqa: BLE001
            last = str(exc)
    raise RuntimeError(f"pandoc PDF failed on all engines: {last}")


def pdf_stats(md: str) -> dict:
    """Rendering telemetry without producing a PDF (for metadata/stats)."""
    sources = []
    for start, end, lang, cap, src in _fences(md or ""):
        if (lang == "mermaid" or (not lang and _MERMAID_HEAD.match(src or ""))) and src:
            if src not in sources:
                sources.append(src)
    return {"mermaid_sources": len(sources)}