"""Render Mermaid diagram sources to PNG images with headless Chromium.

Only stdlib plus PIL. One Chromium launch renders a whole batch of diagrams
on a single page; the page reports each figure's bounding box and PIL crops
the full-page screenshot. Rendered files are cached on disk keyed by source
hash, so repeat PDF exports never relaunch the browser. Anything that fails
(no Chromium binary, a launch timeout, a diagram that does not parse) is
skipped, and the caller keeps its source-text fallback: a missing picture
must never break the export.
"""
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tempfile

BATCH_SIZE = 6
SCALE = 2
PAGE_W = 1100
PAGE_H = 8000
PAD_PX = 10
VIRTUAL_BUDGET_MS = 20000
LAUNCH_TIMEOUT_S = 120

_MERMAID_FIRST_LINE_RE = re.compile(
    r"^(graph|flowchart|sequenceDiagram|classDiagram|stateDiagram|erDiagram"
    r"|journey|gantt|pie|mindmap|timeline|quadrantChart|C4Context)\b",
    re.IGNORECASE)
_BOXES_RE = re.compile(r'<pre id="mm-boxes">(.*?)</pre>', re.S)

_MERMAID_CDN = ("https://cdn.jsdelivr.net/npm/mermaid@10.9.4/"
                "dist/mermaid.min.js")


def _chromium_bin() -> str:
    """The browser, or "" when PDF export must fall back to source text."""
    forced = (os.environ.get("AKM_CHROMIUM_BIN") or "").strip()
    if forced:
        return forced if os.path.isfile(forced) else ""
    for name in ("chromium", "chromium-browser", "google-chrome"):
        found = shutil.which(name)
        if found:
            return found
    return ""


def _mermaid_js() -> str:
    """A ``file://`` URL for the vendored renderer, else the pinned CDN."""
    forced = (os.environ.get("AKM_MERMAID_JS") or "").strip()
    if forced and os.path.isfile(forced):
        return "file://" + forced
    here = os.path.dirname(os.path.abspath(__file__))
    vendored = os.path.join(here, "..", "static", "vendor", "mermaid.min.js")
    if os.path.isfile(vendored):
        return "file://" + os.path.abspath(vendored)
    return _MERMAID_CDN


def _cache_dir() -> str:
    forced = (os.environ.get("AKM_MERMAID_CACHE") or "").strip()
    if forced:
        path = forced
    else:
        try:
            from .database import DATA_DIR
        except Exception:
            DATA_DIR = os.path.join(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))), "data")
        path = os.path.join(DATA_DIR, "mermaid_png")
    os.makedirs(path, exist_ok=True)
    return path


def _key(source: str) -> str:
    return hashlib.sha1(source.encode("utf-8")).hexdigest()


def collect_sources(markdown_text: str,
                    skip_labels: set[str] | None = None) -> list[str]:
    """Every mermaid fence the PDF would otherwise print as source text.

    ``skip_labels`` are figure keys the exporter already draws as vectors
    (``dataflow``/``workflow``/``threat_paths``): they need no picture.
    Order-preserving and deduplicated, so one browser batch covers the
    whole document.
    """
    skip = skip_labels or set()
    out: list[str] = []
    seen: set[str] = set()
    in_fence = False
    lang = ""
    fig = ""
    code: list[str] = []
    for raw in (markdown_text or "").splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if stripped.startswith("```"):
            if not in_fence:
                info = stripped[3:].strip().split()
                lang = info[0].lower() if info else ""
                fig = info[1] if len(info) > 1 and lang == "mermaid" else ""
                code = []
            else:
                if fig not in skip and code:
                    head = next((l.strip() for l in code if l.strip()), "")
                    if lang == "mermaid" or _MERMAID_FIRST_LINE_RE.match(head):
                        src = "\n".join(code).strip()
                        if src and src not in seen:
                            seen.add(src)
                            out.append(src)
                lang, fig, code = "", "", []
            in_fence = not in_fence
            continue
        if in_fence:
            code.append(line)
    return out


def _page_html(sources: list[str], mermaid_js: str) -> str:
    return f"""<!doctype html><html><head><meta charset="utf-8">
<style>body{{margin:0;background:#fff}}.fig{{margin:0 0 32px 0}}</style>
</head><body><div id="host"></div>
<script src="{mermaid_js}"></script>
<script>
window.mermaid.initialize({{startOnLoad:false, securityLevel:'strict'}});
var SOURCES = {json.dumps(sources)};
SOURCES.forEach(function(src, i){{
  var d = document.createElement('div');
  d.className = 'fig'; d.id = 'fig' + i;
  var pre = document.createElement('pre');
  pre.className = 'mermaid'; pre.textContent = src;
  d.appendChild(pre);
  document.getElementById('host').appendChild(d);
}});
window.mermaid.run({{nodes: document.querySelectorAll('.mermaid'),
                    suppressErrors:false}}).then(function(){{
  var boxes = [];
  document.querySelectorAll('.fig').forEach(function(d, i){{
    var svg = d.querySelector('svg');
    var r = (svg || d).getBoundingClientRect();
    boxes.push({{i:i, ok:!!svg, x:r.x, y:r.y, w:r.width, h:r.height}});
  }});
  var p = document.createElement('pre'); p.id = 'mm-boxes';
  p.textContent = JSON.stringify(boxes);
  document.body.appendChild(p);
  document.title = 'MERMAID-DONE';
}}).catch(function(e){{ document.title = 'MERMAID-FAIL ' + e; }});
</script></body></html>"""


def _launch(binary: str, page: str, out_png: str, dump: bool) -> str:
    """One headless run: screenshot, or DOM dump carrying the figure boxes."""
    cmd = [binary, "--headless=new", "--no-sandbox", "--disable-gpu",
           "--disable-dev-shm-usage", "--hide-scrollbars",
           f"--force-device-scale-factor={SCALE}",
           f"--window-size={PAGE_W},{PAGE_H}",
           f"--virtual-time-budget={VIRTUAL_BUDGET_MS}", page]
    if dump:
        cmd.append("--dump-dom")
    else:
        cmd.append(f"--screenshot={out_png}")
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          timeout=LAUNCH_TIMEOUT_S)
    return proc.stdout if dump else ""


def _render_batch(binary: str, mermaid_js: str,
                  sources: list[str]) -> dict[str, bytes]:
    """Screenshot one page of diagrams and crop each figure out of it."""
    from PIL import Image
    got: dict[str, bytes] = {}
    with tempfile.TemporaryDirectory(prefix="mmrender") as tmp:
        page = os.path.join(tmp, "figs.html")
        with open(page, "w", encoding="utf-8") as fh:
            fh.write(_page_html(sources, mermaid_js))
        shot = os.path.join(tmp, "shot.png")
        try:
            _launch(binary, f"file://{page}", shot, dump=False)
            dom = _launch(binary, f"file://{page}", shot, dump=True)
        except Exception:
            return got
        if not os.path.isfile(shot):
            return got
        match = _BOXES_RE.search(dom or "")
        if not match:
            return got
        try:
            boxes = json.loads(match.group(1))
        except Exception:
            return got
        try:
            im = Image.open(shot)
            im.load()
        except Exception:
            return got
        pad = PAD_PX * SCALE
        for box, src in zip(boxes, sources):
            try:
                if not box.get("ok"):
                    continue
                x0 = max(0, int(box["x"] * SCALE) - pad)
                y0 = max(0, int(box["y"] * SCALE) - pad)
                x1 = min(im.width, int((box["x"] + box["w"]) * SCALE) + pad)
                y1 = min(im.height, int((box["y"] + box["h"]) * SCALE) + pad)
                if x1 - x0 < 8 or y1 - y0 < 8:
                    continue
                crop = im.crop((x0, y0, x1, y1))
                buf = io.BytesIO()
                crop.save(buf, format="PNG")
                got[src] = buf.getvalue()
            except Exception:
                continue
    return got


def render_sources(sources: list[str]) -> dict[str, bytes]:
    """PNG bytes keyed by exact source, from disk cache or one browser batch.

    Sources that cannot be rendered are simply absent from the result: the
    caller prints those as source text instead.
    """
    ordered: list[str] = []
    seen: set[str] = set()
    for src in sources or []:
        if src and src not in seen:
            seen.add(src)
            ordered.append(src)
    if not ordered:
        return {}
    try:
        cache = _cache_dir()
    except Exception:
        cache = ""
    got: dict[str, bytes] = {}
    missing: list[str] = []
    for src in ordered:
        blob: bytes | None = None
        if cache:
            path = os.path.join(cache, _key(src) + ".png")
            try:
                if os.path.isfile(path):
                    with open(path, "rb") as fh:
                        blob = fh.read()
            except Exception:
                blob = None
        if blob:
            got[src] = blob
        else:
            missing.append(src)
    if not missing:
        return got
    binary = _chromium_bin()
    if not binary:
        return got
    try:
        mermaid_js = _mermaid_js()
    except Exception:
        return got
    for start in range(0, len(missing), BATCH_SIZE):
        try:
            fresh = _render_batch(binary, mermaid_js,
                                  missing[start:start + BATCH_SIZE])
        except Exception:
            continue
        for src, blob in fresh.items():
            got[src] = blob
            if cache:
                try:
                    with open(os.path.join(cache, _key(src) + ".png"),
                              "wb") as fh:
                        fh.write(blob)
                except Exception:
                    pass
    return got
