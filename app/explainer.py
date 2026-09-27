"""Agentic explainer: research a question on the web, then compose an
illustrated explanation (sections + images + key points + sources).

Runs in a background thread; the GUI polls the Explanation record.
"""
import json
import re
import contextvars
import io
import threading
import time
import traceback
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import httpx
from bs4 import BeautifulSoup

from .database import SessionLocal
from .models import Explanation, Artifact, CorpusPage, Investigation, Relationship
from . import grounding
from . import llm
from .search import search_web, UA

MAX_PAGES = 6
PAGE_TIMEOUT = 15
TEXT_CAP = 5000


def _tok(s):
    return set(re.findall(r"[a-z0-9]{3,}", (s or "").lower())) - set(
        {"the", "and", "for", "how", "what", "does", "was", "are", "you",
         "this", "with", "that", "from", "who", "why", "when", "which",
         "have", "has", "its", "not", "but", "all", "can", "will",
         "about", "your", "into"})


def _jaccard(a, b):
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def _collect_graph_context(db, inv_id: int, question: str, limit: int = 8) -> list:
    """Top artifacts in the investigation, ranked by tag/title overlap with question."""
    qw = _tok(question)
    ranked = []
    for a in db.query(Artifact).filter(Artifact.investigation_id == inv_id).all():
        score = _jaccard(qw, _tok(a.tags))
        score += 0.3 * _jaccard(qw, _tok(a.title))
        if score > 0:
            ranked.append((score, a))
    ranked.sort(key=lambda x: x[0], reverse=True)
    return [{"id": a.id, "title": a.title, "type": a.artifact_type,
             "tags": a.tags or "", "text": (a.description or a.content or "")[:900]}
            for _, a in ranked[:limit]]


def _gap_check(question: str, graph_brief: list) -> dict:
    """LLM triage: does the existing graph already cover the question?"""
    if not graph_brief:
        return {"coverage": "none", "gaps": [], "needs_web": True,
                "followup_queries": [], "known_facts": []}
    brief = "\n".join(
        f"- [#{a['id']}] [{a['type']}] {a['title']}  tags: {a['tags']}\n  {a['text'][:300]}"
        for a in graph_brief)
    try:
        r = llm.chat_json([
            {"role": "system",
             "content": "Knowledge-gap estimator. Judge whether the provided artifacts "
                          "already answer the question. Reply JSON only."},
            {"role": "user",
             "content": f"Question: {question}\n\nExisting knowledge (from this project's "
                          f"knowledge graph):\n{brief}\n\nReply JSON:\n"
                          "{\"coverage\": \"full|partial|none\", "
                          "\"known_facts\": [str], \"gaps\": [str], "
                          "\"needs_web\": bool, \"followup_queries\": [str] (max 2, only if "
                          "needs_web)}"}],
            max_tokens=700)
        r.setdefault("needs_web", True)
        r.setdefault("gaps", [])
        r.setdefault("followup_queries", [])
        return r
    except Exception:
        return {"coverage": "none", "gaps": [], "needs_web": True,
                "followup_queries": [], "known_facts": []}


def _graph_pages(artifacts: list) -> list:
    out = []
    for a in artifacts:
        if (a["text"] or "").strip():
            out.append({"url": f"graph://artifact/{a['id']}", "title": a["title"],
                        "text": a["text"], "images": [], "graph_id": a["id"]})
    return out


def _artifact_candidates(db, inv_id: int, limit: int = 10) -> list:
    """The investigation's own artifacts as attachable items: most relevant
    first. Fail-open (empty list) so a DB hiccup never breaks composition."""
    try:
        rows = (db.query(Artifact)
                .filter(Artifact.investigation_id == inv_id)
                .order_by(Artifact.relevance.desc().nulls_last(),
                          Artifact.id.desc())
                .limit(limit).all())
        return [{"id": r.id, "title": r.title or f"artifact {r.id}",
                 "url": r.url or "", "kind": r.artifact_type or "link"}
                for r in rows]
    except Exception:
        return []


def _abs_url(base: str, src: str) -> str:
    try:
        u = urllib.parse.urljoin(base, (src or "").strip())
        if u.startswith("http://") or u.startswith("https://"):
            return u.split("#")[0]
    except Exception:
        pass
    return ""


# Documents worth attaching, not just reading: presentations, reports, papers.
_DOC_EXTS = {"pdf": "pdf", "pptx": "slides", "ppt": "slides",
             "docx": "doc", "doc": "doc", "txt": "text"}
_DOC_MIMES = {"application/pdf": "pdf",
              "application/vnd.ms-powerpoint": "slides",
              "application/vnd.openxmlformats-officedocument.presentationml.presentation": "slides",
              "application/msword": "doc",
              "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "doc",
              "text/plain": "text"}
_DOC_MAX_BYTES = 15 * 1024 * 1024
_DOC_MAX_PAGES = 15


def _doc_kind(url: str, content_type: str = "") -> str:
    """Classify a URL as an attachable document ('', 'pdf', 'slides', 'doc',
    'text'). Extension first (works before downloading), MIME as backup."""
    try:
        path = urllib.parse.urlparse(url or "").path.lower()
        ext = path.rsplit(".", 1)[-1] if "." in path.rsplit("/", 1)[-1] else ""
        if ext in _DOC_EXTS:
            return _DOC_EXTS[ext]
    except Exception:
        pass
    ctype = (content_type or "").split(";")[0].strip().lower()
    return _DOC_MIMES.get(ctype, "")


def _pretty_doc_title(url: str, hint: str = "") -> str:
    if hint and hint.strip():
        return hint.strip()[:200]
    try:
        stem = urllib.parse.unquote(
            urllib.parse.urlparse(url).path.rsplit("/", 1)[-1])
        stem = re.sub(r"\.(pdf|pptx?|docx?|txt)$", "", stem, flags=re.I)
        stem = re.sub(r"[-_+]+", " ", stem).strip()
        if stem:
            return stem[:200]
    except Exception:
        pass
    return url


def _extract_pptx_text(content: bytes, limit_chars: int = TEXT_CAP) -> tuple:
    """Slide text from a .pptx with stdlib only (a pptx is a zip of XML;
    slide copy lives in <a:t> nodes). Returns (text, slide_count)."""
    import zipfile
    import xml.etree.ElementTree as ET
    try:
        slides = []
        with zipfile.ZipFile(io.BytesIO(content)) as z:
            names = sorted(n for n in z.namelist()
                           if re.fullmatch(r"ppt/slides/slide\d+\.xml", n))
            for name in names:
                try:
                    root = ET.fromstring(z.read(name))
                except ET.ParseError:
                    continue
                texts = [t.text for t in root.iter()
                         if t.tag.endswith("}t") and (t.text or "").strip()]
                if texts:
                    slides.append("\n".join(texts))
        text = re.sub(r"\s+", " ", "\n\n".join(slides))[:limit_chars]
        return text, len(slides)
    except Exception:
        return "", 0


def _fetch_document(url: str, kind: str, content: bytes,
                    hint_title: str = "") -> dict:
    """Fetch result for a document URL. Text is extracted when a parser exists
    (PDF via pypdf, PPTX via stdlib); anything else attaches as metadata-only
    so the user can still open it. Never raises: worst case is a link."""
    title = _pretty_doc_title(url, hint_title)
    text, npages = "", None
    if content and len(content) <= _DOC_MAX_BYTES:
        try:
            if kind == "pdf":
                from pypdf import PdfReader
                reader = PdfReader(io.BytesIO(content))
                npages = len(reader.pages)
                parts = []
                for page in reader.pages[:_DOC_MAX_PAGES]:
                    try:
                        parts.append(page.extract_text() or "")
                    except Exception:
                        continue
                text = re.sub(r"\s+", " ", "\n\n".join(parts))[:TEXT_CAP]
            elif kind == "slides" and url.lower().endswith(".pptx"):
                text, npages = _extract_pptx_text(content)
        except Exception:
            text, npages = "", None
    return {"url": url, "title": title, "text": text, "images": [],
            "published": None, "doc_kind": kind, "doc_pages": npages}


def _fetch_page(url: str, hint_title: str = "") -> dict | None:
    try:
        with httpx.Client(timeout=PAGE_TIMEOUT, headers=UA, follow_redirects=True) as client:
            r = client.get(url, headers={"Accept": "text/html,application/pdf;q=0.9,*/*;q=0.5"})
            if r.status_code != 200:
                return None
            ctype = r.headers.get("content-type") or ""
            kind = _doc_kind(url, ctype)
            if kind:
                return _fetch_document(url, kind, r.content, hint_title)
            if "html" not in ctype:
                return None
            soup = BeautifulSoup(r.text[:500000], "html.parser")
    except Exception:
        return None
    for tag in soup(["script", "style", "nav", "footer", "header", "aside", "form"]):
        tag.decompose()
    title = (soup.title.get_text(strip=True) if soup.title else "")[:300]
    og = soup.find("meta", property="og:image")
    og_image = _abs_url(url, og.get("content") if og else "")
    paras = [p.get_text(" ", strip=True) for p in soup.find_all("p")]
    text = re.sub(r"\s+", " ", "\n".join(p for p in paras if len(p) > 40))[:TEXT_CAP]
    images = []
    if og_image:
        images.append({"src": og_image, "alt": title, "hero": True})
    for img in soup.find_all("img"):
        src = _abs_url(url, img.get("src") or img.get("data-src") or "")
        if not src or src.lower().endswith((".svg", ".gif", ".ico")):
            continue
        if any(bad in src.lower() for bad in ("logo", "icon", "avatar", "sprite",
                                              "pixel", "tracking", "badge")):
            continue
        alt = (img.get("alt") or "")[:200]
        # Context the filename filters cannot see: figcaption, or the nearest
        # heading / paragraph. A hero stock photo on an SEO page has none of
        # these pointing at the article topic, which is exactly what lets the
        # relevance gate below tell it apart from a real figure.
        caption = ""
        fig = img.find_parent("figure")
        if fig is not None:
            cap = fig.find("figcaption")
            if cap is not None:
                caption = cap.get_text(" ", strip=True)[:300]
        if not caption:
            prev = img.find_previous(["h1", "h2", "h3", "p"])
            if prev is not None:
                caption = prev.get_text(" ", strip=True)[:300]
        if all(i["src"] != src for i in images):
            images.append({"src": src, "alt": alt, "caption": caption,
                           "hero": False})
        if len(images) >= 6:
            break
    return {"url": url, "title": title or url, "text": text, "images": images,
            "published": _page_date(soup, text)}


def _page_date(soup, text: str) -> str | None:
    """Best-effort publication date: meta tags, <time> elements, or an ISO-ish date
    found early in the article text. Returns 'YYYY-MM-DD' or None."""
    cands = []
    for tag in ("meta[property='article:published_time']", "meta[itemprop='datePublished']",
                "meta[name='date']", "meta[name='dc.date']", "meta[name='datePublished']",
                "meta[name='citation_date']", "meta[property='og:article:published_time']",
                "meta[property='article:modified_time']"):
        m = soup.select_one(tag)
        if m and m.get("content"):
            cands.append(m.get("content"))
    for t in soup.find_all("time"):
        if t.get("datetime"):
            cands.append(t.get("datetime"))
        elif t.get_text(strip=True):
            cands.append(t.get_text(strip=True))
    for c in cands:
        m = re.search(r"(20\d{2}-\d{2}-\d{2})|(20\d{2}/\d{1,2}/\d{1,2})", c)
        if m:
            d = m.group(1) or m.group(2)
            d = d.replace("/", "-")
            return d
    m = re.search(r"\b(20\d{2}-\d{2}-\d{2})\b", text[:2000])
    return m.group(1) if m else None


MIN_PAGE_CHARS = 300


def _research(question: str, max_pages: int = MAX_PAGES, trace: dict | None = None,
              extra_queries: list | None = None, preferred_domains: list | None = None,
              corpus: dict | None = None, expand_terms: list | None = None
              ) -> tuple[list, list, int]:
    """Returns (pages, image_candidates, document_candidates, corpus_hits_used)."""
    trace = trace if trace is not None else {}
    if extra_queries:
        queries = extra_queries[:3]
    else:
        try:
            plan = llm.chat_json([
                {"role": "system",
                 "content": "Search query planner. Reply JSON only."},
                {"role": "user",
                 "content": f"Question: {question}\nReply {{\"queries\": [str, str, str]}}: "
                            "3 diverse web search queries (2-6 words each) that would "
                            "find explanatory pages, docs, diagrams, or articles."}],
                max_tokens=512)
            queries = [q for q in (plan.get("queries") or []) if isinstance(q, str)][:3]
        except Exception:
            queries = []
    if expand_terms:
        qq = []
        for q in queries:
            qq.append(q)
            for t in expand_terms[:2]:
                qq.append(f"{q} {t}")
        queries = qq
    queries = [q for q in (queries or [question]) if q][:6]
    trace.setdefault("queries", []).append(queries)
    seen, hits = set(), []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=min(4, len(queries))) as pool:
        for batch in pool.map(search_web, queries):
            for h in batch:
                key = (h.get("url") or "").strip().lower()
                if key and key not in seen:
                    seen.add(key)
                    hits.append({**h, "query": queries[-1] if len(queries) == 1 else "multi"})
    # Preferred-domain pinning (#13): keep only domains the user pinned when any are set.
    if preferred_domains:
        prefs = [d.strip().lower() for d in preferred_domains if d.strip()]
        if prefs:
            keep = [h for h in hits
                    if any(_domain(h.get("url") or "").lower().endswith(d) or
                           _domain(h.get("url") or "").lower() == d for d in prefs)]
            if keep:
                hits = keep
            else:
                hits = hits[:3]  # fall back to top hits rather than returning nothing
    trace.setdefault("timings_ms", {})["search"] = int((time.time() - t0) * 1000)
    trace.setdefault("hits", []).extend({
        "url": h.get("url"), "title": h.get("title"), "domain": _domain(h.get("url")),
        "source": h.get("source"), "rank": h.get("rank"), "query": h.get("query"),
    } for h in hits[:30])
    pages, rejected = [], []
    cached = 0
    corpus = corpus or {}
    t0 = time.time()
    tried = [h["url"] for h in hits[:max_pages * 2]]
    results = []
    for url in tried:
        cache = corpus.get(url.lower()) or corpus.get(url)
        if cache and cache.get("text"):
            results.append({"kind": "cache", "url": url, "page": cache})
        else:
            results.append({"kind": "fetch", "url": url})
    to_fetch = [r["url"] for r in results if r["kind"] == "fetch"]
    hit_titles = {}
    for h in hits:
        hit_titles.setdefault((h.get("url") or "").lower(), h.get("title") or "")
    fetched_map = {}
    if to_fetch:
        with ThreadPoolExecutor(max_workers=6) as pool:
            jobs = [(u, hit_titles.get(u.lower(), "")) for u in to_fetch]
            for page in pool.map(lambda t: _fetch_page(*t), jobs):
                if page and page.get("url"):
                    fetched_map[page["url"].lower()] = page
    for r in results:
        if r["kind"] == "cache":
            page = dict(r["page"])
            page["cached"] = True
            cached += 1
            pages.append(page)
        else:
            page = fetched_map.get(r["url"].lower())
            if page:
                pages.append(page)
    kept = [p for p in pages if p.get("text") and len(p.get("text") or "") >= MIN_PAGE_CHARS]
    # Document attachments: every fetched PDF/deck/doc becomes a candidate,
    # even text-less ones (metadata-only still opens for the user). HTML pages
    # are already covered by the sources list, so they stay out of here.
    documents = []
    for p in pages:
        if p.get("doc_kind"):
            if all(d["url"] != p["url"] for d in documents):
                documents.append({"url": p["url"],
                                  "title": p.get("title") or p["url"],
                                  "kind": p["doc_kind"],
                                  "pages": p.get("doc_pages")})
            if len(documents) >= 10:
                break
    pages = kept[:max_pages]
    reject_urls = [u for u in tried if u.lower() not in {p["url"].lower() for p in pages}]
    trace.setdefault("timings_ms", {})["fetch"] = int((time.time() - t0) * 1000)
    trace.setdefault("fetched", []).extend({
        "url": page["url"], "title": page["title"], "kept": True,
        "reason": "document" if page.get("doc_kind") else "page",
        "chars": len(page["text"]), "images": len(page["images"]),
        "cached": bool(page.get("cached")),
    } for page in pages)
    trace.setdefault("fetched", []).extend({
        "url": u, "title": "", "kept": False, "reason": "unreadable",
        "chars": 0, "images": 0,
    } for u in reject_urls)
    trace.setdefault("documents", []).extend(
        {"url": d["url"], "title": d["title"], "kind": d["kind"]} for d in documents)
    images = []
    for p in pages:
        for img in p.get("images") or []:
            if all(i["src"] != img.get("src") for i in images):
                images.append({**img, "page": p.get("title", "")[:80], "page_url": p.get("url")})
            if len(images) >= 14:
                break
    return pages[:max_pages], images, documents, cached


MODES = {
    "explain": "ordinary explanation",
    "compare": "side-by-side comparison",
    "tutor": "Socratic tutorial with checkpoints",
    "critique": "adversarial critique of claims",
    "tldr": "very short summary",
    "glossary": "each section = one key term defined",
    "api_ref": "practical API/usage reference",
    "deep_dive": "in-depth technical deep dive",
}

AUDIENCE_HINTS = {
    "beginner": "Explain like a smart friend who is new to the topic; define jargon inline, "
               "use analogies, sequence prerequisites, avoid acronyms without expanding them.",
    "intermediate": "Assume comfortable technical literacy; move briskly, still define product-"
                    "or-field-specific jargon.",
    "advanced": "Assume deep domain knowledge; be precise and terse, focus on mechanisms, "
                "edge cases, and tradeoffs; no filler.",
}

DEPTH_PLAN = {
    "shallow": {"pages": 3, "sections": 3, "tokens": 2048,
                "instruction": "Keep it brief and high-signal."},
    "balanced": {"pages": 6, "sections": 5, "tokens": 4096,
                 "instruction": "Give a complete, well-structured account."},
    "deep": {"pages": 8, "sections": 7, "tokens": 6144,
             "instruction": "Go into depth: mechanisms, steps, examples, edge cases, tradeoffs."},
}


def _mode_rules(mode: str, depth: str) -> str:
    m = mode or "explain"
    d = DEPTH_PLAN.get(depth, DEPTH_PLAN["balanced"])["instruction"]
    base = {
        "explain": "Structured explanation; write 1-3 short paragraphs per section; outline the "
                   "what, how, and why.",
        "compare": "ALWAYS include a top-level JSON key \"comparison\" = a flat array of rows, each "
                   "row an array of strings [aspect, item A, item B, ...]. Then add sections with "
                   "headings per dimension, plus \"tradeoffs\" = [[str]] and \"recommendation\" = str.",
        "tutor": "Teach interactively: after each section include \"questions\" = array of 1-2 "
                 "Socratic checkpoint questions; add a closing \"practice\" = str exercise.",
        "critique": "Assess the strongest and weakest forms of the claims found in the sources. "
                    "Add \"risk_level\" = low|medium|high and \"critiques\" = [{claim, support, "
                    "weakness, verdict}].",
        "tldr": "Ultra-concise: 1 sentence summary, 3-6 sharp bullets in key_points, optional 1 "
                "short section. No fluff.",
        "glossary": "Each section defines exactly one key term: {term, definition, usage, "
                    "related}. Also add \"terms\" = [{term, definition, citations:[int]}].",
        "api_ref": "Practical: each section covers a capability; add \"endpoints\" = [{name, "
                   "method, path, purpose, params, returns}] where relevant, prefer official docs.",
        "deep_dive": "Drill into mechanisms: add \"mechanism_steps\" = [str] and \"tradeoffs\" = "
                     "[[str]]; each paragraph must cite sources.",
    }.get(m, "")
    rules = [d, base]
    if m == "deep_dive":
        rules.append("Up to 7 sections.")
    return " ".join(x for x in rules if x)


def _coerce_answer(raw):
    """Accept the envelope object, a bare top-level array of sections, or a
    single section object.

    Small models return all three shapes in the wild; coercing beats failing.
    Anything else keeps failing loudly so the repair ladder can try a simpler
    schema instead of crashing downstream.
    """
    if isinstance(raw, dict):
        if isinstance(raw.get("sections"), list):
            return raw
        if isinstance(raw.get("heading"), str) and isinstance(raw.get("body"), str):
            env = dict(raw)
            sec = {k: env.pop(k) for k in ("heading", "body", "image", "claims")
                   if k in env}
            env["sections"] = [sec]
            return env
        raise ValueError("explanation object has no sections")
    if isinstance(raw, list):
        sections = [x for x in raw if isinstance(x, dict)]
        if sections:
            return {"sections": sections}
    raise ValueError(f"expected an explanation object, got {type(raw).__name__}")


_STOPWORDS = set(
    "the a an and or of to in on for with as at by from is are was were be been "
    "it its this that these those they them their he she we you your our ours "
    "his her him us our they than then than so such no nor not only own same too "
    "very can will just should now how what when where which who whom why all any "
    "both each few more most other some into over after before between out about "
    "up down off above below during including using used use uses often also may "
    "might must shall per via within without within".split())


def _valid_documents(proposed: list, candidates: list, limit: int = 6) -> list:
    """Keep only model-proposed documents that match a fetched candidate URL.
    Normalizes trailing slashes so equivalent URLs agree."""
    by_url = {(c.get("url") or "").rstrip("/").lower(): c for c in (candidates or [])}
    out = []
    for d in (proposed or [])[:limit]:
        if not isinstance(d, dict):
            continue
        key = (d.get("url") or "").rstrip("/").lower()
        cand = by_url.get(key)
        if cand and cand.get("url"):
            out.append({"title": (d.get("title") or cand.get("title") or cand["url"])[:200],
                        "url": cand["url"], "kind": cand.get("kind") or "link",
                        "pages": cand.get("pages")})
    return out


def _valid_artifacts(proposed: list, candidates: list, limit: int = 6) -> list:
    """Keep only model-proposed artifacts whose id was offered as a candidate."""
    by_id = {c.get("id"): c for c in (candidates or []) if c.get("id") is not None}
    out = []
    for a in (proposed or [])[:limit]:
        if not isinstance(a, dict):
            continue
        cand = by_id.get(a.get("id"))
        if cand:
            out.append({"id": cand["id"], "title": cand["title"],
                        "url": cand.get("url") or "", "kind": cand.get("kind") or "link"})
    return out


def _content_tokens(s: str) -> list:
    """Lowercased word tokens minus stopwords; short tokens dropped so 'AI'
    and 'de' don't manufacture relevance out of nothing."""
    return [w for w in re.findall(r"[a-z0-9]{3,}", (s or "").lower())
            if w not in _STOPWORDS]


def _image_score(heading: str, body: str, img: dict) -> tuple:
    """Shared-vocabulary score between a section and one image candidate.

    Signals are the image's alt text, its caption/context, and its page title
    -- everything except pixels. The heading counts double: a figure captioned
    with the section's own topic is the strongest non-visual signal available.
    Returns (score, matched_tokens).
    """
    from collections import Counter
    sec = Counter(_content_tokens(heading) * 2 + _content_tokens(body))
    sig = Counter(_content_tokens(img.get("alt") or "") +
                  _content_tokens(img.get("caption") or "") +
                  _content_tokens(img.get("page") or ""))
    shared = sum(min(sec[t], sig[t]) for t in sig if t in sec)
    matched = sorted(t for t in sig if t in sec)
    return shared, matched


def _assign_images(answer: dict, images: list, min_score: int = 3) -> dict:
    """Deterministically (re)assign one image per section, or none.

    The model picks images from a bag of candidates and will happily attach a
    stock hero from an SEO page to an unrelated section. So the model's pick
    only survives if it scores; otherwise the best-scoring candidate wins, and
    sections with no candidate above the bar get no image at all. Images from
    pages the section actually cites get a bonus, grounding the figure to the
    section's evidence. Also stamps ``image_caption`` for display.
    """
    by_url = {i.get("src"): i for i in (images or []) if i.get("src")}
    src_urls = [s.get("url") for s in (answer.get("sources") or [])
                if isinstance(s, dict) and s.get("url")]
    for sec in (answer.get("sections") or []):
        if not isinstance(sec, dict):
            continue
        heading = sec.get("heading") or ""
        body = sec.get("body") or ""
        cited = set()
        for c in (sec.get("claims") or []):
            if not isinstance(c, dict):
                continue
            for cit in (c.get("citations") or []):
                idx = cit.get("sourceIndex") if isinstance(cit, dict) else None
                if isinstance(idx, int) and 0 <= idx < len(src_urls):
                    cited.add(src_urls[idx])
        ranked = []
        for img in by_url.values():
            score, matched = _image_score(heading, body, img)
            if img.get("page_url") in cited:
                score += 2
            ranked.append((score, img.get("hero", False), matched, img))
        ranked.sort(key=lambda r: (r[0], r[1]), reverse=True)
        pick = sec.get("image")
        if pick in by_url:
            img = by_url[pick]
            score, _ = _image_score(heading, body, img)
            if img.get("page_url") in cited:
                score += 2
            if score >= min_score:
                sec["image_caption"] = (img.get("caption")
                                        or img.get("alt") or "")[:200]
                continue
        if ranked and ranked[0][0] >= min_score:
            best = ranked[0][3]
            sec["image"] = best.get("src")
            sec["image_caption"] = (best.get("caption")
                                    or best.get("alt") or "")[:200]
        else:
            sec["image"] = None
            sec.pop("image_caption", None)
    return answer


def _quote_valid(text: str, quote: str) -> bool:
    return grounding.quote_is_verbatim(text, quote)


def _verify_grounding(answer: dict, pages: list) -> dict:
    """Drop invented citations/quotes; keep only ones found verbatim in sources.
    Also score each claim's confidence from how many DISTINCT sources back it.

    The quote rule and the corroboration ladder come from ``app.grounding`` --
    the same ones the ledger applies to a claim. Only the plumbing is local:
    pages are addressed by position here, not by source key.
    """
    stats = {"citations_total": 0, "citations_valid": 0, "citations_dropped": 0,
             "claims_total": 0, "grounding_violations": [],
             "corroboration": {"strong": 0, "moderate": 0, "weak": 0}}
    texts = [p["text"] for p in pages]
    for sec in (answer.get("sections") or []):
        if not isinstance(sec, dict):
            continue
        new_claims = []
        for c in (sec.get("claims") or []):
            if not isinstance(c, dict):
                continue
            stats["claims_total"] += 1
            kept = []
            for cit in (c.get("citations") or [])[:3]:
                idx = cit.get("sourceIndex")
                stats["citations_total"] += 1
                if isinstance(idx, int) and 0 <= idx < len(texts) and _quote_valid(texts[idx], cit.get("quote") or ""):
                    kept.append({"sourceIndex": idx,
                                 "quote": (cit.get("quote") or "")[:grounding.QUOTE_STORE_CHARS]})
                    stats["citations_valid"] += 1
                else:
                    stats["citations_dropped"] += 1
            if kept:
                n_src = len({k["sourceIndex"] for k in kept})
                c["citations"] = kept
                c["confidence"] = grounding.confidence_for(n_src)
                c["n_sources"] = n_src
                stats["corroboration"][
                    "strong" if n_src >= 3 else "moderate" if n_src == 2 else "weak"] += 1
                new_claims.append(c)
            else:
                stats["grounding_violations"].append(
                    {"heading": sec.get("heading"), "claim": (c.get("text") or "")[:120]})
        if new_claims:
            sec["claims"] = new_claims
        else:
            sec.pop("claims", None)
    return stats


def _compose(question: str, pages: list, images: list, mode: str = "explain",
             depth: str = "balanced", audience: str = "intermediate",
             max_tokens: int = 4096, section_plan: list | None = None,
             documents: list | None = None, artifact_cands: list | None = None) -> dict:
    m = mode or "explain"
    ctx = []
    for i, p in enumerate(pages):
        line = f"[{i}] {p['title']}\nURL: {p['url']}"
        if p.get("published"):
            line += f"\nPublished: {p['published']}"
        line += f"\n{p['text'][:2500]}"
        ctx.append(line)
    img_list = "\n".join(
        f"- {img['src']} (from: {img['page']}; alt: {img.get('alt', '')[:100]}"
        f"{'; context: ' + img['caption'][:150] if img.get('caption') else ''})"
        for img in images)
    doc_list = "\n".join(
        f"- {d['url']} ({d.get('kind') or 'link'}; {d.get('title', '')[:120]}"
        f"{'; ' + str(d['pages']) + ' pages' if d.get('pages') else ''})"
        for d in (documents or []))
    art_list = "\n".join(
        f"- id {a['id']}: {a.get('title', '')[:120]}"
        f"{' (' + a['url'] + ')' if a.get('url') else ''}"
        for a in (artifact_cands or []))
    mode_rules = _mode_rules(m, depth)
    aud_hint = AUDIENCE_HINTS.get(audience, AUDIENCE_HINTS["intermediate"])
    section_hint = ""
    if section_plan:
        topics = "; ".join(f"'{s.get('heading')}' (focus: {s.get('sub_question')})"
                           for s in section_plan)
        section_hint = (f"\nStructure the answer with sections in EXACTLY this order and topics: "
                        f"{topics}. Keep each body on-topic.")

    # Repair ladder: on JSON failure, retry with progressively simpler schemas.
    schema_steps = [
        {"claims": "with evidence", "json": "\"sections\": [{\"heading\": str, \"body\": str "
                                          "(markdown-lite, cite like [1], [2] matching source order), "
                                          "\"image\": image URL or null, "
                                          "\"claims\": [{text: str (single factual claim), "
                                          "citations: [{sourceIndex: int, quote: str (verbatim, 12-60 "
                                          "words, from that EXACT source text)}]}] (1-2 claims per "
                                          "section, cites required)}]"},
        {"claims": "fewer, shorter quotes", "json": "\"sections\": [{\"heading\": str, \"body\": str "
                                          "(markdown-lite, cite like [1]), \"image\": image URL or null, "
                                          "\"claims\": [{text: str, citations: [{sourceIndex: int, "
                                          "quote: str (<35 words)} ]}] (1 claim per section)}]"},
        {"claims": "none", "json": "\"sections\": [{\"heading\": str, \"body\": str (markdown-lite, cite "
                                          "like [1], [2]), \"image\": image URL or null}]"},
    ]

    answer = None
    for step in schema_steps:
        try:
            answer = _coerce_answer(llm.chat_json([
                {"role": "system",
                 "content": ("You are a technical explainer. Write a clear, accurate explanation "
                             "grounded ONLY in the provided sources (prefix graph:// = this project's "
                             "own knowledge graph). When sources disagree on any point, say so in "
                             "\"conflicts\". Reply with STRICT, well-formed JSON only. "
                             "Escape all quotes inside strings.")},
                {"role": "user",
                 "content": (f"Question: {question}\n\nAudience: {aud_hint}\n\n{mode_rules}"
                             f"{section_hint}\n\n"
                             f"Source budget: {len(pages)} sources.\n\nSources:\n" + "\n\n".join(ctx) +
                              f"\n\nCandidate images (reference EXACT URLs, don't invent; set a section's "
                              f"\"image\" only when the image actually depicts that section's topic, else null):\n{img_list or '(none)'}\n\n"
                              f"Candidate documents, attach the ones that help understand this topic "
                              f"(reference EXACT URLs, don't invent):\n{doc_list or '(none)'}\n\n"
                              f"This investigation's own artifacts, attach the relevant ones by id:\n{art_list or '(none)'}\n\n"
                             "Reply JSON: {\"summary\": str (2-3 sentences), " + step["json"] + ", "
                             "\"as_of\": str (today's date YYYY-MM-DD), "
                             "\"conflicts\": [{\"topic\": str, \"view_a\": str, \"view_b\": str, "
                             "\"sources_a\": [int], \"sources_b\": [int]}] (only include when sources "
                             "disagree on a substantive point, max 3), "
                             "\"key_points\": [str x3-6], plus any additional keys your mode rules require. "
                             "\"sources\": [{\"title\": str, \"url\": str}] (only URLs from the sources above), "
                             "\"documents\": [{\"title\": str, \"url\": str}] (only URLs from the candidate "
                             "documents above, max 6 — PDFs, decks, reports that help understand the topic), "
                             "\"artifacts\": [{\"id\": int, \"title\": str}] (only ids from this investigation's "
                             "artifacts above, max 6)}")}],
                max_tokens=max_tokens))
            break
        except Exception as e:
            answer = None
            last_err = str(e)[:200]
    if answer is None:
        raise RuntimeError(f"LLM could not produce valid JSON explanation ({last_err})")
    valid_srcs = {p["url"] for p in pages}
    answer["sources"] = [s for s in (answer.get("sources") or [])
                         if isinstance(s, dict) and s.get("url") in valid_srcs][: len(pages)]
    if not answer.get("sources"):
        answer["sources"] = [{"title": p["title"], "url": p["url"]} for p in pages]
    # Deterministic image gate: the model's per-section picks survive only if
    # they actually match the section; otherwise the best-scoring candidate
    # wins, or the section gets no image rather than a random one.
    _assign_images(answer, images)
    # Attachments are validated the same strict way as sources: invented URLs
    # and unknown artifact ids are dropped, never rendered.
    answer["documents"] = _valid_documents(answer.get("documents"), documents)
    answer["artifacts"] = _valid_artifacts(answer.get("artifacts"), artifact_cands)
    n_src = len(answer["sources"])
    conflicts = []
    for c in (answer.get("conflicts") or [])[:3]:
        if not isinstance(c, dict) or not c.get("topic") or not c.get("view_a") or not c.get("view_b"):
            continue
        sa = [i for i in (c.get("sources_a") or []) if isinstance(i, int) and 0 <= i < n_src][:3]
        sb = [i for i in (c.get("sources_b") or []) if isinstance(i, int) and 0 <= i < n_src][:3]
        if not sa and not sb:
            continue
        conflicts.append({"topic": str(c["topic"])[:200], "view_a": str(c["view_a"])[:600],
                          "view_b": str(c["view_b"])[:600], "sources_a": sa, "sources_b": sb})
    answer["conflicts"] = conflicts
    return answer


def _domain(url):
    try:
        from urllib.parse import urlparse
        return urlparse(url).netloc.replace("www.", "")
    except Exception:
        return ""


DIAGRAM_TYPES = {"flowchart", "sequenceDiagram", "graph", "mindmap", "timeline",
                 "classDiagram", "erDiagram", "stateDiagram", "journey", "pie",
                 "gantt", "quadrantChart", "gitGraph", "xychart", "block-beta", "kanban"}


def _validate_mermaid(code: str) -> str | None:
    if not code:
        return None
    code = code.strip()
    code = re.sub(r"^```(?:mermaid)?\s*|\s*```$", "", code, flags=re.IGNORECASE).strip()
    if len(code) > 2500 or "<script" in code.lower() or "javascript:" in code.lower():
        return None
    first = (re.split(r"[\s{:]", code, 1)[0] or "").strip()
    if first not in DIAGRAM_TYPES:
        return None
    return code


def _gen_diagram(question: str, pages: list, mode: str, depth: str) -> dict | None:
    if depth == "shallow" or (mode or "explain") in ("tldr", "glossary"):
        return None
    ctx = "\n".join(f"[{i}] {p['title']}: {p['text'][:700]}" for i, p in enumerate(pages[:8]))
    try:
        r = llm.chat_json([
            {"role": "system",
             "content": "You create Mermaid diagrams that clarify how things work. Reply JSON only."},
            {"role": "user",
             "content": (f"Question: {question}\n\nSources:\n{ctx}\n\n"
                         "BEST diagram type for explaining the mechanism (flow task -> sequence if "
                         "temporal, architecture if components, mindmap if overview): "
                         "Say \"none\" if a diagram adds nothing.\n"
                         "Reply JSON: {\"diagram_type\": \"none|flowchart|sequenceDiagram|graph|"
                         "mindmap|timeline|erDiagram\", "
                         "\"mermaid\": str (valid Mermaid source, no code fences, nodes the core "
                         "concepts/steps, keep under 45 nodes/lines with short labels), "
                         "\"title\": str, \"caption\": str (1 sentence), "
                         "\"references\": [int source indices]}")}],
            max_tokens=1400)
        diag_type = r.get("diagram_type")
        code = _validate_mermaid(r.get("mermaid") or "")
        if not code or diag_type == "none":
            return None
        refs = [i for i in (r.get("references") or []) if isinstance(i, int) and 0 <= i < len(pages)][:3]
        return {"diagram_type": r.get("diagram_type"), "mermaid": code,
                "title": (r.get("title") or "Diagram")[:120],
                "caption": (r.get("caption") or "")[:200], "references": refs,
                "source": "generated"}
    except Exception:
        return None


def _parent_excerpt(parent) -> str:
    try:
        a = json.loads(parent.answer or "{}")
    except Exception:
        return (parent.question or "")[:600]
    try:
        meta = json.loads(parent.meta or "{}")
    except Exception:
        meta = {}
    scope = meta.get("scope")
    idx = meta.get("target_index")
    parts = []

    def push(x):
        if x:
            parts.append(str(x)[:1600])

    if a.get("summary"):
        push(f"Parent summary: {a['summary']}")
    secs = a.get("sections") or []
    if scope in ("section", "claim") and isinstance(idx, int) and 0 <= idx < len(secs):
        s = secs[idx]
        push(f"Section '{s.get('heading')}': {s.get('body')}")
        for c in (s.get("claims") or []):
            push(f"Claim: {c.get('text')}")
    else:
        for s in secs[:4]:
            push(f"{s.get('heading')}: {s.get('body')}")
    return "\n".join(parts) or (parent.question or "")[:600]


def _eval_answer(question: str, answer: dict) -> dict:
    """Post-compose triage: is the explanation complete, or do gaps remain?"""
    n_sections = len(answer.get("sections") or [])
    summary = (answer.get("summary") or "")[:400]
    try:
        r = llm.chat_json([
            {"role": "system",
             "content": "Judge if an answer truly resolves the question or leaves meaningful "
                        "gaps. Reply JSON only, be conservative (favor needs_more=false)."},
            {"role": "user",
             "content": f"Question: {question}\n\nAnswer preview:\n{summary}\n"
                        f"(sections: {n_sections})\n\n"
                        "Reply JSON: {\"complete\": bool, \"needs_more\": bool, "
                        "\"missing_topics\": [str] (max 3, empty if needs_more false)}"}],
            max_tokens=400)
        return {"complete": bool(r.get("complete")), "needs_more": bool(r.get("needs_more")),
                "missing_topics": [str(t) for t in (r.get("missing_topics") or [])][:3]}
    except Exception:
        return {"complete": True, "needs_more": False, "missing_topics": []}


def _extract_concepts(question: str, answer: dict) -> dict:
    """Extract concepts + relations from a composed answer (for structured save)."""
    brief = (answer.get("summary") or "")[:400]
    secs = "\n".join(
        f"- [{i}] {s.get('heading')}: {s.get('body')[:600]}" for i, s in enumerate(answer.get("sections") or []))
    try:
        r = llm.chat_json([
            {"role": "system",
             "content": "Extract the key concepts and typed relationships an explanation relies on. "
                        "Reply JSON only."},
            {"role": "user",
             "content": f"Question: {question}\n\nSummary: {brief}\n\nSections:\n{secs}\n\n"
                        "Reply JSON: {\"concepts\": [{\"name\": str, \"definition\": str (1 sentence)}] "
                        "(max 8), "
                        "\"relations\": [{\"from\": str, \"to\": str, \"type\": "
                        "\"DEPENDS_ON|PREREQUISITE_OF|SUPPORTS|CONTRADICTS\"}] (max 8, both ends "
                        "must be concepts from the list)}"}],
            max_tokens=1200)
        concepts = [c for c in (r.get("concepts") or [])
                    if isinstance(c, dict) and c.get("name")]
        names = {c["name"].strip().lower() for c in concepts}
        relations = [rel for rel in (r.get("relations") or [])
                     if isinstance(rel, dict) and rel.get("from", "").strip().lower() in names
                     and rel.get("to", "").strip().lower() in names
                     and rel.get("type") in ("DEPENDS_ON", "PREREQUISITE_OF",
                                             "SUPPORTS", "CONTRADICTS")]
        return {"concepts": concepts[:8], "relations": relations[:8]}
    except Exception:
        return {"concepts": [], "relations": []}


def _set_meta(exp, meta: dict, db) -> None:
    try:
        exp.meta = json.dumps(meta)
        db.commit()
    except Exception:
        db.rollback()


def _expand_terms_for(inv, db) -> list:
    """Domain vocabulary to append to search queries: keywords + artifact titles."""
    if inv is None:
        return []
    terms = [t.strip() for t in (inv.keywords or "").split(",") if t.strip()]
    try:
        for a in db.query(Artifact).filter(Artifact.investigation_id == inv.id).all():
            terms.append(a.title or "")
    except Exception:
        pass
    return [t for t in terms if t][:6]


def _source_affinity(db, inv_id: int) -> dict:
    """Per-investigation learned source preference from feedback thumbs (#8)."""
    fav = {}
    for e in db.query(Explanation).filter(Explanation.investigation_id == inv_id).all():
        try:
            m = json.loads(e.meta or "{}")
        except Exception:
            m = {}
        for fb in (m.get("feedback") or []):
            url = fb.get("url")
            if not url or fb.get("up") is None:
                continue
            fav[url] = fav.get(url, 0.0) + (0.25 if bool(fb.get("up")) else -0.25)
    return {u: max(0.0, min(1.0, s)) for u, s in fav.items() if s}


def _save_corpus(db, inv_id: int, page: dict) -> None:
    try:
        url = (page.get("url") or "").strip()
        if not url or page.get("graph_id") or page.get("explanation_id"):
            return
        row = db.query(CorpusPage).filter(
            CorpusPage.investigation_id == inv_id,
            CorpusPage.url == url).first()
        if row is None:
            row = CorpusPage(investigation_id=inv_id, url=url)
            db.add(row)
        row.title = (page.get("title") or "")[:500]
        row.text = (page.get("text") or "")[:30000]
        row.domain = _domain(url)
        row.published = page.get("published")
        row.images = json.dumps(page.get("images") or [])[:8000]
        row.fetched_at = datetime.now(timezone.utc)
        db.commit()
    except Exception:
        db.rollback()


def _corpus_images(row) -> list:
    try:
        if not row.images:
            return []
        imgs = json.loads(row.images)
        return imgs if isinstance(imgs, list) else []
    except Exception:
        return []


def _collect_corpus_context(db, inv_id: int, question: str, limit: int = 8,
                            affinity: dict | None = None) -> list:
    """Previously-fetched pages ranked against the question (corpus memory, #2)."""
    qw = _tok(question)
    ranked = []
    for row in db.query(CorpusPage).filter(CorpusPage.investigation_id == inv_id).all():
        text = row.text or ""
        score = 0.4 * _jaccard(qw, _tok(row.title)) + 0.1 * _jaccard(qw, _tok(text))
        score += 0.05 * sum(1 for t in qw if t in text)
        if affinity and row.url in affinity:
            score += 0.25 * affinity[row.url]
        if score > 0:
            ranked.append((score, row))
    ranked.sort(key=lambda x: x[0], reverse=True)
    return [{"url": row.url, "title": row.title or row.url, "text": (row.text or "")[:12000],
             "images": _corpus_images(row), "published": row.published,
             "corpus": True, "corpus_id": row.id}
            for _, row in ranked[:limit]]


def _plan_sections(question: str, mode: str) -> list | None:
    """Outline sections + per-section researchable sub-questions (deep only, #5)."""
    if (mode or "explain") in ("tldr", "glossary"):
        return None
    try:
        r = llm.chat_json([
            {"role": "system",
             "content": "You outline an explanation into sections, each with a focused "
                        "researchable sub-question. Reply JSON only."},
            {"role": "user",
             "content": f"Question: {question}\n\nReply {{\"sections\": [{{\"heading\": str, "
                        "\"sub_question\": str (a specific question one web search could answer)"
                        "}}]}} — 3 to 5 sections, non-overlapping."}],
            max_tokens=700)
        secs = [s for s in (r.get("sections") or []) if isinstance(s, dict)
                and s.get("heading") and s.get("sub_question")][:5]
        return secs if len(secs) >= 2 else None
    except Exception:
        return None


def _critique_answer(question: str, answer: dict, pages: list) -> list | None:
    """Second-pass reviewer: verdict per claim against sources (#12)."""
    claims = []
    for sec in (answer.get("sections") or []):
        for c in (sec.get("claims") or []):
            claims.append((sec.get("heading", ""), c.get("text", "")))
            if len(claims) >= 6:
                break
        if len(claims) >= 6:
            break
    if not claims:
        return None
    brief = "\n".join(f"[{i}] {h}: {t[:200]}" for i, (h, t) in enumerate(claims))
    try:
        r = llm.chat_json([
            {"role": "system",
             "content": "You are a skeptical fact-checker. Judge each claim against the "
                        "provided source excerpts. Reply JSON only."},
            {"role": "user",
             "content": f"Question: {question}\n\nClaim list:\n{brief}\n\nSources ({len(pages)}):\n"
                        + "\n".join(f"- [{i}] {p['title']}: {p['text'][:900]}"
                                    for i, p in enumerate(pages[:8])) +
                        "\n\nReply {\"reviews\": [{\"index\": int, \"verdict\": "
                        "\"supported|unsupported|uncertain\", \"note\": str (1 sentence, only real "
                        "discrepancies — do not nitpick)}]} — one per claim."}],
            max_tokens=2000)
        reviews = [rv for rv in (r.get("reviews") or [])
                   if isinstance(rv, dict) and isinstance(rv.get("index"), int)]
        out = []
        for rv in reviews:
            if not (0 <= rv["index"] < len(claims)):
                continue
            h, t = claims[rv["index"]]
            out.append({"heading": h, "claim": t[:200],
                        "verdict": rv.get("verdict") if rv.get("verdict") in
                        ("supported", "unsupported", "uncertain") else "uncertain",
                        "note": (rv.get("note") or "")[:300]})
        return out
    except Exception:
        return None


def _drift(old: "Explanation", new: "Explanation") -> str:
    try:
        oa = json.loads(old.answer or "{}")
        na = json.loads(new.answer or "{}")
        ok = set(str(k) for k in (oa.get("key_points") or []))
        nk = set(str(k) for k in (na.get("key_points") or []))
        union = ok | nk
        if not union:
            return "same"
        return "same" if len(ok & nk) / len(union) >= 0.5 else "changed"
    except Exception:
        return "changed"


def _investigation_roadmap(db, inv_id: int) -> list:
    """Aggregate open questions across an investigation's explanations (#4)."""
    agg = {}
    exps = db.query(Explanation).filter(Explanation.investigation_id == inv_id).all()
    for e in exps:
        try:
            t = json.loads(e.trace or "{}")
        except Exception:
            t = {}
        def push(q, kind):
            q = (q or "").strip()
            if not q or len(q) < 8:
                return
            item = agg.setdefault(q.lower(),
                                  {"question": q, "kinds": set(), "exps": set()})
            item["kinds"].add(kind)
            item["exps"].add(e.id)
        for q in (t.get("followup_queries") or []):
            push(q, "gap")
        for q in (t.get("gaps") or []):
            push(q, "open")
        hp = t.get("hop_plan") or []
        if hp:
            for q in hp[-1].get("missing_topics") or []:
                push(q, "deepen")
    items = sorted(agg.values(), key=lambda it: -len(it["exps"]))
    for it in items:
        it["kinds"] = sorted(it["kinds"])
        it["exps"] = sorted(it["exps"])
    return items[:30]


def _gate_new_concepts(db, inv_id: int, created: list) -> list:
    """Auto-classify freshly saved concepts as drift (or not).

    Deterministic prefilter first (shared vocabulary with the brief or the
    agent-scored corpus), then one LLM batch verdict over the leftovers.
    Fail-open: any failure marks nothing, and saving already succeeded by the
    time this runs, so drift gating can never break a save. The failure is
    still reported -- ``drift.judge`` lands on the ledger when the judge could
    not finish, so "nothing marked" is distinguishable from "nothing checked".
    """
    from . import drift as drift_mod
    try:
        if not created:
            return []
        inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
        if inv is None:
            return []
        brief = drift_mod.brief_terms(inv.title, inv.keywords, inv.description)
        brief_text = f"{inv.title} | {inv.keywords} | {inv.description}"
        corpus = set()
        corpus_text_parts = []
        for art in db.query(Artifact).filter(
                Artifact.investigation_id == inv_id,
                Artifact.relevance.is_not(None)).all():
            corpus |= drift_mod.item_terms(art.title, art.tags, art.description)
            corpus_text_parts.append(f"{art.title} {art.tags or ''} {art.description or ''}")
        # New concepts carry no description of their own here, so the recall
        # boost comes from the brief and the established corpus.
        cands = drift_mod.drift_candidates(
            brief, corpus, created, brief_text=brief_text,
            corpus_text=" ".join(corpus_text_parts))
        if not cands:
            return []
        report = drift_mod.classify_drift(brief_text, cands)
        drifted = report.get("ids") or set()
        marked = []
        for c in cands:
            if c.get("id") in drifted:
                row = db.get(Artifact, c["id"])
                if row is not None and not row.drift:
                    row.drift = 1
                    marked.append(row.id)
        if marked:
            db.commit()
        return marked
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        return []


def _save_explanation_to_graph(db, exp: "Explanation") -> dict:
    """Persist an answer as essay + concepts + typed relations. Concept extraction is
    cached on exp.meta so a second save (or auto-save + manual) is instant (#3, #9)."""
    answer = json.loads(exp.answer or "{}")
    meta = {}
    try:
        meta = json.loads(exp.meta or "{}")
    except Exception:
        pass
    cached = meta.get("concepts")
    if isinstance(cached, dict) and cached.get("concepts"):
        extracted = cached
    else:
        extracted = _extract_concepts(exp.question, answer)
        meta["concepts"] = {"concepts": extracted["concepts"],
                            "relations": extracted["relations"]}
        exp.meta = json.dumps(meta)
        db.commit()
    concepts, relations = extracted["concepts"], extracted["relations"]

    def norm_title(s):
        return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()

    def find_artifact(title, atype):
        return db.query(Artifact).filter(
            Artifact.investigation_id == exp.investigation_id,
            Artifact.artifact_type == atype,
            Artifact.title == title).first()

    def find_artifact_by_url(url):
        return db.query(Artifact).filter(
            Artifact.investigation_id == exp.investigation_id,
            Artifact.url == url).first()

    root_text = (answer.get("summary") or "") + "\n\n" + "\n\n".join(
        f"## {s.get('heading')}\n{s.get('body')}" for s in answer.get("sections") or [])
    root = find_artifact(exp.question[:200], "essay")
    if not root:
        root = Artifact(investigation_id=exp.investigation_id, title=exp.question[:200],
                        artifact_type="essay", description=(answer.get("summary") or "")[:2000],
                        content=root_text[:6000], author="explainer",
                        tags="explainer," + (exp.mode or "explain"),
                        relevance=None, review="pending", origin="agent")
        db.add(root)
        db.flush()
    elif not (root.content and len(root.content or "") > 100):
        root.content = root_text[:6000]  # refresh stale/empty essay from a previous save

    concept_ids = {}
    matched = 0
    created_concepts = []
    for c in concepts:
        t = c.get("name", "")[:200]
        if not t.strip():
            continue
        existing = None
        for art in db.query(Artifact).filter(
                Artifact.investigation_id == exp.investigation_id,
                Artifact.artifact_type == "concept").all():
            if norm_title(art.title) == norm_title(t):
                existing = art
                break
        if existing:
            concept_ids[norm_title(t)] = existing.id
            matched += 1
        else:
            a = Artifact(investigation_id=exp.investigation_id, title=t[:200],
                         artifact_type="concept",
                         description=(c.get("definition") or "")[:1000],
                         author="explainer", tags="concept,explainer",
                         review="pending", origin="agent")
            db.add(a)
            db.flush()
            concept_ids[norm_title(t)] = a.id
            created_concepts.append({"id": a.id, "title": a.title,
                                     "tags": a.tags or ""})
    _gate_new_concepts(db, exp.investigation_id, created_concepts)

    def add_rel(src, dst, rtype, desc=None):
        if src == dst:
            return False
        exists = (db.query(Relationship).filter(
            Relationship.investigation_id == exp.investigation_id,
            Relationship.source_id == src, Relationship.target_id == dst,
            Relationship.relationship_type == rtype).first())
        if exists:
            return False
        db.add(Relationship(investigation_id=exp.investigation_id, source_id=src,
                            target_id=dst, relationship_type=rtype,
                            description=desc, origin="agent"))
        return True

    n_rel = 0
    for nid in concept_ids.values():
        n_rel += add_rel(root.id, nid, "EXPLAINS")
    for s in answer.get("sources") or []:
        url = s.get("url") or ""
        if not url.startswith("http"):
            continue
        art = find_artifact_by_url(url)
        if not art:
            art = Artifact(investigation_id=exp.investigation_id,
                           title=(s.get("title") or url)[:200], artifact_type="source",
                           url=url, author="explainer",
                           tags="source,explainer", review="pending", origin="agent")
            db.add(art)
            db.flush()
    for sec in answer.get("sections") or []:
        for c in sec.get("claims") or []:
            for cit in c.get("citations") or []:
                idx = cit.get("sourceIndex")
                if not isinstance(idx, int):
                    continue
                src = (answer.get("sources") or [])[idx] if idx < len(answer.get("sources") or []) else None
                if not src or not (src.get("url") or "").startswith("http"):
                    continue
                art = db.query(Artifact).filter(Artifact.url == src["url"]).first()
                if not art:
                    continue
                n_rel += add_rel(root.id, art.id, "CITES")
    n2id = concept_ids
    for r in relations:
        f = n2id.get(norm_title(r.get("from")))
        t = n2id.get(norm_title(r.get("to")))
        if f and t:
            n_rel += add_rel(f, t, r.get("type"))
    db.commit()
    # Record node ids (for entity-resolution pills, #9).
    meta = json.loads(exp.meta or "{}")
    meta["concepts"]["artifact_ids"] = [concept_ids[k] for k in concept_ids]
    exp.meta = json.dumps(meta)
    db.commit()
    return {"created_artifacts": len(concept_ids) + 1,
            "created_relationships": n_rel, "concepts": list(concept_ids.keys()),
            "matched_concepts": matched}


def run_explainer(exp_id: int, max_pages: int = MAX_PAGES, max_hops: int = 0):
    db = SessionLocal()
    trace = {}
    try:
        exp = db.query(Explanation).filter(Explanation.id == exp_id).first()
        if not exp:
            return
        tro = time.time()
        mode = exp.mode or "explain"
        depth = exp.depth or "balanced"
        audience = exp.audience or "intermediate"
        plan = DEPTH_PLAN.get(depth, DEPTH_PLAN["balanced"])
        max_pages = max_pages or plan["pages"]
        max_tokens = plan["tokens"]
        meta = {}
        try:
            meta = json.loads(exp.meta or "{}")
        except Exception:
            pass
        trace = {
            "queries": [], "hits": [], "fetched": [], "timings_ms": {},
            "hops": 0, "pages_read": 0, "rejected_count": 0, "web_skipped": False,
            "graph_context_used": False, "graph_artifacts": [],
            "corpus_hits": [], "corpus_cache_hits": 0,
            "coverage": None, "gaps": [], "web_fallback_reason": None,
        }
        # Follow-up context: reuse the parent's targeted excerpt as a synthetic source.
        parent = None
        if exp.parent_id:
            parent = db.query(Explanation).filter(
                Explanation.id == exp.parent_id).first()
            trace["followup_of"] = exp.parent_id
            trace["scope"] = meta.get("scope")
        graph = _collect_graph_context(db, exp.investigation_id, exp.question)
        graph_brief = _gap_check(exp.question, graph)
        trace["coverage"] = graph_brief.get("coverage")
        trace["gaps"] = graph_brief.get("gaps", [])
        trace["followup_queries"] = graph_brief.get("followup_queries", [])
        trace["graph_artifacts"] = [
            f"#{a['id']} · {a['title'][:60]}" for a in graph]
        if graph:
            trace["graph_context_used"] = not graph_brief.get("needs_web")

        inv = db.query(Investigation).filter(
            Investigation.id == exp.investigation_id).first()
        affinity = _source_affinity(db, exp.investigation_id) if inv else {}
        corpus_map = {}
        if inv:
            for row in db.query(CorpusPage).filter(
                    CorpusPage.investigation_id == inv.id).all():
                corpus_map[row.url.lower()] = {"url": row.url, "title": row.title or row.url,
                                               "text": row.text or "", "images": _corpus_images(row),
                                               "published": row.published}
        expand_terms = _expand_terms_for(inv, db) if inv else []
        pref_domains = [d.strip() for d in (inv.preferred_domains or "").split(",")
                        if d.strip()] if inv else []
        section_plan = _plan_sections(exp.question, mode) if depth == "deep" else None
        if section_plan:
            trace["section_plan"] = [s.get("heading") for s in section_plan]
        corpus_ctx = _collect_corpus_context(db, exp.investigation_id, exp.question,
                                             affinity=affinity)
        trace["corpus_hits"] = [{"url": c["url"], "title": c["title"], "cached": True}
                                for c in corpus_ctx]

        def set_phase(v):
            try:
                meta["phase"] = v
                exp.meta = json.dumps(meta)
                db.commit()
            except Exception:
                db.rollback()

        set_phase("researching")
        pages, images, documents, answer, grounding = [], [], [], None, None
        seen_urls = set()
        hop_list = []
        for hop in range(max_hops + 1):
            hop_pages = []
            if hop == 0:
                if graph and not graph_brief.get("needs_web"):
                    trace["web_skipped"] = True
                    hop_pages = _graph_pages(graph)
                    if corpus_ctx:
                        have = {p["url"] for p in hop_pages}
                        hop_pages += [c for c in corpus_ctx if c["url"] not in have][:4]
                else:
                    if graph_brief.get("gaps") and not graph_brief.get("needs_web"):
                        trace["web_fallback_reason"] = "graph partial"
                    extra = (graph_brief.get("followup_queries")
                             if graph_brief.get("needs_web") else None)
                    if depth == "deep" and section_plan:
                        sq = [s.get("sub_question") for s in section_plan[:3]
                              if s.get("sub_question")]
                        extra = list(dict.fromkeys((extra or []) + sq))
                    hop_pages, images, new_docs, cached_n = _research(
                        exp.question, max_pages, trace=trace, extra_queries=extra,
                        corpus=corpus_map, expand_terms=expand_terms,
                        preferred_domains=pref_domains)
                    for d in new_docs:
                        if all(x["url"] != d["url"] for x in documents):
                            documents.append(d)
                    trace["corpus_cache_hits"] += cached_n
                    if corpus_ctx:
                        have = {p["url"] for p in hop_pages}
                        hop_pages += [c for c in corpus_ctx if c["url"] not in have][:2]
                    if graph:
                        trace["web_fallback_reason"] = "hybrid: graph + web"
                        hop_pages = _graph_pages(graph[:4]) + hop_pages
            else:
                missing = hop_list[-1].get("missing_topics", [])[:2]
                if not missing:
                    break
                hop_pages, new_img, new_docs, cached_n = _research(
                    exp.question, max(int(max_pages * 0.4), 2), trace=trace,
                    extra_queries=missing, corpus=corpus_map, expand_terms=expand_terms,
                    preferred_domains=pref_domains)
                images += new_img
                for d in new_docs:
                    if all(x["url"] != d["url"] for x in documents):
                        documents.append(d)
                trace["corpus_cache_hits"] += cached_n
                hop_list[-1]["new_pages"] = len(
                    [p for p in hop_pages if p["url"] not in seen_urls])
            # Dedupe pages by url (keep first seen).
            for p in hop_pages:
                if p["url"] not in seen_urls:
                    seen_urls.add(p["url"])
                    pages.append(p)
            trace["pages_read"] = len([p for p in pages if not p.get("graph_id")
                                       and not p.get("explanation_id") and p.get("url") and not
                                       p["url"].startswith("explanation://")])
            trace["rejected_count"] = sum(1 for f in trace["fetched"] if not f["kept"])
            # Parent excerpt appended once (as a synthetic cite target).
            if parent:
                pages = [{"url": f"explanation://{parent.id}",
                          "title": f"Parent: {parent.question[:70]}",
                          "text": _parent_excerpt(parent) or parent.question[:800],
                          "images": [], "explanation_id": parent.id, "graph_id": None}] + pages
                parent = None  # only once
            set_phase("composing")
            artifact_cands = _artifact_candidates(db, exp.investigation_id)
            answer = _compose(exp.question, pages[:12], images, mode=mode, depth=depth,
                              audience=audience, max_tokens=max_tokens,
                              section_plan=section_plan, documents=documents,
                              artifact_cands=artifact_cands)
            grounding = _verify_grounding(answer, pages)
            eval_res = _eval_answer(exp.question, answer)
            if eval_res.get("needs_more") and (hop + 1) <= max_hops:
                hop_list.append({"hop": hop + 1,
                                 "missing_topics": eval_res.get("missing_topics", []),
                                 "new_pages": 0})
                set_phase("researching")
                continue
            break
        trace["hops"] = len(hop_list)
        trace["hop_plan"] = hop_list
        answer["as_of"] = datetime.now(timezone.utc).date().isoformat()
        pubmap = {str(p.get("url")): p.get("published") for p in pages
                  if p.get("url") and p.get("published")}
        for s in answer.get("sources") or []:
            if s.get("url") and not s.get("published") and s["url"] in pubmap:
                s["published"] = pubmap[s["url"]]
        set_phase("critique")
        critique = _critique_answer(exp.question, answer, pages)
        if critique:
            answer["critique"] = critique
            trace["critique"] = len(critique)
        trace["citations"] = {k: v for k, v in grounding.items()
                              if k != "grounding_violations"} if grounding else {}
        if grounding and grounding["grounding_violations"]:
            trace["citations"]["grounding_violations"] = grounding["grounding_violations"]
        if grounding:
            answer["grounding"] = {k: v for k, v in grounding.items()
                                   if k != "grounding_violations"}
        exp.answer = json.dumps(answer)  # persist before graph save so it extracts real content
        if exp.parent_id is None and not meta.get("watch_of") and inv is not None:
            auto = inv.auto_save_explanations
            if auto is None:
                auto = 1
            if auto:
                set_phase("saving")
                try:
                    save_result = _save_explanation_to_graph(db, exp)
                    trace["save_to_graph"] = save_result
                    try:
                        meta = json.loads(exp.meta or "{}")
                    except Exception:
                        pass
                except Exception as save_err:
                    trace["save_to_graph"] = {"error": str(save_err)[:300]}
        watch_id = meta.get("watch_of")
        if watch_id:
            old = db.query(Explanation).filter(Explanation.id == int(watch_id)).first()
            if old:
                try:
                    drift = _drift(old, exp)
                    meta["drift"] = drift
                    trace["drift"] = drift
                except Exception:
                    pass
        for p in pages:
            if (p.get("url") and p.get("url").startswith("http")
                    and p.get("text") and not p.get("graph_id")
                    and not p.get("corpus")):
                try:
                    _save_corpus(db, exp.investigation_id, p)
                except Exception:
                    pass
        set_phase("done")
        diagram = _gen_diagram(exp.question, pages, mode, depth)
        if diagram:
            answer["diagram"] = diagram
            trace.setdefault("diagram", diagram["diagram_type"])
        trace["timings_ms"]["compose"] = max(0, int((time.time() - tro) * 1000)
                                             - trace["timings_ms"].get("search", 0)
                                             - trace["timings_ms"].get("fetch", 0))
        trace["timings_ms"]["total"] = int((time.time() - tro) * 1000)
        answer["trace"] = {"pages_read": trace["pages_read"],
                           "rejected_count": trace["rejected_count"],
                           "graph_context_used": trace["graph_context_used"],
                           "web_skipped": trace["web_skipped"],
                           "hops": trace["hops"]}
        exp.answer = json.dumps(answer)
        exp.trace = json.dumps(trace)
        exp.meta = json.dumps(meta)
        exp.status = "done"
        exp.hops = trace.get("hops", 0)
        exp.finished_at = datetime.now(timezone.utc)
        db.commit()
    except Exception as e:
        try:
            exp = db.query(Explanation).filter(Explanation.id == exp_id).first()
            if exp:
                exp.status = "error"
                exp.error = f"{e}\n{traceback.format_exc()[-1500:]}"
                exp.finished_at = datetime.now(timezone.utc)
                if trace:
                    exp.trace = json.dumps(trace)
                db.commit()
        except Exception:
            db.rollback()
    finally:
        db.close()


def launch_explanation(exp_id: int, max_pages: int = MAX_PAGES, max_hops: int = 0):
    t = threading.Thread(target=contextvars.copy_context().run,
                         args=(run_explainer, exp_id, max_pages, max_hops),
                         daemon=True)
    t.start()
    return t


def _question_suggestions(exp: Explanation, db=None) -> list:
    """Suggested next questions for an explanation: agent-generated gaps plus
    closely related artifacts already in the graph."""
    out, seen = [], set()
    t = {}
    try:
        t = json.loads(exp.trace or "{}")
    except Exception:
        pass

    def add(text, kind):
        text = str(text).strip()
        if text and len(text) > 8 and text.lower() not in seen:
            seen.add(text.lower())
            out.append({"text": text, "kind": kind})

    for fq in (t.get("followup_queries") or []):
        add(fq, "gap")
    last = (t.get("hop_plan") or [{}])[-1] if t.get("hop_plan") else {}
    for mt in (last.get("missing_topics") or []):
        add(mt, "deepen")
    for gap in (t.get("gaps") or []):
        add(gap, "open")

    if db is not None:
        qw = _tok(exp.question)
        scored = []
        for a in db.query(Artifact).filter(Artifact.investigation_id == exp.investigation_id):
            if a.artifact_type in ("essay",) and a.id != exp.id:
                continue
            score = _jaccard(qw, _tok(a.tags)) + 0.5 * _jaccard(qw, _tok(a.title))
            scored.append((score, a))
        for _, a in sorted(scored, key=lambda x: -x[0])[:4]:
            if a.id != exp.id and a.title:
                add(a.title, "graph")

    return out[:8]


def _quiz_from_answer(exp: Explanation) -> dict:
    """Generate an interactive quiz (MCQ + rationale) anchored to the answer."""
    a = {}
    try:
        a = json.loads(exp.answer or "{}")
    except Exception:
        pass
    text = []
    core = (a.get("summary") or "").strip()
    if core:
        text.append(core)
    for s in (a.get("sections") or [])[:6]:
        body = " ".join((s.get("body") or "").split())
        if body:
            text.append(f"{s.get('heading')}: {body[:2400]}")
    ground = (a.get("key_points") or [])
    if ground:
        text.append("Key points: " + ". ".join(str(k) for k in ground[:8]))
    material = "\n\n".join(text)[:12000]
    if not material:
        raise ValueError("Answer not ready yet")
    prompt = (
        "You are a sharp science tutor writing a review quiz for the material below. "
        "Create exactly 5 concise multiple-choice questions. "
        "Each question must be answerable from the material; include 4 options, exactly one correct. "
        "Make sure the wrong options are plausible, not silly. "
        "Return STRICT JSON only, an array of items:\n"
        '[{"question": "...", "options": ["a", "b", "c", "d"], '
        '"correct_index": int, "rationale": "why the correct answer is right, from the material"}]\n'
        "No markdown fences, no extra text.\n\nMATERIAL:\n" + material
    )
    raw = llm.chat_json([{"role": "user", "content": prompt}], max_tokens=2000)
    items = []
    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, dict) and isinstance(raw.get("items"), list):
        items = raw["items"]
    clean = []
    for it in items[:8]:
        if not isinstance(it, dict) or not it.get("question"):
            continue
        opts = [o for o in (it.get("options") or []) if isinstance(o, str) and o.strip()]
        if len(opts) != 4 or not isinstance(it.get("correct_index"), int) or not it.get("rationale"):
            continue
        if not (0 <= it["correct_index"] < len(opts)):
            continue
        clean.append({
            "question": it["question"][:500],
            "options": [o[:300] for o in opts],
            "correct_index": it["correct_index"],
            "rationale": str(it["rationale"])[:600],
        })
    if not clean:
        raise ValueError("Could not produce quiz items")
    return {"items": clean}
