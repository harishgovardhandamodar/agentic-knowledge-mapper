"""Agentic explainer: research a question on the web, then compose an
illustrated explanation (sections + images + key points + sources).

Runs in a background thread; the GUI polls the Explanation record.
"""
import json
import re
import threading
import time
import traceback
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import httpx
from bs4 import BeautifulSoup

from .database import SessionLocal
from .models import Explanation, Artifact
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


def _abs_url(base: str, src: str) -> str:
    try:
        u = urllib.parse.urljoin(base, (src or "").strip())
        if u.startswith("http://") or u.startswith("https://"):
            return u.split("#")[0]
    except Exception:
        pass
    return ""


def _fetch_page(url: str) -> dict | None:
    try:
        with httpx.Client(timeout=PAGE_TIMEOUT, headers=UA, follow_redirects=True) as client:
            r = client.get(url, headers={"Accept": "text/html"})
            if r.status_code != 200 or "html" not in (r.headers.get("content-type") or ""):
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
        if all(i["src"] != src for i in images):
            images.append({"src": src, "alt": alt, "hero": False})
        if len(images) >= 6:
            break
    return {"url": url, "title": title or url, "text": text, "images": images}


MIN_PAGE_CHARS = 300


def _research(question: str, max_pages: int = MAX_PAGES, trace: dict | None = None,
              extra_queries: list | None = None) -> tuple[list, list]:
    """Returns (pages, image_candidates)."""
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
    queries = queries or [question]
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
    trace.setdefault("timings_ms", {})["search"] = int((time.time() - t0) * 1000)
    trace.setdefault("hits", []).extend({
        "url": h.get("url"), "title": h.get("title"), "domain": _domain(h.get("url")),
        "source": h.get("source"), "rank": h.get("rank"), "query": h.get("query"),
    } for h in hits[:30])
    pages, rejected = [], []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=6) as pool:
        for page in pool.map(_fetch_page, [h["url"] for h in hits[:max_pages * 2]]):
            if page and page["text"] and len(page["text"]) >= MIN_PAGE_CHARS:
                if len(pages) < max_pages:
                    pages.append(page)
            else:
                rejected.append({"url": "", "reason": page is None and "fetch failed or non-HTML" or "no readable text"})
    # fill rejected with urls we actually tried
    tried = [h["url"] for h in hits[:max_pages * 2]]
    reject_urls = [u for u in tried if u.lower() not in {p["url"].lower() for p in pages}]
    rejected = [{"url": u, "reason": "fetch failed, non-HTML, or no readable text"} for u in reject_urls]
    trace.setdefault("timings_ms", {})["fetch"] = int((time.time() - t0) * 1000)
    trace.setdefault("fetched", []).extend({
        "url": page["url"], "title": page["title"], "kept": True, "reason": "page",
        "chars": len(page["text"]), "images": len(page["images"]),
    } for page in pages)
    trace.setdefault("fetched", []).extend({
        "url": url, "title": "", "kept": False, "reason": "unreadable",
        "chars": 0, "images": 0,
    } for url in reject_urls)
    images = []
    for p in pages:
        for img in p["images"]:
            if all(i["src"] != img["src"] for i in images):
                images.append({**img, "page": p["title"][:80], "page_url": p["url"]})
            if len(images) >= 14:
                break
    return pages, images


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


def _norm(s):
    return re.sub(r"\s+", " ", (s or "").lower()).strip()


def _quote_valid(text: str, quote: str) -> bool:
    nq = _norm(quote)
    nt = _norm(text)
    if not nq or len(nq) < 12:
        return False
    if nq in nt:
        return True
    head, tail = nq[:25], nq[-10:]
    return bool(head and tail and head in nt and tail in nt)


def _verify_grounding(answer: dict, pages: list) -> dict:
    """Drop invented citations/quotes; keep only ones found verbatim in sources."""
    stats = {"citations_total": 0, "citations_valid": 0, "citations_dropped": 0,
             "claims_total": 0, "grounding_violations": []}
    texts = [p["text"] for p in pages]
    for sec in (answer.get("sections") or []):
        new_claims = []
        for c in (sec.get("claims") or []):
            stats["claims_total"] += 1
            kept = []
            for cit in (c.get("citations") or [])[:3]:
                idx = cit.get("sourceIndex")
                stats["citations_total"] += 1
                if isinstance(idx, int) and 0 <= idx < len(texts) and _quote_valid(texts[idx], cit.get("quote") or ""):
                    kept.append({"sourceIndex": idx, "quote": (cit.get("quote") or "")[:180]})
                    stats["citations_valid"] += 1
                else:
                    stats["citations_dropped"] += 1
            if kept:
                c["citations"] = kept
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
             max_tokens: int = 4096) -> dict:
    m = mode or "explain"
    ctx = []
    for i, p in enumerate(pages):
        ctx.append(f"[{i}] {p['title']}\nURL: {p['url']}\n{p['text'][:2500]}")
    img_list = "\n".join(
        f"- {img['src']} (from: {img['page']}; alt: {img['alt'][:100]})"
        for img in images)
    mode_rules = _mode_rules(m, depth)
    aud_hint = AUDIENCE_HINTS.get(audience, AUDIENCE_HINTS["intermediate"])

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
            answer = llm.chat_json([
                {"role": "system",
                 "content": ("You are a technical explainer. Write a clear, accurate explanation "
                             "grounded ONLY in the provided sources (prefix graph:// = this project's "
                             "own knowledge graph). Reply with STRICT, well-formed JSON only. "
                             "Escape all quotes inside strings.")},
                {"role": "user",
                 "content": (f"Question: {question}\n\nAudience: {aud_hint}\n\n{mode_rules}\n\n"
                             f"Source budget: {len(pages)} sources.\n\nSources:\n" + "\n\n".join(ctx) +
                             f"\n\nCandidate images (reference EXACT URLs, don't invent):\n{img_list or '(none)'}\n\n"
                             "Reply JSON: {\"summary\": str (2-3 sentences), " + step["json"] + ", "
                             "\"key_points\": [str x3-6], plus any additional keys your mode rules require. "
                             "\"sources\": [{\"title\": str, \"url\": str}] (only URLs from the sources above)}")}],
                max_tokens=max_tokens)
            break
        except Exception as e:
            answer = None
            last_err = str(e)[:200]
    if answer is None:
        raise RuntimeError(f"LLM could not produce valid JSON explanation ({last_err})")
    valid_srcs = {p["url"] for p in pages}
    valid_imgs = {i["src"] for i in images}
    for s in (answer.get("sections") or []):
        if s.get("image") not in valid_imgs:
            s["image"] = None
    answer["sources"] = [s for s in (answer.get("sources") or [])
                         if isinstance(s, dict) and s.get("url") in valid_srcs][: len(pages)]
    if not answer.get("sources"):
        answer["sources"] = [{"title": p["title"], "url": p["url"]} for p in pages]
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

        pages, images, answer, grounding = [], [], None, None
        seen_urls = set()
        hop_list = []
        for hop in range(max_hops + 1):
            hop_pages = []
            if hop == 0:
                if graph and not graph_brief.get("needs_web"):
                    trace["web_skipped"] = True
                    hop_pages = _graph_pages(graph)
                else:
                    if graph_brief.get("gaps") and not graph_brief.get("needs_web"):
                        trace["web_fallback_reason"] = "graph partial"
                    extra = (graph_brief.get("followup_queries")
                             if graph_brief.get("needs_web") else None)
                    hop_pages, images = _research(exp.question, max_pages,
                                                  trace=trace, extra_queries=extra)
                    if graph:
                        trace["web_fallback_reason"] = "hybrid: graph + web"
                        hop_pages = _graph_pages(graph[:4]) + hop_pages
            else:
                missing = hop_list[-1].get("missing_topics", [])[:2]
                if not missing:
                    break
                hop_pages, new_img = _research(
                    exp.question, max(int(max_pages * 0.4), 2), trace=trace,
                    extra_queries=missing)
                images += new_img
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
            answer = _compose(exp.question, pages[:12], images, mode=mode, depth=depth,
                              audience=audience, max_tokens=max_tokens)
            grounding = _verify_grounding(answer, pages)
            eval_res = _eval_answer(exp.question, answer)
            if eval_res.get("needs_more") and (hop + 1) <= max_hops:
                hop_list.append({"hop": hop + 1,
                                 "missing_topics": eval_res.get("missing_topics", []),
                                 "new_pages": 0})
                continue
            break
        trace["hops"] = len(hop_list)
        trace["hop_plan"] = hop_list
        trace["citations"] = {k: v for k, v in grounding.items()
                              if k != "grounding_violations"} if grounding else {}
        if grounding and grounding["grounding_violations"]:
            trace["citations"]["grounding_violations"] = grounding["grounding_violations"]
        if grounding:
            answer["grounding"] = {k: v for k, v in grounding.items()
                                   if k != "grounding_violations"}
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
    t = threading.Thread(target=run_explainer,
                         args=(exp_id, max_pages, max_hops), daemon=True)
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
