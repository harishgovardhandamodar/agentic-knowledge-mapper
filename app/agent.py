"""Agentic investigation loop: plan -> search -> analyze -> map.

Runs in a background thread with its own DB session. Progress is streamed
as AgentEvents the GUI polls. All reasoning goes through the fox-services
LLM gateway (see app/llm.py).
"""
import contextvars
import json
import re
import threading
import traceback
import urllib.parse
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .database import SessionLocal
from .models import Investigation, Artifact, Relationship, AgentRun, AgentEvent
from . import ledger as L
from . import llm, search as providers
from . import yield_ as yld

ANALYZE_BATCH = 5
KEEP_THRESHOLD = 0.4

# Phases this agent actually reports, declared up front so the mandate can check
# the agent against its own plan instead of rubber-stamping whatever it did.
AGENT_STAGES = ["plan", "search", "analyze", "map", "summary"]


def ledger_run_id(run_id: int) -> str:
    """Ledger id for an ``AgentRun``. Keyed off the product's own row so the
    chain and the run the UI already shows are the same thing."""
    return f"akm-{run_id}"


def _event(db: Session, run_id: int, stage: str, message: str, data: dict | None = None):
    db.add(AgentEvent(run_id=run_id, stage=stage, message=message,
                      data=json.dumps(data or {})))
    db.commit()
    # Same step, onto the chain. No-ops outside a ledger scope, so this costs
    # nothing for callers that are not being audited.
    L.record_agent_step(stage, message, data)


def _collect_run_cves(db, run, inv):
    """Known-issue sweep at the end of a run. Returns the new CVE ids.

    Called from the run tail so every investigation -- new ones included --
    picks up CVE findings as part of the workflow itself, not from a click.
    Fail-open by contract: enrichment must never fail the run it enriches.
    """
    try:
        from . import cve as _cve
        found = _cve.collect_investigation_cves(db, inv.id)
    except Exception:
        return []
    if found["collected"]:
        _event(db, run.id, "cve",
               f"Known issues: collected {len(found['collected'])} CVE(s) "
               f"({', '.join(found['collected'][:5])}).",
               {"cves": found["collected"]})
    return found["collected"]


def _plan_queries(inv: Investigation) -> dict:
    sys = ("You are a research search planner. Given an investigation brief, "
           "produce targeted search queries. Reply with JSON only.")
    user = (f"Title: {inv.title}\nKeywords: {inv.keywords}\n"
            f"Brief: {inv.description}\nEnabled sources: {inv.sources}\n\n"
            "Reply JSON: {\"rationale\": str, \"queries\": "
            "[{\"text\": str, \"sources\": [\"rss\"|\"arxiv\"|\"web\"]}]}. "
            "Max 6 queries, each 2-6 words. Match sources to query type "
            "(papers->arxiv, news/discussion->rss+web). Only use enabled sources. "
            "If the brief names a specific product or vendor, devote at least "
            "one query to official docs, security/trust, or architecture pages.")
    try:
        from . import provider_posture as _pp
        _provider_brief = _pp.is_provider_investigation(
            inv.title or "", inv.keywords or "", inv.description or "")
    except Exception:
        _provider_brief = False
    if _provider_brief:
        user += _provider_prompt_hint()
    plan = llm.chat_json([{"role": "system", "content": sys},
                          {"role": "user", "content": user}], max_tokens=1024)
    queries = (plan.get("queries") or [])[:6]
    enabled = set(s.strip() for s in (inv.sources or "").split(",") if s.strip())
    clean = []
    for q in queries:
        if not isinstance(q, dict) or not q.get("text"):
            continue
        srcs = [s for s in (q.get("sources") or []) if s in enabled] or list(enabled)
        clean.append({"text": q["text"][:120], "sources": srcs})
    _ensure_vendor_doc_query(inv, clean, enabled)
    _ensure_model_queries(inv, clean, enabled)
    _ensure_provider_posture_queries(inv, clean, enabled)
    return {"rationale": plan.get("rationale", ""), "queries": clean or
            [{"text": inv.keywords.split(",")[0].strip() or inv.title, "sources": list(enabled)}]}


_MODEL_FAMILY_HINTS = (
    ("tabular", "tabular foundation model"),
    ("tabpfn", "TabPFN"),
    ("diffusion", "diffusion model"),
    ("stable diffusion", "Stable Diffusion"),
    ("embedding", "embedding model"),
    ("time series", "time-series foundation model"),
    ("multimodal", "multimodal model"),
    ("llm", "large language model"),
    ("gpt", "GPT"), ("llama", "LLaMA"), ("mistral", "Mistral"),
    ("bert", "BERT"), ("clip", "CLIP"),
)


def _ensure_model_queries(inv: Investigation, clean: list[dict],
                          enabled: set[str]) -> None:
    """W1/W2 query families when the brief targets a model.

    A model brief needs adversarial literature (W1: memorization, membership
    inference, extraction, poisoning) and primary model documentation (W2:
    model card, weights, limitations) alongside general material. General
    OWASP/arXiv queries already planned are kept; these families are added,
    capped at six queries total.
    """
    try:
        from . import security as _sec
        prof = _sec.profile_model_subject(
            inv.title or "", inv.description or "",
            (inv.keywords or "").split(","))
        is_model = bool(prof.get("is_model_query"))
    except Exception:
        is_model = False
    if not is_model:
        return
    blob = " ".join(q.get("text") or "" for q in clean).lower()
    brief = f"{inv.title or ''} {inv.keywords or ''}".lower()
    family = ""
    for hint, name in _MODEL_FAMILY_HINTS:
        if hint in brief:
            family = name
            break
    subject = family or " ".join(_vendor_terms(inv)) or "foundation model"
    srcs = ["web", "arxiv"]
    srcs = [s for s in srcs if s in enabled] or sorted(enabled)
    if not srcs:
        return
    if len(clean) < 6 and not re.search(
            r"memorization|membership inference|extraction|poisoning|"
            r"adversarial", blob):
        clean.append({"text": f"{subject} memorization membership "
                              f"inference extraction"[:120], "sources": srcs})
    if len(clean) < 6 and not re.search(
            r"model card|huggingface|weights|checkpoint|red.?team|"
            r"benchmark", blob):
        clean.append({"text": f"{subject} model card weights "
                              f"limitations"[:120], "sources": srcs})
    if len(clean) < 6 and not re.search(
            r"differential privacy|unlearning|watermark|robustness|"
            r"mitigat", blob):
        clean.append({"text": f"differential privacy unlearning "
                              f"watermarking {subject}"[:120],
                      "sources": srcs})


def _vendor_terms(inv: Investigation) -> list[str]:
    """Capitalized words in the title: usually the vendor/product names."""
    seen: set[str] = set()
    out: list[str] = []
    for w in re.findall(r"[A-Z][a-zA-Z0-9]+", inv.title or ""):
        lw = w.lower()
        if lw not in seen and lw not in {"ai", "the", "and", "for", "with",
                                         "from", "that", "this", "what",
                                         "using", "used", "use"}:
            seen.add(lw)
            out.append(w)
    return out[:3]


_DOC_QUERY_RE = re.compile(
    r"doc(s|umentation)?|security|trust|architect|data.?flow|processor|"
    r"compliance|\bdpa\b|privacy", re.I)


def _ensure_vendor_doc_query(inv: Investigation, clean: list[dict],
                             enabled: set[str]) -> None:
    """Guarantee one official-docs query when the brief names a product.

    General threat-model material (OWASP, arXiv) is kept as supporting
    evidence, but a product brief with no vendor-doc query never discovers
    the processor list, region, or audit-log schema the report later
    admits are missing. Mutates ``clean`` in place; capped at six queries.
    """
    vendors = _vendor_terms(inv)
    if not vendors or len(clean) >= 6:
        return
    blob = " ".join(q.get("text") or "" for q in clean)
    if _DOC_QUERY_RE.search(blob) or _DOC_QUERY_RE.search(inv.keywords or ""):
        return
    srcs = ["web"] if "web" in enabled else sorted(enabled)
    if not srcs:
        return
    clean.append({"text": f"{' '.join(vendors)} security architecture "
                          "data flow"[:120], "sources": srcs})


def _provider_prompt_hint() -> str:
    """Planner prompt suffix for provider posture briefs.

    Factored out so tests can pin the wording without invoking the planner
    (whose module-level function other suites stub out).
    """
    # The six-query budget cannot cover policy, trust, safety and feedback
    # families, so the planner itself must spread across them: official
    # terms first, safety literature alongside (never instead), capability
    # comparisons out.
    return (" This is a provider data-posture brief: cover official "
            "privacy and data-usage terms, trust-center material, "
            "feedback and retention terms, and safety evaluations -- "
            "not capability leaderboards or timelines.")


def _ensure_provider_posture_queries(inv: Investigation, clean: list[dict],
                                     enabled: set[str]) -> None:
    """Policy/trust query families for provider posture investigations.

    A posture brief needs official terms (privacy policy, API data usage,
    opt-out, enterprise/ZDR terms, DPA/subprocessors), trust material (SOC 2,
    whitepapers -- claims, not proof) and independent reporting (practices,
    incidents, regulatory actions). Without these families the collection
    fills with capability chatter the brief explicitly anti-focused. Mutates
    ``clean`` in place; capped at six queries total.
    """
    from . import provider_posture as _pp
    blob = f"{inv.title or ''}\n{inv.keywords or ''}\n{inv.description or ''}"
    if not _pp.is_provider_investigation(inv.title or "", inv.keywords or "",
                                         inv.description or ""):
        return
    providers = _pp.detect_providers(blob)
    subject = providers[0]["name"] if providers else "AI provider"
    families = [
        # Primary sources first: official terms decide posture, everything
        # else contextualizes. Order is load-bearing -- the planner caps at
        # six queries, so the first families win the remaining slots.
        f"{subject} privacy policy API data usage training",
        f"{subject} enterprise zero retention DPA subprocessors",
        f"{subject} feedback thumbs training data retention",
        f"{subject} human review chat retention",
        f"{subject} improve the model setting opt-out",
        f"{subject} zero data retention API abuse monitoring",
        f"{subject} trust center SOC 2 security whitepaper",
        f"{subject} training data practices incident regulatory",
        # Safety research sits alongside policy sources, never instead of
        # them: frameworks and eval practice contextualize the lab without
        # answering corpus membership.
        f"{subject} responsible scaling deployment policy",
        f"{subject} system card safety evaluation red team",
        f"{subject} RLHF preference data human feedback",
        f"{subject} covered model retention safety",
        f"{subject} privacy policy RLHF preference data",
    ]
    have = " ".join(q.get("text") or "" for q in clean).lower()
    srcs = ["web"] if "web" in enabled else sorted(enabled)
    if not srcs:
        return
    for text in families:
        if len(clean) >= 6:
            return
        if text.lower() in have:
            continue
        clean.append({"text": text[:120], "sources": srcs})
        have += " " + text.lower()


def _search_one(args) -> list:
    query, src = args
    try:
        if src == "rss":
            return providers.search_rss(query)
        if src == "arxiv":
            return providers.search_arxiv(query)
        if src == "web":
            return providers.search_web(query)
    except Exception:
        pass
    return []


def _is_vendor_primary(cand: dict, vendors: list[str]) -> bool:
    """Official vendor surface: the URL host names the vendor.

    Title matching alone floods (every blog about Collibra mentions it);
    host matching keeps the boost for docs, trust centers and vendor blogs.
    Works on candidate dicts and artifact rows alike (both carry url).
    """
    if not vendors:
        return False
    try:
        host = (urllib.parse.urlsplit(cand.get("url") or "").hostname or "")
    except Exception:
        host = ""
    host = host.lower()
    return any(v.lower() in host for v in vendors if v)


def _keyword_terms(inv: Investigation) -> list:
    raw = f"{inv.title} {inv.keywords} {inv.description}"
    words = re.findall(r"[a-z0-9][a-z0-9\-]{2,}", raw.lower())
    stop = {"the", "and", "for", "with", "from", "that", "this", "what",
            "which", "about", "into", "collect", "recent", "work", "should",
            "agent", "relevant", "including", "between", "such", "are"}
    terms = [w for w in words if w not in stop]
    # brief keywords first (comma-separated carry more weight via order)
    kw = [t.strip().lower() for t in (inv.keywords or "").split(",") if t.strip()]
    return kw + [t for t in terms if t not in kw]


def _prefilter(inv: Investigation, found: list, keep_n: int) -> list:
    """Cheap keyword pre-rank so the LLM only sees the top candidates."""
    terms = _keyword_terms(inv)
    if not terms:
        return found[:keep_n]
    vendors = _vendor_terms(inv)
    scored = []
    for c in found:
        title = (c.get("title") or "").lower()
        desc = (c.get("description") or "").lower()
        s = sum((2 if t in title else 0) + (1 if t in desc else 0) for t in terms)
        if _is_vendor_primary(c, vendors):
            s += 2
        scored.append((s, c))
    scored.sort(key=lambda kv: -kv[0])
    # Always keep at least the top slice even if scores are 0.
    return [c for _, c in scored[:keep_n]]


def _run_searches(queries: list, seen_urls: set) -> list:
    # Fan out across threads: sequential would be minutes (6 queries x sources).
    from concurrent.futures import ThreadPoolExecutor
    tasks = [(q["text"], src) for q in queries for src in q["sources"]]
    found = []
    with ThreadPoolExecutor(max_workers=min(8, len(tasks) or 1)) as pool:
        for hits in pool.map(_search_one, tasks):
            for h in hits:
                key = (h.get("url") or "").strip().lower() or h.get("title", "").lower()
                if not key or key in seen_urls:
                    continue
                seen_urls.add(key)
                found.append(h)
    return found


def _analyze_batch(inv: Investigation, batch: list, existing: list,
                 model_subject: bool = False) -> list:
    """LLM relevance + attribute extraction for up to ANALYZE_BATCH candidates."""
    sys = ("You are a research analyst. Judge candidates against the brief. "
           "Reply with JSON only: a list with one object per candidate.")
    type_list = ("news|paper|essay|research|tweet|interview|book"
                 + ("|adversarial_paper|model_card|benchmark|cve_advisory|"
                    "weights_release|known_issue" if model_subject else ""))
    vendor_note = ""
    if _vendor_terms(inv):
        vendor_note = (" Prefer official vendor pages (docs, trust center, "
                       "security whitepapers) over blogs for product-specific "
                       "facts; keep general material as supporting evidence.")
    items = []
    for i, c in enumerate(batch):
        items.append(f"[{i}] {c['title']}\nURL: {c.get('url','')}\n"
                     f"{(c.get('description') or '')[:800]}")
    ctx = ""
    if existing:
        ctx = ("Already collected (reference by id for relates_to):\n" + "\n".join(
            f"- id {a['id']}: {a['title']} [{a.get('tags','')}]" for a in existing[:40]))
    user = (f"Brief: {inv.title} | {inv.keywords} | {inv.description}\n{ctx}\n\n"
            f"Candidates:\n" + "\n\n".join(items) + vendor_note +
            "\n\nReply JSON list: [{\"index\": i, \"relevance\": 0..1, \"keep\": bool, "
            "\"reason\": str, \"artifact_type\": " + type_list + ", "
            "\"tags\": [max 5 lowercase], \"sentiment\": -1..1, \"summary\": str (1-2 sentences), "
            "\"projection\": null | {\"type\": utopian|dystopian|cautionary|accelerationist|neutral, "
            "\"confidence\": 0..1, \"timeframe\": str, \"summary\": str}, "
            "\"relates_to\": [{\"id\": artifact_id, \"relationship_type\": "
            "references|supports|contradicts|builds_upon|responds_to|similar_to, "
            "\"description\": str}], \"drift\": bool (true if about a topic "
            "entirely outside this brief)}]")
    try:
        verdicts = llm.chat_json([{"role": "system", "content": sys},
                                  {"role": "user", "content": user}], max_tokens=4096)
    except Exception:
        return []
    return verdicts if isinstance(verdicts, list) else []


def _persist(db: Session, inv_id: int, kept: list, run_id: int | None = None) -> list:
    """Insert kept candidates, return [{id, title, tags}]."""
    rows = []
    for cand, v in kept:
        a = Artifact(
            investigation_id=inv_id,
            run_id=run_id,
            title=(cand["title"] or "(untitled)")[:500],
            artifact_type=v.get("artifact_type") or cand.get("artifact_type") or "news",
            url=(cand.get("url") or "")[:1000] or None,
            description=(v.get("summary") or cand.get("description") or "")[:2000],
            content=(cand.get("content") or "")[:4000] or None,
            source=(cand.get("source") or "")[:200],
            author=(cand.get("author") or "")[:200],
            date_published=cand.get("date_published"),
            tags=", ".join((v.get("tags") or [])[:5])[:500],
            sentiment=float(v.get("sentiment", 0) or 0),
            relevance=float(v.get("relevance", 0) or 0),
            relevance_reason=(v.get("reason") or "")[:500],
            review="pending", origin="agent",
            drift=1 if v.get("drift") else 0,
        )
        db.add(a)
        db.flush()
        rows.append({"id": a.id, "title": a.title, "tags": a.tags or "",
                     "relates_to": v.get("relates_to") or []})
    db.commit()
    return rows


def _map_relationships(db: Session, inv_id: int, rows: list,
                       pre_existing_ids: set, run_id: int | None = None) -> int:
    valid = pre_existing_ids | {r["id"] for r in rows}
    made, pairs = 0, set()
    allowed = {"references", "supports", "contradicts", "builds_upon",
               "responds_to", "similar_to"}
    for r in rows:
        for rel in (r.get("relates_to") or [])[:4]:
            try:
                tid = int(rel.get("id"))
            except (TypeError, ValueError):
                continue
            rtype = rel.get("relationship_type") if rel.get("relationship_type") in allowed else "similar_to"
            if tid not in valid or tid == r["id"] or (r["id"], tid) in pairs:
                continue
            pairs.add((r["id"], tid))
            db.add(Relationship(investigation_id=inv_id, source_id=r["id"],
                                target_id=tid, relationship_type=rtype,
                                description=(rel.get("description") or "")[:500],
                                origin="agent", run_id=run_id))
            made += 1
    # Tag-overlap fallback between newly added artifacts (capped).
    tagsets = {r["id"]: set(t.strip().lower() for t in (r["tags"] or "").split(",") if t.strip())
               for r in rows}
    ids = list(tagsets)
    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            if made >= 60:
                break
            if len(tagsets[ids[i]] & tagsets[ids[j]]) >= 2 and (ids[i], ids[j]) not in pairs:
                pairs.add((ids[i], ids[j]))
                db.add(Relationship(investigation_id=inv_id, source_id=ids[i],
                                    target_id=ids[j], relationship_type="similar_to",
                                    description="shared tags", origin="agent",
                                    run_id=run_id))
                made += 1
    db.commit()
    return made


def run_investigation_agent(investigation_id: int, max_items: int = 25,
                            max_rounds: int = 2, trigger: str = "manual",
                            run_id: int | None = None, goal: str | None = None):
    db = SessionLocal()
    rid = None            # ledger run id, once the AgentRun row exists
    try:
        inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
        if not inv:
            return
        if run_id is None:
            run = AgentRun(investigation_id=inv.id, status="running", trigger=trigger)
            db.add(run)
            db.commit()
        else:
            run = db.query(AgentRun).filter(AgentRun.id == run_id).first()
            if not run:
                return
            run.trigger = trigger
            if run.plan is None and goal:
                run.plan = json.dumps({"goal": goal})
            db.commit()
        run_id = run.id
        inv.status = "running"
        db.commit()

        rid = ledger_run_id(run.id)
        mandate = L.Mandate(
            objective=f"map the investigation '{inv.title}'",
            planned_intents=AGENT_STAGES,
            allowed_actors=["agent", "llm", "user", "system", "mcp", "human", "planner", "analyzer"],
        )
        run_label = f"AKM run: {inv.title[:60]}"
        with L.scope(rid, mandate, label=run_label):
            _event(db, run.id, "plan", f"Planning search for '{inv.title}'…")
            try:
                plan = _plan_queries(inv)
            except Exception as e:
                raise RuntimeError(f"planner failed: {e}")
            if goal:
                plan["goal"] = plan.get("goal") or goal
            try:
                from . import security as _sec
                _prof = _sec.profile_model_subject(
                    inv.title or "", inv.description or "",
                    (inv.keywords or "").split(","))
                plan["model_subject"] = bool(_prof.get("is_model_query"))
            except Exception:
                plan["model_subject"] = False
            run.plan = json.dumps(plan)
            db.commit()
            _event(db, run.id, "plan",
                   plan.get("rationale") or f"{len(plan['queries'])} queries planned.",
                   {"queries": plan["queries"]})

            seen = {(a.url or "").strip().lower() for a in
                    db.query(Artifact).filter(Artifact.investigation_id == inv.id).all()
                    if a.url}
            seen |= {a.title.lower() for a in
                     db.query(Artifact).filter(Artifact.investigation_id == inv.id).all()}
            total_kept, total_rels, rounds = 0, 0, 0
            queries = plan["queries"]
            # Spend the first round on what has paid off before. The planner
            # works from a blank slate every run, so without this a shape that
            # returned nothing last time is proposed first again.
            queries = yld.rank_queries(db, inv.id, queries)
            llm_calls_spent = 0
            vendor_forced = False
            refine_forced = False

            while rounds < max_rounds and total_kept < max_items:
                rounds += 1
                _event(db, run.id, "search",
                       f"Round {rounds}: searching {len(queries)} queries…")
                found = _run_searches(queries, seen)
                _event(db, run.id, "search", f"Round {rounds}: {len(found)} candidates.",
                       {"count": len(found),
                        "sample": [f["title"][:80] for f in found[:10]]})
                if not found:
                    break

                # Pre-rank cheaply: LLM analyzes only the top slice (3x target).
                analyze_cap = max(max_items * 3, 10)
                if len(found) > analyze_cap:
                    found = _prefilter(inv, found, analyze_cap)
                    _event(db, run.id, "search",
                           f"Round {rounds}: pre-ranked to top {analyze_cap} for analysis.")

                existing = [{"id": a.id, "title": a.title, "tags": a.tags or ""}
                            for a in db.query(Artifact)
                            .filter(Artifact.investigation_id == inv.id).all()]
                pre_ids = {e["id"] for e in existing}
                kept = []
                batches = 0
                for i in range(0, len(found), ANALYZE_BATCH):
                    batch = found[i:i + ANALYZE_BATCH]
                    batches += 1
                    llm_calls_spent += 1
                    verdicts = _analyze_batch(inv, batch, existing,
                                              model_subject=bool(
                                                  plan.get("model_subject")))
                    by_idx = {v.get("index"): v for v in verdicts
                              if isinstance(v, dict) and isinstance(v.get("index"), int)}
                    for j, cand in enumerate(batch):
                        v = by_idx.get(j)
                        if not v:
                            continue
                        try:
                            rel = float(v.get("relevance", 0))
                        except (TypeError, ValueError):
                            rel = 0
                        if (v.get("keep") or rel >= KEEP_THRESHOLD) and rel > 0:
                            kept.append((cand, v))
                    _event(db, run.id, "analyze",
                           f"Round {rounds}: analyzed {min(i + ANALYZE_BATCH, len(found))}/{len(found)}…")
                # Credit this round to the shapes that were asked, before any
                # early exit below. A round that analyzed candidates and kept
                # none is the single most useful thing to remember, and it is
                # exactly the round that used to leave no trace.
                survived = len(kept)
                try:
                    yld.record_yield(db, inv.id, queries, found=len(found),
                                     kept=survived, llm_calls=batches)
                except Exception as yexc:
                    _event(db, run.id, "analyze",
                           f"Round {rounds}: yield not recorded ({yexc}).")
                kept.sort(key=lambda kv: -float(kv[1].get("relevance", 0) or 0))
                kept = kept[:max(0, max_items - total_kept)]
                if not kept:
                    _event(db, run.id, "analyze", f"Round {rounds}: nothing worth keeping.")
                    break

                rows = _persist(db, inv.id, kept, run_id=run.id)
                rels = _map_relationships(db, inv.id, rows, pre_ids, run_id=run.id)
                total_kept += len(rows)
                total_rels += rels
                _event(db, run.id, "map",
                       f"Round {rounds}: kept {len(rows)}, mapped {rels} relationships.",
                       {"kept": [r["title"][:80] for r in rows]})
                for r in rows:
                    existing.append({"id": r["id"], "title": r["title"], "tags": r["tags"]})

                if total_kept >= max_items or rounds >= max_rounds:
                    break
                # Refinement round: ask planner for follow-up queries.
                # Once per run, if the brief names vendors but nothing kept
                # so far comes from their official surface, force one
                # vendor-doc query instead of hoping the planner
                # rediscovers it.
                if not vendor_forced:
                    vendor_forced = True
                    refine_forced = False
                    _vendors = _vendor_terms(inv)
                    if _vendors:
                        _kept_urls = [
                            a.url or "" for a in db.query(Artifact).filter(
                                Artifact.investigation_id == inv.id).all()]
                        if not any(_is_vendor_primary({"url": u}, _vendors)
                                   for u in _kept_urls):
                            _srcs = ["web"] if "web" in (
                                inv.sources or "") else ["rss"]
                            queries = [{
                                "text": (f"{' '.join(_vendors)} security "
                                         f"architecture documentation")[:120],
                                "sources": _srcs}]
                            refine_forced = True
                            _event(
                                db, run.id, "plan",
                                "Refinement: forced vendor-doc query "
                                "(nothing kept from vendor-primary sources).",
                                {"queries": queries})
                if refine_forced:
                    refine_forced = False
                    continue
                try:
                    follow = llm.chat_json([
                        {"role": "system",
                         "content": "Research search planner. Reply JSON only."},
                        {"role": "user",
                         "content": (f"Brief: {inv.title} | {inv.keywords} | {inv.description}\n"
                                     f"Kept so far ({total_kept}): "
                                     f"{[e['title'][:60] for e in existing[-8:]]}\n"
                                     "Reply {\"queries\": [{\"text\": str, \"sources\": [...]}]} "
                                     "max 3 follow-up queries exploring gaps. "
                                     f"Sources allowed: {inv.sources}")}],
                        max_tokens=512)
                    queries = [{"text": q["text"][:120], "sources": q.get("sources") or ["web"]}
                               for q in (follow.get("queries") or [])[:3] if q.get("text")]
                    if not queries:
                        break
                    # The planner has no memory of what worked; the yield ledger
                    # does, so its proposals are re-ranked before they cost
                    # anything. Order is the only change -- nothing is dropped.
                    queries = yld.rank_queries(db, inv.id, queries)
                    _event(db, run.id, "plan", f"Refinement: {len(queries)} follow-up queries.",
                           {"queries": queries})
                except Exception:
                    break

            shapes = yld.shape_stats(db, inv.id)
            stats = {"rounds": rounds, "artifacts_kept": total_kept,
                     "relationships": total_rels, "llm_calls": llm_calls_spent,
                     "query_shapes": len(shapes)}
            run.stats = json.dumps(stats)
            run.status = "done"
            run.finished_at = datetime.now(timezone.utc)
            inv.status = "ready"
            db.commit()
            _event(db, run.id, "summary",
                   f"Done: {total_kept} artifacts, {total_rels} relationships in {rounds} round(s).",
                   stats)
            _collect_run_cves(db, run, inv)
    except Exception as e:
        try:
            run.status = "error"
            run.error = f"{e}\n{traceback.format_exc()[-2000:]}"
            run.finished_at = datetime.now(timezone.utc)
            inv = db.query(Investigation).filter(
                Investigation.id == investigation_id).first()
            if inv:
                inv.status = "ready"
            db.commit()
            _event(db, run.id, "summary", f"Run failed: {e}")
            # The scope above has closed, so reopen it briefly: a run that died
            # is exactly the run whose reason you need on the chain.
            if rid:
                with L.scope(rid, mandate, label=run_label):
                    L.record_agent_step("summary", f"Run failed: {e}",
                                        {"error": str(e)[:200],
                                         "trigger": trigger})
        except Exception:
            db.rollback()
    finally:
        db.close()


def launch_run(investigation_id: int, max_items: int = 25, max_rounds: int = 2,
               trigger: str = "manual"):
    # copy_context carries the session in: a thread started here does not
    # inherit contextvars, so without this the run would anchor to no session.
    ctx = contextvars.copy_context()
    t = threading.Thread(target=ctx.run,
                         args=(run_investigation_agent, investigation_id,
                               max_items, max_rounds, trigger),
                         daemon=True)
    t.start()
    return t


def _short_goal(goal: str, limit: int = 120) -> str:
    """A one-line plan message that never ends mid-word.

    A hard ``goal[:120]`` slice cut gap text like "...where prompts/outputs
    are transmitted" down to "...are transmit", which reads like a broken
    error in the run log instead of what it is: the announcement that a
    gap-investigation run started. The full goal is already stored on the run's
    plan row; this is only the display line.
    """
    goal = goal or ""
    if len(goal) <= limit:
        return goal
    cut = goal[:limit].rsplit(" ", 1)[0].rstrip(" ,;:")
    return (cut or goal[:limit]) + "…"


def requeue_interrupted_gaps(db, launcher=None) -> list[int]:
    """Relaunch explainer_gap runs killed mid-flight, once each.

    Gap runs are the highest-value follow-up research and they run on bare
    threads, so a restart used to drop them permanently. On boot, a gap run
    still marked running is relaunched with its original goal preserved; the
    attempt counter in the plan caps retries at two so a crash loop cannot
    requeue forever. Returns old plus fresh run ids so callers spare both
    from the generic interrupted marking.
    """
    launcher = launcher or launch_run_with_goal
    relaunched: list[int] = []
    fresh: list[int] = []
    stale = db.query(AgentRun).filter(
        AgentRun.status == "running",
        AgentRun.trigger == "explainer_gap").all()
    for r in stale:
        try:
            plan = json.loads(r.plan or "{}")
        except Exception:
            plan = {}
        goal = (plan.get("goal") or "").strip()
        attempt = plan.get("gap_attempt", 1)
        try:
            attempt = int(attempt)
        except (TypeError, ValueError):
            attempt = 1
        if not goal or attempt >= 2:
            continue
        new_id = launcher(r.investigation_id, goal, max_items=12,
                          max_rounds=1, trigger="explainer_gap",
                          plan_extra={"gap_attempt": attempt + 1})
        fresh.append(new_id)
        r.status = "error"
        r.error = (f"interrupted by server restart; re-queued as run #{new_id}")
        r.finished_at = datetime.now(timezone.utc)
        db.add(AgentEvent(run_id=r.id, stage="summary",
                          message=f"Run interrupted by server restart; "
                                  f"re-queued as run #{new_id}."))
        relaunched.append(r.id)
    db.commit()
    # Both: the old rows are now error (already excluded), and the fresh rows
    # are running *by design* -- the generic stale pass must spare them.
    return relaunched + fresh


def launch_run_with_goal(investigation_id: int, goal: str, max_items: int = 12,
                         max_rounds: int = 1, trigger: str = "explainer_gap",
                         plan_extra: dict | None = None):
    plan = {"goal": goal}
    if plan_extra:
        plan.update(plan_extra)
    db = SessionLocal()
    try:
        run = AgentRun(investigation_id=investigation_id, status="running",
                       trigger=trigger, plan=json.dumps(plan))
        db.add(run)
        db.commit()
        db.refresh(run)
        _event(db, run.id, "plan",
               f"Auto-investigate (from explanation): {_short_goal(goal)}")
        run_id = run.id
    finally:
        db.close()
    ctx = contextvars.copy_context()
    t = threading.Thread(target=ctx.run,
                         kwargs=dict(investigation_id=investigation_id,
                                     run_id=run_id, goal=goal,
                                     max_items=max_items, max_rounds=max_rounds,
                                     trigger=trigger),
                         daemon=True)
    t.start()
    return run_id
