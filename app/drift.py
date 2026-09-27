"""Brief-drift detection for collected artifacts.

Drift means off-brief: an item about a topic foreign to the investigation
(e.g. biomedical virus concepts inside an AI-alignment brief). Drift items
are kept, not deleted -- they are flagged so the list, graph, and review
queue can dim or filter them.

Two stages, because neither works alone:
1. A deterministic prefilter (shared vocabulary with the brief or with the
   already-collected corpus). Cheap, but blind to synonyms -- "Reward
   misspecification" shares no words with its brief yet is on-topic.
2. An LLM batch verdict over the prefilter's candidates only. Semantic, but
   costs a call -- so it never sees items the prefilter already clears.

Stdlib only at import time; the LLM client is imported lazily so this module
stays importable from anywhere without cycles.
"""
import re

_STOPWORDS = set(
    "the a an and or of to in on for with as at by from is are was were be been "
    "it its this that these those they them their he she we you your our ours "
    "his her him us they than then so such no nor not only own same too very can "
    "will just should now how what when where which who whom why all any both "
    "each few more most other some into over after before between out about up "
    "down off above below during including using used use uses often also may "
    "might must shall per via within without".split())


def content_tokens(s: str) -> set:
    """Lowercased word tokens minus stopwords. Short tokens ('AI', 'de') are
    dropped so acronyms and fragments don't manufacture relevance."""
    return {w for w in re.findall(r"[a-z0-9]{3,}", (s or "").lower())
            if w not in _STOPWORDS}


def brief_terms(title: str, keywords: str, description: str) -> set:
    return (content_tokens(title)
            | content_tokens((keywords or "").replace(",", " "))
            | content_tokens(description))


def item_terms(title: str, tags: str) -> set:
    return content_tokens(title) | content_tokens((tags or "").replace(",", " "))


def drift_candidates(brief: set, corpus: set, items: list) -> list:
    """Items sharing no vocabulary with the brief or the collected corpus.

    Each item is {"id":..., "title":..., "tags":...}; returns the subset that
    needs a semantic verdict. Everything else is definitionally on-brief.
    """
    out = []
    for it in items:
        terms = item_terms(it.get("title") or "", it.get("tags") or "")
        if not terms:
            continue
        if not (terms & brief) and not (terms & corpus):
            out.append(it)
    return out


def classify_drift(brief_text: str, candidates: list, limit: int = 30,
                   batch: int = 8) -> set:
    """LLM verdict over prefiltered candidates: ids that are off-brief.

    Candidates go out in small batches: one long list invites truncation
    mid-JSON, which parses to nothing and silently clears real drift.
    Fail-open by contract: any failure (no candidates, LLM error, bad shape)
    returns the empty set, so callers mark nothing rather than mis-marking.
    """
    cands = (candidates or [])[:limit]
    if not cands:
        return set()
    try:
        from . import llm
        drifted = set()
        want = {c.get("id") for c in cands}
        for i in range(0, len(cands), batch):
            chunk = cands[i:i + batch]
            listing = "\n".join(
                f"- id {c.get('id')}: {(c.get('title') or '')[:150]} "
                f"[{c.get('tags') or ''}]" for c in chunk)
            res = llm.chat_json([
                {"role": "system",
                 "content": "Topic-relevance judge. Reply JSON only."},
                {"role": "user",
                 "content": (f"Investigation brief: {brief_text[:800]}\n\n"
                             f"Candidates:\n{listing}\n\n"
                             "Which candidates are about a topic ENTIRELY outside "
                             "this brief (wrong domain, e.g. biomedical terms in "
                             "an AI brief)? Reply {\"drift_ids\": [int, ...]} "
                             "(empty list if none).")}],
                max_tokens=1024)
            if isinstance(res, dict):
                drifted |= {x for x in (res.get("drift_ids") or [])
                            if isinstance(x, int) and x in want}
        return drifted
    except Exception:
        return set()
