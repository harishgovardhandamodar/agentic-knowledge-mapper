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
import time

#: How long to wait before retrying a drift batch. Linear, and tiny: the judge
#: is a handful of small calls, so a slow exponential backoff would cost more
#: than the call it is protecting.
_BACKOFF_S = 0.25

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
                   batch: int = 8, retries: int = 2) -> dict:
    """LLM verdict over prefiltered candidates, reported as a verdict report.

    Returns ``{"ids", "judged", "overflow", "failed", "error", "complete"}``:
    ``ids`` is the set of candidate ids judged off-brief, ``failed`` counts
    batches that never returned a usable verdict, ``overflow`` counts
    candidates past ``limit`` that were never sent, and ``complete`` is True
    only when the whole candidate set was judged.

    Fail-open is still the contract -- a batch that keeps failing marks nothing
    rather than mis-marking, and a caller that only reads ``ids`` behaves
    exactly as before. What changed is that the difference between "no drift
    found" and "we never got to look" is now visible instead of inferred from
    an empty set. That distinction was the whole problem: a dead gateway made
    the corpus look clean.

    Batches are small on purpose. One long list invites truncation mid-JSON,
    which parses to nothing and silently clears real drift.
    """
    cands = (candidates or [])[:limit]
    report = {"ids": set(), "judged": len(cands),
              "overflow": max(0, len(candidates or []) - limit),
              "failed": 0, "error": "", "complete": False}
    if not cands:
        report["complete"] = report["overflow"] == 0
        return report
    try:
        from . import llm
        want = {c.get("id") for c in cands}
        drifted = set()
        for i in range(0, len(cands), batch):
            chunk = cands[i:i + batch]
            ids, err = _judge_batch(llm, brief_text, chunk, want, retries)
            if ids is None:
                report["failed"] += 1
                report["error"] = err
            else:
                drifted |= ids
        report["ids"] = drifted
        # Overflow counts as incomplete: those candidates were never sent, so a
        # clean-looking result covers less of the corpus than it appears to.
        report["complete"] = report["failed"] == 0 and report["overflow"] == 0
    except Exception as exc:  # noqa: BLE001 - fail-open, but report it
        report["failed"] = 1
        report["error"] = f"{type(exc).__name__}: {exc}"
    _audit_judge(report, len(candidates or []))
    return report


def _judge_batch(llm, brief_text: str, chunk: list, want: set,
                 retries: int) -> tuple:
    """One batch, with retries. Returns ``(ids, error)``.

    ``ids is None`` means no usable verdict came back; the error explains why.
    A retry is worth it because the common failures are transient -- a gateway
    blip or a truncated response -- and a batch that eventually answers is
    indistinguishable, downstream, from one that answered first time.
    """
    listing = "\n".join(
        f"- id {c.get('id')}: {(c.get('title') or '')[:150]} "
        f"[{c.get('tags') or ''}]" for c in chunk)
    last = "no attempt made"
    for attempt in range(max(1, retries + 1)):
        try:
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
                return {x for x in (res.get("drift_ids") or [])
                        if isinstance(x, int) and x in want}, ""
            last = f"unexpected response shape: {type(res).__name__}"
        except Exception as exc:  # noqa: BLE001 - retried, then reported
            last = f"{type(exc).__name__}: {exc}"
        if attempt < retries:
            time.sleep(_BACKOFF_S * (attempt + 1))
    return None, last


def _audit_judge(report: dict, n_candidates: int) -> None:
    """Put an incomplete drift verdict on the ledger.

    The prefilter and the judge are the only thing standing between a wrong
    corpus and a confident answer about it, so "we could not check" has to be
    an event on the chain rather than an absence of one. Emitted only when
    something was actually missed -- a clean sweep stays quiet.
    """
    if report.get("complete"):
        return
    try:
        from . import ledger
        detail = {"candidates": n_candidates, "judged": report.get("judged"),
                  "failed_batches": report.get("failed"),
                  "overflow": report.get("overflow"),
                  "error": (report.get("error") or "")[:300],
                  "reason": incomplete_reason(report)}
        ledger.record_internal_event(
            "drift.judge", "drift-judge", data=detail,
            verdict="flag", severity="warn")
    except Exception:  # noqa: BLE001 - auditing must not break the caller
        return


def incomplete_reason(report: dict) -> str:
    bits = []
    if report.get("failed"):
        bits.append(f"{report['failed']} batch(es) returned no verdict")
    if report.get("overflow"):
        bits.append(f"{report['overflow']} candidate(s) past the judge limit")
    return "; ".join(bits) or "incomplete"
