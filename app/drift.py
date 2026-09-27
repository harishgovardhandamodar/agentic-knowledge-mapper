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


#: Size of the character n-grams used for the stem-level net, and how many must
#: be shared with the brief or corpus to clear an item.
#:
#: Three letters was too few: "Encephalitis" shares "ali" and "lit" with
#: "alignment", which is enough to clear a biomedical item out of an
#: interpretability investigation. Four letters survives the real cases and
#: still catches the stems it is for -- "reward hacking" and "Rewarding the
#: wrong thing" share "rewa". The bar is deliberately low, because this stage
#: exists to *find* items for the semantic judge: a false positive costs one
#: cheap batch item, a false negative hides real drift.
NGRAM = 4
MIN_SHARED_NGRAMS = 2


def content_tokens(s: str) -> set:
    """Lowercased word tokens minus stopwords.

    Two- and three-letter tokens survive only when the source text had a
    capital in them, which is what an acronym looks like. The old rule dropped
    every token under four characters, throwing away ``AI``, ``ML`` and
    ``LLM`` -- the words a frontier-AI brief is actually built from, and the
    ones most able to tell a biomedical item from an AI one.

    The capital test is "any capital", not "all capitals", so mixed-case
    acronyms like ``IoT`` and ``iOS`` count too. Sentence-initial capitals
    ("An", "Of", "We") do not get through, because every one of those is
    already a stopword, and lowercase fragments like ``de``/``fr`` never had a
    capital to begin with.
    """
    out = set()
    for m in re.finditer(r"[A-Za-z0-9][A-Za-z0-9\-_]*", s or ""):
        w = m.group(0)
        low = w.lower()
        if low in _STOPWORDS:
            continue
        if len(w) >= 4:
            out.add(low)
        elif len(w) >= 2 and any(c.isupper() for c in w):
            out.add(low)
    return out


def ngrams(s: str, n: int = NGRAM) -> set:
    """Character n-grams over the alphanumeric skeleton of ``s``.

    A vocabulary prefilter is blind to inflection and phrasing: "reward
    misspecification" against a brief about "reward hacking" shares no words,
    yet it is squarely on-brief. N-grams catch the shared stem without a model
    call, a dictionary, or a dependency -- and they are format-agnostic, so
    "reward hacking" and "reward-hacking" produce the same set.

    Punctuation collapses to a single space rather than vanishing, so a match
    cannot be manufactured by joining two unrelated words across a hyphen.
    """
    skeleton = re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()
    if len(skeleton) < n:
        return {skeleton} if skeleton else set()
    return {skeleton[i:i + n] for i in range(len(skeleton) - n + 1)}


def brief_terms(title: str, keywords: str, description: str) -> set:
    return (content_tokens(title)
            | content_tokens((keywords or "").replace(",", " "))
            | content_tokens(description))


def item_terms(title: str, tags: str, description: str = "") -> set:
    """The vocabulary of one item.

    ``description`` matters as much as the title: a paper titled "A study" and
    tagged "research" says what it is about only in its body, and judging that
    on its title alone throws away the evidence the collector already fetched.
    """
    return (content_tokens(title)
            | content_tokens((tags or "").replace(",", " "))
            | content_tokens(description or ""))


def drift_candidates(brief: set, corpus: set, items: list, *,
                     brief_text: str = "", corpus_text: str = "",
                     min_ngrams: int = MIN_SHARED_NGRAMS) -> list:
    """Items sharing no vocabulary with the brief or the collected corpus.

    Each item is ``{"id":..., "title":..., "tags":..., "description":...}``;
    returns the subset that needs a semantic verdict. Everything else is
    definitionally on-brief.

    Three ways to clear an item, because each alone is too strict:

    * a shared word with the brief or the corpus terms;
    * shared character n-grams with the brief or corpus *text* -- the
      stem-level match that catches "Rewarding the wrong thing" against a brief
      about "reward hacking", and which needs no model call;
    * a short item whose own text is a substring of the brief, so a two-word
      title like "Reward hacking" is not sent to the judge on a technicality.

    Without the ``*_text`` arguments the n-gram stages are skipped, which is the
    original term-only behaviour; every caller now passes them.
    """
    brief_grams = ngrams(brief_text) if brief_text else set()
    corpus_grams = ngrams(corpus_text) if corpus_text else set()
    brief_blob = re.sub(r"\s+", " ", (brief_text or "").lower()).strip()
    corpus_blob = re.sub(r"\s+", " ", (corpus_text or "").lower()).strip()
    out = []
    for it in items or []:
        terms = item_terms(it.get("title") or "", it.get("tags") or "",
                           it.get("description") or "")
        if not terms:
            continue
        if terms & brief or terms & corpus:
            continue
        text = re.sub(
            r"\s+", " ",
            " ".join(str(it.get(f) or "")
                     for f in ("title", "tags", "description"))).lower().strip()
        if not text:
            continue
        if _contained_in(text, brief_blob) or _contained_in(text, corpus_blob):
            continue
        if brief_grams or corpus_grams:
            grams = ngrams(text)
            shared = len(grams & brief_grams) + len(grams & corpus_grams)
            if shared >= min_ngrams:
                continue
        out.append(it)
    return out


def _contained_in(text: str, blob: str) -> bool:
    """Is this whole short item literally inside the brief or corpus?

    A phrase that appears verbatim in the brief is on-brief by definition, and
    n-grams cannot tell that reliably for a two-word item -- there are simply
    too few of them to clear the threshold. Only applies to short items, so a
    long item cannot excuse itself by containing a common word.
    """
    if not blob or len(text) > 60 or len(text.split()) > 6:
        return False
    return text in blob


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
