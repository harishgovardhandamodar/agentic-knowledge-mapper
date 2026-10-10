"""The grounding rules, in one place.

A claim is only as good as its sources, and the only way to know a model did
not invent something is to check the text against the text it was given. That
check is the app's main defence against hallucination, so it lives here --
stdlib-only, no app imports, no I/O -- and both the ledger and the explainer
call it.

Before this module the rule was implemented twice: ``ledger.quote_is_verbatim``
and ``explainer._quote_valid``. They were kept in sync by hand, which is exactly
how a grounding gate quietly stops grounding. The ledger kept its own copy
because importing from the explainer would drag in bs4/feedparser through
``llm``; a leaf module has no such edge, so the duplication is now just
removed rather than documented.

Two rules live here:

* :func:`quote_is_verbatim` -- does this quote actually occur in this source?
* :func:`verify_grounding` -- keep only the citations that survive, and score
  the survivors by how many *distinct* sources back them.

Plus the machinery that turns a surviving quote into a *falsifiable span* rather
than a truncated string, and a deliberately weak second opinion for the quotes
that verbatim matching rejects:

* :func:`locate_quote` -- where, exactly, in the original page does the quote
  live? Character offsets and paragraph index, so a claim can be re-checked
  without the corpus in hand and a reader can be pointed at the sentence.
* :func:`entail` / :func:`explain_drop` -- a stdlib heuristic that says *why* a
  quote failed: a negation flip, a swapped number or unit, or an honest
  paraphrase. It is not an NLI model and is not trusted as one; it labels the
  failure so callers (and regression fixtures) can act on the difference.
* :func:`calibrated_confidence` -- confidence as a function of source
  independence, entailment, source quality and recency, rather than a bare
  count. The old ladder is kept for the callers that pin it.
"""
import hashlib
import json
import re

#: A quote shorter than this (after normalisation) proves nothing: any two-word
#: fragment occurs in most prose, so verifying it would manufacture confidence
#: out of a coincidence. Chosen at 12 chars in the original ledger gate and
#: kept deliberately -- moving it changes every claim's verdict.
MIN_QUOTE_CHARS = 12

#: How much of a verified quote is kept. Long enough to re-check by eye, short
#: enough that the ledger row stays small.
QUOTE_STORE_CHARS = 180

# Corroboration ladder: distinct sources -> confidence label.
_CONFIDENCE = ("none", "low", "medium", "high")

_ID_RE = re.compile(r"#(\d+)\b")

#: Word tokenizer for the entailment heuristic. Kept ASCII-simple on purpose:
#: the point is a stable, auditable signal, not linguistic fidelity.
_WORD_RE = re.compile(r"[a-z0-9]+")

#: Negation markers. Used only to flag a *polarity* mismatch between a quote and
#: the source it claims to come from -- the classic "does not" vs "does" flip,
#: which is exactly the failure a substring check cannot see.
_NEGATIONS = frozenset(
    "no not never none neither nor cannot can't won't don't doesn't didn't "
    "isn't aren't wasn't weren't without lacks lack except excluding".split())

#: Numbers with optional decimal, e.g. "0.9" or "14". A quote's numbers that do
#: not appear anywhere in the source are the "number/unit swap" failure mode.
_NUM_RE = re.compile(r"\d+(?:\.\d+)?")

#: A paragraph break: a blank line, possibly with trailing whitespace.
_PARA_RE = re.compile(r"\n[ \t]*\n")


def norm(s: str) -> str:
    """Lowercase, collapse whitespace. The only normalisation applied before
    comparing a quote with its source -- deliberately conservative, because a
    looser rule (stripping punctuation, unicode-folding) starts accepting
    quotes that were paraphrased rather than quoted."""
    return re.sub(r"\s+", " ", (s or "").lower()).strip()


def quote_is_verbatim(text: str, quote: str) -> bool:
    """Does ``quote`` actually appear in ``text``?

    A quote under :data:`MIN_QUOTE_CHARS` normalised chars is rejected -- a
    two-word "quote" matches almost any source and proves nothing.
    """
    nq, nt = norm(quote), norm(text)
    if not nq or len(nq) < MIN_QUOTE_CHARS:
        return False
    if nq in nt:
        return True
    head, tail = nq[:25], nq[-10:]
    return bool(head and tail and head in nt and tail in nt)


def confidence_for(n_sources: int) -> str:
    """Corroboration label for a claim backed by ``n_sources`` distinct sources.

    One source agreeing with itself is not corroboration, hence the ladder
    starting at "low" rather than "high".
    """
    if n_sources >= 3:
        return "high"
    if n_sources == 2:
        return "medium"
    if n_sources == 1:
        return "low"
    return "none"


def _norm_map(text: str) -> tuple[str, list[int]]:
    """Normalise like :func:`norm`, but keep a map back to original offsets.

    Returns ``(normalised, offsets)`` where ``offsets[i]`` is the index in the
    original ``text`` of normalised character ``i``. Whitespace runs collapse to
    a single space anchored at the run's first character, and the result is
    stripped exactly as :func:`norm` strips -- so ``normalised`` equals
    ``norm(text)`` for the text this module sees in practice.
    """
    out: list[str] = []
    idx: list[int] = []
    pending_space = False
    for i, ch in enumerate(text or ""):
        if ch.isspace():
            if out:
                pending_space = True
            continue
        if pending_space:
            out.append(" ")
            idx.append(i)
            pending_space = False
        for c in ch.lower():
            out.append(c)
            idx.append(i)
    return "".join(out), idx


def paragraph_index(text: str, offset: int) -> int:
    """Zero-based paragraph number containing ``offset``.

    Paragraphs are blank-line separated -- the same split a reader would make.
    """
    if offset <= 0:
        return 0
    return len(_PARA_RE.findall((text or "")[:offset]))


def locate_quote(text: str, quote: str) -> dict | None:
    """Where does ``quote`` occur in ``text``? Offsets + paragraph, or ``None``.

    Two ways to match, mirroring :func:`quote_is_verbatim`: an exact normalised
    substring, or the head/tail fallback for a quote the model trimmed. The
    returned ``start``/``end`` are character offsets into the *original* text,
    which is what makes the citation a span a third party can re-check instead
    of a string they have to trust.
    """
    if not text or not quote:
        return None
    nt, idx = _norm_map(text)
    nq, _ = _norm_map(quote)
    if not nq or not idx:
        return None
    pos = nt.find(nq)
    if pos >= 0:
        end_norm, method = pos + len(nq), "exact"
    else:
        head, tail = nq[:25], nq[-10:]
        hp = nt.find(head) if head else -1
        if hp < 0 or not tail:
            return None
        tp = nt.find(tail, hp)
        if tp < 0:
            return None
        pos = hp
        end_norm = tp + len(tail)
        method = "headtail"
    end_norm = min(end_norm, len(idx))
    start = idx[pos]
    end = idx[end_norm - 1] + 1
    return {"start": start, "end": end, "paragraph": paragraph_index(text, start),
            "method": method}


def _tokens(s: str) -> list[str]:
    return _WORD_RE.findall((s or "").lower())


def _best_sentence(text: str, q_tokens: set) -> str:
    """The sentence of ``text`` sharing the most vocabulary with the quote.

    Polarity is judged against *this* sentence, not the whole source: a negation
    anywhere in a page would otherwise mark every quote from it as flipped.
    """
    best, best_n = "", -1
    for sent in re.split(r"(?<=[.!?])\s+", text or ""):
        n = len(q_tokens & set(_tokens(sent)))
        if n > best_n:
            best, best_n = sent, n
    return best


def entail(text: str, quote: str) -> dict:
    """A weak, stdlib entailment heuristic between a quote and source text.

    **Not** an NLI model. It answers three narrower, checkable questions: how
    much of the quote's vocabulary the source contains, whether the quote and
    the source's closest-matching *sentence* disagree in polarity (negation), and
    whether every number in the quote appears in the source. That is enough to
    separate "the model paraphrased" from "the model inverted the meaning" from
    "the model invented a figure", which one binary verbatim verdict cannot.
    Support is deliberately token overlap, so it is high for a truthful
    paraphrase and low for an invention.
    """
    qt, tt = _tokens(quote), set(_tokens(text))
    if not qt:
        return {"support": 0.0, "polarity": "unknown", "numbers": "match",
                "shared_terms": [], "missing_numbers": []}
    qs = set(qt)
    shared = qs & tt
    support = len(shared) / len(qs)
    q_neg = any(w in _NEGATIONS for w in qt)
    local = set(_tokens(_best_sentence(text, qs)))
    t_neg = any(w in _NEGATIONS for w in local)
    q_nums = set(_NUM_RE.findall(quote or ""))
    t_nums = set(_NUM_RE.findall(text or ""))
    missing = sorted(q_nums - t_nums)
    return {
        "support": round(support, 3),
        "polarity": "flip" if q_neg != t_neg else "match",
        "numbers": "swap" if missing else "match",
        "shared_terms": sorted(shared)[:12],
        "missing_numbers": missing,
    }


def explain_drop(text: str, quote: str) -> tuple[str, dict]:
    """Classify *why* a quote failed the verbatim gate.

    Returns ``(reason, entailment)``. The order matters: a swapped figure or an
    inverted polarity is a materially worse failure than an honest paraphrase,
    so those are reported first even when overlap is high.
    """
    e = entail(text, quote)
    if e["numbers"] == "swap":
        return "number_swap", e
    if e["polarity"] == "flip" and e["support"] >= 0.5:
        return "negation_flip", e
    if e["support"] >= 0.6:
        return "paraphrase", e
    return "not_found_in_source", e


def calibrated_confidence(n_sources: int, *, entailment: float = 1.0,
                          source_quality: float = 1.0, recency: float = 1.0,
                          independence: float = 1.0) -> float:
    """A 0..1 confidence that grows with independent corroboration, not raw count.

    The count enters through a saturating curve (``1 - 0.5**n``) so the third
    source adds less than the second, and one source is worth at most 0.5 --
    "one source agreeing with itself is not corroboration". Entailment, source
    quality, recency and independence are multiplicative discounts in 0..1, each
    defaulting to neutral. No evidence is exactly zero, never "low positive".
    """
    if n_sources <= 0:
        return 0.0

    def _clamp(v: float) -> float:
        try:
            return max(0.0, min(1.0, float(v)))
        except (TypeError, ValueError):
            return 1.0

    breadth = 1.0 - (0.5 ** int(n_sources))
    score = (breadth * _clamp(entailment) * _clamp(source_quality)
             * _clamp(recency) * _clamp(independence))
    return round(max(0.0, min(1.0, score)), 4)


def confidence_label(score: float) -> str:
    """Bucket a calibrated score back onto the existing ladder's labels."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "none"
    if s >= 0.75:
        return "high"
    if s >= 0.45:
        return "medium"
    if s > 0.0:
        return "low"
    return "none"


def claim_digest(text: str, citations: list | None = None,
                 offsets: list | None = None) -> str:
    """Content address binding a claim to its text, ordered citations and spans.

    Where :func:`app.ledger.claim_hash` addresses *what was said and on what
    sources*, this additionally folds in the exact offsets, so two claims from
    the same sentence are distinct if they point at different spans. Kept here
    (stdlib-only) so both the ledger and the claim graph can use one address
    without an import edge.
    """
    payload = {"text": (text or "").strip(),
               "citations": citations or [],
               "offsets": offsets or []}
    blob = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:24]



def _source_texts(sources) -> dict:
    """Normalise the two accepted source shapes into {key: text}.

    A list of page dicts (keyed by ``id``/``url``/position) or a mapping of
    source key -> text (or -> page dict with ``text``).
    """
    if isinstance(sources, dict):
        return {k: (v.get("text") if isinstance(v, dict) else str(v))
                for k, v in sources.items()}
    texts = {}
    for idx, page in enumerate(sources or []):
        key = page.get("id", page.get("url", idx)) if isinstance(page, dict) else idx
        texts[key] = page.get("text", "") if isinstance(page, dict) else str(page)
    return texts


def verify_grounding(claim_text: str, citations, sources,
                     *, entail_min: float | None = None) -> dict:
    """The hallucination gate: keep only citations a source actually contains.

    Returns the surviving citations, the dropped ones with a reason, and a
    corroboration score based on how many *distinct* sources back the claim.
    ``violation`` is True when nothing survived -- that is the signal callers
    use to stop a claim propagating.

    Each surviving citation carries the exact ``span`` it was found at (see
    :func:`locate_quote`), so the verdict is a falsifiable proposition rather
    than a truncated string, and each dropped citation carries the *reason* it
    failed (:func:`explain_drop`) -- a negation flip or a number swap is a
    different, worse thing than an honest paraphrase.

    Passing ``entail_min`` enables the second stage: a quote that failed
    verbatim but entails its source above that overlap threshold is kept, tagged
    ``verified_by: "entailment"``. It defaults to ``None`` -- the strict
    verbatim rule -- because the heuristic is weak and should be opted into.
    """
    texts = _source_texts(sources)
    kept, dropped = [], []
    for cit in citations or []:
        if not isinstance(cit, dict):
            dropped.append({"source": None, "quote": "",
                            "reason": "malformed_citation"})
            continue
        key = cit.get("source", cit.get("sourceIndex"))
        quote = cit.get("quote") or ""
        body = texts.get(key)
        if body is None:
            dropped.append({"source": key, "quote": quote[:QUOTE_STORE_CHARS],
                            "reason": "unknown_source"})
            continue
        if quote_is_verbatim(body, quote):
            kept.append({"source": key, "quote": quote[:QUOTE_STORE_CHARS],
                         "verified": True, "verified_by": "verbatim",
                         "span": locate_quote(body, quote)})
            continue
        reason, e = explain_drop(body, quote)
        if entail_min is not None and reason in ("paraphrase", "negation_flip") \
                and e["polarity"] != "flip" and e["numbers"] == "match" \
                and e["support"] >= entail_min:
            kept.append({"source": key, "quote": quote[:QUOTE_STORE_CHARS],
                         "verified": True, "verified_by": "entailment",
                         "support": e["support"],
                         "span": locate_quote(body, quote) or
                                 _best_span(body, e["shared_terms"])})
            continue
        dropped.append({"source": key, "quote": quote[:QUOTE_STORE_CHARS],
                        "reason": reason, "entailment": e})

    n_sources = len({k["source"] for k in kept})
    return {
        "kept": kept, "dropped": dropped, "n_sources": n_sources,
        "confidence": confidence_for(n_sources),
        "verdict": "unverified" if n_sources == 0 else "supported",
        "violation": n_sources == 0, "claim": (claim_text or "")[:200],
    }


def _best_span(body: str, terms: list) -> dict | None:
    """Locate the first occurrence of any shared term -- the anchor for a
    paraphrase that has no single verbatim span of its own."""
    for term in terms or []:
        span = locate_quote(body, term if len(term) >= MIN_QUOTE_CHARS else "")
        if span:
            return span
    return None


def cited_ids(text: str) -> list:
    """Artifact ids referenced as ``#12`` in free prose, in order, de-duplicated.

    Used to check a drafted paragraph against the evidence it was actually
    given: a model asked to "cite the evidence by artifact #id" will sometimes
    invent an id, and an id that matches nothing in the evidence list is the
    only externally visible sign of it.
    """
    out, seen = [], set()
    for m in _ID_RE.finditer(text or ""):
        i = int(m.group(1))
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def verify_citation_ids(text: str, valid_ids) -> dict:
    """Check ``#id`` references in prose against the ids actually supplied.

    This is the cheap half of grounding for outputs that carry no quotes --
    an executive paragraph, a summary line. It cannot tell whether the prose is
    *true*; it can tell whether the artefacts it leans on exist. An id the
    model invented is caught, and a paragraph citing nothing at all is reported
    as unbacked so the caller can fall back to deterministic text.

    ``valid_ids`` may be ints or a mapping keyed by int.
    """
    valid = set()
    for v in (valid_ids or []):
        try:
            valid.add(int(v))
        except (TypeError, ValueError):
            continue
    cited = cited_ids(text)
    good = [i for i in cited if i in valid]
    invented = [i for i in cited if i not in valid]
    return {
        "cited": cited, "kept": good, "invented": invented,
        "n_cited": len(good),
        "verdict": "unverified" if not good else "supported",
        "violation": not good,
    }
