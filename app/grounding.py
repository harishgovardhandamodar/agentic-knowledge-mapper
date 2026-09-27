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
"""
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


def verify_grounding(claim_text: str, citations, sources) -> dict:
    """The hallucination gate: keep only citations a source actually contains.

    Returns the surviving citations, the dropped ones with a reason, and a
    corroboration score based on how many *distinct* sources back the claim.
    ``violation`` is True when nothing survived -- that is the signal callers
    use to stop a claim propagating.
    """
    texts = _source_texts(sources)
    kept, dropped = [], []
    for cit in citations or []:
        if not isinstance(cit, dict):
            dropped.append({"source": None, "quote": "", "reason": "malformed_citation"})
            continue
        key = cit.get("source", cit.get("sourceIndex"))
        quote = cit.get("quote") or ""
        body = texts.get(key)
        if body is not None and quote_is_verbatim(body, quote):
            kept.append({"source": key, "quote": quote[:QUOTE_STORE_CHARS],
                         "verified": True})
        else:
            dropped.append({"source": key, "quote": quote[:QUOTE_STORE_CHARS],
                            "reason": "not_found_in_source"})

    n_sources = len({k["source"] for k in kept})
    return {
        "kept": kept, "dropped": dropped, "n_sources": n_sources,
        "confidence": confidence_for(n_sources),
        "verdict": "unverified" if n_sources == 0 else "supported",
        "violation": n_sources == 0, "claim": (claim_text or "")[:200],
    }


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
