"""Atomic claims: the unit of evidence-bound assertion.

An assessment's headline number is only as honest as the prose it rests on, and
prose is not checkable in the aggregate -- a paragraph can be nine-tenths true
and still launder one invented sentence into a report. This module decomposes
free text into *atomic claims* (sentences, with their exact character spans) and
verifies each one against the pages it was drawn from, so the verdict attaches
to the smallest falsifiable unit rather than to a blob.

Three things live here:

* :func:`atomic_claims` -- split text into sentences and bullet items, each with
  the character offsets it occupied. Structural lines (headings, labels, a bare
  ``-``) are returned as ``kind="structural"`` so a reassembled document keeps
  its shape.
* :func:`verify_claim` -- one atomic claim against the source pages: which
  ``#id`` references resolve, how much of the claim's vocabulary the best source
  contains, and whether polarity or a number was inverted (via
  :mod:`app.grounding`). The result is a *span-anchored* verdict, not a string.
* :func:`guard_free_text` / :func:`verify_free_text` -- apply the gate to every
  free-text producer (executive paragraph, critique, drift judgment, report
  section). Unsupported sentences are dropped, with the dropped spans returned
  so the ledger can record exactly what was removed and why.

The support signal is the same deliberately-weak overlap heuristic the quote
gate uses; this module adds no new oracle, only decomposition and reassembly.
Nothing here imports the app: it depends on :mod:`app.grounding` alone, which is
stdlib-only, so it can be called from the ledger, the explainer and the agents
without an import edge.
"""
import re

from . import grounding as G

#: A trailing sentence end or a line break ends a segment.
_SEG_RE = re.compile(r"[.!?](?=\s|$)|\n")

#: Leading list markers stripped before deciding whether a segment is a claim.
_BULLET_RE = re.compile(r"^(?:[-*•+]|\d+[.)])\s+")

#: Below this many characters a segment is structure, not an assertion.
MIN_CLAIM_CHARS = 20

#: Default support floor for calling an atomic claim "supported".
SUPPORTED = 0.6
#: Support in [WEAK, SUPPORTED) is "weak": present but not enough to publish.
WEAK = 0.35


def _segments(text: str):
    """Yield raw segment spans covering ``text`` in order.

    Each item is ``(start, end, raw)``. Segments are sentences or lines; the
    union of the spans is the whole input, so a caller can rebuild the text by
    concatenating the ``raw`` of whichever segments it keeps.
    """
    if not text:
        return
    start = 0
    for m in _SEG_RE.finditer(text):
        yield start, m.end(), text[start:m.end()]
        start = m.end()
    if start < len(text):
        yield start, len(text), text[start:]


def _classify(raw: str) -> tuple[str, int]:
    """(kind, leading offset to strip) for one raw segment."""
    body = raw.lstrip()
    lead = len(raw) - len(body)
    stripped = body.strip()
    if not stripped or stripped.startswith("#"):
        return "structural", lead
    m = _BULLET_RE.match(body)
    if m:
        lead += m.end()
        body = body[m.end():]
    if len(body.strip()) < MIN_CLAIM_CHARS or not re.search(r"[A-Za-z]", body):
        return "structural", lead
    return "claim", lead


def atomic_claims(text: str, *, max_claims: int = 400) -> list[dict]:
    """Every atomic claim in ``text``, with its character span.

    Short fragments, headings and list punctuation are structural, not claims.
    Order is preserved, so offsets in the result index into the original text.
    """
    out: list[dict] = []
    for start, _end, raw in _segments(text):
        kind, lead = _classify(raw)
        if kind != "claim":
            continue
        claim_text = raw[lead:].strip()
        start_off = start + lead
        out.append({"index": len(out), "text": claim_text,
                    "start": start_off, "end": start_off + len(claim_text)})
        if len(out) >= max_claims:
            break
    return out


def _page_texts(pages) -> list[tuple]:
    """[(key, text)] from the two page shapes the app uses."""
    out = []
    for i, p in enumerate(pages or []):
        if isinstance(p, dict):
            key = p.get("id", p.get("url", i))
            text = p.get("text", "")
        else:
            key, text = i, str(p)
        out.append((key, text or ""))
    return out


def _best_source(claim_text: str, pages, prefer_keys=None) -> dict | None:
    """The page that best supports a claim, by the entailment heuristic.

    Pages named by a resolved ``#id`` are checked first: if the claim cites its
    source, that source is the one to judge it against, not whichever page
    happens to share more words.
    """
    prefer = list(prefer_keys or [])
    indexed = _page_texts(pages)
    ordered = sorted(indexed,
                     key=lambda kv: 0 if kv[0] in prefer else 1)
    best = None
    for key, body in ordered:
        e = G.entail(body, claim_text)
        score = e["support"]
        if key in prefer:
            score = min(1.0, score + 0.15)
        if best is None or score > best["score"]:
            span = G.locate_quote(body, claim_text)
            best = {"source": key, "score": round(score, 3),
                    "polarity": e["polarity"], "numbers": e["numbers"],
                    "shared_terms": e["shared_terms"], "span": span}
    return best


def verify_claim(claim: dict, pages, valid_ids=None, *, entail_min=SUPPORTED) -> dict:
    """Verify one atomic claim against source pages.

    Returns ``{text, span, verdict, support, source, ids, ...}``. ``verdict`` is
    one of ``supported`` (score at or above ``entail_min``), ``weak`` (between
    :data:`WEAK` and the floor) or ``unsupported``. A claim whose cited ids are
    all invented is unsupported no matter how many words it shares, because the
    reference is the claim's own assertion of grounds.
    """
    text = claim.get("text", "") if isinstance(claim, dict) else str(claim)
    ids = G.verify_citation_ids(text, valid_ids or [])
    best = _best_source(text, pages, prefer_keys=ids.get("kept"))
    support = best["score"] if best else 0.0
    if ids.get("invented") and not ids.get("kept"):
        verdict = "unsupported"
    elif support >= entail_min:
        verdict = "supported"
    elif support >= WEAK:
        verdict = "weak"
    else:
        verdict = "unsupported"
    return {
        "text": text,
        "start": claim.get("start"),
        "end": claim.get("end"),
        "verdict": verdict,
        "support": support,
        "source": best["source"] if best else None,
        "span": best["span"] if best else None,
        "polarity": best["polarity"] if best else None,
        "numbers": best["numbers"] if best else None,
        "shared_terms": best["shared_terms"] if best else [],
        "cited": ids.get("kept", []),
        "invented": ids.get("invented", []),
        "claim_id": G.claim_digest(
            text, ids.get("kept", []),
            [(best["span"] or {}).get("start")] if best else []),
    }


def verify_free_text(text: str, pages, valid_ids=None, *,
                     entail_min=SUPPORTED) -> dict:
    """Verify every atomic claim in a free-text block.

    Returns the per-claim verdicts plus aggregate counts. Does not modify the
    text; use :func:`guard_free_text` to also strip the unsupported claims.
    """
    claims = atomic_claims(text)
    results = [verify_claim(c, pages, valid_ids, entail_min=entail_min)
               for c in claims]
    counts = {"supported": 0, "weak": 0, "unsupported": 0}
    for r in results:
        counts[r["verdict"]] += 1
    return {
        "claims": results,
        "stats": {"total": len(results), **counts,
                  "support_rate": round(
                      (counts["supported"] + counts["weak"]
                       * 0.5) / len(results), 3) if results else None},
        # A block is a violation only when *nothing* it asserts is supported;
        # partial support is reported per claim, not hidden behind one flag.
        "violation": bool(results) and counts["supported"] == 0
                     and counts["weak"] == 0,
    }


def guard_free_text(text: str, pages, valid_ids=None, *,
                    entail_min=SUPPORTED, keep_weak=False) -> dict:
    """Strip unsupported atomic claims from ``text``, preserving structure.

    Structural segments (headings, bullets, labels) are always kept, so the
    result still reads as the document it was. A claim is kept when it is
    ``supported`` -- or ``weak`` if ``keep_weak`` is set. Returns the rewritten
    text and the dropped spans, which is what the ledger records.
    """
    results = {r["start"]: r["verdict"]
               for r in verify_free_text(text, pages, valid_ids,
                                         entail_min=entail_min)["claims"]}
    kept_parts, kept, dropped = [], [], []
    for start, _end, raw in _segments(text):
        kind, lead = _classify(raw)
        if kind != "claim":
            kept_parts.append(raw)
            continue
        verdict = results.get(start + lead, "unsupported")
        keep = verdict == "supported" or (keep_weak and verdict == "weak")
        if keep:
            kept_parts.append(raw)
            kept.append({"start": start + lead, "verdict": verdict})
        else:
            dropped.append({"start": start + lead, "verdict": verdict,
                            "text": raw.strip()[:200]})
    return {
        "text": "".join(kept_parts),
        "kept": kept,
        "dropped": dropped,
        "stats": {"kept": len(kept), "dropped": len(dropped)},
        "violation": not kept,
    }


def claim_graph(verified: list[dict]) -> dict:
    """Nodes, source edges and contradiction edges for verified claims.

    Downstream this is the "claim -> event -> hop" picture and the input to
    uncertainty aggregation: each claim is a node, each cited source an edge
    from the claim, and two claims that share vocabulary but disagree in
    polarity get a ``contradicts`` edge -- the tension a cross-path checker
    should surface rather than average away.
    """
    nodes, edges = [], []
    for r in verified or []:
        nodes.append({"id": r.get("claim_id") or G.claim_digest(r.get("text", "")),
                      "text": (r.get("text") or "")[:200],
                      "verdict": r.get("verdict"), "support": r.get("support")})
    for i, a in enumerate(verified or []):
        for j, b in enumerate(verified or []):
            if j <= i:
                continue
            shared = set(a.get("shared_terms") or []) & set(b.get("shared_terms") or [])
            if len(shared) < 3:
                continue
            if (a.get("polarity") != b.get("polarity")
                    and "flip" in (a.get("polarity"), b.get("polarity"))):
                edges.append({"from": i, "to": j, "kind": "contradicts",
                              "terms": sorted(shared)[:6]})
    for i, r in enumerate(verified or []):
        if r.get("source") is not None:
            edges.append({"from": i, "to": r.get("source"), "kind": "cites_source"})
    return {"nodes": nodes, "edges": edges,
            "stats": {"nodes": len(nodes), "edges": len(edges),
                      "contradictions": sum(1 for e in edges
                                            if e["kind"] == "contradicts")}}
