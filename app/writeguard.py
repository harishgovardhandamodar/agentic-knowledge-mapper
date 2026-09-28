"""In-the-loop hallucination and drift control for the explainer's writing pass.

The explainer used to hand the whole question to the model once and check the
result afterwards: invented citations were dropped, and a second pass
fact-checked the claims it had produced. That catches a wrong *citation*. It
does nothing about the prose itself -- a section can assert a specific, entirely
unsourced fact and keep it, and a section can drift off the brief and keep its
place in the answer. Both defects are invisible downstream, because everything
after this point treats the written text as the answer.

This module closes that gap with a write-verify-repair loop that runs while the
answer is still being composed:

1. **Audit** every section's prose against the retrieved sources. The test is
   deliberately asymmetric: a sentence that makes no checkable assertion is
   never touched (framing prose like "this matters because" is not a
   hallucination), and a sentence carrying a *specific* -- a number, a date, a
   version, an identifier -- is only kept when that specific appears verbatim in
   a source or the sentence shares real vocabulary with one. An unsourced
   specific is the signature of a hallucination, and is the thing worth
   refusing.
2. **Repair** it. One rewrite per affected section asks for a version that uses
   only sourced facts, and the rewrite is audited again. If it still fails, the
   offending sentences are *stripped* rather than re-generated: deleting text
   cannot introduce a new falsehood, and a missing sentence is honest where an
   invented one is not.
3. **Gate drift** per section. A section that shares no vocabulary with the
   question and none with its planned sub-question is a candidate; a single
   batched judge confirms the candidates, and confirmed sections are removed
   from the answer. Their headings are reported rather than silently discarded.

Everything fails open: a disabled guard, an unreachable model, a malformed
judge reply or a total inability to verify a section all leave the answer as the
model wrote it. The guard can only ever remove text, never add it, so the worst
case is a shorter answer, never a wrong one. Knobs: ``AKM_WRITEGUARD=0``,
``AKM_WRITEGUARD_REPAIRS=0`` (strip instead of rewriting), ``AKM_WRITEGUARD_JUDGE=0``.

What it does not do, measured rather than assumed: replayed over the stored
explanations with the page sets their runs actually retrieved, the deterministic
audit flags 5 of 865 sentences (0.58%). Two things it structurally cannot see:

* A value that is wrong but *paraphrased* rather than invented. "90,000 cases"
  against a source saying 70,000, in otherwise identical wording, has maximal
  vocabulary overlap and is left for :mod:`app.grounding` to catch against the
  cited page. Deleting it here would mean deleting correct paraphrases too.
* A claim backed by a source the run did not retrieve. The guard audits against
  the pages it was handed, so a figure supported by page 9 of 12 can read as
  unsourced. It reports rather than guesses, which is why the drift gate keeps
  its own ceiling.
"""
import os
import re
import time

from . import llm

# A sentence shorter than this is a heading or a fragment, not an assertion.
MIN_SENTENCE_CHARS = 24
# Content words a sentence must share with a source for an unquotable value to
# be treated as paraphrase rather than invention. Two incidental words is a low
# bar on purpose -- see the note in audit_section.
MIN_SHARED_TOKENS = 2
# Never remove so much that the answer is gutted: if this fraction of sections
# would disappear, keep them and report instead.
MAX_SECTION_LOSS = 0.34

_STOP = {
    "the", "and", "for", "how", "what", "does", "was", "are", "you", "this",
    "with", "that", "from", "who", "why", "when", "which", "have", "has",
    "its", "not", "but", "all", "can", "will", "about", "your", "into", "they",
    "them", "then", "than", "there", "their", "these", "those", "been", "being",
    "would", "could", "should", "must", "may", "might", "also", "such", "each",
    "some", "more", "most", "other", "over", "under", "between", "because",
    "however", "therefore", "thus", "while", "where", "which", "does", "do",
    "did", "if", "as", "at", "by", "in", "is", "it", "on", "or", "an", "be",
    "we", "our", "us", "one", "two", "use", "used", "using", "make", "made",
    "get", "got", "new", "way", "ways", "e.g", "i.e",
}

# Things that look like checkable facts. A sentence containing one of these is
# asserting something concrete, and therefore falsifiable.
_SPECIFIC_PATTERNS = (
    (re.compile(r"\b(?:cve|cnvd|ghsa|ad|ids)-\d{4}-\d{3,7}\b", re.I), "identifier"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}\b"), "date"),
    (re.compile(r"\bv?\d+\.\d+(?:\.\d+)?\b"), "version"),
    (re.compile(r"\b\d+(?:\.\d+)?\s?%"), "percentage"),
    (re.compile(r"[$€£]\s?\d[\d,.]*"), "money"),
    (re.compile(r"\b\d{4}\b"), "year"),
    (re.compile(r"\b\d[\d,.]*\s?(?:ms|s|kb|mb|gb|tb|usd|eur)\b", re.I), "quantity"),
    (re.compile(r"\b\d[\d,.]*\b"), "number"),
)

_SENT_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\"'(\[])")
_BULLET = re.compile(r"^\s*(?:[-*+]|\d+\.)\s+")


def _flag(name: str) -> bool:
    return os.environ.get(name, "1").strip().lower() not in ("0", "false", "no")


def _tokens(text: str) -> set:
    return set(re.findall(r"[a-z0-9][a-z0-9\-_.]{2,}", (text or "").lower())) - _STOP


def _canon(text: str) -> str:
    """Normalize text for "is this value present in the sources" lookups.

    Sources and prose disagree about pure typography: "30 %" vs "30%", "100,000"
    vs "100 000" vs "100000", en dashes, non-breaking spaces. A guard that reads
    those as different facts deletes correct numbers over a space, which is the
    fastest way to make an operator distrust it and switch it off. Every
    normalization here widens a match; none of them can invent one.
    """
    s = (text or "").lower()
    s = s.replace("\u00a0", " ").replace("\u202f", " ").replace("\u2009", " ")
    s = s.replace("\u2013", "-").replace("\u2014", "-").replace("\u2212", "-")
    s = re.sub(r"(?<=\d)[.,](?=\d{3}\b)", "", s)   # 100,000 and 1.000 -> 100000
    s = re.sub(r"(?<=\d)\s+(?=\d)", "", s)        # 100 000 -> 100000
    s = re.sub(r"\s*%", "%", s)                    # "30 %" -> "30%"
    return s


def _specifics(sentence: str) -> list:
    """Checkable assertions in a sentence, as ``(text, kind)`` pairs."""
    out = []
    seen = set()
    for pat, kind in _SPECIFIC_PATTERNS:
        for m in pat.finditer(sentence or ""):
            v = m.group(0).strip()
            if v.lower() in seen:
                continue
            seen.add(v.lower())
            out.append((v, kind))
    return out


def _units(body: str) -> list:
    """Split a markdown body into the units the guard may remove.

    A list item is one unit *even when it wraps across lines*: splitting it would
    judge a fragment and can delete half an argument, leaving the remainder to
    read as nonsense. A paragraph is split into sentences instead, so a single
    unsourced clause can come out without taking its neighbours.

    Each unit keeps its ``text`` exactly as it appeared plus the number of blank
    lines that separated it from the previous one, so rebuilding the body from
    the survivors preserves bullets, nesting, tight vs loose lists and layout.
    ``bullets`` marks a unit that is a list item; it is judged as a single
    sentence and, if it fails, removed whole.
    """
    units, buf = [], []
    gap, unit_gap = 0, 0  # blank lines seen since the last content / before this block

    def add():
        units.append({"text": "\n".join(buf), "bullets": bool(_BULLET.match(buf[0])),
                      "gap": unit_gap})
        del buf[:]

    for line in (body or "").split("\n"):
        # A blank line or a new list marker starts a new block; anything else
        # belongs to the current one, which is exactly how markdown reads lazy
        # continuation lines of a wrapped list item.
        if not line.strip():
            if buf:
                add()
            gap += 1
        elif _BULLET.match(line):
            if buf:
                add()
            unit_gap, gap = gap, 0
            buf.append(line)
        else:
            if not buf:
                unit_gap = gap
            gap = 0
            buf.append(line)
    if buf:
        add()
    for u in units:
        if u["bullets"]:
            u["sentences"] = [re.sub(r"\s+", " ", u["text"]).strip()]
        else:
            u["sentences"] = [p.strip() for p in _SENT_SPLIT.split(u["text"]) if p.strip()]
    return units


def _sentences(body: str) -> list:
    """Every judged sentence in a body, in order (see :func:`_units`)."""
    return [s for u in _units(body) for s in u["sentences"]]


def _best_shared(sent_tok: set, page_toks: list) -> int:
    return max((len(sent_tok & pt) for pt in page_toks), default=0)


def audit_section(section: dict, page_norms: list, page_toks: list) -> dict:
    """Classify a section's sentences without calling a model.

    Returns ``{"checked", "unsupported": [{"sentence", "reason", "detail"}],
    "supported", "framing"}``. ``unsupported`` means: the sentence asserts
    something specific and nothing in the sources backs it.
    """
    sentences = _sentences(section.get("body") or "")
    res = {"checked": 0, "unsupported": [], "supported": 0, "framing": 0}
    for sent in sentences:
        bare = _BULLET.sub("", sent).strip()
        if len(bare) < MIN_SENTENCE_CHARS:
            continue
        res["checked"] += 1
        specs = _specifics(bare)
        if not specs:
            # No falsifiable content: framing, transition, or a definition.
            # Refusing these would gut every explanation, so they pass.
            res["framing"] += 1
            continue
        found = [v for v, _ in specs
                 if any(_canon(v) in pn for pn in page_norms)]
        if len(found) == len(specs):
            res["supported"] += 1
            continue
        # The overlap escape hatch: a sentence that shares real vocabulary with
        # the evidence is a paraphrase of it, and a value the sources phrase
        # differently is not an invention. Calibrated by replaying the
        # deterministic audit over the stored explanations with the page sets
        # their runs actually retrieved: this floor flags 5 of 865 sentences
        # (0.58%), touching 4 sections of 37. Requiring the shared tokens to be
        # half of the sentence's own vocabulary instead -- the stricter, more
        # defensible-looking rule -- flags 72 of 865 (8.3%) across 47 sections,
        # almost all of it well-grounded technical prose, so it is not used.
        sent_tok = _tokens(bare)
        shared = _best_shared(sent_tok, page_toks)
        if shared >= MIN_SHARED_TOKENS:
            res["supported"] += 1
            continue
        unsourced = sorted({k for v, k in specs
                            if _canon(v) not in {_canon(f) for f in found}})
        res["unsupported"].append({
            "sentence": sent,
            "reason": "no_evidence_for",
            "detail": "unsourced " + ", ".join(unsourced[:3]),
        })
    return res


def _strip_sentences(section: dict, bad: list) -> int:
    """Delete the given sentences from a section body. Never adds text.

    Rebuilds from the units that survive, reusing their original text, so a list
    that loses one item keeps its remaining items as list items rather than
    collapsing into loose paragraphs.
    """
    bad_set = {b["sentence"] for b in bad}
    kept_units, removed = [], 0
    for u in _units(section.get("body") or ""):
        if u["bullets"]:
            if u["sentences"][0] in bad_set:
                removed += 1
                continue
            kept_units.append(u)
            continue
        keep = [s for s in u["sentences"] if s not in bad_set]
        removed += len(u["sentences"]) - len(keep)
        if keep:
            kept_units.append({"text": " ".join(keep), "bullets": False, "gap": u["gap"]})
    if not kept_units:
        section["body"] = ""
        return removed
    # Re-emit the original separation: one newline between adjacent list items,
    # a blank line between blocks. Joining everything with a blank line would
    # turn a tight list into a loose one.
    parts = []
    for i, u in enumerate(kept_units):
        sep = "" if i == 0 else ("\n" * (u["gap"] + 1))
        parts.append(sep + u["text"])
    section["body"] = "".join(parts).strip()
    return removed


def _rewrite_section(question: str, section: dict, bad: list, pages: list) -> dict | None:
    """Ask for a version of the section that only says sourced things."""
    ctx = []
    for i, p in enumerate(pages[:8]):
        ctx.append(f"[{i}] {p.get('title','')}\n{(p.get('text') or '')[:1500]}")
    try:
        r = llm.chat_json([
            {"role": "system",
             "content": "You edit text for factual accuracy. Use ONLY facts present in the "
                        "provided sources. If a statement is not supported by a source, delete "
                        "it rather than softening or guessing. Never introduce a new fact, "
                        "number, name or citation. Reply with STRICT JSON only."},
            {"role": "user",
             "content": (f"Question being answered: {question}\n\nSection heading: "
                         f"{section.get('heading','')}\n\nCurrent section body:\n"
                         f"{section.get('body','')}\n\nThese sentences could not be supported "
                         f"by any source:\n"
                         + "\n".join(f"- {b['sentence']}" for b in bad)
                         + f"\n\nSources ({len(pages)}):\n" + "\n\n".join(ctx)
                         + "\n\nReply {\"body\": str (the corrected body), \"removed\": [str] "
                           "(sentences you deleted, for the audit log)}")},
        ], temperature=0.1, max_tokens=1400)
    except Exception:
        return None
    body = r.get("body") if isinstance(r, dict) else None
    if not isinstance(body, str) or not body.strip():
        return None
    return {"body": body.strip(),
            "removed": [str(x)[:200] for x in (r.get("removed") or [])][:8]}


def _judge_drift(question: str, candidates: list, pages: list) -> dict:
    """One batched call: which candidate sections are genuinely off-brief."""
    if not candidates:
        return {}
    listing = "\n".join(
        f"- id {c['id']}: heading '{c['section'].get('heading','')}' — "
        f"{(c['section'].get('body') or '')[:400]}" for c in candidates)
    try:
        r = llm.chat_json([
            {"role": "system",
             "content": "You judge whether each draft section is still relevant to the "
                        "question it is answering. Answer only about relevance to that "
                        "question, never about style or length. Reply JSON only."},
            {"role": "user",
             "content": (f"Question: {question}\n\nDraft sections:\n{listing}\n\nReply "
                         "{\"off_brief\": [int ids that do not help answer the question]} — "
                         "ids only, and omit any section that is even partly relevant. "
                         "A section is off-brief only if it is about a different subject "
                         "than the question.")},
        ], temperature=0.0, max_tokens=700)
    except Exception:
        return {}
    out = {}
    if isinstance(r, dict):
        for v in (r.get("off_brief") or []):
            try:
                out[int(v)] = True
            except (TypeError, ValueError):
                continue
    return out


def _shares(a: set, b: set) -> bool:
    """Do these token sets overlap at all?

    A 5-character prefix counts as overlap, so "retain" and "retention",
    "train" and "training", "expose" and "exposure" match. Without it a section
    about telemetry retention is a drift candidate for a question that says
    "retain", which spends a judge call on an obvious section.
    """
    if a & b:
        return True
    for x in a:
        if len(x) >= 5:
            for y in b:
                if y.startswith(x[:5]) or x.startswith(y[:5]):
                    return True
    return False


def _drift_candidate(section: dict, q_tok: set, plan_tok: set = frozenset()) -> bool:
    """Cheap prefilter: shares no real vocabulary with the brief at all.

    ``q_tok`` should already include the investigation brief, not just the
    question: drift means off-brief, and a section can be squarely on-brief
    while sharing little with the specific question asked this time.

    ``plan_tok`` is the vocabulary of this section's planned sub-question. A
    section that matches its own plan is on-brief even when it shares little
    with the top-level question, which is the normal case for a deep dive whose
    sub-question is deliberately narrower.
    """
    if not q_tok:
        return False
    body_tok = _tokens((section.get("heading") or "") + " " + (section.get("body") or ""))
    if not body_tok:
        return False
    if plan_tok and _shares(plan_tok, body_tok):
        return False
    return not _shares(q_tok, body_tok)


def audit_answer(question: str, answer: dict, pages: list, *,
                 brief_text: str = "", section_plan: list | None = None,
                 max_repairs: int = 2,
                 repair: bool | None = None, judge: bool | None = None) -> dict:
    """Write-verify-repair one answer. Mutates ``answer`` in place.

    ``question`` is what was asked, ``brief_text`` the investigation's own
    title/keywords/description -- drift is off-*brief*, and a section can be
    squarely on-brief while sharing little with this particular question.
    ``section_plan`` exempts a section that matches its planned sub-question.
    ``max_repairs`` caps the model calls; every other failure is fail-open.

    The report is returned for the run trace; ``answer["write_audit"]`` gets the
    same dict so the GUI can show it next to the answer.
    """
    t0 = time.time()
    repair = _flag("AKM_WRITEGUARD_REPAIRS") if repair is None else repair
    judge = _flag("AKM_WRITEGUARD_JUDGE") if judge is None else judge
    report = {
        "enabled": True, "sections_total": 0, "sentences_checked": 0,
        "unsupported": 0, "removed": 0, "repairs": 0, "repairs_held": 0,
        "unsupported_remaining": 0,
        "sections_stripped": 0, "sections_emptied": 0,
        "drift_candidates": 0, "drift_flagged": 0, "sections_dropped": 0,
        "by_reason": {"no_evidence_for": 0}, "examples": [],
        "dropped_sections": [], "elapsed_ms": 0,
    }
    if not _flag("AKM_WRITEGUARD"):
        report["enabled"] = False
        return report

    sections = [s for s in (answer.get("sections") or []) if isinstance(s, dict)]
    if not sections:
        report["elapsed_ms"] = int((time.time() - t0) * 1000)
        return report

    page_norms = [_canon(p.get("text") or "") for p in pages]
    page_toks = [_tokens(p.get("text") or "") for p in pages]
    # Drift is judged against the brief as well as the question.
    q_tok = _tokens(question) | _tokens(brief_text or "")
    report["sections_total"] = len(sections)

    # --- pass 1: audit, and repair the worst offenders -----------------------
    audited = []
    for sec in sections:
        a = audit_section(sec, page_norms, page_toks)
        report["sentences_checked"] += a["checked"]
        audited.append((sec, a))

    offenders = [(sec, a) for sec, a in audited if a["unsupported"]]
    report["unsupported"] = sum(len(a["unsupported"]) for _, a in offenders)

    if repair and offenders:
        for sec, a in offenders[:max_repairs]:
            report["repairs"] += 1
            fixed = _rewrite_section(question, sec, a["unsupported"], pages)
            if not fixed:
                continue
            before = sec.get("body")
            sec["body"] = fixed["body"]
            after = audit_section(sec, page_norms, page_toks)
            if len(after["unsupported"]) < len(a["unsupported"]):
                report["repairs_held"] += 1
            else:
                # The rewrite did not help; keep the original wording.
                sec["body"] = before
            sec["rewrite_removed"] = fixed["removed"]

    # --- pass 2: strip whatever is still unsupported ------------------------
    for sec in sections:
        a = audit_section(sec, page_norms, page_toks)
        if not a["unsupported"]:
            continue
        for bad in a["unsupported"]:
            report["by_reason"][bad["reason"]] = report["by_reason"].get(bad["reason"], 0) + 1
            if len(report["examples"]) < 6:
                report["examples"].append({
                    "section": (sec.get("heading") or "")[:80],
                    "sentence": bad["sentence"][:200], "reason": bad["reason"],
                    "detail": bad["detail"]})
        n = _strip_sentences(sec, a["unsupported"])
        report["removed"] += n
        if n:
            report["sections_stripped"] += 1
        if not (sec.get("body") or "").strip():
            report["sections_emptied"] += 1

    sections[:] = [s for s in sections if (s.get("body") or "").strip()]

    # What survived: should be zero whenever the guard is on, which is the point
    # of the counter -- a non-zero value means a strip failed to remove its
    # target and the operator should see that rather than assume it is clean.
    for sec in sections:
        report["unsupported_remaining"] += len(
            audit_section(sec, page_norms, page_toks)["unsupported"])

    # --- pass 3: drift gate --------------------------------------------------
    if judge:
        plan = {i: _tokens(f"{p.get('heading','')} {p.get('sub_question','')}")
                for i, p in enumerate(section_plan or [])}
        cands = [{"id": i, "section": s} for i, s in enumerate(sections)
                 if _drift_candidate(s, q_tok, plan.get(i, frozenset()))]
        report["drift_candidates"] = len(cands)
        if cands:
            verdicts = _judge_drift(question, cands, pages)
            drop_idx = {c["id"] for c in cands if verdicts.get(c["id"])}
            if drop_idx and len(drop_idx) <= max(1, int(len(sections) * MAX_SECTION_LOSS)):
                for c in cands:
                    if c["id"] in drop_idx:
                        report["dropped_sections"].append({
                            "heading": (c["section"].get("heading") or "")[:120],
                            "reason": "off_brief"})
                report["drift_flagged"] = len(drop_idx)
                report["sections_dropped"] = len(drop_idx)
                keep = [s for i, s in enumerate(sections) if i not in drop_idx]
                answer["sections"] = keep
                sections[:] = keep
            elif drop_idx:
                # Almost everything looked off-brief: that is a sign the judge or
                # the question is wrong, not the answer. Keep it, report it.
                report["dropped_sections"] = [
                    {"heading": (c["section"].get("heading") or "")[:120],
                     "reason": "off_brief_not_removed"} for c in cands if c["id"] in drop_idx]

    answer["sections"] = sections
    report["elapsed_ms"] = int((time.time() - t0) * 1000)
    return report
