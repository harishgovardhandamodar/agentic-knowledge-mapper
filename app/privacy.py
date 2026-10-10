"""Privacy as a measured property of the engine, not a promise in a doc.

The system already does the hard structural things right: digests not content,
PII counts not values, local inference, redaction before a ledger write. What it
did not have was a *number* for how much it had reached out, a test for whether
its own stored explanations leak their sources, and a way to honour a deletion
request without breaking an append-only audit chain. This module adds those
three, all as pure functions over data the rest of the app already has.

* :func:`privacy_budget` -- an approximate-DP-style spend account per
  investigation: external queries issued plus the *novelty* of the pages returned
  (a page nobody had seen is information the engine imported; a page already in
  the corpus is not). Exhausting it is a first-class state the caller can act on,
  not a silent overrun.
* :func:`extraction_resistance` -- run the same adversarial catalog the engine
  applies to models *against the engine's own stored artifacts*: does a stored
  explanation reproduce a source's distinctive phrasing verbatim? A hit is a
  leak the way a model memorising a canary is, and it is scored on the same
  RM-style severity scale.
* :func:`erasure_commitment` -- a salted commitment stored on the ledger, so the
  operational record (the content) can be forgotten while the chain still proves
  *that* an assessment of a named subject happened, without revealing which.

Stdlib only, no app imports, no I/O.
"""
import hashlib
import re

#: Default spend ceiling for one investigation. Chosen to allow a genuine
#: multi-round research run while forcing a deliberate decision before the
#: engine starts fanning out. Callers may override per investigation.
DEFAULT_BUDGET = {"max_spend": 60.0, "query_cost": 1.0, "novel_page_cost": 1.5}

#: Gram length for the distinctive-phrase overlap test. Long enough that a match
#: is a real reproduction, not incidental shared vocabulary.
NGRAM = 8

_URL_HOST = re.compile(r"^[a-z]+://([^/]+)", re.I)
_WORD = re.compile(r"[a-z0-9]+")


def domain_of(url: str) -> str:
    m = _URL_HOST.match((url or "").strip())
    return (m.group(1).lower() if m else "").split(":")[0]


def _is_external(url: str) -> bool:
    return (url or "").startswith(("http://", "https://"))


def _digest(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()[:16]


def privacy_budget(pages, *, queries: int = 0, budget: dict | None = None,
                   seen_hashes=None) -> dict:
    """Approximate-DP-style spend for one investigation.

    ``pages`` are the pages this run touched; ``queries`` the external searches
    issued. A page is charged full ``novel_page_cost`` only if its content hash
    was not already in ``seen_hashes`` -- re-reading the corpus is not new
    exposure. Distinct external domains are reported because they are the unit
    a privacy reviewer actually cares about ("how many parties saw a query?").
    """
    cfg = {**DEFAULT_BUDGET, **(budget or {})}
    seen = set(seen_hashes or [])
    ext = [p for p in (pages or []) if _is_external(p.get("url", ""))]
    domains = sorted({domain_of(p["url"]) for p in ext if domain_of(p["url"])})
    novel = 0
    for p in ext:
        if _digest(p.get("text", "")) not in seen:
            novel += 1
    spend = (queries * cfg["query_cost"]) + (novel * cfg["novel_page_cost"])
    remaining = max(0.0, cfg["max_spend"] - spend)
    return {
        "spend": round(spend, 2),
        "remaining": round(remaining, 2),
        "max_spend": cfg["max_spend"],
        "exhausted": remaining <= 0.0,
        "queries": queries,
        "external_pages": len(ext),
        "novel_pages": novel,
        "distinct_domains": len(domains),
        "domains": domains[:20],
        # A one-word state a caller can branch on: keep collecting, slow down,
        # or stop. Degrading is not failure -- it is the budget doing its job.
        "advice": ("refuse" if remaining <= 0.0
                   else "degrade" if remaining <= cfg["max_spend"] * 0.2
                   else "ok"),
    }


def _ngrams(text: str) -> set:
    words = _WORD.findall((text or "").lower())
    return {" ".join(words[i:i + NGRAM]) for i in range(len(words) - NGRAM + 1)}


def extraction_resistance(artifacts, outputs, *, max_reports: int = 20) -> dict:
    """Which stored artifacts are reproduced verbatim by the given outputs?

    ``artifacts`` is an iterable of ``(id, text)``; ``outputs`` an iterable of
    emitted strings (model answers, explanations). An artifact whose distinctive
    N-gram appears in an output has been extracted. Severity scales with the
    fraction of the artifact's N-grams that surfaced: one shared phrase is
    incidental, most of the artifact is a leak.
    """
    art = [(aid, text) for aid, text in (artifacts or [])]
    emit = list(outputs or [])
    out_grams = [_ngrams(o) for o in emit]
    findings = []
    for aid, text in art:
        grams = _ngrams(text)
        if not grams:
            continue
        hit = set()
        for og in out_grams:
            hit |= (grams & og)
        if not hit:
            continue
        frac = len(hit) / len(grams)
        severity = round(min(100.0, frac * 120.0), 1)
        findings.append({
            "risk_id": f"PRIV-EXTRACT-{aid}",
            "artifact_id": aid,
            "exposed_ngrams": len(hit),
            "total_ngrams": len(grams),
            "fraction": round(frac, 3),
            "severity": severity,
            "severity_band": ("high" if severity >= 70
                              else "medium" if severity >= 40 else "low"),
        })
    findings.sort(key=lambda f: -f["severity"])
    high = [f for f in findings if f["severity_band"] == "high"]
    return {
        "findings": findings[:max_reports],
        "stats": {"artifacts": len(art), "outputs": len(emit),
                  "extracted": len(findings), "high": len(high)},
        # A single high extraction is enough to fail the check; the count is for
        # context, not for averaging the result away.
        "ok": not high,
    }


def membership_inference(canary: str, outputs, *, baseline_outputs=None) -> dict:
    """A loss-threshold style membership signal for a planted canary.

    A canary is a distinctive string inserted into the corpus. If it surfaces in
    an engine *output*, that output has effectively confirmed the canary was in
    the material it read -- the engine-level analogue of a training-data
    membership attack. ``baseline_outputs`` (outputs from a run without the
    canary) turn the absolute signal into a comparative one.
    """
    cg = _ngrams(canary)
    present = any(cg and (cg & _ngrams(o)) for o in (outputs or []))
    baseline_present = any(cg and (cg & _ngrams(o))
                           for o in (baseline_outputs or []))
    if present and not baseline_present:
        signal = "member"
    elif present and baseline_present:
        signal = "inconclusive"
    else:
        signal = "non-member"
    score = {"member": 1.0, "inconclusive": 0.5, "non-member": 0.0}[signal]
    return {
        "signal": signal,
        "score": score,
        "canary_ngrams": len(cg),
        "outputs_checked": len(outputs or []),
    }


def erasure_commitment(subject: str, run_id: str, *, salt: str) -> dict:
    """A commitment that lets content be forgotten while the chain still proves it.

    The audit chain cannot be rewritten -- that is its whole value -- but that
    conflicts with a right-to-erasure request over the *content* of an
    assessment. The resolution is a commitment: store ``commitment =
    sha256(subject | run_id | salt)`` on the ledger and keep the operational
    mapping (subject, salt) outside it. Delete the mapping and the content is
    gone for all practical queries; disclose the mapping to an auditor and the
    commitment proves the assessment happened for that subject. Erasure and
    auditability stop being a trade-off.
    """
    blob = f"{subject}\x1f{run_id}\x1f{salt}".encode()
    return {
        "scheme": "sha256-salted",
        "commitment": hashlib.sha256(blob).hexdigest(),
        "run_id": run_id,
    }


def verify_erasure(subject: str, run_id: str, *, salt: str,
                   commitment: str) -> bool:
    """Does a disclosed (subject, salt) open the stored commitment?"""
    return (erasure_commitment(subject, run_id, salt=salt)["commitment"]
            == (commitment or "").strip())
