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
import math
import re

#: Default spend ceiling for one investigation. Chosen to allow a genuine
#: multi-round research run while forcing a deliberate decision before the
#: engine starts fanning out. Callers may override per investigation.
DEFAULT_BUDGET = {"max_spend": 60.0, "query_cost": 1.0, "novel_page_cost": 1.5}

#: Gram length for the distinctive-phrase overlap test. Long enough that a match
#: is a real reproduction, not incidental shared vocabulary.
NGRAM = 8

_URL_HOST = re.compile(r"^[a-z]+://([^/]+)", re.I)
# Case-insensitive on purpose. A canary is very often machine-generated in caps
# (ZKQ7XQ PROVINCEDIAMOND42 ...); a lowercase-only tokeniser silently drops
# those words, and a short all-caps canary then produces *no* n-grams at all --
# a detector that can never fire, reported as "non-member".
_WORD = re.compile(r"[a-z0-9]+", re.I)


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


# --------------------------------------------------------------------------
# Differential-privacy accounting
# --------------------------------------------------------------------------
#
# The spend account above is a budget, not a bound: it counts what was fetched
# but makes no statement about how much an observer could learn. A privacy
# reviewer asking "is this (epsilon, delta)-DP?" needs an actual accountant, so
# this section provides one over the *sensitivity* of each query.
#
# The accounting is honest about what it can and cannot claim:
#
# * The engine adds no randomised noise to anything, so this is NOT a claim
#   that the system is differentially private. It measures the *sensitivity*
#   structure that would drive such a claim, and reports the composition bound
#   that the observed reach would imply if noise at a chosen scale were added.
# * Sensitivity is per-query and domain-weighted: touching one more host is a
#   weaker leak than touching one more page of the same host, because a single
#   host cannot correlate its own observations across subjects.
#
# The RDP accountant is the standard conversion (Canonne et al.), so a reader can
# check it against the literature rather than taking the constant on trust.

#: Default target delta for converting RDP to (epsilon, delta).
DEFAULT_DELTA = 1e-5

#: Sensitivity weight per distinct external domain reached. One host is one
#: observer; several pages from one host is not several observers.
DOMAIN_SENSITIVITY = 1.0
#: Additional sensitivity per novel page beyond the first on a host.
PAGE_SENSITIVITY = 0.25


def _log_add(a: float, b: float) -> float:
    """log(exp(a) + exp(b)) without the overflow."""
    m = max(a, b)
    return m + math.log(math.exp(a - m) + math.exp(b - m))


def rdp_epsilon(orders: list[float], noise_multiplier: float) -> float:
    """Renyi DP of order ``orders`` for the Gaussian mechanism.

    ``epsilon(alpha) = alpha / (2 * sigma^2)``, the standard closed form for the
    Gaussian mechanism without subsampling. Kept as a function of the order
    because the conversion to (epsilon, delta) optimizes over orders rather than
    picking one.
    """
    s2 = max(1e-12, float(noise_multiplier) ** 2)
    return sum(a / (2.0 * s2) for a in orders)


def epsilon_from_rdp(orders: list[float], noise_multiplier: float,
                     delta: float = DEFAULT_DELTA) -> tuple[float, float]:
    """Convert RDP guarantees to the best (epsilon, delta) at any order.

    Returns ``(epsilon, optimal_order)``. This is the standard
    ``eps = min_alpha (rdp_alpha + log(1/delta)) / (alpha - 1)`` conversion.
    """
    best_eps, best_alpha = float("inf"), 2.0
    for a in orders:
        if a <= 1.0:  # the (alpha-1) conversion is undefined at alpha=1
            continue
        eps = (rdp_epsilon([a], noise_multiplier) + math.log(1.0 / delta)) / (a - 1.0)
        if eps < best_eps:
            best_eps, best_alpha = eps, a
    return round(best_eps, 4), best_alpha


def dp_accounting(pages, *, queries: int = 0, noise_multiplier: float = 1.0,
                  delta: float = DEFAULT_DELTA,
                  seen_hashes=None) -> dict:
    """(epsilon, delta) implied by the reach of one research run.

    Composes per-domain sensitivities the way a budget composes -- but by
    composition, not by addition, which is the difference the spend counter
    cannot express. Returns the composed bound plus the per-domain breakdown, so
    a reviewer can see *which* hosts drove the number.

    ``noise_multiplier`` is the sigma a differentially private mechanism would
    use; the engine currently applies no noise, so this reports what the bound
    *would* be. ``mechanism`` names that explicitly so the number is never
    quoted as a guarantee the system does not make.
    """
    cfg_seen = set(seen_hashes or [])
    ext = [p for p in (pages or []) if _is_external(p.get("url", ""))]
    by_domain: dict[str, int] = {}
    for p in ext:
        d = domain_of(p.get("url", ""))
        if not d:
            continue
        by_domain[d] = by_domain.get(d, 0) + (0 if _digest(
            p.get("text", "")) in cfg_seen else 1)

    # Per-domain sensitivity: each distinct observer costs its own unit, plus a
    # marginal cost per additional novel page from the same observer.
    sens = sum(DOMAIN_SENSITIVITY + PAGE_SENSITIVITY * (n - 1)
               for n in by_domain.values())
    # A query touches the search path, which sees the subject; charge it once.
    total_sensitivity = sens + (DOMAIN_SENSITIVITY if queries else 0.0)

    orders = [a / 2.0 for a in range(4, 129)]  # 2.0 .. 64.0; alpha>1 only
    # The composed epsilon for a sensitivity-S query is S times the unit bound.
    unit_eps, alpha = epsilon_from_rdp(orders, noise_multiplier, delta)
    eps = unit_eps * total_sensitivity
    return {
        "epsilon": round(eps, 4),
        "delta": delta,
        "optimal_order": alpha,
        "noise_multiplier": noise_multiplier,
        "sensitivity": round(total_sensitivity, 4),
        "per_domain": [{"domain": d, "novel_pages": n,
                        "sensitivity": round(
                            DOMAIN_SENSITIVITY + PAGE_SENSITIVITY * (n - 1), 4)}
                       for d, n in sorted(by_domain.items())],
        "distinct_domains": len(by_domain),
        "queries": queries,
        "mechanism": "accounted-not-enforced",
        "note": ("The engine adds no noise, so this is NOT a differential-"
                 "privacy guarantee. It is the composed sensitivity structure "
                 "that such a guarantee would have to be calibrated to. To "
                 "claim (epsilon, delta)-DP, add a noise mechanism at the "
                 "stated multiplier and report this number alongside it."),
    }


# --------------------------------------------------------------------------
# Domain-distinct spend
# --------------------------------------------------------------------------


def domain_spend(pages, *, queries: int = 0, budget: dict | None = None,
                 seen_hashes=None) -> dict:
    """Spend weighted by *distinct observers*, not raw fetches.

    Reaching three hosts once each is a wider exposure than fetching ten pages
    from one host, because a single host cannot correlate its own observations
    while three can. The first novel page on a host costs full price; further
    pages from the same host are discounted, which is the concavity the
    query-counter budget lacks.

    Returns the concave spend alongside the linear one so a caller can show
    both: the linear number is what the existing budget charges, the concave is
    what the exposure actually is.
    """
    cfg = {**DEFAULT_BUDGET, **(budget or {})}
    seen = set(seen_hashes or [])
    ext = [p for p in (pages or []) if _is_external(p.get("url", ""))]
    by_domain: dict[str, int] = {}
    for p in ext:
        d = domain_of(p.get("url", ""))
        if not d:
            continue
        if _digest(p.get("text", "")) not in seen:
            by_domain[d] = by_domain.get(d, 0) + 1

    concave = 0.0
    for n in by_domain.values():
        first = cfg["novel_page_cost"]
        rest = cfg["novel_page_cost"] * 0.4  # same observer, correlated views
        concave += first + rest * (n - 1)
    concave += queries * cfg["query_cost"]

    linear = queries * cfg["query_cost"] + sum(by_domain.values()) * \
        cfg["novel_page_cost"]
    return {
        "concave_spend": round(concave, 2),
        "linear_spend": round(linear, 2),
        "spread": round(linear - concave, 2),
        "per_domain": [{"domain": d, "novel_pages": n} for d, n in
                       sorted(by_domain.items())],
        "distinct_domains": len(by_domain),
        "note": ("Concave spend discounts repeat views from an observer you "
                 "already reached. A non-zero spread means raw fetch count "
                 "overstates the exposure."),
    }


# --------------------------------------------------------------------------
# Detector operating characteristics
# --------------------------------------------------------------------------
#
# An 8-gram overlap detector is either useful or it is not, and "useful" is an
# empirical question: at what threshold does it start flagging real extractions,
# and how many innocent coincidences does it flag on the way? Without a measured
# ROC, a single hit is being treated as proof of leakage when it may just be
# boilerplate.
#
# The calibration set below is synthetic by construction, which is stated rather
# than hidden: it measures the detector against *planted* positives and clean
# negatives, which is the only way to get ground truth without a leak catalogue.
# It bounds the detector's behaviour; it does not certify it.


def _roc_points(scores: list[float], labels: list[bool],
                thresholds: list[float]) -> list[dict]:
    """TPR/FPR at each threshold (positive = true extraction)."""
    pos = sum(labels)
    neg = len(labels) - pos
    out = []
    for t in thresholds:
        pairs = list(zip(scores, labels, strict=False))
        tp = sum(1 for s, lab in pairs if lab and s >= t)
        fp = sum(1 for s, lab in pairs if not lab and s >= t)
        out.append({
            "threshold": round(t, 3),
            "tpr": round(tp / pos, 3) if pos else 0.0,
            "fpr": round(fp / neg, 3) if neg else 0.0,
            "precision": round(tp / (tp + fp), 3) if (tp + fp) else 0.0,
            "tp": tp, "fp": fp,
        })
    return out


def _auc(scores: list[float], labels: list[bool]) -> float:
    """ROC AUC via the rank-sum identity (ties averaged)."""
    pos = [s for s, lab in zip(scores, labels, strict=False) if lab]
    neg = [s for s, lab in zip(scores, labels, strict=False) if not lab]
    if not pos or not neg:
        return 0.0
    wins = 0.0
    for p in pos:
        for n in neg:
            wins += 1.0 if p > n else (0.5 if p == n else 0.0)
    return round(wins / (len(pos) * len(neg)), 4)


def _extraction_score(artifact_text: str, output: str) -> float:
    """Fraction of an artifact's distinctive N-grams present in one output."""
    grams = _ngrams(artifact_text)
    if not grams:
        return 0.0
    out = _ngrams(output)
    return len(grams & out) / len(grams)


def detector_roc(thresholds: list[float] | None = None) -> dict:
    """Measure the extraction detector on a planted-positive calibration set.

    Positives are artifacts reproduced verbatim in an output; negatives are the
    same artifacts against unrelated outputs. Reports AUC and the TPR/FPR curve
    so the operating point used by :func:`extraction_resistance` can be chosen
    against numbers rather than intuition.
    """
    thresholds = thresholds or [0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.7, 0.9]
    artifacts = [
        "the vendor stores telemetry in the eu region for thirty days and "
        "deletes it automatically afterwards",
        "prompt retention defaults to zero days when the workspace is marked "
        "as containing regulated personal data",
        "agent tool calls execute inside a sandbox with no network route to "
        "the host filesystem and read only the declared working directory",
        "credentials are brokered at call time and never persisted to the "
        "agent context window or the conversation transcript",
        "classification is enforced before any model call renders output into "
        "a connected asset record",
    ]
    # Unrelated outputs: no artifact's distinctive phrasing appears.
    negatives = [
        "the quarterly revenue increased by eleven percent year over year "
        "driven mainly by the enterprise segment",
        "we recommend reviewing the deployment guide before upgrading to the "
        "latest release candidate",
        "the documentation portal lists supported regions and their data "
        "residency commitments for each plan tier",
        "customer support tickets are triaged daily and escalated after the "
        "acknowledged response window expires",
        "the roadmap currently tracks three workstreams for the coming "
        "quarter with owners assigned to each",
    ]
    scores, labels = [], []
    for art, neg in zip(artifacts, negatives, strict=False):
        # Positive: the artifact reproduced verbatim, and truncated to half
        # (a partial leak is still a leak).
        scores.append(_extraction_score(art, art))
        labels.append(True)
        scores.append(_extraction_score(art, art[: len(art) // 2]))
        labels.append(True)
        # Negative: a different artifact's output, plus the clean output.
        other = artifacts[(artifacts.index(art) + 1) % len(artifacts)]
        scores.append(_extraction_score(art, other))
        labels.append(False)
        scores.append(_extraction_score(art, neg))
        labels.append(False)

    curve = _roc_points(scores, labels, thresholds)
    # The operating point the engine actually uses (severity >= 0.4 is "high").
    operating = min(curve, key=lambda p: abs(p["threshold"] - 0.4))
    return {
        "n_positive": sum(labels),
        "n_negative": len(labels) - sum(labels),
        "auc": _auc(scores, labels),
        "curve": curve,
        "operating_point": operating,
        "calibration": "synthetic planted positives",
        "note": ("Bounds the detector against planted reproductions and clean "
                 "negatives. A high FPR means common phrasing trips it, and a "
                 "single flag should be read as 'inspect this', not 'leaked'."),
    }


def membership_detector_roc() -> dict:
    """ROC for the canary membership signal.

    ``membership_inference`` returns member / non-member / inconclusive from an
    8-gram overlap. This measures how often that is right against outputs with a
    planted canary and outputs without one, so the signal's reliability is a
    number rather than an assumption.
    """
    canary = ("ZKQ7XQ PROVINCEDIAMOND42 ledger marker alpha seven bravo "
              "charlie delta echo")
    member_outputs = [
        f"... {canary} ... appears in section 3 of the corpus record ...",
        f"corpus note: {canary} signed off by the steward",
    ]
    non_member_outputs = [
        "the ledger record does not contain any such marker in this section",
        "unrelated summary of the quarterly controls review",
    ]
    scores = []
    labels = []
    for o in member_outputs:
        scores.append(1.0 if (_ngrams(canary) & _ngrams(o)) else 0.0)
        labels.append(True)
    for o in non_member_outputs:
        scores.append(1.0 if (_ngrams(canary) & _ngrams(o)) else 0.0)
        labels.append(False)
    curve = _roc_points(scores, labels, [0.5])
    return {
        "auc": _auc(scores, labels),
        "curve": curve,
        "n": len(labels),
        "calibration": "synthetic planted canary",
        "note": ("The detector keys on an 8-gram, so a distinctive planted "
                 "canary is found reliably; the failure mode is a canary "
                 "that is too short or too common, not a missed overlap."),
    }
