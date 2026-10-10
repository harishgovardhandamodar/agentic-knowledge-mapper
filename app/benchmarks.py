"""Benchmarks and calibration: bind the catalogue to external authority and
check that the numbers the engine emits are actually reliable.

Two separate gaps are closed here.

* **Provenance.** The threat catalogue (*T01*…) and the model mitigation
  catalogue (*MM01*…) are the engine's own ids. They mean nothing to an auditor
  who speaks OWASP, STRIDE or MITRE ATLAS. :data:`THREAT_BENCHMARKS` and
  :data:`MITIGATION_BENCHMARKS` are a small, *versioned* crosswalk from each
  internal id to the external ticket it represents, and :func:`coverage` turns
  the crosswalk into a "how much of the catalogue is even mapped?" number so an
  unmapped id is visible rather than assumed.

* **Reliability.** A risk score is only as good as the agreement behind it.
  :func:`cohens_kappa` measures whether two raters (or two runs) agree on the
  ordered L/I scale beyond chance, and :func:`reliability` turns
  ``(predicted_confidence, outcome)`` pairs into a Brier score and an
  expected-calibration-error -- the check that "70% confident" really happens
  about 70% of the time. A model that is confidently wrong is caught here.

Stdlib only. The benchmark tables carry a version; changing one is a deliberate
act with a diff, matching how the threat pack is versioned.
"""

#: Bump when any mapping below changes, so a stored assessment names the table
#: it was graded against.
BENCHMARK_VERSION = "2026.1"

#: Internal threat id -> external authority. ``atlas`` is ``None`` where MITRE
#: ATLAS has no first-class tactic and an OWASP/STRIDE ticket is the honest
#: mapping; coverage counts only ids that resolve to *something* external.
THREAT_BENCHMARKS = {
    "T01": {"owasp": "LLM02", "stride": "Information Disclosure",
            "atlas": "AML.T0057"},
    "T02": {"owasp": "LLM02", "stride": "Information Disclosure",
            "atlas": "AML.T0057"},
    "T03": {"owasp": "LLM08", "stride": "Tampering", "atlas": None},
    "T04": {"owasp": "LLM07", "stride": "Information Disclosure",
            "atlas": "AML.T0056"},
    "T05": {"owasp": "LLM01", "stride": "Spoofing / Elevation",
            "atlas": "AML.T0051"},
    "T06": {"owasp": "LLM06", "stride": "Information Disclosure",
            "atlas": "AML.T0057"},
    "T07": {"owasp": "LLM10", "stride": "Information Disclosure",
            "atlas": "AML.T0010"},
    "T08": {"owasp": "LLM09", "stride": "Repudiation", "atlas": None},
    "T09": {"owasp": "LLM09", "stride": "Tampering", "atlas": None},
    "T10": {"owasp": "LLM08", "stride": "Elevation of Privilege",
            "atlas": None},
    "T11": {"owasp": "LLM02", "stride": "Information Disclosure",
            "atlas": "AML.T0057"},
    "T12": {"owasp": "Governance", "stride": "Repudiation", "atlas": None},
}

#: Internal model-mitigation id -> the external practice it implements.
MITIGATION_BENCHMARKS = {
    "MM01": {"owasp": "LLM02", "standard": "NIST AI 100-2e",
             "atlas": "AML.M0004"},
    "MM02": {"owasp": "LLM02", "standard": "NIST AI 100-2e", "atlas": None},
    "MM03": {"owasp": "LLM02", "standard": "GDPR Art.17", "atlas": None},
    "MM04": {"owasp": "LLM06", "standard": "NIST AI 100-2e", "atlas": None},
    "MM05": {"owasp": "LLM02", "standard": "NIST AI 100-2e", "atlas": None},
    "MM06": {"owasp": "LLM01", "standard": "NIST AI 100-2e",
             "atlas": "AML.M0009"},
    "MM07": {"owasp": "LLM01", "standard": "OWASP LLM01", "atlas": None},
    "MM08": {"owasp": "LLM06", "standard": "OWASP LLM06", "atlas": None},
    "MM09": {"owasp": "LLM10", "standard": "OWASP LLM10", "atlas": None},
    "MM10": {"owasp": "LLM10", "standard": "ISO 27001 A.8.24", "atlas": None},
    "MM11": {"owasp": "LLM10", "standard": "OWASP LLM10", "atlas": None},
    "MM12": {"owasp": "LLM09", "standard": "NIST AI RMF", "atlas": None},
    "MM13": {"owasp": "LLM09", "standard": "NIST AI RMF", "atlas": None},
    "MM14": {"owasp": "LLM02", "standard": "ISO 27001 A.8.24", "atlas": None},
    "MM15": {"owasp": "LLM09", "standard": "ISO 27001 A.5.12", "atlas": None},
    "MM16": {"owasp": "LLM06", "standard": "OWASP LLM06", "atlas": None},
}

_TABLES = {
    "threat": THREAT_BENCHMARKS,
    "mitigation": MITIGATION_BENCHMARKS,
}


def benchmark_version() -> str:
    return BENCHMARK_VERSION


def _table(kind: str) -> dict:
    return _TABLES.get(kind, THREAT_BENCHMARKS)


def benchmark_for(node_id: str, *, kind: str = "threat") -> dict | None:
    """External crosswalk for one internal id, or ``None`` if unmapped."""
    return _table(kind).get(node_id)


def external_refs(node_id: str, *, kind: str = "threat") -> list:
    """Flat list of external references (``OWASP LLM01``, ``AML.T0051`` …)."""
    row = benchmark_for(node_id, kind=kind)
    if not row:
        return []
    refs = []
    if row.get("owasp"):
        refs.append(f"OWASP {row['owasp']}")
    if row.get("stride"):
        refs.append(f"STRIDE: {row['stride']}")
    if row.get("atlas"):
        refs.append(row["atlas"])
    if row.get("standard"):
        refs.append(row["standard"])
    return refs


def coverage(ids=None, *, kind: str = "threat") -> dict:
    """How much of a catalogue resolves to an external benchmark.

    ``ids`` defaults to every id in the table. Passing the *live* ids of an
    assessment answers the audit question directly: of the threats this report
    actually names, how many are externally grounded?
    """
    table = _table(kind)
    ids = list(ids) if ids is not None else list(table)
    mapped = [i for i in ids if table.get(i)]
    unmapped = [i for i in ids if i not in table or not table.get(i)]
    return {
        "version": BENCHMARK_VERSION,
        "kind": kind,
        "total": len(ids),
        "mapped": len(mapped),
        "unmapped": unmapped,
        # A fraction, not a pass/fail: partial coverage is normal and the
        # unmapped list is the actionable part.
        "fraction": round(len(mapped) / len(ids), 3) if ids else 1.0,
    }


def cohens_kappa(a, b) -> float:
    """Chance-corrected agreement between two ordered ratings in [0,1]."""
    pairs = [(x, y) for x, y in zip(a, b, strict=False)]
    n = len(pairs)
    if n == 0:
        return 0.0
    cats = sorted({x for x, _ in pairs} | {y for _, y in pairs})
    idx = {c: i for i, c in enumerate(cats)}
    k = len(cats)
    obs = [[0] * k for _ in range(k)]
    for x, y in pairs:
        obs[idx[x]][idx[y]] += 1
    po = sum(obs[i][i] for i in range(k)) / n
    ra = [sum(obs[i]) / n for i in range(k)]
    rb = [sum(obs[j][i] for j in range(k)) / n for i in range(k)]
    pe = sum(ra[i] * rb[i] for i in range(k))
    if abs(1.0 - pe) < 1e-12:
        return 1.0 if abs(po - 1.0) < 1e-12 else 0.0
    return round((po - pe) / (1.0 - pe), 4)


def inter_rater(rows, *, keys=("likelihood", "impact")) -> dict:
    """Agreement across two raters on the ordered L/I scales.

    ``rows`` is an iterable of ``(rater_a_dict, rater_b_dict)``. Each scale gets
    its own kappa; the result also carries a plain-text interpretation band so
    a low agreement is legible ("slight") rather than a bare number.
    """
    pairs = list(rows or [])
    out = {"n": len(pairs)}
    for key in keys:
        a = [r[0].get(key) for r in pairs]
        b = [r[1].get(key) for r in pairs]
        kappa = cohens_kappa(a, b)
        out[key] = {"kappa": kappa, "band": _kappa_band(kappa)}
    if pairs and len(keys):
        out["mean_kappa"] = round(
            sum(out[k]["kappa"] for k in keys) / len(keys), 4)
        out["band"] = _kappa_band(out["mean_kappa"])
    return out


def _kappa_band(kappa: float) -> str:
    if kappa >= 0.81:
        return "almost perfect"
    if kappa >= 0.61:
        return "substantial"
    if kappa >= 0.41:
        return "moderate"
    if kappa >= 0.21:
        return "fair"
    if kappa > 0.0:
        return "slight"
    return "poor"


def reliability(samples, *, bins: int = 5) -> dict:
    """Calibration of confidence statements against realised outcomes.

    ``samples`` is an iterable of ``(predicted_confidence_in_[0,1], outcome_bool)``.
    Returns the Brier score (lower is better, 0.25 is the no-skill baseline for
    balanced data) and the expected calibration error: how far, on average, each
    confidence bin's realised rate is from its stated confidence. A well-behaved
    engine has a small ECE even if the Brier score is modest.
    """
    s = [(float(p), bool(o)) for p, o in (samples or [])]
    n = len(s)
    if n == 0:
        return {"n": 0, "brier": 0.0, "ece": 0.0, "bins": []}
    brier = sum((p - (1.0 if o else 0.0)) ** 2 for p, o in s) / n
    edges = [i / bins for i in range(bins + 1)]
    detail = []
    ece = 0.0
    for i in range(bins):
        lo, hi = edges[i], edges[i + 1]
        bucket = [(p, o) for p, o in s
                  if (lo < p <= hi) or (i == 0 and p <= hi)]
        if not bucket:
            detail.append({"lo": round(lo, 2), "hi": round(hi, 2),
                           "n": 0, "mean_conf": None, "accuracy": None})
            continue
        mean_conf = sum(p for p, _ in bucket) / len(bucket)
        acc = sum(1 for _, o in bucket if o) / len(bucket)
        ece += (len(bucket) / n) * abs(mean_conf - acc)
        detail.append({"lo": round(lo, 2), "hi": round(hi, 2),
                       "n": len(bucket), "mean_conf": round(mean_conf, 3),
                       "accuracy": round(acc, 3)})
    return {
        "n": n,
        "brier": round(brier, 4),
        "ece": round(ece, 4),
        "band": _ece_band(ece),
        "bins": detail,
    }


def _ece_band(ece: float) -> str:
    if ece <= 0.05:
        return "well-calibrated"
    if ece <= 0.1:
        return "acceptable"
    if ece <= 0.2:
        return "weak"
    return "mis-calibrated"
