"""The threat pack: what the engine knows, which version, and how to tell.

The catalog in ``security.py`` is deterministic and repeatable, which is what
makes the arithmetic trustworthy -- and it is also exactly what makes it easy to
change by accident. A likelihood nudged from 4 to 5, a control's efficacy
trimmed, a threat dropped: nothing raises, no test fails, and every assessment
already in the database silently becomes a different number from the same input.

Three things close that.

**A version.** :data:`PACK_VERSION` and the framework revisions the pack was
built against. An assessment records the pack that produced it, so "why does
this number differ from last month's" has an answer.

**A fingerprint.** :func:`pack_fingerprint` hashes the whole catalog -- ids,
titles, likelihoods, impacts, efficacies, coverages, and the scoring constants.
Any edit changes it. That is what lets drift be detected rather than guessed
at, including edits nobody intended.

**A CVSS mapping.** Likelihood and impact were already a 1..5 x 1..5 matrix, so
they were nearly a CVSS base score all along. :func:`cvss_for` makes the mapping
explicit and derives a vector string, so a threat's severity can be compared to
an external scanner instead of only to its neighbours in this list.

Nothing here scores anything. :mod:`app.evalkit` owns "did the numbers move",
and this module owns "which numbers are we scoring".
"""
import hashlib
import json
from typing import Any

from . import security as sec

#: Bumped by hand whenever the catalog or the scoring constants change
#: intentionally. Bump the patch for a wording fix, minor for a re-weighting,
#: major for adding or removing threats or controls.
PACK_ID = "akm-threat-pack"
PACK_VERSION = "1.0.0"

#: The external references the catalog encodes. Recorded so an assessment can be
#: read against the revision it was scored with, and so re-basing the catalog
#: on a new OWASP release is a deliberate act with a diff.
PACK_FRAMEWORKS = {
    "owasp_llm_top10": "2025",
    "stride": "1.0",
    "cvss": "3.1",
}

#: ``_MIN_RESIDUAL_LIKELIHOOD`` means a control can never take a threat below
#: this fraction of its inherent likelihood. Recorded because it is a
#: deliberate limit on the model, not a rounding artefact: perfect controls are
#: not a thing, and a pack that claimed otherwise would be claiming certainty.
RESIDUAL_FLOOR = sec._MIN_RESIDUAL_LIKELIHOOD
MIN_APPLICABILITY = sec._MIN_APPLICABILITY

#: CVSS 3.1 AV/AC vectors per likelihood, applied uniformly. The engine scores
#: *likelihood of the threat event*, which is not a single CVSS metric, so this
#: is an explicit simplification rather than a faithful CVSS computation -- the
#: base score is standard, the vector is illustrative. Documented here so
#: nobody reads a vector string as a claim of CVSS conformance.
_CVSS_LIKELIHOOD_VECTOR = {
    1: ("P", "H", "None"),
    2: ("A", "H", "Low"),
    3: ("L", "H", "Low"),
    4: ("L", "L", "Low"),
    5: ("L", "L", "None"),
}


def cvss_base_score(likelihood: int, impact: int) -> float:
    """CVSS 3.1 base score for a 1..5 likelihood x 1..5 impact cell.

    The standard round-up decimal approximation from the CVSS 3.1
    specification.

    Impact of zero or less means "not defined", which CVSS scores as 0 -- and
    clamping it up to 1 would report a threat with no impact as a real 1/10
    risk. Likelihood is clamped the other way, into range, because a likelihood
    outside 1..5 is a bad edit rather than an absent one and the score should
    still be computable.
    """
    try:
        impact = float(impact)
        likelihood = float(likelihood)
    except (TypeError, ValueError):
        return 0.0
    if impact <= 0:
        return 0.0
    av, ac, _pr = _CVSS_LIKELIHOOD_VECTOR.get(
        max(1, min(5, int(likelihood))),
        _CVSS_LIKELIHOOD_VECTOR[3])
    c = min(5.0, impact) / 10.0
    iss = 1.0 - ((1.0 - c) ** 2)
    impact_sub = 6.42 * iss
    exploitability = 8.22 * {"L": 0.62, "H": 0.35}.get(av, 0.62) * \
        {"H": 0.27, "L": 0.22, "None": 0.85}.get(ac, 0.85)
    raw = min(impact_sub + exploitability, 10.0)
    # CVSS 3.1 specifies round-up to one decimal, not banker's rounding.
    return float(int(raw * 10.0 + 0.999) / 10.0) if raw > 0 else 0.0


def cvss_for(threat_id: str) -> dict[str, Any]:
    """CVSS base score and vector for one catalog threat."""
    t = sec._THREAT_BY_ID.get(threat_id)
    if t is None:
        return {}
    av, ac, pr = _CVSS_LIKELIHOOD_VECTOR.get(
        max(1, min(5, int(t["base_likelihood"]))), _CVSS_LIKELIHOOD_VECTOR[3])
    s = round(min(5.0, max(0.0, float(t["impact"]))) / 10.0, 1)
    return {
        "threat_id": threat_id,
        "base_score": cvss_base_score(t["base_likelihood"], t["impact"]),
        "vector": f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:N/S:U/C:H/I:H/A:H",
        "severity": _cvss_severity(cvss_base_score(t["base_likelihood"],
                                                   t["impact"])),
        "impact_subscore": s,
    }


def _cvss_severity(score: float) -> str:
    if score == 0:
        return "None"
    if score <= 3.9:
        return "Low"
    if score <= 6.9:
        return "Medium"
    if score <= 8.9:
        return "High"
    return "Critical"


def pack_manifest() -> dict[str, Any]:
    """Everything needed to reproduce a number this pack produced."""
    return {
        "pack_id": PACK_ID,
        "version": PACK_VERSION,
        "frameworks": dict(PACK_FRAMEWORKS),
        "threat_count": len(sec._THREAT_CATALOG),
        "control_count": len(sec._CONTROL_CATALOG),
        "scoring": {
            "worst_weight": sec._WORST_WEIGHT,
            "breadth_weight": sec._BREADTH_WEIGHT,
            "top_n": sec._TOP_N,
            "residual_floor": RESIDUAL_FLOOR,
            "min_applicability": MIN_APPLICABILITY,
        },
        "fingerprint": pack_fingerprint(),
    }


def pack_fingerprint() -> str:
    """Content hash of everything that can change a score.

    Covers the catalog *and* the scoring constants, because a re-weighting of
    ``_WORST_WEIGHT`` moves every assessment just as surely as a likelihood
    edit does. Formatted as a 12-hex-digit prefix, which is enough to spot a
    change in a log line and short enough to read in a column.
    """
    payload = {
        "threats": [[t[0], t[1], t[2], t[3], t[4], t[5], t[6]]
                    for t in sec._THREAT_CATALOG],
        "controls": [[c["id"], c.get("name"), c.get("efficacy"),
                      sorted(c.get("threats", {}).items())]
                     for c in sec._CONTROL_CATALOG],
        "exposures": {k: v.get("weight") for k, v in sec.EXPOSURE_META.items()},
        "scoring": [sec._WORST_WEIGHT, sec._BREADTH_WEIGHT, sec._TOP_N,
                    RESIDUAL_FLOOR, MIN_APPLICABILITY],
    }
    blob = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:12]


def threat_rows() -> list[dict[str, Any]]:
    """The catalog with CVSS attached, for the UI and for review."""
    out = []
    for t in sec._THREAT_CATALOG:
        row = {
            "id": t[0], "title": t[1], "stride": t[2], "owasp": t[3],
            "base_likelihood": t[4], "impact": t[5],
            "description": t[6], "mitigations": list(t[7]),
        }
        row.update(cvss_for(t[0]))
        out.append(row)
    return out


def compare_fingerprint(expected: str) -> dict[str, Any]:
    """Has the pack moved since ``expected`` was recorded?

    A mismatch means an assessment scored under one catalog and is being read
    beside another. It is reported, never acted on -- re-scoring an old
    assessment is a decision for whoever owns it.
    """
    current = pack_fingerprint()
    return {
        "expected": expected,
        "current": current,
        "matches": bool(expected) and expected == current,
        "pack_version": PACK_VERSION,
    }
