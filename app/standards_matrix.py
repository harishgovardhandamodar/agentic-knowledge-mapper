"""AI Standards & Regulations score matrix, scoped to a security assessment.

The dashboard (``standards-dashboard/``) owns the taxonomy: 34 frameworks, each
scored 0|1|2 on 10 control pillars, published as a static ``data.json``. This
module re-serves that same data through the :8204 API so the AI Security
Engineering & Evaluation Agent can show it as a sub-tab, plus a deterministic
relevance score per framework for the assessment in view.

Relevance is token overlap, using the dashboard's own matching semantics
(``engine.ts``: lowercase, split on ``[^a-z0-9+]+``, drop 1-char tokens; exact
token match counts 2, a substring match either way counts 1). The query is the
assessment itself -- threat ids/titles/STRIDE/OWASP mappings, the active
controls' names and cited standards (``ISO 27001 A.5.12``, ``OWASP LLM02``),
and known-exploit attack classes. No model is involved, so the ranking is
stable for a given assessment and the matched tokens explain it.
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any

import requests

from . import security as sec_engine
from .models import SecurityAssessment

BASE_URL = os.environ.get("STANDARDS_BASE_URL", "http://standards").rstrip("/")
TIMEOUT_S = float(os.environ.get("STANDARDS_TIMEOUT_S", "10"))
CACHE_TTL_S = float(os.environ.get("STANDARDS_CACHE_TTL_S", "900"))

_TAXONOMY_PATH = os.path.join(os.path.dirname(__file__), "standards_taxonomy.json")
_TOKEN_SPLIT = re.compile(r"[^a-z0-9+]+")

# Threat -> control pillars. Curated from the STRIDE category and OWASP
# mapping of each catalogue entry in app/security.py; the test suite pins
# full coverage of the catalogue so a new threat id fails loudly instead of
# silently dropping out of the findings view.
THREAT_PILLARS: dict[str, list[str]] = {
    "T01": ["privacy", "data_governance", "human_oversight"],
    "T02": ["privacy", "data_governance", "transparency"],
    "T03": ["data_governance", "accountability"],
    "T04": ["privacy", "transparency"],
    "T05": ["security", "robustness"],
    "T06": ["security", "privacy", "accountability"],
    "T07": ["security", "lifecycle_eval", "accountability"],
    "T08": ["accountability", "incident_response"],
    "T09": ["robustness", "transparency", "human_oversight"],
    "T10": ["security", "accountability"],
    "T11": ["privacy", "data_governance", "accountability"],
    "T12": ["accountability", "risk_management"],
}


def threat_pillars(threat_id: Any) -> list[str]:
    return list(THREAT_PILLARS.get(str(threat_id or ""), []))


def standing(pillars: list[str], coverage: dict[str, Any]) -> tuple[int | None, list[str]]:
    """(standing 0|1|2|None, via pillars) of one finding vs one framework.

    The finding stands as well as the best-covered of its pillars; ``via``
    names the pillars that reach that best score. No pillar mapping means no
    standing (None), which the GUI shows as unmapped rather than a gap.
    """
    if not pillars:
        return None, []
    scored = [(coverage.get(p, 0), p) for p in pillars]
    top = max(s for s, _ in scored)
    return top, sorted(p for s, p in scored if s == top)


def findings_section(threats: list[Any],
                     coverages: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Assessment findings with per-framework standings, worst residual first."""
    out = []
    for t in threats:
        if not isinstance(t, dict):
            continue
        pillars = threat_pillars(t.get("id"))
        stands = {}
        for fid, cov in coverages.items():
            s, via = standing(pillars, cov)
            if s is not None:
                stands[fid] = {"s": s, "via": via}
        out.append({
            "id": t.get("id"), "title": t.get("title"),
            "residual_severity": t.get("residual_severity"),
            "residual_score": t.get("residual_score"),
            "coverage": t.get("coverage"),
            "pillars": pillars,
            "controls": t.get("controls") or [],
            "standings": stands,
        })
    out.sort(key=lambda f: -(f["residual_score"] or 0)
             if isinstance(f["residual_score"], (int, float)) else 0)
    return out


# Query-side stopwords: exact matches on these say nothing ("the" hits every
# framework), and as substrings they match everything ("or" is inside "for").
_STOP = frozenset("""
    a an the and or of to in on for with from that this these those it its
    is are was were be been has have had will would can could should may
    not no all any each per via into over under between within without such
    than then them they their our your you your we he she him her his as at
    by do does did done who which what when where how why there here
    """.split())

# Substring matches below this length are noise ("or" inside "for", "of"
# inside "of" is exact and fine, but "ai" inside "said" is not a signal).
_MIN_PARTIAL_LEN = 4

_CACHE: dict[str, Any] = {"at": 0.0, "data": None}


class StandardsUnavailable(Exception):
    """The dashboard container could not be reached or returned bad data."""

    def __init__(self, detail: str):
        super().__init__(detail)
        self.detail = detail


class AssessmentNotFound(Exception):
    pass


def tokens(s: Any) -> list[str]:
    """Dashboard-compatible tokenizer (see ``engine.ts``)."""
    return [t for t in _TOKEN_SPLIT.split(str(s or "").lower()) if len(t) > 1]


def coverage_pct(coverage: dict[str, Any], dim_ids: list[str]) -> float:
    """Average of the 0|1|2 pillar scores, as a 0..100 percentage."""
    vals = [coverage.get(d, 0) for d in dim_ids]
    if not vals:
        return 0.0
    try:
        avg = sum(float(v) for v in vals) / len(vals)
    except (TypeError, ValueError):
        return 0.0
    return round(avg / 2 * 100, 1)


def load_taxonomy() -> dict[str, Any]:
    with open(_TAXONOMY_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def fetch_dashboard() -> dict[str, Any]:
    """The dashboard's ``data.json`` over the compose network, cached briefly."""
    now = time.monotonic()
    if _CACHE["data"] is not None and now - _CACHE["at"] < CACHE_TTL_S:
        return _CACHE["data"]
    try:
        r = requests.get(f"{BASE_URL}/data.json", timeout=TIMEOUT_S)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        raise StandardsUnavailable(
            f"AI Standards dashboard unreachable at {BASE_URL}/data.json: {e}")
    if not isinstance(data, dict) or not isinstance(data.get("frameworks"), list):
        raise StandardsUnavailable(
            f"AI Standards dashboard at {BASE_URL}/data.json returned no frameworks")
    _CACHE["at"] = now
    _CACHE["data"] = data
    return data


def reset_cache() -> None:
    _CACHE["at"] = 0.0
    _CACHE["data"] = None


def framework_haystack(fw: dict[str, Any]) -> str:
    """The text a framework can be relevant through (mirrors ``engine.ts``)."""
    parts = [fw.get("id"), fw.get("name"), fw.get("issuer"),
             fw.get("jurisdiction"), fw.get("kind"), fw.get("summary")]
    for key in ("controls", "scenarios", "riskTiers"):
        vals = fw.get(key) or []
        parts.append(" ".join(str(v) for v in vals))
    return " ".join(p for p in parts if p)


def relevance(query_tokens: list[str], fw: dict[str, Any],
              cap: int = 8) -> tuple[float, list[str]]:
    """(0..100 score, matched query tokens) for one framework.

    Dashboard-compatible semantics (exact 2, substring 1), tightened for an
    explanatory ranking: a substring match only counts when both sides are
    long enough to mean something.
    """
    if not query_tokens:
        return 0.0, []
    hay = set(tokens(framework_haystack(fw)))
    if not hay:
        return 0.0, []
    total = 0
    matched: list[str] = []
    for q in query_tokens:
        if q in hay:
            total += 2
            matched.append(q)
        elif len(q) >= _MIN_PARTIAL_LEN and any(
                len(h) >= _MIN_PARTIAL_LEN and (q in h or h in q) for h in hay):
            total += 1
            matched.append(q)
    return round(total / (2 * len(query_tokens)) * 100, 1), matched[:cap]


def assessment_query(assessment: dict[str, Any]) -> tuple[list[str], dict[str, int]]:
    """Token query + basis counts for one stored assessment record.

    ``assessment`` is the ``_security_json``-shaped record: threats carry
    ``id``/``title``/``stride``/``owasp``/``description`` plus per-threat
    ``controls`` contributor ids; ``active_controls`` lists the enabled
    control ids resolved against the catalogue (name, cited standard,
    description); known exploits carry ``attack_class``/``title``.
    """
    seen: set[str] = set()
    query: list[str] = []

    def add(text: Any) -> None:
        for t in tokens(text):
            if t not in seen:
                seen.add(t)
                query.append(t)

    threats = assessment.get("threats") or []
    active = [c for c in (assessment.get("active_controls") or []) if c]
    if not active:
        # Records that predate the active-controls field still name their
        # controls per threat row; fall back to those contributor ids.
        for t in threats:
            if isinstance(t, dict):
                active.extend((t.get("controls") or []))
    controls = [sec_engine._CONTROL_BY_ID[c] for c in dict.fromkeys(active)
                if c in sec_engine._CONTROL_BY_ID]
    exploits = assessment.get("known_exploits") or []

    for t in threats:
        if not isinstance(t, dict):
            continue
        for key in ("id", "title", "stride", "owasp", "description"):
            add(t.get(key))
    for c in controls:
        for key in ("id", "name", "standard", "description"):
            add(c.get(key))
    for e in exploits:
        if not isinstance(e, dict):
            continue
        for key in ("id", "title", "attack_class", "description"):
            add(e.get(key))
    query = [t for t in query if t not in _STOP]
    basis = {"threats": len(threats), "controls": len(controls),
             "exploits": len(exploits), "query_tokens": len(query)}
    return query, basis


def build_matrix(db=None, assessment_id: int | None = None) -> dict[str, Any]:
    """Score-matrix payload, optionally scoped to one assessment."""
    tax = load_taxonomy()
    dim_ids = [d["id"] for d in tax.get("dimensions", [])]
    data = fetch_dashboard()
    frameworks = data.get("frameworks", [])

    query: list[str] = []
    basis: dict[str, int] = {"threats": 0, "controls": 0, "exploits": 0,
                             "query_tokens": 0}
    assessment_meta: dict[str, Any] | None = None
    record: dict[str, Any] = {}
    if assessment_id is not None:
        if db is None:
            raise AssessmentNotFound()
        rec = db.query(SecurityAssessment).filter(
            SecurityAssessment.id == assessment_id).first()
        if rec is None:
            raise AssessmentNotFound()
        # Imported here: main.py owns the record serializer, and main imports
        # this module, so a top-level import would be circular.
        from . import main as main_mod
        record = main_mod._security_json(rec)
        if record.get("assessment_path") == "model":
            # Model-path assessments are never mapped onto AI-standards
            # frameworks: the taxonomy scores product controls, and a
            # weights-and-data question is answered from the model, not the
            # catalogue. The frontend renders this as an explanation, and
            # direct API callers get the same answer (not an empty matrix
            # that reads as "no coverage").
            return {"generated": data.get("generated"),
                    "dimensions": tax.get("dimensions", []),
                    "score_legend": tax.get("scoreLegend", {}),
                    "assessment": {"id": rec.id,
                                   "product": getattr(rec, "product_name", ""),
                                   "skipped": True},
                    "frameworks": [],
                    "findings": None,
                    "skipped": True,
                    "skip_reason": ("Model-path assessment: AI-standards "
                                    "frameworks describe product controls; this "
                                    "assessment scores model internals by "
                                    "dimension weight instead. See the "
                                    "assessment's subject-profile section.")}
        query, basis = assessment_query(record)
        assessment_meta = {"id": rec.id,
                           "product": getattr(rec, "product_name", ""),
                           "basis": basis}

    rows = []
    for fw in frameworks:
        if not isinstance(fw, dict):
            continue
        cov = fw.get("coverage") or {}
        pct = coverage_pct(cov, dim_ids)
        rel, matched = relevance(query, fw)
        rows.append({
            "id": fw.get("id"), "name": fw.get("name"),
            "issuer": fw.get("issuer"), "jurisdiction": fw.get("jurisdiction"),
            "kind": fw.get("kind"), "version": fw.get("version"),
            "status": fw.get("status"), "url": fw.get("url"),
            "summary": fw.get("summary"),
            "controls": fw.get("controls") or [],
            "scenarios": (fw.get("scenarios") or [])[:6],
            "risk_tiers": fw.get("riskTiers") or [],
            "last_checked": fw.get("lastChecked"),
            "coverage": {d: cov.get(d, 0) for d in dim_ids},
            "coverage_pct": pct,
            "relevance": rel if query else 100.0,
            "matched": matched,
            "relevant": bool(rel) if query else True,
        })
    if query:
        rows.sort(key=lambda r: (-r["relevance"], -r["coverage_pct"],
                                 str(r["name"] or "")))
    else:
        rows.sort(key=lambda r: (-r["coverage_pct"], str(r["name"] or "")))
    findings = None
    if assessment_meta is not None:
        coverages = {r["id"]: r["coverage"] for r in rows if r.get("id")}
        findings = findings_section(record.get("threats") or [], coverages)
    return {"generated": data.get("generated"),
            "dimensions": tax.get("dimensions", []),
            "score_legend": tax.get("scoreLegend", {}),
            "assessment": assessment_meta,
            "frameworks": rows,
            "findings": findings}
