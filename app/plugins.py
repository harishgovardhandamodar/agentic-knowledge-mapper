"""Investigation types as plugins, all researched by the council.

The five investigation types share one shape so the manager, the API,
and the CLI can treat them uniformly:

* ``adoption`` -- adoption advice against the organisation's nature
  (deterministic pack, quotes prior analyses);
* ``security`` -- security and privacy assessment (assessment modes,
  latest-row read adapter);
* ``vulnerability`` -- known-vulnerability search and landscape (CVE
  collection runs ambiently; the plugin reads the findings back);
* ``writeup`` -- explainer write-ups (latest explanation read adapter);
* ``hypothesis`` -- scenario enumeration, inherent and derived.

Every plugin declares which research-council seats it needs, whether a
manager command routes to it, the topics such a command plans, and a
deterministic ``analyze`` entry. Launches stay in their home modules
(security_agent, explainer, cve collectors); plugins never duplicate
execution paths, they only route and read.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

PLUGIN_VERSIONS = {
    "adoption": "1.1.0",
    "security": "1.0.0",
    "vulnerability": "1.0.0",
    "writeup": "1.0.0",
    "hypothesis": "1.0.0",
}

_VULN_RES = (
    re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE),
    re.compile(r"\bknown vulnerabilit\w*\b", re.IGNORECASE),
    re.compile(r"\bsecurity advisor\w*\s+for\b", re.IGNORECASE),
    re.compile(r"\blist\s+.*\b(advisories|CVEs?)\b", re.IGNORECASE),
)

_HYP_RES = (
    re.compile(r"\bscenarios?\b.*\b(what|all|possible|enumerate|list)\b",
               re.IGNORECASE),
    re.compile(r"\b(what|all)\b.*\bscenarios?\b", re.IGNORECASE),
    re.compile(r"\bwhat\b.*\bcould happen\b", re.IGNORECASE),
)

_ADOPTION_RES = (
    re.compile(r"\bshould we adopt\b", re.IGNORECASE),
    re.compile(r"^\s*adopt\b", re.IGNORECASE),
    re.compile(r"\broll\s?out\b", re.IGNORECASE),
)

_QUESTION_RES = (
    re.compile(r"^\s*(what|how|why|explain|compare)\b", re.IGNORECASE),
    re.compile(r"\?\s*$"),
)


def match_command(command: str) -> list[dict]:
    """Which plugins take part in an episode for this command.

    Shown by the manager when a command parses so the operator sees the
    investigation mix before choosing a depth. Matches are independent
    (an incident question can also match writeup); security is the
    default lens and always matches because assessments run unless
    unchecked.
    """
    text = command or ""
    matched = {
        "adoption": (any(rx.search(text) for rx in _ADOPTION_RES),
                     "adoption language"),
        "security": (True, "default lens"),
        "vulnerability": (_vuln_detect(text), "CVE/advisory language"),
        "writeup": (any(rx.search(text) for rx in _QUESTION_RES),
                    "question form"),
        "hypothesis": (_hyp_detect(text), "scenario language"),
    }
    out = []
    for key, plugin in PLUGINS.items():
        is_match, via = matched[key]
        out.append({"key": key, "title": plugin.title,
                    "version": plugin.version,
                    "matched": bool(is_match), "via": via})
    return out


def _clean_vuln_subject(command: str) -> str:
    text = re.sub(r"\s+", " ", (command or "")).strip().rstrip(".?")
    text = re.sub(r"^(list|show|find|search|what are)\b\s+", "", text,
                  flags=re.IGNORECASE)
    text = re.sub(r"\b(known vulnerabilit\w*|security advisor\w*|"
                  r"advisories|CVEs?|affecting|for)\b", "", text,
                  flags=re.IGNORECASE)
    return re.sub(r"\s+", " ", text).strip(" -:,")[:120] or "the product"


def _adoption_analyze(db, inv_id: int) -> dict[str, Any]:
    from . import adoption_advice as _aa
    from .models import Investigation
    inv = db.query(Investigation).filter(
        Investigation.id == inv_id).first()
    if inv is None:
        return {"verdict": {"key": "insufficient_evidence",
                            "label": "no such investigation"},
                "version": PLUGIN_VERSIONS["adoption"],
                "fingerprint": _aa.adoption_advice_fingerprint()}
    return _aa.adoption_advice(db, query=getattr(inv, "title", "") or "",
                               investigation_id=inv_id)


def _security_analyze(db, inv_id: int) -> dict[str, Any]:
    import json as _json

    from .models import SecurityAssessment
    try:
        rec = (db.query(SecurityAssessment)
               .filter(SecurityAssessment.investigation_id == inv_id)
               .order_by(SecurityAssessment.id.desc()).first())
    except Exception:
        rec = None
    if rec is None:
        return {"assessment": None,
                "gap": "no assessment stored: launch one first",
                "version": PLUGIN_VERSIONS["security"],
                "fingerprint": f"security-adapter-"
                               f"{PLUGIN_VERSIONS['security']}"}
    try:
        scoring = _json.loads(rec.scoring_json or "{}")
    except Exception:
        scoring = {}
    try:
        threats = _json.loads(rec.threats_json or "[]")
    except Exception:
        threats = []
    top = [t for t in threats if isinstance(t, dict)][:5]
    return {"assessment_id": rec.id,
            "product": getattr(rec, "product_name", ""),
            "exposure": getattr(rec, "exposure", ""),
            "residual_pct": getattr(rec, "residual_pct", None),
            "overall_pct": getattr(rec, "overall_pct", None),
            "assessment_path": scoring.get("assessment_path"),
            "top_threats": [
                {"title": t.get("title") or t.get("name") or "",
                 "severity": t.get("severity") or
                 t.get("residual") or ""} for t in top],
            "created_at": (rec.created_at.isoformat()
                           if getattr(rec, "created_at", None) else None),
            "version": PLUGIN_VERSIONS["security"],
            "fingerprint": f"security-adapter-"
                           f"{PLUGIN_VERSIONS['security']}"}


def _vulnerability_analyze(db, inv_id: int) -> dict[str, Any]:
    from .models import Artifact, CveFinding
    try:
        cves = (db.query(Artifact)
                .filter(Artifact.investigation_id == inv_id,
                        Artifact.artifact_type == "cve")
                .order_by(Artifact.id.desc()).all())
    except Exception:
        cves = []
    try:
        findings = (db.query(CveFinding)
                    .filter(CveFinding.investigation_id == inv_id).all())
    except Exception:
        findings = []
    rows = []
    for a in cves[:15]:
        rows.append({"id": a.id, "title": (a.title or "")[:160],
                     "url": a.url,
                     "relevance": getattr(a, "relevance", None)})
    return {"cve_artifacts": len(cves), "findings": len(findings),
            "top": rows,
            "gap": ("no CVE artifacts collected yet"
                    if not cves else ""),
            "version": PLUGIN_VERSIONS["vulnerability"],
            "fingerprint": f"vulnerability-adapter-"
                           f"{PLUGIN_VERSIONS['vulnerability']}"}


def _writeup_analyze(db, inv_id: int) -> dict[str, Any]:
    from .models import Explanation
    try:
        exps = (db.query(Explanation)
                .filter(Explanation.investigation_id == inv_id)
                .order_by(Explanation.id.desc()).all())
    except Exception:
        exps = []
    if not exps:
        return {"explanation": None,
                "gap": "no write-up yet: ask a question first",
                "version": PLUGIN_VERSIONS["writeup"],
                "fingerprint": f"writeup-adapter-"
                               f"{PLUGIN_VERSIONS['writeup']}"}
    latest = exps[0]
    answer = getattr(latest, "answer", None)
    head = ""
    diagrams = 0
    if isinstance(answer, str):
        try:
            import json as _json
            answer = _json.loads(answer)
        except Exception:
            pass
    if isinstance(answer, dict):
        for key in ("summary", "answer", "text"):
            if isinstance(answer.get(key), str) and answer[key].strip():
                head = answer[key][:500]
                break
        diagrams = len(answer.get("diagrams") or []) + (
            1 if answer.get("diagram") else 0)
    return {"explanation_id": latest.id,
            "question": getattr(latest, "question", ""),
            "status": getattr(latest, "status", ""),
            "mode": getattr(latest, "mode", ""),
            "answer_head": head, "diagrams": diagrams,
            "thread": len(exps),
            "version": PLUGIN_VERSIONS["writeup"],
            "fingerprint": f"writeup-adapter-"
                           f"{PLUGIN_VERSIONS['writeup']}"}


def _hypothesis_analyze(db, inv_id: int) -> dict[str, Any]:
    from . import hypothesiser as _hy
    return _hy.enumerate_scenarios(db, inv_id)


def _vuln_detect(command: str) -> bool:
    return any(rx.search(command or "") for rx in _VULN_RES)


def _hyp_detect(command: str) -> bool:
    return any(rx.search(command or "") for rx in _HYP_RES)


def _vuln_plan(command: str) -> list | None:
    if not _vuln_detect(command):
        return None
    subject = _clean_vuln_subject(command)
    return [{
        "title": f"Known vulnerabilities affecting {subject}"[:120],
        "subject": subject[:120],
        "task": "vulnerability_landscape",
        "description": ("Known-vulnerability search and landscape: CVEs, "
                        "advisories, and disclosures affecting "
                        f"{subject}, newest and most severe first. "
                        "Evidence only; no residual scoring."),
        "keywords": f"{subject}, CVE, advisory, known vulnerabilities",
        "focus": ["cve", "advisories", "affected versions", "patches",
                  "severity"][:8],
        "anti_focus": ["residual scoring", "unrelated products"],
        "exposure": None,
    }]


def _hyp_plan(command: str) -> list | None:
    if not _hyp_detect(command):
        return None
    subject = _clean_vuln_subject(command)
    subject = re.sub(r"\bscenarios?\b", "", subject,
                     flags=re.IGNORECASE).strip(" -:,") or subject
    return [{
        "title": f"Scenarios for {subject}: inherent and derived"[:120],
        "subject": subject[:120],
        "task": "hypothesis_scenarios",
        "description": ("Hypothesis scenarios for "
                        f"{subject}: enumerate every scenario the "
                        f"collected evidence admits, inherent (one "
                        f"finding each) and derived (compositions with "
                        f"cited parents). Unknowns stay unknown."),
        "keywords": f"{subject}, scenarios, hypotheses",
        "focus": ["scenarios", "inherent", "derived", "evidence"][:8],
        "anti_focus": ["invented scenarios"],
        "exposure": None,
    }]


def _adoption_fingerprint() -> str:
    from . import adoption_advice as _aa
    return _aa.adoption_advice_fingerprint()


def _hypothesis_fingerprint() -> str:
    from . import hypothesiser as _hy
    return _hy.hypothesis_fingerprint()


@dataclass(frozen=True)
class Plugin:
    """One investigation type: routing, planning, and reading back."""

    key: str
    title: str
    version: str
    seats: tuple
    detect_command: Callable[[str], bool]
    plan_topics: Callable[[str], list | None]
    analyze: Callable[[Any, int], dict[str, Any]]
    fingerprint: Callable[[], str]


PLUGINS: dict[str, Plugin] = {
    "adoption": Plugin(
        key="adoption", title="Adoption advice",
        version=PLUGIN_VERSIONS["adoption"], seats=(),
        detect_command=lambda command: False,
        plan_topics=lambda command: None,
        analyze=_adoption_analyze, fingerprint=_adoption_fingerprint),
    "security": Plugin(
        key="security", title="Security and privacy assessment",
        version=PLUGIN_VERSIONS["security"],
        seats=("news", "papers", "official", "cve", "provider"),
        detect_command=lambda command: False,
        plan_topics=lambda command: None,
        analyze=_security_analyze,
        fingerprint=lambda: f"security-adapter-"
                            f"{PLUGIN_VERSIONS['security']}"),
    "vulnerability": Plugin(
        key="vulnerability",
        title="Known vulnerability search and landscape",
        version=PLUGIN_VERSIONS["vulnerability"],
        seats=("news", "cve"),
        detect_command=_vuln_detect, plan_topics=_vuln_plan,
        analyze=_vulnerability_analyze,
        fingerprint=lambda: f"vulnerability-adapter-"
                            f"{PLUGIN_VERSIONS['vulnerability']}"),
    "writeup": Plugin(
        key="writeup", title="Write-up / explainer",
        version=PLUGIN_VERSIONS["writeup"], seats=("news", "papers"),
        detect_command=lambda command: False,
        plan_topics=lambda command: None,
        analyze=_writeup_analyze,
        fingerprint=lambda: f"writeup-adapter-"
                            f"{PLUGIN_VERSIONS['writeup']}"),
    "hypothesis": Plugin(
        key="hypothesis", title="Hypothesiser: inherent and derived",
        version=PLUGIN_VERSIONS["hypothesis"],
        seats=("news", "papers", "official", "cve", "provider",
               "incident"),
        detect_command=_hyp_detect, plan_topics=_hyp_plan,
        analyze=_hypothesis_analyze,
        fingerprint=_hypothesis_fingerprint),
}


def plan_for(command: str) -> dict | None:
    """First plugin whose detector claims the command plans its topics.

    Returns a manager-plan-shaped dict (with ``plugin`` set) or None.
    Checked after the incident/provider templates, before the LLM.
    """
    for key in ("vulnerability", "hypothesis"):
        plugin = PLUGINS[key]
        try:
            topics = plugin.plan_topics(command or "")
        except Exception:
            topics = None
        if not topics:
            continue
        return {"domain": f"{key}_investigation",
                "exposure": "confidential_data",
                "plugin": key,
                "topics": topics,
                "summary": {
                    "title": f"{plugin.title}: "
                             f"{(command or '')[:120]}"[:300],
                    "description": f"Planned by the {key} plugin."},
                "parsed_by": f"{key}-template"}
    return None
