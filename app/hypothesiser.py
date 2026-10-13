"""Hypothesiser: every scenario the evidence admits, none it doesn't.

Two kinds, both derived from stored rows, never invented:

* inherent scenarios come straight from one kept artifact or claim each
  (what that finding directly implies);
* derived scenarios compose parents through explicit rules (shared
  subject matter, a recorded relationship edge, a threat meeting the
  artifact that exhibits it).

Each scenario cites its provenance (artifact/claim ids plus the rule
for derived ones); single-source scenarios are flagged as fragile, and
an empty collection returns ``insufficient_evidence`` instead of a
cast. No LLM is involved.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

HYPOTHESIS_VERSION = "1.0.0"

CHANGE_POLICY = {
    "major": "verdict levels, scenario kinds, or provenance rules changed",
    "minor": "new composition rules or caps (verdicts stable)",
    "patch": "wording, caps, or parsing robustness without meaning change",
    "version": HYPOTHESIS_VERSION,
}

HYPOTHESIS_TAG = "hypothesis-scenarios"

_INHERENT_CAP = 20
_DERIVED_CAP = 20


def _safe(text: str, limit: int = 80) -> str:
    return re.sub(r"[`\"{}()#;]", " ",
                  re.sub(r"\s+", " ", text or "").strip())[:limit]


def _words(text: str) -> set[str]:
    return {w for w in re.split(r"[^a-z0-9+]+", (text or "").lower())
            if len(w) > 3}


def _tags(text: str | None) -> set[str]:
    return {t.strip().lower() for t in (text or "").split(",") if t.strip()}


def _kept_artifacts(db, inv_id: int) -> list:
    from .models import Artifact
    try:
        rows = (db.query(Artifact)
                .filter(Artifact.investigation_id == inv_id,
                        Artifact.review != "rejected")
                .order_by(Artifact.id).all())
    except Exception:
        return []
    return rows


def _claims(db, inv_id: int) -> tuple[list, int | None]:
    """Latest assessment threats + id (read-only, no new semantics)."""
    from .models import SecurityAssessment
    try:
        rec = (db.query(SecurityAssessment)
               .filter(SecurityAssessment.investigation_id == inv_id)
               .order_by(SecurityAssessment.id.desc()).first())
    except Exception:
        return [], None
    if rec is None:
        return [], None
    try:
        threats = json.loads(rec.threats_json or "[]")
    except Exception:
        threats = []
    return ([t for t in threats if isinstance(t, dict)], rec.id)


def _edges(db, inv_id: int) -> list:
    from .models import Relationship
    try:
        return (db.query(Relationship)
                .filter(Relationship.investigation_id == inv_id).all())
    except Exception:
        return []


def _conf(relevance) -> str:
    try:
        r = float(relevance)
    except (TypeError, ValueError):
        return "low"
    return "high" if r >= 0.7 else "medium" if r >= 0.4 else "low"


def enumerate_scenarios(db, inv_id: int) -> dict[str, Any]:
    """Build the scenario space for one investigation, deterministically."""
    arts = _kept_artifacts(db, inv_id)
    threats, assessment_id = _claims(db, inv_id)
    edges = _edges(db, inv_id)
    inherent: list[dict] = []
    for a in arts[:_INHERENT_CAP]:
        title = getattr(a, "title", "") or ""
        desc = getattr(a, "description", "") or ""
        first = re.split(r"(?<=[.!?])\s+", desc.strip())
        statement = (title[:120] + (" -- " + first[0][:160] if first and
                                    first[0] else ""))
        inherent.append({"id": f"S{len(inherent)}",
                         "kind": "inherent",
                         "statement": statement[:280] or "reported finding",
                         "confidence": _conf(getattr(a, "relevance", None)),
                         "provenance": {"artifacts": [a.id]},
                         "fragile": True})
    for t in threats:
        label = (t.get("title") or t.get("name") or
                 t.get("description") or "")[:200]
        if not label:
            continue
        inherent.append({"id": f"S{len(inherent)}",
                         "kind": "inherent",
                         "statement": f"assessed claim: {label}"[:280],
                         "confidence": str(t.get("confidence") or
                                           t.get("severity") or "unknown"),
                         "provenance": {"assessment_id": assessment_id,
                                        "claim": label[:120]},
                         "fragile": True})
        if len(inherent) >= _INHERENT_CAP:
            break
    derived: list[dict] = []
    by_id = {s["id"]: s for s in inherent}

    def _add(statement: str, parents: list[str], rule: str) -> None:
        if len(derived) >= _DERIVED_CAP:
            return
        derived.append({"id": f"D{len(derived)}", "kind": "derived",
                        "statement": statement[:280],
                        "confidence": "low",
                        "provenance": {"parents": parents, "rule": rule},
                        "fragile": True})

    art_of = {}
    for s in inherent:
        for aid in (s.get("provenance") or {}).get("artifacts", []):
            art_of.setdefault(s["id"], aid)
    tag_of = {}
    for s in inherent:
        aids = (s.get("provenance") or {}).get("artifacts", [])
        if aids:
            a = next((x for x in arts if x.id == aids[0]), None)
            tag_of[s["id"]] = _tags(getattr(a, "tags", None)) if a else set()
    ids = list(by_id)
    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            a, b = ids[i], ids[j]
            shared = tag_of.get(a, set()) & tag_of.get(b, set())
            shared -= {"news", "paper", "web"}
            if len(shared) >= 2:
                _add(f"combined exposure via shared subject matter "
                     f"({', '.join(sorted(shared)[:3])}): "
                     f"{by_id[a]['statement'][:100]} + "
                     f"{by_id[b]['statement'][:100]}",
                     [a, b], "shared-subject")
            ta = _tags_of_statement(by_id[a]["statement"])
            tb = _tags_of_statement(by_id[b]["statement"])
            if len(ta & tb) >= 4 and len(shared) < 2:
                _add(f"linked findings (shared terms "
                     f"{', '.join(sorted(ta & tb)[:3])}): "
                     f"{by_id[a]['statement'][:100]} + "
                     f"{by_id[b]['statement'][:100]}",
                     [a, b], "shared-terms")
    for e in edges:
        src = next((s["id"] for s in inherent
                    if art_of.get(s["id"]) == e.source_id), None)
        dst = next((s["id"] for s in inherent
                    if art_of.get(s["id"]) == e.target_id), None)
        if src and dst and src != dst:
            _add(f"chained finding ({e.relationship_type}): "
                 f"{by_id[src]['statement'][:100]} -> "
                 f"{by_id[dst]['statement'][:100]}",
                 [src, dst], "recorded-edge")
    gaps = []
    if not inherent:
        gaps.append("no kept artifacts or claims: nothing to enumerate")
    if inherent and not derived:
        gaps.append("no compositions found: scenarios are all single-source")
    gaps.append(f"{sum(1 for s in inherent + derived if s['fragile'])} "
                f"single-source scenario(s): corroborate before acting")
    verdict = ("enumerated" if inherent else "insufficient_evidence")
    pack = {"investigation_id": inv_id,
            "verdict": {"key": verdict,
                        "label": ("scenario space from stored evidence"
                                  if inherent else
                                  "no evidence collected: nothing to "
                                  "enumerate")},
            "inherent": inherent, "derived": derived, "gaps": gaps,
            "counts": {"inherent": len(inherent), "derived": len(derived)},
            "version": HYPOTHESIS_VERSION,
            "fingerprint": hypothesis_fingerprint()}
    pack["diagrams"] = {"scenario_map": _map_mermaid(pack)}
    return pack


def _tags_of_statement(text: str) -> set[str]:
    return _words(text) - {"with", "from", "that", "this", "have", "were",
                           "been", "they", "their", "which", "into"}


def _map_mermaid(pack: dict) -> str:
    """Scenario map: parents point at what they compose."""
    lines = ["flowchart LR"]
    inherent = pack.get("inherent") or []
    derived = pack.get("derived") or []
    if not inherent:
        lines.append('    S0["no scenarios: no evidence"]')
        return "\n".join(lines) + "\n"
    for s in inherent[:12]:
        lines.append(f'    {s["id"]}["{_safe(s["statement"], 60)}"]')
    for d in derived[:12]:
        lines.append(f'    {d["id"]}{{{{{_safe(d["statement"], 60)}}}}}')
        for p in (d.get("provenance") or {}).get("parents", [])[:3]:
            lines.append(f"    {p} --> {d['id']}")
    return "\n".join(lines) + "\n"


def render_markdown(pack: dict) -> str:
    """The scenario space as report markdown with the map figure."""
    L = ["## Hypothesis scenarios", ""]
    v = pack.get("verdict") or {}
    L.append(f"**Verdict: {v.get('key', '?')}** -- {v.get('label', '')}")
    L.append("")
    if pack.get("inherent"):
        L.append("### Inherent (one finding each)")
        L.append("")
        for s in pack["inherent"]:
            L.append(f"- **{s['id']}** [{s.get('confidence', '?')}] "
                     f"{s.get('statement', '')}")
        L.append("")
    if pack.get("derived"):
        L.append("### Derived (compositions with cited parents)")
        L.append("")
        for s in pack["derived"]:
            parents = ", ".join(
                (s.get("provenance") or {}).get("parents", []))
            L.append(f"- **{s['id']}** [{(s.get('provenance') or {}).get('rule', '?')}"
                     f" {parents}] {s.get('statement', '')}")
        L.append("")
    L.append("### Scenario map")
    L.append("")
    L.append("```mermaid scenarios")
    L.append((pack.get("diagrams") or {}).get("scenario_map",
                                              "").rstrip())
    L.append("```")
    L.append("")
    if pack.get("gaps"):
        L.append("### Gaps")
        L.append("")
        for g in pack["gaps"]:
            L.append(f"- {g}")
        L.append("")
    return "\n".join(L).strip() + "\n"


def store_scenarios(db, inv_id: int) -> dict[str, Any]:
    """Enumerate and persist; idempotent per investigation."""
    from .models import Artifact
    try:
        existing = (db.query(Artifact)
                    .filter(Artifact.investigation_id == inv_id,
                            Artifact.tags.like(f"%{HYPOTHESIS_TAG}%"))
                    .order_by(Artifact.id.desc()).first())
    except Exception:
        existing = None
    pack = enumerate_scenarios(db, inv_id)
    if existing is not None and existing.content:
        return {"artifact_id": existing.id, "existing": True, "pack": pack}
    art = Artifact(
        investigation_id=inv_id,
        title="Hypothesis scenarios: inherent and derived",
        artifact_type="research",
        description=(f"Scenario enumeration "
                     f"({pack['verdict']['key']}) from stored evidence."),
        content=render_markdown(pack),
        source="agentic-manager",
        tags=HYPOTHESIS_TAG)
    db.add(art)
    db.commit()
    db.refresh(art)
    return {"artifact_id": art.id, "existing": False, "pack": pack}


def hypothesis_fingerprint() -> str:
    """Pin the deterministic content: rules, caps, verdicts."""
    canon = {"version": HYPOTHESIS_VERSION,
             "kinds": ("inherent", "derived"),
             "rules": ("shared-subject", "shared-terms", "recorded-edge"),
             "caps": {"inherent": _INHERENT_CAP, "derived": _DERIVED_CAP}}
    return hashlib.sha256(json.dumps(canon, sort_keys=True).encode()
                          ).hexdigest()[:12]
