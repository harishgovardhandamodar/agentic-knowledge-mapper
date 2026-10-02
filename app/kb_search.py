"""Elastic-like knowledge base search — FTS first, LIKE fallback.

Index contents (KB):
  Risk: id, title, plain summary, layer, scope, status, tags, owner
  Artifact/evidence: title, description, content chunk, tags, source, review
  Asset: model/product/provider name, family, deployment
  Finding: PDP/RLHF/RM/T-id codes, claims text
  Decision: type, rationale, actor, timestamp
  Report brief: title, section headings, body

Phase A: SQLite FTS5 (or LIKE) over risk titles/summaries, artifact title/description/content,
assessment markdown excerpts, provider findings, decision rationales.
Operators: AND/OR (default AND), "exact phrase", prefix memoriz* .
Phase B: field filters layer:privacy severity:high etc.
Accepted-only default for non-researcher personas is applied at query time.

Single-node FTS is the default; true Elastic behind SearchIndex interface later.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .database import SessionLocal

FTS_AVAILABLE = False
try:
    from sqlalchemy import text

    _db = SessionLocal()
    try:
        _db.execute(text("CREATE VIRTUAL TABLE IF NOT EXISTS _fts_check USING fts5(x)"))
        _db.execute(text("DROP TABLE IF EXISTS _fts_check"))
        _db.commit()
        FTS_AVAILABLE = True
    except Exception:
        try:
            _db.rollback()
        except Exception:
            pass
    finally:
        _db.close()
except Exception:
    pass


def _parse_query(q: str) -> dict[str, Any]:
    q = (q or "").strip()
    filters: dict[str, str] = {}
    for m in re.finditer(r"(\w+):([^\s]+)", q):
        filters[m.group(1).lower()] = m.group(2).lower()
        q = q.replace(m.group(0), " ")
    phrases = re.findall(r'"([^"]+)"', q)
    for p in phrases:
        q = q.replace(f'"{p}"', " ")
    q = re.sub(r"\s+", " ", q).strip()
    terms = [t for t in q.split() if t]
    prefix_terms = [t[:-1] for t in terms if t.endswith("*")]
    terms = [t for t in terms if not t.endswith("*")]
    return {"terms": terms, "prefix_terms": prefix_terms, "phrases": phrases, "filters": filters, "raw": q}


def _matches(text: str, parsed: dict[str, Any], op: str = "AND") -> bool:
    text_l = (text or "").lower()
    for p in parsed["phrases"]:
        if p.lower() not in text_l:
            return False
    for pre in parsed["prefix_terms"]:
        if not re.search(r"\b" + re.escape(pre.lower()), text_l):
            return False
    if not parsed["terms"]:
        return True if not parsed["phrases"] and not parsed["prefix_terms"] else True
    if op.upper() == "OR":
        return any(t.lower() in text_l for t in parsed["terms"])
    return all(t.lower() in text_l for t in parsed["terms"])


def _highlight(text: str, parsed: dict[str, Any]) -> str:
    out = text
    for term in parsed["terms"] + parsed["phrases"] + parsed["prefix_terms"]:
        if not term:
            continue
        out = re.sub(re.escape(term), lambda m: f"<mark>{m.group(0)}</mark>", out, flags=re.I)
    return out[:400]


def search(
    q: str = "",
    types: list[str] | None = None,
    layer: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    limit: int = 20,
    offset: int = 0,
    investigation_id: int | None = None,
    accepted_only: bool = True,
) -> dict[str, Any]:
    parsed = _parse_query(q)
    if layer:
        parsed["filters"]["layer"] = layer.lower()
    if severity:
        parsed["filters"]["severity"] = severity.lower()
    if status:
        parsed["filters"]["status"] = status.lower()
    limit = max(1, min(limit, 50))
    offset = max(0, offset)
    db = SessionLocal()
    hits: list[dict[str, Any]] = []
    try:
        from .models import Artifact, Investigation, RiskEntry, SecurityAssessment

        type_filter = set(t.lower() for t in (types or []))
        want_risk = not type_filter or "risks" in type_filter or "risk" in type_filter
        want_evidence = not type_filter or any(t in type_filter for t in ("evidence", "artifacts", "artifact"))
        want_assets = not type_filter or any(t in type_filter for t in ("assets", "asset", "models", "providers"))
        want_decisions = not type_filter or any(t in type_filter for t in ("decisions", "decision"))

        if want_risk:
            qset = db.query(RiskEntry)
            if investigation_id:
                qset = qset.filter(RiskEntry.investigation_id == investigation_id)
            for r in qset.limit(500).all():
                if parsed["filters"].get("layer") and r.layer.lower() != parsed["filters"]["layer"]:
                    continue
                if parsed["filters"].get("severity"):
                    sev = (r.confidence_band or r.severity or "").lower()
                    if sev != parsed["filters"]["severity"]:
                        try:
                            sv = float(r.severity or 0)
                            band = "critical" if sv >= 80 else "high" if sv >= 60 else "medium" if sv >= 40 else "low"
                            if band != parsed["filters"]["severity"]:
                                continue
                        except Exception:
                            continue
                if parsed["filters"].get("status") and (r.status or "").lower() != parsed["filters"]["status"]:
                    continue
                text = f"{r.title or ''} {r.risk_id or ''} {r.source_ref or ''} {r.layer or ''} {r.scope or ''} {r.owner or ''} {r.situation_tags_json or ''} {r.plain_summary or ''} {r.treatment_plan_json or ''}"
                if q.strip() and not _matches(text, parsed):
                    continue
                snippet = _highlight(f"{r.title or ''} — {r.risk_id or ''} ({r.layer}/{r.scope}, {r.status}) {r.plain_summary or ''}", parsed)
                score = 3 if (parsed["terms"] and any(t.lower() in (r.title or "").lower() for t in parsed["terms"])) else 1
                hits.append({"type": "risk", "id": r.id, "title": r.title or r.risk_id, "snippet": snippet, "score": score, "highlights": snippet, "layer": r.layer, "severity": r.confidence_band or str(r.severity or ""), "status": r.status, "investigation_id": r.investigation_id})

        if want_evidence:
            qset = db.query(Artifact)
            if investigation_id:
                qset = qset.filter(Artifact.investigation_id == investigation_id)
            if accepted_only:
                qset = qset.filter(Artifact.review == "accepted")
            else:
                qset = qset.filter(Artifact.review != "rejected")
            for a in qset.limit(500).all():
                text = f"{a.title or ''} {a.description or ''} {(a.content or '')[:800]} {a.tags or ''} {a.source or ''}"
                if q.strip() and not _matches(text, parsed):
                    continue
                snippet = _highlight(f"{a.title or ''}: {(a.description or a.content or '')[:200]}", parsed)
                score = 2 if (parsed["terms"] and any(t.lower() in (a.title or "").lower() for t in parsed["terms"])) else 1
                hits.append({"type": "evidence", "id": a.id, "title": a.title or "(untitled)", "snippet": snippet, "score": score, "highlights": snippet, "review": a.review, "investigation_id": a.investigation_id})

        if want_assets:
            qset = db.query(Investigation)
            if investigation_id:
                qset = qset.filter(Investigation.id == investigation_id)
            for inv in qset.limit(200).all():
                text = f"{inv.title or ''} {inv.keywords or ''} {inv.description or ''}"
                if q.strip() and not _matches(text, parsed):
                    continue
                snippet = _highlight(inv.title or "", parsed)
                hits.append({"type": "asset", "id": inv.id, "title": inv.title or f"Investigation {inv.id}", "snippet": snippet, "score": 1, "highlights": snippet, "investigation_id": inv.id})

        if want_decisions:
            qset = db.query(RiskEntry).filter(RiskEntry.status == "accepted")
            if investigation_id:
                qset = qset.filter(RiskEntry.investigation_id == investigation_id)
            for r in qset.limit(200).all():
                text = f"{r.acceptance_note or ''} {r.accepted_by or ''} {r.title or ''}"
                if q.strip() and not _matches(text, parsed):
                    continue
                snippet = _highlight(f"Accepted {r.risk_id} by {r.accepted_by or '?'}: {r.acceptance_note or ''}", parsed)
                hits.append({"type": "decision", "id": r.id, "title": f"Accept {r.risk_id}", "snippet": snippet, "score": 1, "highlights": snippet, "investigation_id": r.investigation_id})

        hits.sort(key=lambda h: (-h["score"], h["type"], h["id"]))
        total = len(hits)
        facets: dict[str, dict[str, int]] = {"type": {}, "layer": {}, "status": {}}
        for h in hits:
            facets["type"][h["type"]] = facets["type"].get(h["type"], 0) + 1
            if h.get("layer"):
                facets["layer"][h["layer"]] = facets["layer"].get(h["layer"], 0) + 1
            if h.get("status"):
                facets["status"][h["status"]] = facets["status"].get(h["status"], 0) + 1
        hits = hits[offset : offset + limit]
        return {"hits": hits, "facets": facets, "total": total, "q": q, "accepted_only": accepted_only}
    finally:
        db.close()


def suggest(q: str, investigation_id: int | None = None, limit: int = 8) -> dict[str, Any]:
    res = search(q=q, limit=limit, investigation_id=investigation_id, accepted_only=True)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for h in res["hits"][:limit]:
        grouped.setdefault(h["type"], []).append(h)
    return {"q": q, "suggestions": grouped, "total": res["total"]}
