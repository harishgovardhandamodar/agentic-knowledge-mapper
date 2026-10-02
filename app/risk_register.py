"""Risk register helpers — load, score, persist.

Thin layer over RiskEntry + risk_scoring. No LLM, no hidden mutation.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from . import risk_scoring as rs


def _row_to_dict(r) -> dict[str, Any]:
    return {
        "id": r.id,
        "risk_id": r.risk_id,
        "layer": r.layer,
        "severity": r.severity,
        "exposure": r.exposure,
        "scope": r.scope,
        "evidence_ids": json.loads(r.evidence_ids_json or "[]"),
        "status": r.status,
        "owner": r.owner,
        "review_by": r.review_by.isoformat() if r.review_by else None,
        "situation_tags_json": r.situation_tags_json,
        "confidence": r.confidence,
        "confidence_band": r.confidence_band,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "aging_days": (datetime.now(timezone.utc) - r.created_at).days if r.created_at and r.created_at.tzinfo else (datetime.utcnow() - r.created_at).days if r.created_at else 0,
        "has_owner": bool(r.owner),
        "mitigation_ids": json.loads(r.mitigation_ids_json or "[]"),
        "treatment_plan": json.loads(r.treatment_plan_json or "{}") if r.treatment_plan_json else {},
        "inherent_score": r.inherent_score,
        "residual_score": r.residual_score,
        "priority_score": r.priority_score,
        "band": r.band,
    }


def score_and_persist(db, risk_id: int) -> dict[str, Any]:
    from .models import RiskEntry

    r = db.get(RiskEntry, risk_id)
    if not r:
        raise LookupError(f"risk {risk_id} not found")
    row = _row_to_dict(r)
    # treatment coverage from mitigation_ids
    row["mitigation_ids"] = json.loads(r.mitigation_ids_json or "[]")
    scored = rs.score_risk(row)
    r.inherent_score = scored["inherent_score"]
    r.residual_score = scored["residual_score"]
    r.priority_score = scored["priority_score"]
    r.band = scored["band"]
    r.confidence = scored["confidence"]
    r.scoring_method = scored["scoring_method"]
    r.scoring_fingerprint = scored["scoring_fingerprint"]
    r.score_rationale = scored["score_rationale"]
    r.inputs_hash = scored["inputs_hash"]
    r.scored_at = datetime.now(timezone.utc)
    db.commit()
    return scored


def rescore_scope(db, investigation_id: int | None = None, initiative_id: int | None = None) -> dict[str, Any]:
    from .models import RiskEntry

    q = db.query(RiskEntry)
    if investigation_id:
        q = q.filter(RiskEntry.investigation_id == investigation_id)
    if initiative_id:
        q = q.filter(RiskEntry.initiative_id == initiative_id)
    count = 0
    for r in q.all():
        row = _row_to_dict(r)
        scored = rs.score_risk(row)
        # only write if inputs changed
        if r.inputs_hash == scored["inputs_hash"]:
            continue
        r.inherent_score = scored["inherent_score"]
        r.residual_score = scored["residual_score"]
        r.priority_score = scored["priority_score"]
        r.band = scored["band"]
        r.confidence = scored["confidence"]
        r.scoring_method = scored["scoring_method"]
        r.scoring_fingerprint = scored["scoring_fingerprint"]
        r.score_rationale = scored["score_rationale"]
        r.inputs_hash = scored["inputs_hash"]
        r.scored_at = datetime.now(timezone.utc)
        count += 1
    db.commit()
    return {"rescored": count}
