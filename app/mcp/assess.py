"""mcp-assess — get_assessment, list_findings."""

from __future__ import annotations

from typing import Any

from ..database import SessionLocal


def get_assessment(assessment_id: int) -> dict[str, Any]:
    from ..models import SecurityAssessment
    import json

    db = SessionLocal()
    try:
        r = db.get(SecurityAssessment, assessment_id)
        if not r:
            raise LookupError(f"assessment {assessment_id} not found")
        return {
            "id": r.id, "investigation_id": r.investigation_id, "product_name": r.product_name,
            "overall_pct": r.overall_pct, "posture": r.posture,
            "threats": json.loads(r.threats_json or "[]"),
            "model_json": json.loads(r.model_json or "{}") if r.model_json else {},
            "scoring": json.loads(r.scoring_json or "{}") if r.scoring_json else {},
        }
    finally:
        db.close()


def list_findings(investigation_id: int, layer: str | None = None) -> list[dict[str, Any]]:
    from ..portfolio import register_with_state

    db = SessionLocal()
    try:
        rows = register_with_state(db, investigation_id)
        if layer:
            rows = [r for r in rows if r.get("layer") == layer]
        return rows
    finally:
        db.close()
