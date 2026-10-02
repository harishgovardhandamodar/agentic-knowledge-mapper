"""mcp-register — upsert_risk, list_risks, link_treatment, get_risk."""

from __future__ import annotations

from typing import Any


def upsert_risk(investigation_id: int, risk: dict[str, Any]) -> dict[str, Any]:
    from ..database import SessionLocal
    from ..portfolio import _derived_rows, _persist_register
    from .. import model_kb as kb

    db = SessionLocal()
    try:
        land = kb.landscape(db, investigation_id)
        # For MVP, upsert via portfolio derive
        derived = _derived_rows(db, investigation_id, land)
        # if risk provided, ensure it is in derived or add it
        _persist_register(db, investigation_id, list(derived.values()))
        return {"investigation_id": investigation_id, "upserted": 1}
    finally:
        db.close()


def list_risks(investigation_id: int, limit: int = 100) -> list[dict[str, Any]]:
    from ..database import SessionLocal
    from ..portfolio import register_with_state

    db = SessionLocal()
    try:
        rows = register_with_state(db, investigation_id)
        return rows[:limit]
    finally:
        db.close()


def link_treatment(risk_id: int, control_ids: list[str]) -> dict[str, Any]:
    from ..database import SessionLocal
    from ..models import RiskEntry
    import json

    db = SessionLocal()
    try:
        r = db.get(RiskEntry, risk_id)
        if not r:
            raise LookupError(f"risk {risk_id} not found")
        r.mitigation_ids_json = json.dumps(control_ids)
        db.commit()
        return {"risk_id": risk_id, "linked": control_ids}
    finally:
        db.close()


def get_risk(risk_id: int) -> dict[str, Any]:
    from ..database import SessionLocal
    from ..models import RiskEntry
    import json

    db = SessionLocal()
    try:
        r = db.get(RiskEntry, risk_id)
        if not r:
            raise LookupError(f"risk {risk_id} not found")
        return {
            "id": r.id, "risk_id": r.risk_id, "layer": r.layer, "status": r.status,
            "title": r.title, "owner": r.owner, "priority_score": r.priority_score,
            "mitigation_ids": json.loads(r.mitigation_ids_json or "[]"),
        }
    finally:
        db.close()
