"""HTTP surface for the Agentic Payments Security & Privacy Evaluation.

Runs under the Agentic Manager umbrella (``/api/payments-eval``). Operators
answer a seeded catalog against a payment-capable agent; scoring is
deterministic; Markdown/JSON reports are exported.

AuthZ: every endpoint requires a named operator (``X-AKM-Actor`` or a session
key). When ``PAYMENTS_EVAL_ROLES`` is set to a comma-separated list, callers
must also send ``X-AKM-Role`` in that set (the app has no built-in role
system, so this is an optional hard gate that can be wired to a proxy).
All writes are recorded on the audit ledger with the actor.
"""

from __future__ import annotations

import json
import os
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from . import ledger_api
from . import payments_eval as pe
from .database import get_db
from .models import EvaluationRun

router = APIRouter(prefix="/api/payments-eval", tags=["payments-eval"])

_REQUIRED_ROLES = [r.strip().lower() for r in
                   os.getenv("PAYMENTS_EVAL_ROLES", "").split(",") if r.strip()]


def _require_operator(request: Request) -> str:
    """Named operator required; optional role gate via PAYMENTS_EVAL_ROLES."""
    if _REQUIRED_ROLES:
        role = (request.headers.get("X-AKM-Role") or "").strip().lower()
        if role not in _REQUIRED_ROLES:
            raise HTTPException(
                403, "this endpoint requires an admin/security role "
                     "(X-AKM-Role)")
    actor = ledger_api.request_actor_or_empty(request)
    if not actor:
        raise HTTPException(
            401, "attribute this action to a named operator (X-AKM-Actor)")
    return actor


def _run(db: Session, run_id: int) -> EvaluationRun:
    run = db.query(EvaluationRun).filter(EvaluationRun.id == run_id).first()
    if run is None:
        raise HTTPException(404, "Evaluation run not found")
    return run


def _audit(request: Request, kind: str, data: dict) -> None:
    try:
        ledger_api.human_action(request, kind, data)
    except Exception:
        pass  # audit must never break an evaluation write


# ----------------------------------------------------------------- request bodies

class RunCreateRequest(BaseModel):
    target_agent_id: str
    title: str = ""
    catalog_version: str = pe.CATALOG_VERSION


class AnswerPatchRequest(BaseModel):
    answer_value: Any = None
    risk_rating: str
    evidence_url: str = ""
    notes: str = ""


# ------------------------------------------------------------------- reads

@router.get("/catalogs")
def list_catalogs(db: Session = Depends(get_db)):
    pe.seed_catalog_v1(db)
    from .models import EvaluationCatalog, EvaluationQuestion, EvaluationSection
    from sqlalchemy import func
    rows = (db.query(EvaluationCatalog,
                     func.count(func.distinct(EvaluationSection.id)),
                     func.count(func.distinct(EvaluationQuestion.id)))
            .outerjoin(EvaluationSection, EvaluationSection.catalog_id == EvaluationCatalog.id)
            .outerjoin(EvaluationQuestion, EvaluationQuestion.section_id == EvaluationSection.id)
            .group_by(EvaluationCatalog.id).all())
    return {"catalogs": [{
        "id": c.id, "version": c.version, "name": c.name,
        "description": c.description, "sections": s, "questions": q,
    } for c, s, q in rows]}


@router.get("/catalogs/{catalog_id}")
def get_catalog(catalog_id: int, db: Session = Depends(get_db)):
    pe.seed_catalog_v1(db)
    try:
        return pe.get_catalog(db, catalog_id)
    except LookupError:
        raise HTTPException(404, "Catalog not found")


# ------------------------------------------------------------------- runs

@router.post("/runs", status_code=201)
def create_run(data: RunCreateRequest, request: Request,
               db: Session = Depends(get_db)):
    actor = _require_operator(request)
    try:
        run = pe.create_run(db, data.target_agent_id, data.title,
                            catalog_id=None, actor=actor)
    except ValueError as e:
        raise HTTPException(400, str(e))
    _audit(request, "payments_eval.run_created", {
        "run_id": run.id, "target_agent_id": run.target_agent_id,
        "actor": actor})
    return _run_view(db, run)


@router.get("/runs/{run_id}")
def get_run(run_id: int, db: Session = Depends(get_db)):
    return _run_view(db, _run(db, run_id))


@router.patch("/runs/{run_id}/answers/{question_id}")
def patch_answer(run_id: int, question_id: int, data: AnswerPatchRequest,
                 request: Request, db: Session = Depends(get_db)):
    actor = _require_operator(request)
    run = _run(db, run_id)
    try:
        answer = pe.upsert_answer(
            db, run, question_id, answer_value=data.answer_value,
            risk_rating=data.risk_rating, evidence_url=data.evidence_url,
            notes=data.notes, actor=actor)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except LookupError as e:
        raise HTTPException(404, str(e))
    _audit(request, "payments_eval.answer_upserted", {
        "run_id": run.id, "question_id": question_id,
        "risk_rating": answer.risk_rating, "actor": actor})
    return _run_view(db, run)


@router.post("/runs/{run_id}/complete")
def complete_run(run_id: int, request: Request,
                 db: Session = Depends(get_db)):
    actor = _require_operator(request)
    run = _run(db, run_id)
    try:
        result = pe.complete_run(db, run, actor=actor)
    except ValueError as e:
        raise HTTPException(400, str(e))
    _audit(request, "payments_eval.run_completed", {
        "run_id": run.id, "overall_score": result["overall_score"],
        "counts": result["counts"], "actor": actor})
    return _run_view(db, run)


# ------------------------------------------------------------------- reports

@router.get("/runs/{run_id}/report.json")
def get_report_json(run_id: int, db: Session = Depends(get_db)):
    run = _run(db, run_id)
    return pe.report_json(db, run)


@router.get("/runs/{run_id}/report.md")
def get_report_markdown(run_id: int, db: Session = Depends(get_db)):
    run = _run(db, run_id)
    md = pe.report_markdown(db, run)
    return Response(
        content=md, media_type="text/markdown",
        headers={"Content-Disposition":
                 f'attachment; filename="payments-eval-run-{run_id}.md"'})


# ------------------------------------------------------------------- helpers

def _run_view(db: Session, run: EvaluationRun) -> dict[str, Any]:
    p = pe.run_payload(db, run)
    p["run"]["answered"] = sum(1 for sec in p["sections"]
                               for q in sec["questions"]
                               if q["risk_rating"])
    p["run"]["total_questions"] = sum(len(sec["questions"])
                                      for sec in p["sections"])
    return p