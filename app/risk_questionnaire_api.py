"""HTTP surface for the AI security risk assessment questionnaire.

``/api/risk-questionnaire`` turns a free-text description of an AI system
into a fillable, team-routed questionnaire and reports the AI-standards
coverage the answers evidence.

The shape of a request: ``POST /generate`` with the team's description, read
the draft (and its ``report.md`` to hand around), ``POST /drafts/{id}/seed``
to open a run, then ``PATCH`` answers as each team works through its slice,
``POST /runs/{id}/complete`` to score, ``GET /runs/{id}/coverage`` to see
which standards controls the answers actually evidence.

AuthZ matches the payments evaluation: a named actor is required on every
write (``X-AKM-Actor`` or a session key), with an optional role hard gate via
``RISK_QUESTIONNAIRE_ROLES``. Reads of the standards tag library are open.
Every write is recorded on the audit ledger with the actor.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from . import ledger_api
from . import payments_eval as pe
from . import risk_questionnaire as rq
from .database import get_db
from .models import EvaluationDraft, EvaluationRun

router = APIRouter(prefix="/api/risk-questionnaire",
                   tags=["risk-questionnaire"])

_REQUIRED_ROLES = [r.strip().lower() for r in
                   os.getenv("RISK_QUESTIONNAIRE_ROLES", "").split(",")
                   if r.strip()]


def _require_operator(request: Request) -> str:
    """Named actor required; optional role gate via RISK_QUESTIONNAIRE_ROLES."""
    if _REQUIRED_ROLES:
        role = (request.headers.get("X-AKM-Role") or "").strip().lower()
        if role not in _REQUIRED_ROLES:
            raise HTTPException(
                403, "this endpoint requires a listed role (X-AKM-Role)")
    actor = ledger_api.request_actor_or_empty(request)
    if not actor:
        raise HTTPException(
            401, "attribute this action to a named operator (X-AKM-Actor)")
    return actor


def _audit(request: Request, kind: str, data: dict) -> None:
    try:
        ledger_api.human_action(request, kind, data)
    except Exception:
        pass  # audit must never break a questionnaire write


def _draft(db: Session, draft_id: int) -> EvaluationDraft:
    d = db.query(EvaluationDraft).filter(EvaluationDraft.id == draft_id).first()
    if d is None:
        raise HTTPException(404, "Questionnaire draft not found")
    return d


def _run(db: Session, run_id: int) -> EvaluationRun:
    run = db.query(EvaluationRun).filter(EvaluationRun.id == run_id).first()
    if run is None:
        raise HTTPException(404, "Questionnaire run not found")
    return run


class GenerateRequest(BaseModel):
    query: str = ""
    depth: str = "standard"  # brief|standard|full


class SeedRequest(BaseModel):
    target: str = ""
    title: str = ""


class AnswerPatchRequest(BaseModel):
    answer_value: Any = None
    risk_rating: str = ""
    evidence_url: str = ""
    notes: str = ""


@router.get("/frameworks")
def list_frameworks():
    """The tag library: every standards control a question may be tagged with.

    Open, because the client renders pickers from it; generation and answers
    still require an actor.
    """
    return {
        "generator_version": rq.GENERATOR_VERSION,
        "roles": rq.ANSWERER_ROLES,
        "answer_options": rq.ANSWER_OPTIONS,
        "axes": rq.AXIS_LIBRARY,
        "frameworks": [
            {"id": fw["id"], "name": fw["name"],
             "controls": [{"id": c, "label": label,
                           "tag": f"{fw['id']}:{c}"} for c, label in fw["controls"]]}
            for fw in rq.FRAMEWORK_LIBRARY],
    }


@router.post("/generate")
def generate(data: GenerateRequest, request: Request,
             db: Session = Depends(get_db)):
    """Frame a questionnaire from the team's description of their AI system."""
    actor = _require_operator(request)
    try:
        draft = rq.generate(db, data.query, depth=data.depth, actor=actor)
    except ValueError as e:
        raise HTTPException(400, str(e))
    _audit(request, "risk_questionnaire.generated", {
        "draft_id": draft["draft"]["id"], "target": draft["draft"]["target"],
        "axes": draft["frame"]["axes"], "source": draft["draft"]["source"],
        "questions": draft["quality"]["questions"], "actor": actor})
    return draft


@router.get("/drafts")
def list_drafts(limit: int = Query(20, ge=1, le=100), db: Session = Depends(get_db)):
    rows = (db.query(EvaluationDraft)
            .filter(EvaluationDraft.source.isnot(None))
            .order_by(EvaluationDraft.id.desc()).limit(limit).all())
    return {"drafts": [
        {"id": d.id, "target": d.target, "depth": d.depth, "status": d.status,
         "source": d.source, "created_by": d.created_by,
         "created_at": d.created_at.isoformat() if d.created_at else None,
         "seeded_catalog_id": d.seeded_catalog_id} for d in rows]}


@router.get("/drafts/{draft_id}")
def get_draft(draft_id: int, db: Session = Depends(get_db)):
    return rq.draft_payload(db, _draft(db, draft_id))


@router.get("/drafts/{draft_id}/report.md")
def get_draft_report(draft_id: int,
                     format: str = Query("form", description="form|brief"),
                     db: Session = Depends(get_db)):
    draft = _draft(db, draft_id)
    if format not in ("form", "brief"):
        raise HTTPException(400, "format must be form or brief")
    md = rq.questionnaire_markdown(db, draft, fmt=format)
    return Response(
        content=md, media_type="text/markdown",
        headers={"Content-Disposition":
                 f'attachment; filename="risk-questionnaire-{draft_id}-{format}.md"'})


@router.post("/drafts/{draft_id}/seed")
def seed_draft(draft_id: int, data: SeedRequest, request: Request,
               db: Session = Depends(get_db)):
    """Open a run the product/services teams fill in."""
    actor = _require_operator(request)
    draft = _draft(db, draft_id)
    try:
        out = rq.seed(db, draft, target=data.target, title=data.title,
                      actor=actor)
    except ValueError as e:
        raise HTTPException(400, str(e))
    _audit(request, "risk_questionnaire.seeded", {
        "draft_id": draft.id, "run_id": out["run_id"],
        "catalog_id": out["catalog_id"], "questions": out["questions"],
        "actor": actor})
    return out


@router.get("/runs")
def list_runs(limit: int = Query(20, ge=1, le=100),
              db: Session = Depends(get_db)):
    runs = (db.query(EvaluationRun)
            .join(rq.EvaluationCatalog)
            .filter(rq.EvaluationCatalog.version.like(
                f"{rq.CATALOG_VERSION_PREFIX}%"))
            .order_by(EvaluationRun.id.desc()).limit(limit).all())
    out = []
    for run in runs:
        state = rq.fill_state(db, run)
        out.append({**state["run"], "completion": state["completion"]})
    return {"runs": out}


@router.get("/runs/{run_id}")
def get_run(run_id: int, db: Session = Depends(get_db)):
    """Fill state: per-team completion and every question with its answer."""
    return rq.fill_state(db, _run(db, run_id))


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
    _audit(request, "risk_questionnaire.answer_upserted", {
        "run_id": run.id, "question_id": question_id,
        "risk_rating": answer.risk_rating, "actor": actor})
    return rq.fill_state(db, run)


@router.get("/runs/{run_id}/coverage")
def get_coverage(run_id: int, db: Session = Depends(get_db)):
    """Standards coverage from the filled answers."""
    return rq.coverage(db, _run(db, run_id))


@router.post("/runs/{run_id}/complete")
def complete_run(run_id: int, request: Request,
                 db: Session = Depends(get_db)):
    """Score the run and lock it."""
    actor = _require_operator(request)
    run = _run(db, run_id)
    try:
        result = pe.complete_run(db, run, actor=actor)
    except ValueError as e:
        raise HTTPException(400, str(e))
    _audit(request, "risk_questionnaire.completed", {
        "run_id": run.id, "overall_score": result["overall_score"],
        "counts": result["counts"], "actor": actor})
    return {**result, "coverage": rq.coverage(db, run)}


@router.get("/runs/{run_id}/report.md")
def get_run_report(run_id: int, db: Session = Depends(get_db)):
    """Filled report: the markdown report plus the coverage summary."""
    run = _run(db, run_id)
    try:
        md = pe.report_markdown(db, run)
    except Exception as e:
        raise HTTPException(400, f"report unavailable: {e}")
    cov = rq.coverage(db, run)
    summary = ["\n\n## Standards coverage\n",
               f"{cov['counts']['controls']} controls addressed: "
               f"{cov['counts']['pass']} pass, {cov['counts']['partial']} "
               f"partial, {cov['counts']['fail']} fail, "
               f"{cov['counts']['na']} n/a, {cov['counts']['unanswered']} "
               f"unanswered.\n\n",
               "| Control | Status | Answered |\n|---|---|---|\n"]
    for entry in cov["controls"]:
        summary.append(f"| {entry['label']} | {entry['status']} | "
                       f"{entry['answered']}/{entry['questions']} |\n")
    return Response(
        content=md + "".join(summary), media_type="text/markdown",
        headers={"Content-Disposition":
                 f'attachment; filename="risk-questionnaire-run-{run_id}.md"'})
