"""HTTP surface for Agentic Manager — deep-research question drafting.

``/api/eval-draft`` drafts domain-agnostic evaluation/research question sets
through the reasoning workflow (frame → axes → draft → quality pass →
package), persists each draft for auditability, and can seed a draft straight
into the EvaluationCatalog so the payments-eval run machinery scores it.

AuthZ mirrors the evaluation APIs: a named operator is required, an optional
``PAYMENTS_EVAL_ROLES`` gate applies, and every write is ledgered.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from . import eval_drafting as ed
from . import ledger_api
from .database import get_db
from .models import EvaluationDraft
from .payments_eval_api import _require_operator

router = APIRouter(prefix="/api/eval-draft", tags=["eval-draft"])


class DraftRequest(BaseModel):
    domain: str
    target: str = ""
    depth: str = "deep"          # deep | exec
    axes: Optional[list[str]] = None


class SeedRequest(BaseModel):
    start_run: bool = False
    run_target_agent_id: Optional[str] = None
    run_title: str = ""


def _draft(db: Session, draft_id: int) -> EvaluationDraft:
    d = db.query(EvaluationDraft).filter(
        EvaluationDraft.id == draft_id).first()
    if d is None:
        raise HTTPException(404, "Draft not found")
    return d


def _audit(request: Request, kind: str, data: dict) -> None:
    try:
        ledger_api.human_action(request, kind, data)
    except Exception:
        pass


@router.post("", status_code=201)
def create_draft(data: DraftRequest, request: Request,
                 db: Session = Depends(get_db)):
    actor = _require_operator(request)
    try:
        draft = ed.draft_evaluation_catalog(
            db, data.domain, data.target, depth=data.depth,
            axes=data.axes, actor=actor)
    except ValueError as e:
        raise HTTPException(400, str(e))
    _audit(request, "eval_draft.created", {
        "draft_id": draft["draft_id"], "domain": draft["domain"],
        "axes": draft["axes"], "source": draft["source"], "actor": actor})
    return draft


@router.get("/{draft_id}")
def get_draft(draft_id: int, db: Session = Depends(get_db)):
    return ed.draft_payload(db, _draft(db, draft_id))


@router.get("/{draft_id}/catalog.json")
def get_draft_catalog(draft_id: int, db: Session = Depends(get_db)):
    """The draft as seedable EvaluationCatalog JSON (sections + questions)."""
    d = _draft(db, draft_id)
    sections = ed._draft_sections(d)
    total = sum(len(s.get("questions", [])) for s in sections)
    return {"version": ed.DRAFTING_VERSION, "domain": d.domain,
            "target": d.target, "sections": sections,
            "questions": total}


@router.post("/{draft_id}/seed")
def seed_draft(draft_id: int, data: SeedRequest, request: Request,
               db: Session = Depends(get_db)):
    actor = _require_operator(request)
    d = _draft(db, draft_id)
    try:
        result = ed.seed_draft(
            db, d, actor=actor, start_run=data.start_run,
            run_target_agent_id=data.run_target_agent_id,
            run_title=data.run_title)
    except ValueError as e:
        raise HTTPException(400, str(e))
    _audit(request, "eval_draft.seeded", {
        "draft_id": draft_id, "catalog_id": result["seeded_catalog_id"],
        "start_run": bool(data.start_run), "actor": actor})
    return result


@router.get("/{draft_id}/report.md")
def get_draft_report(draft_id: int,
                     format: str = Query("brief",
                                         description="brief|agenda|adversarial|catalog"),
                     db: Session = Depends(get_db)):
    d = _draft(db, draft_id)
    fmt = format if format in ("brief", "agenda", "adversarial", "catalog") \
        else "brief"
    md = ed.draft_markdown(db, d, fmt=fmt)
    return Response(
        content=md, media_type="text/markdown",
        headers={"Content-Disposition":
                 f'attachment; filename="eval-draft-{draft_id}-{fmt}.md"'})