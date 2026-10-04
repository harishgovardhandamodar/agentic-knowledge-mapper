import json
import os
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Query, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .database import init_db, get_db
from .models import (Investigation, Artifact, Relationship, AgentRun, AgentEvent,
                     Explanation, SecurityAssessment, CveFinding,
                     Initiative, RiskEntry)
from . import llm, scheduler
from . import ledger_api
from . import drift as drift_mod
from . import kb_search as search_mod
from . import console as console_mod
from . import yield_ as yld
from . import recommend as rec
from . import threatpack, evalkit
from . import approvals
from . import cve
from .agent import launch_run, launch_run_with_goal
from . import security_agent
from . import security as sec_engine
from . import standards_matrix
from . import design_docs
from . import manager as manager_mod
from . import dossier
from .explainer import (launch_explanation, _extract_concepts, MODES,
                        DEPTH_PLAN, AUDIENCE_HINTS, _question_suggestions,
                        _quiz_from_answer, _save_explanation_to_graph,
                        _investigation_roadmap)
from .explainer import investigation_suggestions as investigation_suggestions_fn

os.makedirs("data", exist_ok=True)

app = FastAPI(title="Agentic Knowledge Mapper",
              # Every request carries its "sitting" if the client offers one, so
              # work started by a click and work started by a background thread
              # end up on the same session spine. Requests without a session key
              # are unaffected -- this resolves to None and stays out of the way.
              dependencies=[Depends(ledger_api.open_session)])

# Audit ledger: its own router so the review/audit surface can be reasoned about
# (and locked down) separately from the product API.
app.include_router(ledger_api.router)
app.include_router(console_mod.router)
from . import payments_eval as payments_eval_mod
from . import payments_eval_api as payments_eval_api_mod
app.include_router(payments_eval_api_mod.router)
from . import eval_draft_api as eval_draft_api_mod
app.include_router(eval_draft_api_mod.router)
RISK_CONSOLE_ENABLED = os.getenv("RISK_CONSOLE_ENABLED", "1") != "0"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir, html=True), name="static")

    from fastapi.responses import FileResponse

    @app.get("/")
    def serve_index():
        # Single-file app: markup + CSS + JS all live in index.html, so a
        # stale copy means stale layout. Force revalidation (cheap 304 via
        # etag when unchanged) instead of heuristic caching.
        return FileResponse(
            os.path.join(static_dir, "index.html"),
            headers={"Cache-Control": "no-cache"},
        )

    @app.get("/console")
    @app.get("/console/")
    def serve_console():
        if not RISK_CONSOLE_ENABLED:
            raise HTTPException(404, "Risk Console disabled")
        console_index = os.path.join(static_dir, "console", "index.html")
        if os.path.isfile(console_index):
            return FileResponse(console_index, headers={"Cache-Control": "no-cache"})
        raise HTTPException(404, "Console not built")

    @app.get("/console/{path:path}")
    def serve_console_assets(path: str):
        if not RISK_CONSOLE_ENABLED:
            raise HTTPException(404, "Risk Console disabled")
        console_file = os.path.join(static_dir, "console", path)
        if os.path.isfile(console_file):
            return FileResponse(console_file)
        console_index = os.path.join(static_dir, "console", "index.html")
        if os.path.isfile(console_index):
            return FileResponse(console_index, headers={"Cache-Control": "no-cache"})
        raise HTTPException(404, "Not found")


@app.on_event("startup")
def on_start():
    init_db()
    # Payments evaluation catalog: seeded idempotently so the questionnaire is
    # always present without a migration step.
    try:
        from .database import SessionLocal as _SL
        from . import payments_eval as _pe
        _pe.seed_catalog_v1(_SL())
    except Exception as exc:
        import logging
        logging.getLogger(__name__).warning(
            "payments-eval catalog seed failed: %s", exc)
    scheduler.start()
    # Queue recovery comes first, and it is what makes the sweep below correct.
    # A job whose worker died with its lease expired is re-queued here; doing it
    # lazily on the next launch would leave it stuck, because a process that
    # restarts with nothing queued would never look at it again.
    recovered = set()
    try:
        recovered = set(security_agent.recover_jobs())
    except Exception as exc:  # noqa: BLE001 - never block startup on recovery
        obs.log("jobs.recovery_failed", level="error",
                error=f"{type(exc).__name__}: {exc}")
    try:
        security_agent.start_worker()
    except Exception as exc:  # noqa: BLE001 - a dead queue is not a dead app
        obs.log("jobs.worker_start_failed", level="error",
                error=f"{type(exc).__name__}: {exc}")
    # Crash recovery: runs stuck in "running" (killed mid-flight) would
    # otherwise block new runs via the 429 guard. A run whose job was just
    # re-queued is *not* one of them -- it is about to be picked up again, so
    # marking it interrupted would be a false record of a crash that is being
    # repaired.
    db = next(get_db())
    try:
        # Gap runs carry the highest-value follow-ups and run on bare
        # threads: relaunch the interrupted ones before the generic pass
        # below marks everything still running as dead.
        try:
            from . import agent as agent_mod
            recovered |= set(agent_mod.requeue_interrupted_gaps(db))
        except Exception as exc:  # noqa: BLE001 - never block startup
            obs.log("jobs.gap_requeue_failed", level="error",
                    error=f"{type(exc).__name__}: {exc}")
        stale = db.query(AgentRun).filter(AgentRun.status == "running").all()
        for r in stale:
            if r.id in recovered:
                continue
            r.status = "error"
            r.error = "interrupted by server restart"
            r.finished_at = datetime.now(timezone.utc)
            db.add(AgentEvent(run_id=r.id, stage="summary",
                              message="Run interrupted by server restart."))
            inv = db.query(Investigation).filter(
                Investigation.id == r.investigation_id).first()
            if inv and inv.status == "running":
                inv.status = "ready"
        db.commit()
    finally:
        db.close()


# ---------- schemas ----------

class InvestigationCreate(BaseModel):
    title: str
    keywords: str = ""
    description: str = ""
    sources: str = "rss,arxiv,web"


class InvestigationUpdate(BaseModel):
    title: Optional[str] = None
    keywords: Optional[str] = None
    description: Optional[str] = None
    sources: Optional[str] = None


class HiddenUpdate(BaseModel):
    hidden: bool = True


class RunRequest(BaseModel):
    max_items: int = 25
    max_rounds: int = 2


class ArtifactCreate(BaseModel):
    title: str
    artifact_type: str = "news"
    url: Optional[str] = None
    description: Optional[str] = None
    author: Optional[str] = None
    tags: Optional[str] = None


class ReviewUpdate(BaseModel):
    review: str  # pending|accepted|rejected


class DriftUpdate(BaseModel):
    drift: bool = True


class DetectDriftRequest(BaseModel):
    ids: Optional[list[int]] = None


class RelationshipCreate(BaseModel):
    source_id: int
    target_id: int
    relationship_type: str = "similar_to"
    description: Optional[str] = None


class ScheduleUpdate(BaseModel):
    enabled: bool
    cron: str = "0 4 * * *"
    max_items: int = 25
    max_rounds: int = 2


class ExplainRequest(BaseModel):
    question: str
    max_pages: int = 6
    mode: str = "explain"
    depth: str = "balanced"
    audience: str = "intermediate"
    max_hops: int = 0


class SecurityAssessRequest(BaseModel):
    product_name: Optional[str] = ""
    product_url: Optional[str] = ""
    exposure: Optional[str] = "confidential_data"
    use_case: Optional[str] = ""
    workflow_text: Optional[str] = ""
    doc_urls: Optional[list[str]] = []
    focus: Optional[list[str]] = ["accidental_copy", "misclassification"]
    declared_controls: Optional[list[str]] = []
    require_approval: bool = False
    # Which question to ask about a model subject: "target" (is it sound?),
    # "adversarial" (what can someone build with it?), or "hypothesis" (which
    # of those claims is true, and what would settle it). Empty means read the
    # wording -- and never means hypothesis, which is only ever asked for
    # explicitly because it needs the other two to have run.
    assessment_mode: str = ""
    # Hypothesis synthesis reads the target + adversarial rows: refuse to
    # launch on partial priors unless the caller explicitly allows it.
    allow_partial: bool = True
    # Where this model actually runs: data handled, channel, actors, which
    # controls are evidenced rather than merely declared, and how far a leak
    # travels. The same model scores differently in a research notebook than in
    # a customer-facing chat, so this is the input the portfolio layer reads.
    # Every field is optional; absent ones stay unknown and are reported as
    # unknown rather than filled in with a default.
    situation: Optional[dict] = None
    initiative_id: Optional[int] = None
    # Model-engineering assessments target a model, not a product workflow.
    # Ignored unless assessment_mode == "model_engineering".
    model_name: Optional[str] = ""
    model_family: Optional[str] = ""
    modality: Optional[str] = ""
    weights_source: Optional[str] = ""
    training_data_posture: Optional[str] = ""
    deployment_pattern: Optional[str] = ""
    model_focus_terms: Optional[list[str]] = []
    workflows: Optional[list[str]] = []
    # Assurance layer (app/assurance.py). architecture_checklist is what the
    # vendor attests to (log retention, tenant isolation, ...); leaving it
    # empty is the honest answer and is scored as unknown, which forces the
    # architecture gate rather than silently passing. exposure_inventory is
    # what makes blast radius computable, and is required for a go/no-go on a
    # restricted or confidential tier. full_metadata_context controls how much
    # verbatim provider text is scored -- full is expensive, truncated is the
    # default, and the recorded choice travels with the result.
    architecture_checklist: Optional[dict] = None
    exposure_inventory: Optional[dict] = None
    full_metadata_context: bool = False


class SecurityRescoreRequest(BaseModel):
    active_controls: Optional[list[str]] = None
    applicability: Optional[dict] = None
    persist: bool = False


class SecuritySubjectRequest(BaseModel):
    """Subject text for the pre-run classifier. No side effects: the form
    calls it while the user is still typing."""
    product_name: str = ""
    use_case: str = ""
    focus: Optional[list[str]] = []


class SecurityApprovalRequest(BaseModel):
    decision: str = "approve"  # approve | reject
    active_controls: Optional[list[str]] = None
    applicability: Optional[dict] = None
    note: str = ""


class AgentInvokeRequest(BaseModel):
    to: str = "research-collector"
    intent: str = "collect_research"
    payload: Optional[dict] = None
    task_id: Optional[str] = None


# ---------- helpers ----------

def _inv_json(inv: Investigation, db: Session) -> dict:
    n_art = db.query(Artifact).filter(Artifact.investigation_id == inv.id).count()
    n_rel = db.query(Relationship).filter(Relationship.investigation_id == inv.id).count()
    n_runs = db.query(AgentRun).filter(AgentRun.investigation_id == inv.id).count()
    return {
        "id": inv.id, "title": inv.title, "keywords": inv.keywords,
        "description": inv.description, "sources": inv.sources,
        "status": inv.status, "hidden": bool(inv.hidden),
        "artifacts": n_art, "relationships": n_rel,
        "runs": n_runs,
        "schedule": {
            "enabled": bool(inv.schedule_enabled),
            "cron": inv.schedule_cron,
            "max_items": inv.schedule_max_items,
            "max_rounds": inv.schedule_rounds,
            "last_scheduled_at": inv.last_scheduled_at.isoformat()
            if inv.last_scheduled_at else None,
            "next_run_at": inv.next_run_at.isoformat() if inv.next_run_at else None,
        },
        "created_at": inv.created_at.isoformat() if inv.created_at else None,
        "updated_at": inv.updated_at.isoformat() if inv.updated_at else None,
    }


def _artifact_json(a: Artifact) -> dict:
    return {
        "id": a.id, "investigation_id": a.investigation_id, "title": a.title,
        "artifact_type": a.artifact_type, "url": a.url, "description": a.description,
        "source": a.source, "author": a.author,
        "date_published": a.date_published.isoformat() if a.date_published else None,
        "tags": a.tags, "sentiment": a.sentiment, "relevance": a.relevance,
        "relevance_reason": a.relevance_reason, "review": a.review, "origin": a.origin,
        "drift": bool(a.drift),
    }


# ---------- health ----------

@app.get("/api/health")
def health():
    return {"status": "ok", "llm": llm.health()}


# ---------- investigations ----------

@app.get("/api/investigations")
def list_investigations(include_hidden: bool = False,
                        db: Session = Depends(get_db)):
    q = db.query(Investigation).order_by(Investigation.updated_at.desc())
    if not include_hidden:
        q = q.filter(Investigation.hidden == 0)
    return {"items": [_inv_json(i, db) for i in q.all()]}


@app.post("/api/investigations")
def create_investigation(data: InvestigationCreate, request: Request,
                         db: Session = Depends(get_db)):
    if not data.title.strip():
        raise HTTPException(400, "Title is required")
    inv = Investigation(title=data.title.strip()[:300],
                        keywords=(data.keywords or "")[:1000],
                        description=(data.description or ""),
                        sources=(data.sources or "rss,arxiv,web")[:200])
    db.add(inv)
    db.commit()
    db.refresh(inv)
    ledger_api.human_action(request, "created_investigation",
                            {"investigation": inv.id, "title": inv.title,
                             "sources": inv.sources})
    return _inv_json(inv, db)


@app.get("/api/investigations/{inv_id}")
def get_investigation(inv_id: int, request: Request, db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    # The UI calls this whenever the user opens an investigation, which makes it
    # the honest place to see "what was this person working on".
    ledger_api.human_action(request, "opened_investigation",
                            {"investigation": inv.id, "title": inv.title})
    out = _inv_json(inv, db)
    runs = (db.query(AgentRun).filter(AgentRun.investigation_id == inv_id)
            .order_by(AgentRun.id.desc()).limit(10).all())
    out["recent_runs"] = [{"id": r.id, "status": r.status,
                           "trigger": r.trigger or "manual",
                           "stats": json.loads(r.stats) if r.stats else {},
                           "started_at": r.started_at.isoformat() if r.started_at else None,
                           "finished_at": r.finished_at.isoformat() if r.finished_at else None,
                           "error": (r.error or "")[:500] if r.error else None}
                          for r in runs]
    return out


@app.put("/api/investigations/{inv_id}")
def update_investigation(inv_id: int, data: InvestigationUpdate,
                         db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    if data.title is not None:
        inv.title = data.title.strip()[:300]
    if data.keywords is not None:
        inv.keywords = data.keywords[:1000]
    if data.description is not None:
        inv.description = data.description
    if data.sources is not None:
        inv.sources = data.sources[:200]
    inv.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(inv)
    return _inv_json(inv, db)


@app.delete("/api/investigations/{inv_id}")
def delete_investigation(inv_id: int, db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    db.query(Relationship).filter(Relationship.investigation_id == inv_id).delete()
    for r in db.query(AgentRun).filter(AgentRun.investigation_id == inv_id).all():
        db.query(AgentEvent).filter(AgentEvent.run_id == r.id).delete()
    db.query(AgentRun).filter(AgentRun.investigation_id == inv_id).delete()
    db.query(Artifact).filter(Artifact.investigation_id == inv_id).delete()
    db.delete(inv)
    db.commit()
    return {"ok": True}


@app.patch("/api/investigations/{inv_id}/hidden")
def set_investigation_hidden(inv_id: int, data: HiddenUpdate, request: Request,
                             db: Session = Depends(get_db)):
    """Hide an investigation from the list (or bring it back). Hiding is not
    deleting: runs, artifacts and history are kept, and a hidden investigation
    can still be opened directly."""
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    inv.hidden = 1 if data.hidden else 0
    inv.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(inv)
    ledger_api.human_action(request,
                             "hid_investigation" if data.hidden else "unhid_investigation",
                             {"investigation": inv.id, "title": inv.title})
    return _inv_json(inv, db)


# ---------- agent runs ----------

@app.post("/api/investigations/{inv_id}/run")
def start_run(inv_id: int, req: RunRequest, request: Request,
              db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    if db.query(AgentRun).filter(AgentRun.investigation_id == inv_id,
                                 AgentRun.status == "running").first():
        raise HTTPException(429, "A run is already in progress for this investigation")
    ledger_api.human_action(request, "started_agent_run",
                            {"investigation": inv_id, "title": inv.title,
                             "max_items": req.max_items, "max_rounds": req.max_rounds})
    # launch_run copies this context, so the run anchors to the same session
    # the click came from.
    launch_run(inv_id, max_items=max(1, min(req.max_items, 100)),
               max_rounds=max(1, min(req.max_rounds, 3)))
    return {"status": "started"}


@app.get("/api/runs")
def list_runs(investigation_id: int = Query(...), limit: int = Query(10, le=50),
              db: Session = Depends(get_db)):
    runs = (db.query(AgentRun).filter(AgentRun.investigation_id == investigation_id)
            .order_by(AgentRun.id.desc()).limit(limit).all())
    return {"items": [{"id": r.id, "status": r.status,
                       "trigger": r.trigger or "manual",
                       "stats": json.loads(r.stats) if r.stats else {},
                       "plan": json.loads(r.plan) if r.plan else None,
                       "started_at": r.started_at.isoformat() if r.started_at else None,
                       "finished_at": r.finished_at.isoformat() if r.finished_at else None,
                       "error": (r.error or "")[:1000] if r.error else None}
                      for r in runs]}


@app.get("/api/runs/{run_id}")
def get_run(run_id: int, db: Session = Depends(get_db)):
    r = db.query(AgentRun).filter(AgentRun.id == run_id).first()
    if not r:
        raise HTTPException(404, "Run not found")
    events = (db.query(AgentEvent).filter(AgentEvent.run_id == run_id)
              .order_by(AgentEvent.id).all())
    return {
        "id": r.id, "investigation_id": r.investigation_id, "status": r.status,
        "trigger": r.trigger or "manual",
        "stats": json.loads(r.stats) if r.stats else {},
        "plan": json.loads(r.plan) if r.plan else None,
        "error": r.error,
        "events": [{"id": e.id, "stage": e.stage, "message": e.message,
                    "data": json.loads(e.data) if e.data else {},
                    "created_at": e.created_at.isoformat() if e.created_at else None}
                   for e in events],
    }


@app.get("/api/runs/{run_id}/events")
def poll_events(run_id: int, after_id: int = Query(0),
                db: Session = Depends(get_db)):
    r = db.query(AgentRun).filter(AgentRun.id == run_id).first()
    if not r:
        raise HTTPException(404, "Run not found")
    events = (db.query(AgentEvent).filter(AgentEvent.run_id == run_id,
                                          AgentEvent.id > after_id)
              .order_by(AgentEvent.id).limit(200).all())
    return {"status": r.status,
            "events": [{"id": e.id, "stage": e.stage, "message": e.message,
                        "data": json.loads(e.data) if e.data else {}}
                       for e in events]}


# ---------- schedule ----------

@app.put("/api/investigations/{inv_id}/schedule")
def update_schedule(inv_id: int, data: ScheduleUpdate,
                    db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    if data.enabled:
        if not scheduler.valid_cron(data.cron):
            raise HTTPException(400, "Invalid cron expression (e.g. '0 4 * * *')")
        inv.schedule_enabled = 1
        inv.schedule_cron = data.cron.strip()
        inv.schedule_max_items = max(1, min(data.max_items, 100))
        inv.schedule_rounds = max(1, min(data.max_rounds, 3))
        inv.next_run_at = scheduler.compute_next(inv)
    else:
        inv.schedule_enabled = 0
        inv.next_run_at = None
    inv.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(inv)
    return _inv_json(inv, db)["schedule"]


# ---------- timeline & compare ----------

def _dt(dt):
    return dt.isoformat() if dt else None


@app.get("/api/investigations/{inv_id}/timeline")
def get_timeline(inv_id: int, db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    runs = (db.query(AgentRun).filter(AgentRun.investigation_id == inv_id)
            .order_by(AgentRun.id).all())
    entries = []
    for r in runs:
        n_art = db.query(Artifact).filter(Artifact.run_id == r.id).count()
        n_rel = db.query(Relationship).filter(Relationship.run_id == r.id).count()
        entries.append({
            "kind": "run", "id": r.id, "trigger": r.trigger or "manual",
            "status": r.status, "started_at": _dt(r.started_at),
            "finished_at": _dt(r.finished_at),
            "stats": json.loads(r.stats) if r.stats else {},
            "added_artifacts": n_art, "added_relationships": n_rel,
        })
    manual = (db.query(Artifact)
              .filter(Artifact.investigation_id == inv_id,
                      Artifact.run_id.is_(None))
              .order_by(Artifact.id).all())
    return {
        "runs": entries,
        "manual": [{"id": a.id, "title": a.title, "origin": a.origin,
                    "review": a.review, "created_at": _dt(a.created_at)}
                   for a in manual],
        "totals": {
            "runs": len(entries),
            "artifacts": db.query(Artifact)
            .filter(Artifact.investigation_id == inv_id).count(),
            "relationships": db.query(Relationship)
            .filter(Relationship.investigation_id == inv_id).count(),
        },
    }


@app.get("/api/investigations/{inv_id}/compare")
def compare_runs(inv_id: int, from_run: int = Query(...),
                to_run: int = Query(...), db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    base = db.query(AgentRun).filter(
        AgentRun.id == from_run, AgentRun.investigation_id == inv_id).first()
    target = db.query(AgentRun).filter(
        AgentRun.id == to_run, AgentRun.investigation_id == inv_id).first()
    if not base or not target:
        raise HTTPException(404, "Run not found in this investigation")

    now = datetime.now(timezone.utc)
    from_anchor = base.finished_at or base.started_at or now
    to_anchor = target.finished_at or now
    if from_anchor.tzinfo is None:
        from_anchor = from_anchor.replace(tzinfo=timezone.utc)
    if to_anchor.tzinfo is None:
        to_anchor = to_anchor.replace(tzinfo=timezone.utc)

    def _aware(dt):
        if not dt:
            return None
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

    new_nodes = []
    for a in db.query(Artifact).filter(Artifact.investigation_id == inv_id).all():
        if a.run_id == target.id:
            new_nodes.append(a)
        elif _aware(a.created_at) and _aware(a.created_at) > from_anchor \
                and _aware(a.created_at) <= to_anchor and a.run_id != base.id:
            new_nodes.append(a)

    new_edges = []
    for r in db.query(Relationship).filter(
            Relationship.investigation_id == inv_id).all():
        if r.run_id == target.id:
            new_edges.append(r)
        elif _aware(r.created_at) and _aware(r.created_at) > from_anchor \
                and _aware(r.created_at) <= to_anchor and r.run_id != base.id:
            new_edges.append(r)

    return {
        "from_run": {"id": base.id, "trigger": base.trigger or "manual",
                     "status": base.status, "started_at": _dt(base.started_at),
                     "finished_at": _dt(base.finished_at)},
        "to_run": {"id": target.id, "trigger": target.trigger or "manual",
                   "status": target.status, "started_at": _dt(target.started_at),
                   "finished_at": _dt(target.finished_at)},
        "new_node_ids": sorted(a.id for a in new_nodes),
        "new_edge_ids": sorted(r.id for r in new_edges),
        "new_nodes": [{"id": a.id, "title": a.title,
                       "artifact_type": a.artifact_type,
                       "relevance": a.relevance} for a in new_nodes],
    }


# ---------- artifacts ----------

# Provenance labels live in app.dossier so this API and the dossier's
# collection inventory read an artifact the same way; two copies of these
# would let a PDF and the on-screen report attribute the same artifact to
# different actors.
_artifact_actor = dossier.artifact_actor
_artifact_purpose = dossier.artifact_purpose


@app.get("/api/investigations/{inv_id}/recommendations")
def recommendations(inv_id: int, assessment_id: Optional[int] = None,
                    limit: int = Query(8, ge=1, le=50),
                    db: Session = Depends(get_db)):
    """What to do next, computed from what is already on disk.

    Pull-only and model-free: each figure here is either a count of stored
    artifacts or the difference between two evaluations of the same deterministic
    scorer, so nothing is estimated. An empty ``recommended`` list means there is
    genuinely nothing to suggest, which is a different claim from having no
    opinion.
    """
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    return rec.digest(db, inv_id, assessment_id=assessment_id, limit=limit)


@app.get("/api/investigations/{inv_id}/query-yields")
def query_yields(inv_id: int, db: Session = Depends(get_db),
                 reset: bool = False):
    """What each shape of query has cost and returned for this investigation.

    The agent's only stopping rule is a fixed round and item budget, so it has
    to spend that budget on the most productive questions available or spend it
    re-asking the same fruitless one. This is the memory that decides which.
    """
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    cleared = yld.clear_yields(db, inv_id) if reset else 0
    shapes = yld.shape_stats(db, inv_id)
    productive = [s for s in shapes if s["kept"] > 0]
    barren = [s for s in shapes if s["kept"] == 0]
    return {
        "investigation": inv_id,
        "total": len(shapes),
        "shapes": shapes,
        "productive": len(productive),
        "barren": len(barren),
        # The headline the loop is actually optimising: a fixed budget spent
        # on the most productive questions it can find.
        "artifacts_kept": sum(s["kept"] for s in shapes),
        "llm_calls": sum(s["llm_calls"] for s in shapes),
        "suggested": yld.suggest_queries(db, inv_id),
        "cleared": cleared,
    }


@app.get("/api/investigations/{inv_id}/artifacts/overview")
def artifacts_overview(inv_id: int, db: Session = Depends(get_db)):
    """Collection overview: every artifact with its timeline position, purpose,
    and collecting actor, plus per-actor involvement shares."""
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    runs = {r.id: r for r in db.query(AgentRun)
            .filter(AgentRun.investigation_id == inv_id).all()}
    arts = (db.query(Artifact).filter(Artifact.investigation_id == inv_id)
            .order_by(Artifact.created_at.desc(), Artifact.id.desc()).all())
    items = []
    counts: dict = {}
    days: dict = {}
    for a in arts:
        run = runs.get(a.run_id) if a.run_id else None
        actor = _artifact_actor(a, run)
        counts[actor] = counts.get(actor, 0) + 1
        day = a.created_at.date().isoformat() if a.created_at else "unknown"
        days[day] = days.get(day, 0) + 1
        items.append({
            "id": a.id, "title": a.title, "artifact_type": a.artifact_type,
            "url": a.url, "actor": actor,
            "purpose": _artifact_purpose(a, run),
            "collected_at": a.created_at.isoformat() if a.created_at else None,
            "review": a.review, "drift": bool(a.drift),
            "relevance": a.relevance,
        })
    total = len(items) or 1
    by_actor = [{"actor": k, "count": v, "pct": round(100.0 * v / total, 1)}
                for k, v in sorted(counts.items(), key=lambda kv: -kv[1])]
    timeline = [{"day": k, "count": v} for k, v in sorted(days.items())]
    return {"total": len(items), "by_actor": by_actor,
            "timeline": timeline, "items": items}


@app.get("/api/investigations/{inv_id}/artifacts")
def list_artifacts(inv_id: int, review: Optional[str] = Query(None),
                   search: Optional[str] = Query(None),
                   drift: Optional[int] = Query(None),
                   limit: int = Query(200, le=500), offset: int = Query(0),
                   db: Session = Depends(get_db)):
    q = db.query(Artifact).filter(Artifact.investigation_id == inv_id)
    if review and review != "all":
        q = q.filter(Artifact.review == review)
    if drift is not None:
        q = q.filter(Artifact.drift == (1 if drift else 0))
    if search:
        q = q.filter(Artifact.title.ilike(f"%{search}%")
                     | Artifact.description.ilike(f"%{search}%")
                     | Artifact.tags.ilike(f"%{search}%"))
    total = q.count()
    items = q.order_by(Artifact.relevance.desc(), Artifact.id.desc()).offset(offset).limit(limit).all()
    return {"total": total, "items": [_artifact_json(a) for a in items]}


@app.post("/api/investigations/{inv_id}/artifacts")
def create_artifact(inv_id: int, data: ArtifactCreate, db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    a = Artifact(investigation_id=inv_id, title=data.title[:500],
                 artifact_type=data.artifact_type, url=data.url,
                 description=data.description, author=data.author, tags=data.tags,
                 review="accepted", origin="manual")
    db.add(a)
    db.commit()
    db.refresh(a)
    return _artifact_json(a)


@app.patch("/api/artifacts/{artifact_id}")
def review_artifact(artifact_id: int, data: ReviewUpdate, request: Request,
                    db: Session = Depends(get_db)):
    if data.review not in ("pending", "accepted", "rejected"):
        raise HTTPException(400, "Invalid review state")
    a = db.query(Artifact).filter(Artifact.id == artifact_id).first()
    if not a:
        raise HTTPException(404, "Artifact not found")
    a.review = data.review
    db.commit()
    # A review decision is the most consequential human act in the product: it
    # is what later work is allowed to treat as accepted.
    ledger_api.human_action(request, f"review_{data.review}",
                            {"artifact": artifact_id, "title": a.title,
                             "investigation": a.investigation_id,
                             "url": a.url})
    return _artifact_json(a)


@app.patch("/api/artifacts/{artifact_id}/drift")
def set_artifact_drift(artifact_id: int, data: DriftUpdate, request: Request,
                       db: Session = Depends(get_db)):
    """Hand-mark one artifact as off-brief drift (or clear it). Drift is a
    classification, not a verdict: the item stays, but lists and the graph
    can dim or filter it."""
    a = db.query(Artifact).filter(Artifact.id == artifact_id).first()
    if not a:
        raise HTTPException(404, "Artifact not found")
    a.drift = 1 if data.drift else 0
    db.commit()
    db.refresh(a)
    ledger_api.human_action(request,
                            "marked_drift" if data.drift else "cleared_drift",
                            {"artifact": artifact_id, "title": a.title,
                             "investigation": a.investigation_id})
    return _artifact_json(a)


@app.post("/api/investigations/{inv_id}/detect-drift")
def detect_investigation_drift(inv_id: int, data: DetectDriftRequest,
                               request: Request,
                               db: Session = Depends(get_db)):
    """Tag off-brief items as drift. With explicit ``ids`` the marking is
    manual (no LLM); otherwise every unflagged item goes through the
    deterministic prefilter and only the leftovers get one LLM batch verdict.
    """
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    if data.ids is not None:
        rows = db.query(Artifact).filter(
            Artifact.investigation_id == inv_id,
            Artifact.id.in_([i for i in data.ids if isinstance(i, int)])).all()
        for a in rows:
            a.drift = 1
        db.commit()
        marked = [a.id for a in rows]
        ledger_api.human_action(request, "marked_drift",
                                {"investigation": inv_id, "artifacts": marked,
                                 "mode": "manual"})
        return {"checked": len(rows), "candidates": len(rows), "marked": marked}
    untagged = db.query(Artifact).filter(
        Artifact.investigation_id == inv_id,
        (Artifact.drift.is_(None) | (Artifact.drift == 0))).all()
    brief = drift_mod.brief_terms(inv.title, inv.keywords, inv.description)
    brief_text = f"{inv.title} | {inv.keywords} | {inv.description}"
    corpus = set()
    corpus_text_parts = []
    for art in db.query(Artifact).filter(
            Artifact.investigation_id == inv_id,
            Artifact.relevance.is_not(None)).all():
        corpus |= drift_mod.item_terms(art.title, art.tags, art.description)
        corpus_text_parts.append(f"{art.title} {art.tags or ''} {art.description or ''}")
    # Descriptions reach both sides of the prefilter: they supply the item's own
    # vocabulary, and an already-relevant artifact's text becomes the corpus the
    # next candidates are compared against.
    items = [{"id": a.id, "title": a.title, "tags": a.tags or "",
              "description": a.description or ""} for a in untagged]
    cands = drift_mod.drift_candidates(brief, corpus, items,
                                        brief_text=brief_text,
                                        corpus_text=" ".join(corpus_text_parts))
    report = drift_mod.classify_drift(brief_text, cands)
    drifted = report.get("ids") or set()
    marked = []
    for a in untagged:
        if a.id in drifted and not a.drift:
            a.drift = 1
            marked.append(a.id)
    db.commit()
    ledger_api.human_action(request, "marked_drift",
                            {"investigation": inv_id, "artifacts": marked,
                             "mode": "auto", "checked": len(untagged),
                             "candidates": len(cands),
                             "judge_complete": report.get("complete", True),
                             "failed_batches": report.get("failed", 0),
                             "overflow": report.get("overflow", 0)})
    # Say plainly when the pass was partial. "Marked nothing" reads as a clean
    # result otherwise, which is the failure mode this reporting exists to
    # prevent.
    out = {"checked": len(untagged), "candidates": len(cands), "marked": marked,
           "judged": report.get("judged", 0),
           "complete": report.get("complete", True)}
    if not out["complete"]:
        out["incomplete_reason"] = drift_mod.incomplete_reason(report)
        if report.get("error"):
            out["error"] = report["error"]
    return out


@app.delete("/api/artifacts/{artifact_id}")
def delete_artifact(artifact_id: int, db: Session = Depends(get_db)):
    a = db.query(Artifact).filter(Artifact.id == artifact_id).first()
    if not a:
        raise HTTPException(404, "Artifact not found")
    db.query(Relationship).filter((Relationship.source_id == a.id)
                                  | (Relationship.target_id == a.id)).delete()
    db.delete(a)
    db.commit()
    return {"ok": True}


@app.get("/api/artifacts/{artifact_id}")
def get_artifact(artifact_id: int, db: Session = Depends(get_db)):
    a = db.query(Artifact).filter(Artifact.id == artifact_id).first()
    if not a:
        raise HTTPException(404, "Artifact not found")

    out_rels = (
        db.query(Relationship, Artifact)
        .join(Artifact, Relationship.target_id == Artifact.id)
        .filter(Relationship.source_id == a.id)
        .all()
    )
    in_rels = (
        db.query(Relationship, Artifact)
        .join(Artifact, Relationship.source_id == Artifact.id)
        .filter(Relationship.target_id == a.id)
        .all()
    )
    result = _artifact_json(a)
    # Full content is detail-only: the list endpoint reuses _artifact_json
    # for many rows and stays light, but the overlay and the manager summary
    # view both read detail.content -- omitting it stranded them empty.
    result["content"] = a.content
    result["relationships"] = [
        {"id": r.Relationship.id, "direction": "outgoing",
         "target_id": r.Relationship.target_id, "target_title": r.Artifact.title,
         "type": r.Relationship.relationship_type,
         "description": r.Relationship.description}
        for r in out_rels
    ] + [
        {"id": r.Relationship.id, "direction": "incoming",
         "source_id": r.Relationship.source_id, "source_title": r.Artifact.title,
         "type": r.Relationship.relationship_type,
         "description": r.Relationship.description}
        for r in in_rels
    ]
    return result


@app.get("/api/artifacts/{artifact_id}/similar")
def similar_artifacts(artifact_id: int, limit: int = Query(8, le=20),
                      db: Session = Depends(get_db)):
    a = db.query(Artifact).filter(Artifact.id == artifact_id).first()
    if not a:
        raise HTTPException(404, "Artifact not found")

    a_tags = _tag_set(a.tags)
    others = (db.query(Artifact)
              .filter(Artifact.investigation_id == a.investigation_id,
                      Artifact.id != artifact_id).all())
    scored = []
    for other in others:
        score, reasons, shared = 0.0, [], []
        o_tags = _tag_set(other.tags)
        if a_tags and o_tags:
            overlap, union = a_tags & o_tags, a_tags | o_tags
            jaccard = len(overlap) / len(union) if union else 0
            if jaccard > 0:
                score += jaccard * 0.4
                shared = sorted(overlap)
                reasons.append(f"{len(overlap)} shared tags")
        if other.author and a.author and other.author.lower() == a.author.lower():
            score += 0.3
            reasons.append("same author")
        if other.artifact_type == a.artifact_type:
            score += 0.15
            reasons.append("same type")
        rels = (db.query(Relationship).filter(
            ((Relationship.source_id == a.id) & (Relationship.target_id == other.id))
            | ((Relationship.target_id == a.id) & (Relationship.source_id == other.id))
        ).all())
        if rels:
            score += 0.3
            reasons.append(f"connected via {rels[0].relationship_type}")
        if other.description and a.description:
            overlap = len(set(a.description.lower().split())
                          & set(other.description.lower().split()))
            if overlap > 10:
                score += 0.15
                reasons.append("content overlap")
        # Relevance proximity: similarly-scored items are likely about the same facet.
        if a.relevance is not None and other.relevance is not None:
            if abs(a.relevance - other.relevance) < 0.2:
                score += 0.1
                reasons.append("close relevance")
        if score > 0:
            scored.append((round(score, 2), reasons, other, shared))
    scored.sort(key=lambda x: -x[0])
    return {"items": [{**_artifact_json(s), "similarity": sc, "reasons": reasons,
                       "shared_tags": st}
                      for sc, reasons, s, st in scored[:limit]]}


@app.post("/api/relationships")
def create_relationship(data: RelationshipCreate, db: Session = Depends(get_db)):
    src = db.query(Artifact).filter(Artifact.id == data.source_id).first()
    tgt = db.query(Artifact).filter(Artifact.id == data.target_id).first()
    if not src or not tgt or src.investigation_id != tgt.investigation_id:
        raise HTTPException(404, "Artifacts must exist in the same investigation")
    rel = Relationship(investigation_id=src.investigation_id, source_id=data.source_id,
                       target_id=data.target_id, relationship_type=data.relationship_type,
                       description=data.description, origin="manual")
    db.add(rel)
    db.commit()
    db.refresh(rel)
    return {"id": rel.id}


@app.get("/api/search")
def search(
    q: str = Query("", description="Query string with optional field filters"),
    types: str = Query("", description="Comma-separated types: risks,evidence,assets,decisions"),
    layer: str | None = Query(None),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    limit: int = Query(20, le=50),
    offset: int = Query(0, ge=0),
    investigation_id: int | None = Query(None),
    accepted_only: bool = Query(True, description="Accepted-only default for DPO/Legal/Exec"),
    db: Session = Depends(get_db),
):
    types_list = [t.strip() for t in types.split(",") if t.strip()] if types else None
    return search_mod.search(
        q=q, types=types_list, layer=layer, severity=severity, status=status,
        limit=limit, offset=offset, investigation_id=investigation_id, accepted_only=accepted_only,
    )


@app.get("/api/search/suggest")
def search_suggest(
    q: str = Query("", description="Prefix for as-you-type suggestions"),
    investigation_id: int | None = Query(None),
    db: Session = Depends(get_db),
):
    return search_mod.suggest(q=q, investigation_id=investigation_id, limit=8)


# ---------- explainer ----------

def _expl_json(e: Explanation) -> dict:
    return {
        "id": e.id, "investigation_id": e.investigation_id,
        "question": e.question,
        "answer": json.loads(e.answer) if e.answer else None,
        "trace": json.loads(e.trace) if e.trace else None,
        "status": e.status, "error": (e.error or "")[:1000] if e.error else None,
        "created_at": e.created_at.isoformat() if e.created_at else None,
        "finished_at": e.finished_at.isoformat() if e.finished_at else None,
        "mode": e.mode or "explain", "depth": e.depth or "balanced",
        "audience": e.audience or "intermediate",
        "max_pages": e.max_pages, "hops": e.hops or 0,
        "parent_id": e.parent_id, "thread_id": e.thread_id,
        "quiz": json.loads(e.quiz) if e.quiz else None,
        "bookmarked": bool(e.bookmarked),
        "watched": bool(e.watched),
        "watch_of": (json.loads(e.meta or "{}") or {}).get("watch_of"),
        "drift": (json.loads(e.meta or "{}") or {}).get("drift"),
        "phase": (json.loads(e.meta or "{}") or {}).get("phase"),
    }


@app.post("/api/investigations/{inv_id}/explain")
def ask_explainer(inv_id: int, req: ExplainRequest, request: Request,
                   db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    if not req.question.strip():
        raise HTTPException(400, "Question is required")
    if req.mode not in MODES:
        raise HTTPException(400, "mode must be one of: %s" % ", ".join(MODES))
    if req.depth not in DEPTH_PLAN:
        raise HTTPException(400, "depth must be one of: shallow, balanced, deep")
    if req.audience not in AUDIENCE_HINTS:
        raise HTTPException(400, "audience must be one of: beginner, intermediate, advanced")
    busy = (db.query(Explanation)
            .filter(Explanation.investigation_id == inv_id,
                    Explanation.status == "running").first())
    if busy:
        raise HTTPException(429, "An explanation is already in progress")
    exp = Explanation(investigation_id=inv_id, question=req.question.strip()[:1000],
                      mode=req.mode, depth=req.depth, audience=req.audience,
                      max_pages=max(2, min(req.max_pages, 10)))
    db.add(exp)
    db.commit()
    db.refresh(exp)
    # The question itself is the interesting part, so it is recorded verbatim
    # (it is already user input, not model output or a credential).
    ledger_api.human_action(request, "asked_explainer",
                            {"investigation": inv_id, "explanation": exp.id,
                             "question": exp.question, "mode": req.mode,
                             "depth": req.depth})
    hops = 1 if req.depth == "deep" else max(0, req.max_hops)
    launch_explanation(exp.id, max_pages=exp.max_pages, max_hops=hops)
    return _expl_json(exp)


@app.get("/api/investigations/{inv_id}/explanations")
def list_explanations(inv_id: int, bookmarked: bool = False, db: Session = Depends(get_db)):
    q = (db.query(Explanation).filter(Explanation.investigation_id == inv_id))
    if bookmarked:
        q = q.filter(Explanation.bookmarked == 1)
    items = q.order_by(Explanation.id.desc()).limit(50).all()
    out = []
    for e in items:
        d = _expl_json(e)
        d["answer"] = None  # list view: question + status only, fetch detail to read
        d["trace"] = None
        d["quiz"] = None
        out.append(d)
    return {"items": out}


@app.get("/api/explanations/{exp_id}")
def get_explanation(exp_id: int, db: Session = Depends(get_db)):
    e = db.query(Explanation).filter(Explanation.id == exp_id).first()
    if not e:
        raise HTTPException(404, "Explanation not found")
    return _expl_json(e)


@app.delete("/api/explanations/{exp_id}")
def delete_explanation(exp_id: int, db: Session = Depends(get_db)):
    e = db.query(Explanation).filter(Explanation.id == exp_id).first()
    if not e:
        raise HTTPException(404, "Explanation not found")
    # children removed too (they reference the parent)
    db.query(Explanation).filter(Explanation.parent_id == exp_id).delete()
    db.delete(e)
    db.commit()
    return {"ok": True}


class FollowupRequest(BaseModel):
    question: str
    scope: str = "whole"  # whole|section|claim
    target_index: Optional[int] = None
    max_pages: int = 4


class BookmarkRequest(BaseModel):
    bookmarked: bool


@app.post("/api/explanations/{exp_id}/followup")
def ask_followup(exp_id: int, req: FollowupRequest, db: Session = Depends(get_db)):
    parent = db.query(Explanation).filter(Explanation.id == exp_id).first()
    if not parent:
        raise HTTPException(404, "Explanation not found")
    if parent.status != "done":
        raise HTTPException(409, "Explanation must be finished before follow-up")
    if not req.question.strip():
        raise HTTPException(400, "Question is required")
    if req.scope not in ("whole", "section", "claim"):
        raise HTTPException(400, "scope must be whole|section|claim")
    idx = req.target_index
    if req.scope in ("section", "claim") and (
            idx is None or not isinstance(idx, int) or idx < 0):
        raise HTTPException(400, "target_index required for scoped follow-up")
    child = Explanation(
        investigation_id=parent.investigation_id,
        question=req.question.strip()[:1000],
        parent_id=parent.id,
        thread_id=parent.thread_id or parent.id,
        mode=parent.mode or "explain",
        depth=((parent.depth or "balanced")
               if (parent.depth or "balanced") not in ("deep",) else "balanced"),
        audience=parent.audience or "intermediate",
        max_pages=max(2, min(req.max_pages, 8)),
        meta=json.dumps({"scope": req.scope, "target_index": idx}),
    )
    db.add(child)
    db.commit()
    db.refresh(child)
    launch_explanation(child.id, max_pages=child.max_pages)
    return _expl_json(child)


@app.get("/api/explanations/{exp_id}/thread")
def explanation_thread(exp_id: int, db: Session = Depends(get_db)):
    root = db.query(Explanation).filter(Explanation.id == exp_id).first()
    if not root:
        raise HTTPException(404, "Explanation not found")
    tid = root.thread_id or root.id
    items = (db.query(Explanation).filter(
        Explanation.thread_id == tid).order_by(Explanation.id).all())
    out = []
    for e in items:
        d = _expl_json(e)
        d["answer"] = None
        d["trace"] = None
        out.append(d)
    return {"root_id": root.id, "thread_id": tid, "items": out}


@app.post("/api/explanations/{exp_id}/save_to_graph")
def save_explanation_to_graph(exp_id: int, db: Session = Depends(get_db)):
    e = db.query(Explanation).filter(Explanation.id == exp_id).first()
    if not e:
        raise HTTPException(404, "Explanation not found")
    if e.status != "done" or not e.answer:
        raise HTTPException(409, "Explanation has no finished answer")
    return _save_explanation_to_graph(db, e)


@app.post("/api/explanations/{exp_id}/investigate_gaps")
def investigate_explainer_gaps(exp_id: int, db: Session = Depends(get_db)):
    e = db.query(Explanation).filter(Explanation.id == exp_id).first()
    if not e:
        raise HTTPException(404, "Explanation not found")
    missing = []
    try:
        t = json.loads(e.trace or "{}")
        missing += t.get("gaps") or []
        missing += (t.get("hop_plan") or [{}])[-1].get("missing_topics", []) or []
    except Exception:
        pass
    if not missing:
        raise HTTPException(409, "No open gaps found for this explanation")
    goal = "Investigate open questions from an explanation: " + "; ".join(missing[:3])
    run_id = launch_run_with_goal(e.investigation_id, goal, max_items=12,
                                  max_rounds=1, trigger="explainer_gap")
    return {"run_id": run_id, "status": "running", "goal": goal}


@app.get("/api/explanations/{exp_id}/suggestions")
def explanation_suggestions(exp_id: int, db: Session = Depends(get_db)):
    e = db.query(Explanation).filter(Explanation.id == exp_id).first()
    if not e:
        raise HTTPException(404, "Explanation not found")
    return {"items": _question_suggestions(e, db=db)}


@app.get("/api/investigations/{inv_id}/suggestions")
def investigation_suggestions(inv_id: int, limit: int = 14, db: Session = Depends(get_db)):
    """Proactive, security-first explanation prompts for an investigation.

    Scoped to the investigation rather than to one explanation so the panel is
    useful before the first run, and built only from rows already stored for
    this investigation (CVEs, threat assessment, artefacts, past traces).
    """
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    return {"items": investigation_suggestions_fn(db, inv_id, limit=max(1, min(limit, 30)))}


@app.post("/api/explanations/{exp_id}/quiz")
def explanation_quiz(exp_id: int, db: Session = Depends(get_db)):
    e = db.query(Explanation).filter(Explanation.id == exp_id).first()
    if not e:
        raise HTTPException(404, "Explanation not found")
    if e.quiz:
        return {"id": e.id, "quiz": json.loads(e.quiz)}
    if e.status != "done":
        raise HTTPException(409, "Wait for the explanation to finish first")
    try:
        qz = _quiz_from_answer(e)
    except (ValueError, llm.LLMError) as ex:
        raise HTTPException(409, str(ex))
    e.quiz = json.dumps(qz)
    db.commit()
    return {"id": e.id, "quiz": qz}


@app.post("/api/explanations/{exp_id}/bookmark")
def explanation_bookmark(exp_id: int, req: BookmarkRequest, db: Session = Depends(get_db)):
    e = db.query(Explanation).filter(Explanation.id == exp_id).first()
    if not e:
        raise HTTPException(404, "Explanation not found")
    e.bookmarked = 1 if req.bookmarked else 0
    db.commit()
    return {"id": e.id, "bookmarked": bool(e.bookmarked)}


class WatchRequest(BaseModel):
    watched: bool


@app.post("/api/explanations/{exp_id}/watch")
def explanation_watch(exp_id: int, req: WatchRequest, db: Session = Depends(get_db)):
    """Watch a root explanation: the scheduler re-answers it periodically and
    marks drift when the new answer diverges."""
    e = db.query(Explanation).filter(Explanation.id == exp_id).first()
    if not e:
        raise HTTPException(404, "Explanation not found")
    if req.watched and e.parent_id is not None:
        raise HTTPException(409, "Only root explanations can be watched")
    e.watched = 1 if req.watched else 0
    db.commit()
    return {"id": e.id, "watched": bool(e.watched), "drift": json.loads(e.meta or "{}").get("drift")}


class FeedbackRequest(BaseModel):
    claim: str = ""
    up: bool
    url: str = ""


@app.post("/api/explanations/{exp_id}/feedback")
def explanation_feedback(exp_id: int, req: FeedbackRequest, db: Session = Depends(get_db)):
    """Thumbs up/down on a claim; feeds the learned source-affinity ranking."""
    e = db.query(Explanation).filter(Explanation.id == exp_id).first()
    if not e:
        raise HTTPException(404, "Explanation not found")
    meta = json.loads(e.meta or "{}")
    fb = meta.get("feedback") or []
    fb.append({"claim": req.claim[:300], "up": bool(req.up), "url": req.url[:500],
               "at": datetime.now(timezone.utc).isoformat()})
    meta["feedback"] = fb[-200:]
    e.meta = json.dumps(meta)
    db.commit()
    return {"id": e.id, "feedback_count": len(fb)}


@app.get("/api/investigations/{inv_id}/roadmap")
def investigation_roadmap(inv_id: int, db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    return {"items": _investigation_roadmap(db, inv_id)}


class GapResearchRequest(BaseModel):
    top_n: int = 3
    max_items: int = 12


@app.get("/api/investigations/{inv_id}/research-gaps")
def investigation_gaps(inv_id: int, db: Session = Depends(get_db)):
    """Open questions ranked by coverage, plus novel areas. No side effects."""
    from .explainer import investigation_gaps as gaps_fn
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    return gaps_fn(db, inv_id)


@app.post("/api/investigations/{inv_id}/research-gaps/run")
def investigation_gaps_run(inv_id: int, data: GapResearchRequest,
                           db: Session = Depends(get_db)):
    """Launch a paper-first collection run on the least-covered gaps."""
    from .explainer import launch_gap_research
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    return launch_gap_research(db, inv_id, top_n=data.top_n or 3,
                               max_items=data.max_items or 12)


@app.get("/api/investigations/{inv_id}/summary")
def investigation_summary(inv_id: int, db: Session = Depends(get_db)):
    """Executive summary with supporting artifacts and top findings."""
    from .explainer import investigation_summary as summary_fn
    try:
        return summary_fn(db, inv_id)
    except LookupError:
        raise HTTPException(404, "Investigation not found")


@app.post("/api/investigations/{inv_id}/summary/regenerate")
def regenerate_summary(inv_id: int, request: Request,
                       db: Session = Depends(get_db)):
    """Recompute the executive summary from the current review flags.

    The summary is always computed live, so this is the same payload as GET --
    but explicit, and on the ledger: re-flagging artifacts in Review and then
    regenerating visibly changes what the summary stands on, and when."""
    from .explainer import investigation_summary as summary_fn
    try:
        out = summary_fn(db, inv_id)
    except LookupError:
        raise HTTPException(404, "Investigation not found")
    flags = out.get("flags") or {}
    ledger_api.human_action(request, "regenerated_summary",
                            {"investigation": inv_id,
                             "synthesis": out.get("synthesis"),
                             "accepted": flags.get("accepted", 0),
                             "rejected": flags.get("rejected", 0)})
    out["regenerated"] = True
    return out


# ---- investigation dossier: the full audit write-up ---------------------
# The executive summary is the answer; this is the working. One payload
# serves the on-screen preview, the markdown download and the PDF, so the
# three can never disagree about what was investigated or how a score was
# reached.


@app.get("/api/investigations/{inv_id}/dossier")
def get_dossier(inv_id: int, db: Session = Depends(get_db)):
    from .dossier import investigation_dossier
    try:
        return investigation_dossier(db, inv_id)
    except LookupError:
        raise HTTPException(404, "Investigation not found")


@app.get("/api/investigations/{inv_id}/dossier/markdown")
def get_dossier_markdown(inv_id: int, db: Session = Depends(get_db)):
    from .dossier import dossier_markdown
    try:
        md = dossier_markdown(db, inv_id)
    except LookupError:
        raise HTTPException(404, "Investigation not found")
    return Response(
        content=md, media_type="text/markdown",
        headers={"Content-Disposition":
                 f'attachment; filename="investigation-{inv_id}-dossier.md"'})


@app.get("/api/investigations/{inv_id}/dossier/bundle")
def get_dossier_bundle(inv_id: int, db: Session = Depends(get_db)):
    from .dossier import dossier_bundle
    try:
        bundle = dossier_bundle(db, inv_id)
    except LookupError:
        raise HTTPException(404, "Investigation not found")
    return Response(
        content=bundle, media_type="application/zip",
        headers={"Content-Disposition":
                 f'attachment; filename="investigation-{inv_id}-dossier.zip"'})


@app.get("/api/investigations/{inv_id}/dossier/pdf")
def get_dossier_pdf(inv_id: int, engine: str = Query("pandoc"),
                    db: Session = Depends(get_db)):
    from .dossier import dossier_markdown, investigation_dossier
    from . import dossier_pdf
    try:
        # One read, one payload: the cover's numbers and the body are the same
        # snapshot, so the verdict block cannot disagree with the sections.
        d = investigation_dossier(db, inv_id)
        md = dossier_markdown(db, inv_id, dossier=d)
    except LookupError:
        raise HTTPException(404, "Investigation not found")
    inv = d["investigation"]
    col = d["collection"]
    # Default: the full dossier printed via pandoc + LaTeX (A4, TOC, mermaid
    # figures). `?engine=reportlab` keeps the shorter reportlab leaflet.
    if engine != "reportlab":
        try:
            pdf = dossier_pdf.build_pdf(
                md, title=f"Investigation dossier — {inv['title']}")
        except RuntimeError as exc:
            raise HTTPException(501, str(exc))
        return Response(
            content=pdf, media_type="application/pdf",
            headers={"Content-Disposition":
                     f'attachment; filename="investigation-{inv_id}-dossier.pdf"'})
    # One verdict block only when a single score exists: a dossier that
    # reports three scores on different scales must not print one of them
    # as the number, so it prints the scope table instead.
    latest = [r for r in d["scores"]["rows"] if r["is_latest"]]
    single = len(latest) == 1
    try:
        pdf = sec_engine.build_pdf(
            md, title=f"Investigation dossier — {inv['title']}",
            meta={
                "product": inv["title"],
                "overall": latest[0]["score"] if single else -1,
                "posture": latest[0]["detail"].get("posture", "") if single else "",
                "exposure_label": (latest[0]["inputs"].get("exposure_label")
                                   if single else ""),
                "report_name": "Investigation dossier",
                "highlights_title": "What this investigation covers",
                "highlights_label": "Scope",
                "perspectives": [
                    {"label": r["label"],
                     "headline": (f"{r['score']:g}/100 — {r['score_meaning']}"
                                  + (f" · {len(r['detail'].get('items') or [])}"
                                     f" items" if r["detail"].get("items") is not None
                                     else ""))}
                    for r in latest] + [
                    {"label": "Collected",
                     "headline": (f"{col['totals']['artifacts']} artifacts "
                                  f"({col['flags']['accepted']} accepted, "
                                  f"{col['flags']['rejected']} rejected), "
                                  f"{col['totals']['relationships']} relationships, "
                                  f"{len(d['runs'])} run(s), "
                                  f"{col['totals']['answered']} answered questions")},
                ],
                "date": d["generated"][:10],
            })
    except RuntimeError as exc:
        raise HTTPException(501, str(exc))
    return Response(
        content=pdf, media_type="application/pdf",
        headers={"Content-Disposition":
                 f'attachment; filename="investigation-{inv_id}-dossier.pdf"'})


class PrefsRequest(BaseModel):
    preferred_domains: Optional[str] = None
    auto_save_explanations: Optional[int] = None


@app.get("/api/investigations/{inv_id}/prefs")
def get_investigation_prefs(inv_id: int, db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    return {"preferred_domains": inv.preferred_domains or "",
            "auto_save_explanations": 1 if inv.auto_save_explanations is None
            else inv.auto_save_explanations}


@app.put("/api/investigations/{inv_id}/prefs")
def put_investigation_prefs(inv_id: int, req: PrefsRequest,
                            db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    if req.preferred_domains is not None:
        inv.preferred_domains = req.preferred_domains.strip()[:500]
    if req.auto_save_explanations is not None:
        inv.auto_save_explanations = 1 if req.auto_save_explanations else 0
    db.commit()
    return {"preferred_domains": inv.preferred_domains or "",
            "auto_save_explanations": inv.auto_save_explanations}


# ---------- AI security agent ----------

def _security_json(rec: SecurityAssessment) -> dict:
    def _load(raw, default):
        try:
            return json.loads(raw) if raw else default
        except Exception:
            return default

    ev = _load(getattr(rec, "evidence_json", None), {})
    tr = _load(getattr(rec, "a2a_trace_json", None), {})
    ctl = _load(getattr(rec, "controls_json", None), {})
    scoring = _load(getattr(rec, "scoring_json", None), {})
    if not isinstance(ev, dict):
        ev = {}
    if not isinstance(tr, dict):
        tr = {}
    if not isinstance(ctl, dict):
        ctl = {}
    if not isinstance(scoring, dict):
        scoring = {}
    perspectives = _load(getattr(rec, "perspectives_json", None), [])
    if not isinstance(perspectives, list):
        perspectives = []
    # Reported alongside the numbers, because a score read next to a different
    # pack is two results wearing one id. `matches` is False for rows that
    # predate versioned packs, which is a distinct thing from having drifted.
    pack = {
        "version": getattr(rec, "threat_pack_version", None),
        "fingerprint": getattr(rec, "threat_pack_fingerprint", None),
    }
    try:
        pack.update(threatpack.compare_fingerprint(pack["fingerprint"]))
    except Exception:
        pass
    try:
        _model = _load(getattr(rec, "model_json", None), {}) or {}
    except Exception:
        _model = {}
    if not isinstance(_model, dict):
        _model = {}
    try:
        _hypjs = _load(getattr(rec, "hypothesis_json", None), {}) or {}
    except Exception:
        _hypjs = {}
    if not isinstance(_hypjs, dict):
        _hypjs = {}
    if not _model.get("experiments") and _hypjs.get("experiments"):
        _model = dict(_model, experiments=_hypjs.get("experiments"))
    # The assurance pass is stored whole, so the API reports the verdict the
    # row was written under rather than re-deriving it against today's pack.
    _ass = _load(getattr(rec, "assurance_json", None), {})
    if not isinstance(_ass, dict):
        _ass = {}
    return {
        "id": rec.id,
        "investigation_id": rec.investigation_id,
        "run_id": rec.run_id,
        "product_name": rec.product_name,
        "model": _model.get("meta") or {},
        "adoption_dimensions": _model.get("dimensions") or [],
        "experiments": _model.get("experiments") or [],
        "mitigation": {**{k: (_model.get("mitigation") or {}).get(k)
                              for k in ("plan", "deferred", "uncovered_risks",
                                        "roadmap")
                              if (_model.get("mitigation") or {}).get(k)
                              is not None},
                         "w3": _model.get("w3") or {},
                         "approved_mitigation_plan":
                             _model.get("approved_mitigation_plan"),
                         "approved_by": _model.get("approved_by"),
                         "approved_at": _model.get("approved_at")}
        if ((_model.get("mitigation") or {}).get("plan")
                or _model.get("w3")) else {},
        "product_url": rec.product_url,
        "exposure": rec.exposure,
        "use_case": rec.use_case,
        "workflow_text": getattr(rec, "workflow_text", None),
        "doc_urls": _load(getattr(rec, "doc_urls_json", None), []),
        "focus": _load(getattr(rec, "focus_json", None), []),
        "require_approval": bool(getattr(rec, "require_approval", 0)),
        "overall_pct": rec.overall_pct,
        "inherent_pct": getattr(rec, "inherent_pct", None),
        "residual_pct": getattr(rec, "residual_pct", None),
        "delta": scoring.get("delta"),
        "active_controls": ctl.get("active_controls", []),
        "control_plan": ctl.get("control_plan", {}),
        "openshell": ctl.get("openshell", {}),
        "scoring": scoring,
        "perspectives": perspectives,
        "artifact_count": next(
            ((p.get("investigation") or {}).get("total_artifacts", 0)
             for p in perspectives if isinstance(p, dict) and p.get("investigation")),
            0,
        ),
        "posture": rec.posture,
        "markdown": rec.markdown,
        "diagrams": _load(rec.diagrams_json, {}),
        "threats": _load(rec.threats_json, []),
        "evidence": ev.get("evidence", []),
        "queries_run": ev.get("queries_run", []),
        "scope": ev.get("scope", ""),
        "known_exploits": ev.get("known_exploits", []),
        "exec_paragraph": ev.get("exec_paragraph", ""),
        "a2a_task_id": tr.get("task_id", ""),
        "a2a_trace": tr.get("trace", []),
        "threat_pack": pack,
        # --- assurance (app/assurance.py) ---
        # `assessed: False` is a real answer, not an error: it marks a scoring
        # path that does not run the gates. Reporting it explicitly is what
        # stops a consumer treating an unassessed row as a passing one.
        "assurance": _ass or {"assessed": False,
                              "reason": "This assessment predates the assurance "
                                        "layer, or its scoring path does not "
                                        "run the gates."},
        "assurance_decision": getattr(rec, "assurance_decision", None),
        "assurance_decided_by": getattr(rec, "assurance_decided_by", None),
        "assurance_decided_at": (rec.assurance_decided_at.isoformat()
                                 if getattr(rec, "assurance_decided_at", None)
                                 else None),
        "assurance_decision_note": getattr(rec, "assurance_decision_note", None),
        "assurance_decision_expires_at": (
            rec.assurance_decision_expires_at.isoformat()
            if getattr(rec, "assurance_decision_expires_at", None) else None),
        "evidence_confidence": getattr(rec, "evidence_confidence", None),
        "product_family": getattr(rec, "product_family", None),
        "created_at": rec.created_at.isoformat() if rec.created_at else None,
        **_assessment_path_fields(rec, scoring),
    }


def _assessment_path_fields(rec, scoring: dict) -> dict:
    """How this assessment was produced: standard catalog, model-internals
    target path, or model-misuse adversarial path. Stored rows predate the
    markers, so they are re-derived from the row's own product/use_case/focus
    when absent -- the profiler is deterministic, so derivation then and now
    agree. Re-derivation can only produce target or standard: a row without a
    stored marker cannot have come from the adversarial path, which is newer.
    """
    path = scoring.get("assessment_path")
    profile = None
    if path not in ("model", "model_adversarial", "model_hypothesis",
                    "model_engineering", "standard"):
        try:
            import json as _json
            focus = _json.loads(rec.focus_json) if rec.focus_json else []
        except Exception:
            focus = []
        profile = sec_engine.profile_model_subject(rec.product_name or "",
                                                   rec.use_case or "",
                                                   focus or [])
        path = "model" if profile["is_model_query"] else "standard"
    if profile is None:
        profile = sec_engine.profile_model_subject(rec.product_name or "",
                                                   rec.use_case or "", [])
    return {"assessment_path": path, "subject_profile": profile}


@app.get("/api/security/threat-pack")
def get_threat_pack():
    """Which pack this build scores with, and what is in it.

    Also the CVSS view of the catalog: the likelihood/impact matrix was already
    CVSS-shaped, so a threat's severity can be compared to an external scanner
    rather than only to its neighbours in this list.
    """
    return {"manifest": threatpack.pack_manifest(),
            "threats": threatpack.threat_rows()}


@app.get("/api/security/eval")
def get_security_eval():
    """Run the scoring regression suite on demand.

    Eight pinned scenarios and five structural invariants, in milliseconds with
    no model call. `ok` is false the moment an edit to the catalog or the
    scoring constants moves a number a user might have quoted.
    """
    return evalkit.run_eval()


@app.get("/api/security/controls")
def list_security_controls():
    """Control catalogue for the GUI checklist + what-if re-scorer."""
    return {"controls": sec_engine.control_catalog(),
            "exposure_tiers": [{"id": k, **{kk: vv for kk, vv in v.items()}}
                               for k, v in sec_engine.EXPOSURE_META.items()],
            "scoring": {
                "worst_weight": sec_engine._WORST_WEIGHT,
                "breadth_weight": sec_engine._BREADTH_WEIGHT,
                "top_n": sec_engine._TOP_N,
                "min_residual_floor": sec_engine._MIN_RESIDUAL_LIKELIHOOD,
                "min_applicability": sec_engine._MIN_APPLICABILITY,
                "severity_bands": sec_engine.SEVERITY_BANDS,
            }}


@app.get("/api/standards/score-matrix")
def standards_score_matrix(assessment_id: Optional[int] = None,
                           db: Session = Depends(get_db),
                           response: Response = None):
    """AI Standards & Regulations score matrix for the Security agent sub-tab.

    Without ``assessment_id`` every framework is returned sorted by coverage.
    With one, each framework also carries a deterministic relevance score for
    that assessment (token overlap of its threats, active controls and known
    exploits against the framework text) and rows sort by relevance first.

    Never cacheable: the payload depends on the assessment, and a cached
    error here once stranded the sub-tab on a stale failure.
    """
    if response is not None:
        response.headers["Cache-Control"] = "no-store"
    try:
        return standards_matrix.build_matrix(db, assessment_id)
    except standards_matrix.AssessmentNotFound:
        raise HTTPException(404, "Assessment not found")
    except standards_matrix.StandardsUnavailable as e:
        raise HTTPException(503, e.detail)


# ---------------------------------------------------------------- design set --
# The Mermaid design documents under design/, made selectable by the Design &
# Architecture tab. Read-only and content-static: no database, no LLM, and no
# caller-supplied path -- the id selects from a fixed index (app/design_docs.py).

@app.get("/api/design/docs")
def design_docs_index():
    """Every design document, in reading order, with kind and diagram count."""
    return design_docs.list_docs()


@app.get("/api/design/docs/{doc_id}")
def design_doc(doc_id: str):
    """One design document's Markdown, for the browser to render."""
    try:
        return design_docs.get_doc(doc_id)
    except design_docs.UnknownDoc:
        raise HTTPException(404, "Unknown design document")
    except FileNotFoundError as e:
        raise HTTPException(404, f"Design document not on disk: {e}")


@app.post("/api/security/assessments/{assessment_id}/rescore")
def rescore_security_assessment(assessment_id: int, data: SecurityRescoreRequest,
                                request: Request,
                                db: Session = Depends(get_db)):
    """What-if re-score: pure deterministic function, no LLM, no research.

    Takes the stored inherent threat rows and re-runs the scoring engine with a
    different control set (and optionally applicability) so the GUI can show the
    effect of enabling controls live. Optionally persists the new baseline.
    """
    rec = db.query(SecurityAssessment).filter(
        SecurityAssessment.id == assessment_id).first()
    if not rec:
        raise HTTPException(404, "Assessment not found")
    try:
        stored_scoring = json.loads(rec.scoring_json or "{}")
    except Exception:
        stored_scoring = {}
    if _assessment_path_fields(rec, stored_scoring).get("assessment_path") in (
            "model", "model_adversarial", "model_hypothesis",
            "model_engineering"):
        # The what-if re-scorer varies catalog controls against catalog
        # threats; a model assessment has neither (dimension weights or
        # hypothesis confidence instead). Re-running catalog math on it would
        # produce numbers from the wrong method wearing this id.
        _ap = _assessment_path_fields(rec, stored_scoring).get("assessment_path")
        _label = {"model_adversarial": "Adversarial",
                  "model_hypothesis": "Hypothesis",
                  "model_engineering": "Model-engineering"}.get(_ap, "Model")
        raise HTTPException(
            422, f"{_label}-path "
                 "assessment: re-score does not apply (no catalog threats or "
                 "controls to vary). Re-run the assessment to recompute its "
                 "dimension weights.")
    try:
        stored_threats = json.loads(rec.threats_json or "[]")
    except Exception:
        stored_threats = []
    if not stored_threats:
        raise HTTPException(422, "Assessment has no stored threat rows to re-score")

    # Rebuild the exposure-scaled inherent rows from the stored residual rows:
    # inherent likelihood is recoverable (residual likelihood = L*(1-cov) or the
    # floor), so we recompute the baseline exactly as build_assessment would.
    from .security import _THREAT_CATALOG, _scale_likelihood, EXPOSURE_META
    exposure = rec.exposure if rec.exposure in EXPOSURE_META else "confidential_data"
    weight = float(EXPOSURE_META[exposure]["weight"])
    inherent = [{"id": t[0], "title": t[1], "stride": t[2], "owasp": t[3],
                 "likelihood": float(_scale_likelihood(t[4], weight)),
                 "impact": float(t[5]), "description": t[6], "mitigations": t[7]}
                for t in _THREAT_CATALOG if t[0] not in sec_engine.DEPRECATED_THREATS]

    ctl = {}
    try:
        ctl = json.loads(rec.controls_json or "{}")
    except Exception:
        ctl = {}
    active = data.active_controls
    if active is None:
        active = ctl.get("active_controls", [])

    result = sec_engine.score_assessment(
        exposure, inherent,
        active_controls=active,
        applicability=data.applicability,
    )
    prev_residual = getattr(rec, "residual_pct", None)
    new_id = None
    if data.persist:
        # History is immutable: persist writes a NEW row pointing back, never
        # edits this one. The dossier then shows both (current + change log)
        # instead of one row quietly becoming different numbers.
        prior = _security_json(rec)
        from . import threatpack as _tp
        new_rec = SecurityAssessment(
            investigation_id=rec.investigation_id,
            run_id=rec.run_id,
            requested_by=getattr(rec, "requested_by", None),
            product_name=rec.product_name,
            product_url=rec.product_url,
            exposure=rec.exposure,
            use_case=rec.use_case,
            workflow_text=rec.workflow_text,
            doc_urls_json=rec.doc_urls_json,
            focus_json=rec.focus_json,
            require_approval=rec.require_approval,
            overall_pct=result["residual_pct"],
            inherent_pct=result["inherent_pct"],
            residual_pct=result["residual_pct"],
            controls_json=json.dumps({
                "active_controls": result["active_controls"],
                "control_plan": ctl.get("control_plan", {}),
                "openshell": ctl.get("openshell", {}),
            }),
            scoring_json=json.dumps(result),
            perspectives_json=json.dumps(sec_engine._perspective_views({
                "threats": result["threats"],
                "scoring": result,
                "control_plan": ctl.get("control_plan", {}),
                "evidence": prior.get("evidence", []),
                "known_exploits": prior.get("known_exploits", []),
                "artifacts": sec_engine._load_investigation_artifacts(
                    db, getattr(rec, "investigation_id", None)),
                "exposure": exposure,
                "product_name": rec.product_name,
                "inherent_pct": result["inherent_pct"],
                "residual_pct": result["residual_pct"],
                "posture": result["posture"],
            })),
            posture=result["posture"],
            markdown=rec.markdown,
            diagrams_json=rec.diagrams_json,
            threats_json=json.dumps(result["threats"]),
            evidence_json=rec.evidence_json,
            a2a_trace_json=rec.a2a_trace_json,
            threat_pack_version=_tp.PACK_VERSION,
            threat_pack_fingerprint=_tp.pack_fingerprint(),
            supersedes_id=rec.id,
        )
        db.add(new_rec)
        db.commit()
        db.refresh(new_rec)
        new_id = new_rec.id
        ledger_api.human_action(request, "rescored_assessment", {
            "previous_assessment_id": rec.id, "assessment_id": new_id,
            "previous_residual_pct": prev_residual,
            "residual_pct": result["residual_pct"],
            "previous_pack_version": rec.threat_pack_version,
            "pack_version": _tp.PACK_VERSION,
            "pack_fingerprint": _tp.pack_fingerprint(),
        })
    return {
        "assessment_id": new_id if new_id is not None else assessment_id,
        "inherent_pct": result["inherent_pct"],
        "residual_pct": result["residual_pct"],
        "previous_residual_pct": prev_residual,
        "delta": result["delta"],
        "delta_vs_previous": (round(result["residual_pct"] - prev_residual, 1)
                              if prev_residual is not None else None),
        "posture": result["posture"],
        "active_controls": result["active_controls"],
        "distribution": result["distribution"],
        "breakdown": result["breakdown"],
        "threats": result["threats"],
        "persisted": data.persist,
    }


@app.post("/api/investigations/{inv_id}/security/assess")
def start_security_assessment(inv_id: int, data: SecurityAssessRequest,
                              request: Request, db: Session = Depends(get_db)):
    """Launch the AI Security Engineering & Evaluation Agent as a background
    run (polled via /api/runs/{run_id}). The run executes the agent-to-agent
    workflow with agentic search over this investigation's knowledge graph."""
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    # Reject an unknown mode rather than treating it as auto. A typo'd
    # "adversarial" would otherwise silently run the internals question and
    # return a report that looks like an answer to a question nobody asked.
    if data.assessment_mode not in ("", "target", "adversarial", "hypothesis",
                                      "model_engineering"):
        raise HTTPException(422, "assessment_mode must be one of: target, "
                                 "adversarial, hypothesis, model_engineering, "
                                 "or empty for auto")
    model_meta: dict = {}
    if (data.assessment_mode or "") == "model_engineering":
        from . import model_eval as _me
        model_meta = _me.normalize_model_meta({
            "model_name": data.model_name, "model_family": data.model_family,
            "modality": data.modality, "weights_source": data.weights_source,
            "training_data_posture": data.training_data_posture,
            "deployment_pattern": data.deployment_pattern,
            "focus_terms": data.model_focus_terms, "workflows": data.workflows})
        if not model_meta["model_name"]:
            raise HTTPException(422, "model_engineering requires model_name")
    if security_agent.security_run_busy(
            db, inv_id,
            assessment_mode=data.assessment_mode or "",
            product_name=data.product_name or "",
            use_case=data.use_case or "",
            focus=data.focus or []):
        raise HTTPException(429, "A security assessment of this kind is already "
                                 "running here")
    # Resolve the mode before queueing, so the plan records what the run will
    # actually do and the UI can render the right pipeline from the response
    # instead of guessing from the requested string.
    from . import security as sec_engine
    _prof = sec_engine.profile_model_subject(data.product_name or "",
                                             data.use_case or "",
                                             data.focus or [])
    _mode = sec_engine.resolve_model_mode(data.product_name or "",
                                          data.use_case or "", data.focus or [],
                                          data.assessment_mode or "",
                                          subject_profile=_prof)
    _path = {"target": "model", "adversarial": "model_adversarial",
             "hypothesis": "model_hypothesis",
             "model_engineering": "model_engineering"}.get(_mode, "standard")
    if _mode == "hypothesis" and not data.allow_partial:
        # A hypothesis over missing priors synthesizes gap claims instead of
        # verdicts. Allowed on explicit request (the gap claims are the
        # point then), refused by default when the caller asked for strictness.
        have = set()
        for r in db.query(SecurityAssessment).filter(
                SecurityAssessment.investigation_id == inv_id).all():
            try:
                have.add((json.loads(r.scoring_json or "{}") or {})
                         .get("assessment_path"))
            except Exception:
                pass
        missing = [p for p in ("model", "model_adversarial") if p not in have]
        if missing:
            raise HTTPException(
                409, "Hypothesis needs terminal target + adversarial rows; "
                f"missing: {', '.join(missing)}. Re-run with "
                "allow_partial=true to synthesize gap claims instead.")
    ledger_api.human_action(request, "started_security_assessment",
                            {"investigation": inv.id, "title": inv.title,
                             "product": data.product_name or "Target product",
                             "assessment_mode": _mode,
                             "require_approval": bool(data.require_approval)})
    run_id = security_agent.launch_security_assessment(inv.id, {
        "product_name": (model_meta.get("model_name")
                         if _mode == "model_engineering" else "") or
        data.product_name or "Target product",
        "product_url": data.product_url or "",
        "exposure": data.exposure or "confidential_data",
        "use_case": data.use_case or "",
        "workflow_text": data.workflow_text or "",
        "doc_urls": data.doc_urls or [],
        "focus": data.focus or [],
        "declared_controls": data.declared_controls or [],
        "require_approval": bool(data.require_approval),
        "assessment_mode": _mode,
        "model_meta": model_meta,
        "situation": data.situation,
        "initiative_id": data.initiative_id,
        # Assurance inputs. Empty stays empty on purpose: an absent
        # architecture checklist scores as unknown and forces the gate.
        "architecture_checklist": data.architecture_checklist,
        "exposure_inventory": data.exposure_inventory,
        "full_metadata_context": bool(data.full_metadata_context),
    }, requested_by=ledger_api.request_actor(request))
    return {"status": "started", "run_id": run_id,
            "assessment_mode": _mode, "assessment_path": _path}


@app.post("/api/security/runs/{run_id}/approval")
def approve_security_run(run_id: int, data: SecurityApprovalRequest,
                         request: Request, db: Session = Depends(get_db)):
    """Approve or reject a run parked at the control-plan gate.

    On approval the operator may override the control set and applicability the
    control-analyst proposed; the run then resumes from the next stage.

    The approver must be a different person from whoever requested the run. A
    gate the requester can pass alone is not a control, so the identity is
    compared before anything is changed, and the decision -- approve, reject,
    or edit-then-approve -- is recorded on the ledger naming both people.
    """
    run = db.query(AgentRun).filter(AgentRun.id == run_id).first()
    if not run:
        raise HTTPException(404, "Run not found")
    if run.status != "awaiting_approval":
        raise HTTPException(409, "Run is not waiting for approval")
    try:
        stats = json.loads(run.stats or "{}")
    except Exception:
        stats = {}
    plan = stats.get("control_plan", {}) or {}
    decision = (data.decision or "approve").lower()

    # Strict: an approval has to be attributable, so a request with no name and
    # no session is refused rather than signed with the shared default.
    approver = ledger_api.request_actor_or_empty(request)
    requester = approvals.requester_of(run.stats)
    try:
        approver = approvals.check_approver(approver=approver,
                                            requester=requester, run_id=run_id)
    except approvals.ApprovalError as exc:
        # A refused attempt is itself worth a record: somebody tried to approve
        # their own run, which is the thing the gate exists to prevent.
        ledger_api.human_action(request, "approval_refused", {
            "run_id": run_id, "reason": exc.reason, **exc.detail,
            "decision": decision})
        raise HTTPException(exc.status, exc.reason)

    if decision == "reject":
        run.status = "error"
        run.error = "Control plan rejected by operator"
        run.finished_at = datetime.now(timezone.utc)
        db.commit()
        security_agent._event(
            db, run.id, "gate", "Control plan rejected by operator — assessment aborted.",
            {"control_plan": plan})
        ledger_api.human_action(request, "rejected_control_plan", approvals.decision_record(
            run_id=run_id, decision="reject", approver=approver,
            requester=requester, plan=plan, note=data.note))
        return {"status": "rejected", "run_id": run_id, "approver": approver}

    edited = (data.active_controls is not None) or (data.applicability is not None)
    if data.active_controls is not None:
        plan["declared_controls"] = [c for c in data.active_controls]
    if data.applicability is not None:
        plan["applicability"] = data.applicability
    try:
        # Persist the operator-approved plan back onto the gate state; the
        # resume path reads run.stats to rebuild its params.
        stats["control_plan"] = plan
        run.stats = json.dumps(stats)
        run.plan = json.dumps({
            **(json.loads(run.plan or "{}")),
            "controls": plan.get("declared_controls", []),
        })
        db.commit()
    except Exception:
        db.rollback()
    resumed = security_agent.resume_security_assessment(
        run_id, approved_by=approver, note=data.note)
    if not resumed:
        raise HTTPException(409, "Could not resume run")
    ledger_api.human_action(request, "approved_control_plan", approvals.decision_record(
        run_id=run_id, decision="approve", approver=approver, requester=requester,
        plan=plan, edited=edited, note=data.note))
    return {"status": "resumed", "run_id": run_id, "approver": approver,
            "requester": requester, "edited": edited,
            "approved_controls": plan.get("declared_controls", [])}


@app.get("/api/investigations/{inv_id}/security/assessments")
def list_security_assessments(inv_id: int, db: Session = Depends(get_db)):
    recs = (db.query(SecurityAssessment)
            .filter(SecurityAssessment.investigation_id == inv_id)
            .order_by(SecurityAssessment.id.desc()).limit(50).all())
    run_ids = [r.run_id for r in recs if getattr(r, "run_id", None)]
    stats_by_run: dict[int, dict] = {}
    if run_ids:
        for run in db.query(AgentRun).filter(AgentRun.id.in_(run_ids)).all():
            try:
                stats_by_run[run.id] = json.loads(run.stats or "{}") or {}
            except Exception:
                stats_by_run[run.id] = {}
    items = []
    for r in recs:
        d = _security_json(r)
        d.pop("markdown", None)
        d["threat_count"] = len(d.get("threats", []))
        d["exploit_count"] = len(d.get("known_exploits", []))
        # The GUI warns when the run behind an assessment left no measurable
        # stats: a score with no cost, duration or pack provenance behind it.
        st = stats_by_run.get(getattr(r, "run_id", -1) or -1, {})
        d["stats_complete"] = bool(
            isinstance(st, dict) and st.get("assessment_id") is not None
            and st.get("residual_pct") is not None)
        # ...and when the row was scored on older catalogs than today's.
        # Old numbers stand; the badge says so instead of re-arithmeticking.
        try:
            _pack = d.get("threat_pack") or {}
            d["pack_stale"] = dossier.pack_staleness(
                d.get("scoring") or {}, _pack.get("version"),
                _pack.get("fingerprint"))
        except Exception:
            d["pack_stale"] = False
        items.append(d)
    return {"items": items}


@app.get("/api/packs/changelog")
def get_pack_changelog():
    """The catalog version history as data (newest first)."""
    from . import threatpack as _tp
    return {"entries": _tp.pack_changelog()}


@app.get("/api/security/assessments/{assessment_id}/compare/{other_id}")
def compare_assessments(assessment_id: int, other_id: int,
                        db: Session = Depends(get_db)):
    """Side-by-side numbers for two assessments, same method only.

    Product rows compare inherent/residual; model rows compare W1/W2 (and
    W3 when both ran it). Different score meanings are refused with 422:
    a confidence next to a residual is two answers wearing one table, the
    same averaging the system refuses everywhere else. A pack change
    between the rows is reported, not hidden — that is the pack-diff
    use case (old row vs re-scored row).
    """
    recs = {r.id: r for r in db.query(SecurityAssessment).filter(
        SecurityAssessment.id.in_([assessment_id, other_id])).all()}
    if len(recs) < 2:
        raise HTTPException(404, "Both assessments must exist")
    a, b = (recs[assessment_id], recs[other_id])
    if a.investigation_id != b.investigation_id:
        raise HTTPException(422, "Assessments are from different "
                                 "investigations")
    def _scoring(r):
        try:
            return json.loads(r.scoring_json or "{}") or {}
        except Exception:
            return {}
    sa, sb = _scoring(a), _scoring(b)
    pa = sa.get("assessment_path") or "standard"
    pb = sb.get("assessment_path") or "standard"
    if pa != pb:
        raise HTTPException(422, f"Incomparable methods: {pa} vs {pb}. "
                                 "Only same-path assessments compare.")
    def _num(x):
        try:
            return float(x)
        except (TypeError, ValueError):
            return None
    out = {
        "a": {"id": a.id, "path": pa,
              "pack_version": a.threat_pack_version,
              "pack_fingerprint": a.threat_pack_fingerprint,
              "created_at": a.created_at.isoformat() if a.created_at else None,
              "supersedes_id": getattr(a, "supersedes_id", None)},
        "b": {"id": b.id, "path": pb,
              "pack_version": b.threat_pack_version,
              "pack_fingerprint": b.threat_pack_fingerprint,
              "created_at": b.created_at.isoformat() if b.created_at else None,
              "supersedes_id": getattr(b, "supersedes_id", None)},
        "same_pack": (a.threat_pack_version == b.threat_pack_version
                      and (a.threat_pack_fingerprint or None) ==
                      (b.threat_pack_fingerprint or None)),
    }
    if pa == "model_engineering":
        for key in ("w1", "w2"):
            va = (sa.get(key) or {}).get("overall_pct")
            vb = (sb.get(key) or {}).get("overall_pct")
            out[key] = {"a": va, "b": vb,
                        "delta": (round(vb - va, 1)
                                  if va is not None and vb is not None
                                  else None)}
        w3a, w3b = sa.get("w3"), sb.get("w3")
        if w3a is not None or w3b is not None:
            out["w3_present"] = {"a": w3a is not None, "b": w3b is not None}
    elif pa == "model_hypothesis":
        out["confidence"] = {"a": sa.get("overall_pct"),
                             "b": sb.get("overall_pct")}
    else:
        for key in ("inherent_pct", "residual_pct"):
            va, vb = _num(getattr(a, key, None)), _num(getattr(b, key, None))
            out[key] = {"a": va, "b": vb,
                        "delta": (round(vb - va, 1)
                                  if va is not None and vb is not None
                                  else None)}
    return out


@app.get("/api/security/assessments/{assessment_id}")
def get_security_assessment(assessment_id: int, db: Session = Depends(get_db)):
    rec = db.query(SecurityAssessment).filter(
        SecurityAssessment.id == assessment_id).first()
    if not rec:
        raise HTTPException(404, "Assessment not found")
    return _security_json(rec)


# ---------------------------------------------- assurance endpoints -------
# The assurance surface is deliberately separate from the score endpoints: a
# caller who wants the number can still have it, but a caller who wants to sign
# off on it is handed the confidence, gate status and blast radius too.

class AssuranceDecisionRequest(BaseModel):
    """A leadership acceptance, rejection or time-bounded exception."""
    # accept | guardrails | reject | exception, or any alias in
    # leadership.DECISION_ALIASES. The long stored constants are what the
    # assurance pass derives; the short spellings are what a UI offers, and
    # accepting only the long form made the documented `reject` a 422.
    decision: str
    actor: str = ""
    rationale: str = ""
    expires_days: Optional[int] = None
    override: bool = False


class EvidenceReviewRequest(BaseModel):
    """Accept or reject a collected artifact as primary evidence.

    Only accepted primary evidence moves the verified residual. Pending rows
    stay in the queue and contribute nothing, which is why this endpoint
    reports what the decision would change rather than implying it already did.
    """
    review: str = "accepted"  # accepted | rejected
    reviewer: str = ""
    note: str = ""


def _assessment_or_404(assessment_id: int, db: Session) -> SecurityAssessment:
    rec = db.query(SecurityAssessment).filter(
        SecurityAssessment.id == assessment_id).first()
    if not rec:
        raise HTTPException(404, "Assessment not found")
    return rec


def _assurance_or_422(rec: SecurityAssessment) -> dict:
    from . import assurance as _a
    try:
        ens = json.loads(rec.assurance_json or "{}") or {}
    except Exception:
        ens = {}
    if ens.get("assessed") is not True:
        raise HTTPException(422, "This assessment was not scored through the "
                                 "assurance layer; there are no gates to report")
    return ens


@app.get("/api/security/assessments/{assessment_id}/assurance")
def get_assurance(assessment_id: int, db: Session = Depends(get_db)):
    """The current assessment: declared vs verified residual and its gates.

    Returns both numbers plus the evidence confidence that sits between them.
    A caller wanting only `verified.residual_pct` can have it -- but the
    confidence, gate status and blast radius travel with it in the same object.
    """
    from . import leadership as _ld
    rec = _assessment_or_404(assessment_id, db)
    ens = _assurance_or_422(rec)
    return {
        "assessment_id": rec.id,
        "investigation_id": rec.investigation_id,
        "product_name": rec.product_name,
        "product_family": getattr(rec, "product_family", None),
        "exposure": rec.exposure,
        "assurance": ens,
        # The decision as leadership sees it: derived, overridden, or expired.
        "decision_state": _ld._decision_state(_ld._assessment_dict(rec)),
        "recorded_decision": getattr(rec, "assurance_decision", None),
        "decision_derived": (ens.get("decision") or {}).get("decision"),
        "decision_expires_at": (
            rec.assurance_decision_expires_at.isoformat()
            if getattr(rec, "assurance_decision_expires_at", None) else None),
        "evidence_confidence": getattr(rec, "evidence_confidence", None),
        "threat_pack": {"version": getattr(rec, "threat_pack_version", None),
                        "fingerprint": getattr(rec, "threat_pack_fingerprint", None)},
    }


@app.get("/api/security/assessments/{assessment_id}/vendor-questionnaire")
def get_vendor_questionnaire(assessment_id: int,
                             db: Session = Depends(get_db)):
    """Questions to send the vendor, with the threat each one unblocks.

    Built from the open architecture gate and the missing evidence classes, so
    it cannot ask about something already answered and cannot omit the
    question holding a threat at its inherent score.
    """
    from . import assurance as _a
    rec = _assessment_or_404(assessment_id, db)
    ens = _assurance_or_422(rec)
    q = _a.vendor_questionnaire(ens.get("architecture_gate"),
                                ens.get("forensics"),
                                ens.get("chains"))
    return {"assessment_id": rec.id, "product_name": rec.product_name, **q}


@app.get("/api/security/assessments/{assessment_id}/review-queue")
def get_assurance_review_queue(assessment_id: int,
                               db: Session = Depends(get_db)):
    """Evidence and architecture items awaiting a human, with the threat each
    one would move. Ordered by the residual it would release."""
    from . import assurance as _a
    rec = _assessment_or_404(assessment_id, db)
    _assurance_or_422(rec)
    arts = db.query(Artifact).filter(
        Artifact.investigation_id == rec.investigation_id,
        Artifact.review == "pending").all()
    return {"assessment_id": rec.id,
            **_a.review_queue([_artifact_json(a) for a in arts])}


@app.get("/api/security/assessments/{assessment_id}/assurance/register")
def get_canonical_register(assessment_id: int, db: Session = Depends(get_db)):
    """The de-duplicated control register this assessment contributes to.

    Reported as keys, not rows: the register itself is derived on read from
    every assessment sharing a product family, so what this endpoint proves is
    that two runs of the same family address the same entries instead of
    appending a slightly different threat list.
    """
    from . import assurance as _a
    rec = _assessment_or_404(assessment_id, db)
    ens = _assurance_or_422(rec)
    family = getattr(rec, "product_family", None) or rec.product_name
    keys = []
    for layer in ("own", "model", "platform", "third_party"):
        for t in (ens.get("threats") or []):
            if not isinstance(t, dict):
                continue
            ref = (t.get("control_id") or t.get("id") or "?")
            keys.append(_a.canonical_register_key(family, layer, ref))
    return {
        "assessment_id": rec.id,
        "product_family": family,
        "canonical_keys": sorted(set(keys)),
        "count": len(set(keys)),
        "note": ("Two runs of one product family resolve to the same keys, so "
                 "the second updates coverage instead of duplicating the list."),
    }


@app.post("/api/security/assessments/{assessment_id}/decision")
def record_assurance_decision(assessment_id: int, data: AssuranceDecisionRequest,
                              request: Request, db: Session = Depends(get_db)):
    """Record a leadership decision against an assessment.

    Written to the row and to the hash-chained ledger with identity and
    rationale. An exception is always time-bounded: it expires and the row
    returns to open rather than becoming a permanent override.
    """
    from . import leadership as _ld
    # request_actor_or_empty, not request_actor: a decision signed with the
    # shared default actor is not signed by anyone, so a caller with no name
    # and no session is refused rather than quietly given "user".
    actor = (data.actor or "").strip() or ledger_api.request_actor_or_empty(request)
    try:
        return _ld.record_decision(
            db, assessment_id, data.decision, actor=actor,
            rationale=data.rationale, expires_days=data.expires_days,
            override=data.override)
    except LookupError:
        raise HTTPException(404, "Assessment not found")
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@app.post("/api/security/assessments/{assessment_id}/evidence/{artifact_id}/review")
def review_assurance_evidence(assessment_id: int, artifact_id: int,
                              data: EvidenceReviewRequest, request: Request,
                              db: Session = Depends(get_db)):
    """Accept or reject one artifact as primary evidence for an assessment.

    The response states what the review would change and how much: an accepted
    artifact does not retroactively edit the stored residual, it changes the
    next one. Saying so is what stops a reviewer believing the score on screen
    already reflects their click.
    """
    from . import assurance as _a
    from . import leadership as _ld
    rec = _assessment_or_404(assessment_id, db)
    art = db.query(Artifact).filter(Artifact.id == artifact_id).first()
    if not art:
        raise HTTPException(404, "Artifact not found")
    if art.assessment_id and int(art.assessment_id) != int(rec.id):
        raise HTTPException(409, "Artifact belongs to a different assessment")
    review = (data.review or "").lower()
    if review not in ("accepted", "rejected"):
        raise HTTPException(422, "review must be accepted or rejected")
    reviewer = (data.reviewer or "").strip() or ledger_api.request_actor(request)
    art.review = review
    if data.note:
        art.relevance_reason = (art.relevance_reason or "")
        art.description = data.note
    db.commit()
    ens = _assurance_or_422(rec)
    # What the review would change, computed rather than asserted: an accepted
    # artifact only moves the verified layer if it is primary and relevant
    # enough, so a click on a marketing page changes nothing and saying so is
    # the useful part of the response.
    impact = _evidence_review_impact(art, ens)
    ledger_api.human_action(request, "reviewed_evidence", {
        "assessment": rec.id, "artifact": artifact_id, "review": review,
        "reviewer": reviewer})
    db.refresh(rec)
    return {
        "assessment_id": rec.id,
        "artifact_id": artifact_id,
        "review": review,
        "reviewer": reviewer,
        "evidence_confidence": getattr(rec, "evidence_confidence", None),
        "impact": impact,
        "note": ("The stored residual is unchanged: the stored assurance pass "
                 "is the record of what was true when it was scored. The next "
                 "assessment reflects this review."),
    }


def _evidence_review_impact(art: Artifact, ens: dict) -> dict:
    """How much residual credit this artifact would release if accepted."""
    from . import assurance as _a
    art_type = (art.artifact_type or art.origin or "").lower()
    primary = art_type in _a._PRIMARY_TYPES
    relevance = art.relevance if art.relevance is not None else 0.0
    drifted = bool(art.drift)
    qualifies = bool(primary and relevance >= _a.MIN_ACCEPTED_RELEVANCE
                     and not drifted)
    threats = []
    for t in (ens.get("threats") or []):
        if isinstance(t, dict) and (t.get("coverage_confidence_pct") or 0) < 100:
            threats.append({"threat_id": t.get("id"), "title": t.get("title"),
                            "coverage_confidence_pct": t.get("coverage_confidence_pct")})
    return {
        "counts_as_primary": primary,
        "relevance": relevance,
        "drifted": drifted,
        "qualifies_for_verified_credit": qualifies,
        "would_raise_coverage_for": threats[:5],
        "note": ("Pending artifacts never reduce the verified residual. Only "
                 "accepted primary evidence above the relevance floor, with "
                 "no drift flag, releases credit."),
    }


@app.get("/api/security/assessments/{assessment_id}/ledger/integrity")
def get_assurance_ledger_integrity(assessment_id: int,
                                   db: Session = Depends(get_db)):
    """Chain integrity plus event-class completeness for one assessment's run.

    An intact chain proves events were not edited. It does not prove the
    events that should have happened did -- that is what the completeness and
    absence checks report alongside it.
    """
    from . import assurance_ledger as _al
    rec = _assessment_or_404(assessment_id, db)
    run_id = f"akm-run-{rec.run_id}" if rec.run_id else f"akm-assessment-{rec.id}"
    return _al.integrity_report(run_id, db=db)


@app.get("/api/security/assessments/{assessment_id}/evidence-pack")
def get_assurance_evidence_pack(assessment_id: int,
                                db: Session = Depends(get_db)):
    """Audit-ready evidence pack: hash-chained events, exports and assertions.

    Deliberately a pack and not a document -- the reader can verify it without
    trusting this service, which is the point of an assurance artifact.
    """
    from . import assurance_ledger as _al
    rec = _assessment_or_404(assessment_id, db)
    run_id = f"akm-run-{rec.run_id}" if rec.run_id else f"akm-assessment-{rec.id}"
    return _al.evidence_pack(run_id, db=db)


@app.get("/api/assurance/ledger/integrity-monitor")
def assurance_integrity_monitor(limit: int = 40, db: Session = Depends(get_db)):
    """§8.4 continuous integrity monitoring: which recent runs still verify."""
    from . import assurance_ledger as _al
    return _al.monitor_integrity(db=db, limit=limit)


@app.get("/api/assurance/ledger/siem-export")
def assurance_siem_export(limit: int = 40, db: Session = Depends(get_db)):
    """§8.4 streaming export: recent ledger events as minimised JSON lines.

    One event per line, payload minimised (hashes, not prompts), ready to be
    piped into a SIEM / SOAR ingestion point.
    """
    from fastapi.responses import PlainTextResponse
    from . import assurance_ledger as _al

    lines: list[str] = []
    _al.export_siem_events(db=db, limit=limit, sink=lines.append)
    return PlainTextResponse("\n".join(lines), media_type="application/x-ndjson")


@app.get("/api/assurance/ledger/re-score-triggers")
def assurance_re_score_triggers(investigation_id: Optional[int] = None,
                                db: Session = Depends(get_db)):
    """Assessments whose evidence or architecture basis changed after scoring.

    Phase 3: the ledger watches for the event that makes a residual stale --
    an artifact accepted after the assessment, or an architecture explainer
    run that finished after it -- and names the row that should be re-scored.
    """
    from . import assurance_ledger as _al
    return _al.re_score_triggers(db=db, investigation_id=investigation_id)


@app.post("/api/assurance/assessments/{assessment_id}/re-score")
def assurance_re_score(assessment_id: int,
                       request: Request,
                       db: Session = Depends(get_db)):
    """Re-queue an assessment from its stored row, so the next run reflects
    the evidence or architecture that changed since it was scored.

    The signed row is never edited: a re-score is a new run that supersedes
    it, which is what keeps the history immutable.
    """
    import json as _json

    from . import assurance_ledger as _al, security_agent as _sa
    rec = _assessment_or_404(assessment_id, db)
    triggers = _al.re_score_triggers(db=db)["triggers"]
    reason = next((t["reason"] for t in triggers
                   if t["assessment_id"] == rec.id), None)
    if reason is None:
        raise HTTPException(409, "No evidence or architecture change recorded "
                                 "since this assessment was scored")
    scoring = _json.loads(rec.scoring_json or "{}") or {}
    controls = _json.loads(rec.controls_json or "{}") or {}
    params = {
        "product_name": rec.product_name or "",
        "product_url": rec.product_url or "",
        "exposure": rec.exposure or "confidential_data",
        "use_case": rec.use_case or "",
        "workflow_text": rec.workflow_text or "",
        "focus": _json.loads(rec.focus_json or "[]"),
        "doc_urls": _json.loads(rec.doc_urls_json or "[]"),
        "declared_controls": controls.get("active_controls", []),
        "assessment_mode": (scoring.get("assessment_path")
                            if scoring.get("assessment_path") != "standard"
                            else ""),
        "require_approval": bool(getattr(rec, "require_approval", 0)),
    }
    actor = request.headers.get("X-AKM-Actor") or "system"
    new_run = _sa.launch_security_assessment(rec.investigation_id, params,
                                             requested_by=actor)
    return {"queued_run_id": new_run, "supersedes_assessment_id": rec.id,
            "reason": reason}


# ------------------------------------- leadership dashboard endpoints -----

def _csv_states(raw: Optional[str]) -> Optional[list[str]]:
    """Parse a comma-separated query list, keeping ``None`` meaning 'default'.

    An empty string is a caller asking for an empty set rather than the
    default, so it is preserved as an empty list instead of collapsing to None.
    """
    if raw is None:
        return None
    return [s.strip() for s in str(raw).split(",") if s.strip()]


@app.get("/api/leadership/board")
def leadership_board(investigation_id: Optional[int] = None,
                     window_days: int = 90, persona: str = "executive",
                     initiative_id: Optional[int] = None,
                     layer: Optional[str] = None,
                     exposure: Optional[str] = None,
                     tier: Optional[str] = None,
                     states: Optional[str] = None,
                     sort: str = "residual",
                     limit: int = 25, offset: int = 0,
                     sla_days: int = 14,
                     include_acknowledged: bool = False,
                     db: Session = Depends(get_db)):
    """The leadership decision view: risk position, decision queue, assurance
    health, exposure lens, system integrity, alerts, exceptions and the change
    log in one payload, layered by persona lens.

    ``states`` is a comma-separated list, so the queue can be reviewed after the
    fact (``accepted``) instead of only ever showing what is still open.
    """
    from . import leadership as _ld
    try:
        return _ld.board(db, investigation_id, window_days=window_days,
                         persona=persona, initiative_id=initiative_id,
                         layer=layer, exposure=exposure, tier=tier,
                         queue_states=_csv_states(states), sort=sort,
                         limit=limit, offset=offset, sla_days=sla_days,
                         include_acknowledged=include_acknowledged)
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@app.get("/api/leadership/board.md")
def leadership_board_markdown(investigation_id: Optional[int] = None,
                              window_days: int = 90, persona: str = "executive",
                              initiative_id: Optional[int] = None,
                              layer: Optional[str] = None,
                              exposure: Optional[str] = None,
                              db: Session = Depends(get_db)):
    """The board as one Markdown snapshot, for a regulator or an archive."""
    from fastapi.responses import PlainTextResponse
    from . import leadership as _ld
    try:
        md = _ld.export_markdown(db, investigation_id, window_days=window_days,
                                 persona=persona, initiative_id=initiative_id,
                                 layer=layer, exposure=exposure)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    return PlainTextResponse(md, media_type="text/markdown; charset=utf-8")


def _board_posture(rp: dict) -> str:
    """One line for the PDF cover, from figures the board already reports."""
    conf = (rp.get("evidence_confidence") or {}).get("mean_pct")
    tiers = len(rp.get("tiers") or [])
    assessed = rp.get("assessments") or 0
    share = (rp.get("verified_vs_declared") or {}).get("verified_share_pct")
    parts = [f"{assessed} assessment{'s' if assessed != 1 else ''} across "
             f"{tiers} tier{'s' if tiers != 1 else ''}"]
    if conf is not None:
        parts.append(f"mean evidence confidence {conf}%")
    if share is not None:
        parts.append(f"{share}% of the claimed reduction is evidence-backed")
    return "; ".join(parts)


@app.get("/api/leadership/board.pdf")
def leadership_board_pdf(investigation_id: Optional[int] = None,
                         window_days: int = 90, persona: str = "executive",
                         initiative_id: Optional[int] = None,
                         layer: Optional[str] = None,
                         exposure: Optional[str] = None,
                         db: Session = Depends(get_db)):
    """The same snapshot as a PDF, built from the same Markdown.

    Rendering the exported Markdown rather than a second template is the point:
    the page a board member reads and the page a regulator is handed are the
    same document, so they cannot drift apart.
    """
    from . import leadership as _ld
    try:
        md = _ld.export_markdown(db, investigation_id, window_days=window_days,
                                 persona=persona, initiative_id=initiative_id,
                                 layer=layer, exposure=exposure)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    rp = _ld.risk_position(db, investigation_id, window_days=window_days,
                           initiative_id=initiative_id, layer=layer,
                           exposure=exposure)
    try:
        pdf = sec_engine.build_pdf(md, title="Leadership assurance board", meta={
            "product": investigation_id and f"Investigation {investigation_id}"
                     or "Portfolio-wide assurance board",
            "exposure_label": persona,
            "posture": _board_posture(rp),
            "report_name": "Leadership assurance board",
        })
    except RuntimeError as exc:
        # Missing reportlab is a deployment gap, not a bad request: say so in
        # the message rather than returning a 500 with a stack trace.
        raise HTTPException(503, str(exc))
    from fastapi.responses import Response
    name = f"assurance-board-{investigation_id or 'portfolio'}.pdf"
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition":
                             f'attachment; filename="{name}"'})


@app.get("/api/leadership/personas")
def leadership_personas(db: Session = Depends(get_db)):
    """The persona lenses and what each one emphasises."""
    from . import leadership as _ld
    return {"personas": _ld.persona_names()}


@app.get("/api/leadership/infrastructure")
def leadership_infrastructure():
    """Fox-services nodes: declared trust boundary and hardware, live status.

    Status is probed with a short timeout; unreachable is data, not a 500, and
    a node with no configured probe endpoint reports unprobed rather than a
    guess. No database read: this is the compute estate the pipeline runs on,
    not a portfolio row.
    """
    from . import fox_nodes as _fn
    return _fn.infrastructure()


@app.get("/api/leadership/risk-position")
def leadership_risk_position(investigation_id: Optional[int] = None,
                             window_days: int = 90,
                             initiative_id: Optional[int] = None,
                             layer: Optional[str] = None,
                             exposure: Optional[str] = None,
                             db: Session = Depends(get_db)):
    """Verified residual by data tier, each with its evidence confidence."""
    from . import leadership as _ld
    try:
        return _ld.risk_position(db, investigation_id, window_days=window_days,
                                 initiative_id=initiative_id, layer=layer,
                                 exposure=exposure)
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@app.get("/api/leadership/decision-queue")
def leadership_decision_queue(investigation_id: Optional[int] = None,
                              states: Optional[str] = None,
                              tier: Optional[str] = None,
                              exposure: Optional[str] = None,
                              sort: str = "residual",
                              limit: int = 25, offset: int = 0,
                              sla_days: int = 14,
                              initiative_id: Optional[int] = None,
                              layer: Optional[str] = None,
                              db: Session = Depends(get_db)):
    """Everything waiting on a decision, and what would change the answer."""
    from . import leadership as _ld
    try:
        return _ld.decision_queue(db, investigation_id,
                                  states=_csv_states(states), limit=limit,
                                  offset=offset, tier=tier, exposure=exposure,
                                  sort=sort, sla_days=sla_days,
                                  initiative_id=initiative_id, layer=layer)
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@app.get("/api/leadership/assurance-health")
def leadership_assurance_health(investigation_id: Optional[int] = None,
                                initiative_id: Optional[int] = None,
                                layer: Optional[str] = None,
                                exposure: Optional[str] = None,
                                db: Session = Depends(get_db)):
    """Controls verified vs declared, forensics, ledger integrity, stalled runs."""
    from . import leadership as _ld
    try:
        return _ld.assurance_health(db, investigation_id,
                                   initiative_id=initiative_id, layer=layer,
                                   exposure=exposure)
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@app.get("/api/leadership/exposure")
def leadership_exposure(investigation_id: Optional[int] = None,
                        initiative_id: Optional[int] = None,
                        layer: Optional[str] = None,
                        exposure: Optional[str] = None,
                        db: Session = Depends(get_db)):
    """Restricted/confidential assets, privileged users and material items."""
    from . import leadership as _ld
    try:
        return _ld.exposure_lens(db, investigation_id,
                                 initiative_id=initiative_id, layer=layer,
                                 exposure=exposure)
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@app.get("/api/leadership/system-integrity")
def leadership_system_integrity(investigation_id: Optional[int] = None,
                                initiative_id: Optional[int] = None,
                                layer: Optional[str] = None,
                                exposure: Optional[str] = None,
                                db: Session = Depends(get_db)):
    """Swarm health, threat-pack currency, ledger completeness, time-to-close."""
    from . import leadership as _ld
    try:
        return _ld.system_integrity(db, investigation_id,
                                    initiative_id=initiative_id, layer=layer,
                                    exposure=exposure)
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@app.get("/api/leadership/alerts")
def leadership_alerts(investigation_id: Optional[int] = None,
                      initiative_id: Optional[int] = None,
                      layer: Optional[str] = None,
                      exposure: Optional[str] = None,
                      sla_days: int = 14,
                      include_acknowledged: bool = False,
                      db: Session = Depends(get_db)):
    """What needs a person now, at block/warn severity."""
    from . import leadership as _ld
    try:
        return _ld.alerts(db, investigation_id, initiative_id=initiative_id,
                          layer=layer, exposure=exposure, sla_days=sla_days,
                          include_acknowledged=include_acknowledged)
    except ValueError as exc:
        raise HTTPException(422, str(exc))


class AlertAckRequest(BaseModel):
    # Optional here because the path form supplies it. Required on the
    # body-addressable endpoint, where there is nothing else to key off.
    alert_id: str = ""
    actor: str = ""
    status: str = "acknowledged"
    note: str = ""
    snooze_days: Optional[int] = None
    finding_hash: Optional[str] = None


@app.post("/api/leadership/alerts/ack")
def leadership_acknowledge_alert(data: AlertAckRequest, request: Request,
                                 db: Session = Depends(get_db)):
    """Record that a named person has seen an alert.

    Only the response is stored. The alert itself is recomputed from live state
    every call, so acknowledging hides a notification and never suppresses a
    finding that is still true.
    """
    from . import leadership as _ld
    if not data.alert_id:
        raise HTTPException(422, "alert_id is required")
    actor = (data.actor or "").strip() or ledger_api.request_actor_or_empty(request)
    try:
        return _ld.acknowledge_alert(
            db, data.alert_id, actor=actor, status=data.status, note=data.note,
            snooze_days=data.snooze_days, finding_hash=data.finding_hash)
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@app.post("/api/leadership/alerts/{alert_id}/ack")
def leadership_acknowledge_alert_by_id(alert_id: str, data: AlertAckRequest,
                                        request: Request,
                                        db: Session = Depends(get_db)):
    """Path-addressable twin of the body-addressable ack endpoint.

    The id in the path is the id that gets acknowledged, whatever the body says:
    a mismatch is a client bug, not two alerts to answer.
    """
    if data.alert_id and data.alert_id != alert_id:
        raise HTTPException(422, f"alert_id in path ({alert_id}) does not match "
                                 f"body ({data.alert_id})")
    return leadership_acknowledge_alert(
        data.model_copy(update={"alert_id": alert_id}), request, db)


@app.get("/api/leadership/exceptions")
def leadership_exceptions(investigation_id: Optional[int] = None,
                          initiative_id: Optional[int] = None,
                          layer: Optional[str] = None,
                          exposure: Optional[str] = None,
                          db: Session = Depends(get_db)):
    """Time-bounded exceptions and their expiry status."""
    from . import leadership as _ld
    try:
        return _ld.exception_register(db, investigation_id,
                                      initiative_id=initiative_id, layer=layer,
                                      exposure=exposure)
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@app.get("/api/leadership/change-log")
def leadership_change_log(investigation_id: Optional[int] = None,
                          initiative_id: Optional[int] = None,
                          layer: Optional[str] = None,
                          exposure: Optional[str] = None,
                          db: Session = Depends(get_db)):
    """Current vs superseded assessments, portfolio-wide when unscoped."""
    from . import leadership as _ld
    try:
        return _ld.change_log(db, investigation_id,
                              initiative_id=initiative_id, layer=layer,
                              exposure=exposure)
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@app.get("/api/leadership/change-log/{investigation_id}")
def leadership_change_log_for_investigation(investigation_id: int,
                                            db: Session = Depends(get_db)):
    """Path form of the change log, kept so existing callers keep working."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    return leadership_change_log(investigation_id=investigation_id, db=db)


def _hypothesis_rec(assessment_id: int, db: Session):
    from . import dossier as _dossier
    rec = db.query(SecurityAssessment).filter(
        SecurityAssessment.id == assessment_id).first()
    if not rec:
        raise HTTPException(404, "Assessment not found")
    try:
        scoring = json.loads(rec.scoring_json or "{}") or {}
    except Exception:
        scoring = {}
    if _assessment_path_fields(rec, scoring).get("assessment_path") != \
            "model_hypothesis":
        raise HTTPException(422, "Hypothesis builder needs a hypothesis-path "
                                 "assessment")
    return rec


@app.get("/api/security/assessments/{assessment_id}/hypotheses")
def get_hypothesis_register(assessment_id: int,
                            db: Session = Depends(get_db)):
    """The claim register: scored claims overlaid with builder edits."""
    from . import dossier as _dossier
    return {"assessment_id": assessment_id,
            "claims": _dossier.hypothesis_register(
                _hypothesis_rec(assessment_id, db))}


class HypothesisPatchRequest(BaseModel):
    claims: list[dict] = []
    note: str = ""


class ExperimentBuildRequest(BaseModel):
    hypothesis_ids: Optional[list[str]] = []


@app.post("/api/security/assessments/{assessment_id}/experiments/build")
def build_experiments(assessment_id: int, data: ExperimentBuildRequest,
                      request: Request, db: Session = Depends(get_db)):
    """Plan ranked experiments for what is still open. Plan only: nothing
    here executes anything. Reads stored rows (W1/W2/MM, hypothesis claims);
    never touches scores. May run without a full W3 when hypothesis or W2
    gaps exist."""
    from . import model_eval as _me
    rec = db.query(SecurityAssessment).filter(
        SecurityAssessment.id == assessment_id).first()
    if not rec:
        raise HTTPException(404, "Assessment not found")
    try:
        scoring = json.loads(rec.scoring_json or "{}") or {}
    except Exception:
        scoring = {}
    path = _assessment_path_fields(rec, scoring).get("assessment_path")
    if path not in ("model_engineering", "model_hypothesis"):
        raise HTTPException(422, "Experiment planning needs a model_engineering "
                                 "or model_hypothesis assessment")
    try:
        model_json = json.loads(getattr(rec, "model_json", None) or "{}") or {}
    except Exception:
        model_json = {}
    if not isinstance(model_json, dict):
        model_json = {}
    meta = model_json.get("meta") or {}
    findings = model_json.get("attacks") or []
    dimensions = model_json.get("dimensions") or []
    mitigation = model_json.get("mitigation") or {}
    hyps: list[dict] = []
    if path == "model_hypothesis":
        from . import dossier as _dossier
        hyps = [h for h in _dossier.hypothesis_register(rec)
                if not data.hypothesis_ids
                or (h.get("hypothesis_id") or h.get("id"))
                in data.hypothesis_ids]
    else:
        inv_id = rec.investigation_id
        for r in db.query(SecurityAssessment).filter(
                SecurityAssessment.investigation_id == inv_id).all():
            try:
                s = json.loads(r.scoring_json or "{}") or {}
            except Exception:
                continue
            if s.get("assessment_path") == "model_hypothesis":
                from . import dossier as _dossier
                hyps.extend(_dossier.hypothesis_register(r))
    from . import agents as _agents
    env = _agents.new_envelope(
        "security-orchestrator", "experiment-planner", "plan_experiments",
        {"model_meta": meta, "findings": findings, "dimensions": dimensions,
         "hypotheses": hyps,
         "mitigation_plan": (mitigation.get("plan") or [])})
    planned = _agents.experiment_planner_handle(env, None)["payload"]
    plan = {"experiments": planned.get("experiments", []),
            "roadmap": planned.get("roadmap",
                                   {"30d": [], "60d": [], "90d": []}),
            "method": planned.get("method", _me.EXPERIMENT_METHOD),
            "method_version": planned.get(
                "method_version", _me.EXPERIMENT_VERSION),
            "method_fingerprint": planned.get(
                "method_fingerprint", _me.experiment_fingerprint()),
            "note": planned.get("note", "")}
    # Model rows keep experiments with the model payload; hypothesis rows
    # keep them with the builder register both sides already read.
    if path == "model_hypothesis":
        try:
            hjs = json.loads(rec.hypothesis_json or "{}") or {}
        except Exception:
            hjs = {}
        if not isinstance(hjs, dict):
            hjs = {}
        hjs["experiments"] = plan["experiments"]
        hjs["experiments_roadmap"] = plan["roadmap"]
        hjs["experiment_method"] = plan["method"]
        rec.hypothesis_json = json.dumps(hjs)
    else:
        model_json["experiments"] = plan["experiments"]
    model_json["experiments_roadmap"] = plan["roadmap"]
    model_json["experiment_method"] = plan["method"]
    model_json["experiment_method_version"] = plan["method_version"]
    model_json["experiment_method_fingerprint"] = plan["method_fingerprint"]
    rec.model_json = json.dumps(model_json)
    db.commit()
    ledger_api.human_action(request, "built_experiment_plan", {
        "assessment_id": assessment_id,
        "experiments": len(plan["experiments"])})
    return {"assessment_id": assessment_id,
            "experiments": plan["experiments"],
            "roadmap": plan["roadmap"], "method": plan["method"],
            "note": plan["note"]}


@app.patch("/api/security/assessments/{assessment_id}/hypotheses")
def patch_hypothesis_register(assessment_id: int, data: HypothesisPatchRequest,
                              request: Request,
                              db: Session = Depends(get_db)):
    """Edit falsifiers/status/evidence links on the register.

    Writes only `hypothesis_json`: scoring and threats stay byte-identical,
    so the scored confidence cannot move under an edit. Returns 422 for
    unknown claim ids or bad statuses rather than silently dropping them.
    """
    from . import dossier as _dossier
    rec = _hypothesis_rec(assessment_id, db)
    register = _dossier.hypothesis_register(rec)
    known = {c.get("hypothesis_id") or c.get("id") for c in register}
    try:
        stored = json.loads(rec.hypothesis_json or "{}") or {}
    except Exception:
        stored = {}
    if not isinstance(stored, dict):
        stored = {}
    claims = [c for c in stored.get("claims", [])
              if isinstance(c, dict)]
    by_id = {c.get("hypothesis_id") or c.get("id"): c for c in claims}
    for patch in data.claims or []:
        hid = patch.get("hypothesis_id") or patch.get("id")
        if hid not in known:
            raise HTTPException(422, f"Unknown hypothesis id: {hid!r}")
        entry = by_id.setdefault(hid, {"hypothesis_id": hid})
        if "status" in patch:
            if patch["status"] not in _dossier.HYPOTHESIS_STATUSES:
                raise HTTPException(
                    422, "status must be one of: "
                    + ", ".join(_dossier.HYPOTHESIS_STATUSES))
            entry["status"] = patch["status"]
        if "falsifiers" in patch:
            fals = [str(f).strip() for f in (patch["falsifiers"] or [])
                    if str(f).strip()]
            if not fals:
                raise HTTPException(422, "falsifiers must not empty the list")
            entry["falsifiers"] = fals[:8]
        if "add_evidence" in patch:
            aids = [a for a in (patch["add_evidence"] or [])
                    if isinstance(a, int) and not isinstance(a, bool)]
            entry["add_evidence"] = sorted(
                set(entry.get("add_evidence", [])) | set(aids))[:16]
        if data.note:
            entry["note"] = data.note[:300]
    stored["claims"] = list(by_id.values())
    stored["updated_at"] = datetime.now(timezone.utc).isoformat()
    rec.hypothesis_json = json.dumps(stored)
    db.commit()
    ledger_api.human_action(request, "edited_hypothesis_register", {
        "assessment_id": assessment_id,
        "claims": sorted(by_id)})
    return {"assessment_id": assessment_id,
            "claims": _dossier.hypothesis_register(rec)}


@app.post("/api/security/assessments/{assessment_id}/hypotheses/{hypothesis_id}/collect-evidence")
def collect_hypothesis_evidence(assessment_id: int, hypothesis_id: str,
                                db: Session = Depends(get_db)):
    """Enqueue a collection run for one claim's falsifiers."""
    from . import dossier as _dossier
    rec = _hypothesis_rec(assessment_id, db)
    register = _dossier.hypothesis_register(rec)
    claim = next((c for c in register
                  if (c.get("hypothesis_id") or c.get("id")) == hypothesis_id),
                 None)
    if claim is None:
        raise HTTPException(404, "Hypothesis not found on this assessment")
    fals = claim.get("falsifiers") or []
    goal = (f"Collect evidence for hypothesis {hypothesis_id}: "
            f"{str(claim.get('claim') or '')[:160]}"
            + (f" — test falsifiers: {'; '.join(fals[:3])}" if fals else ""))
    run_id = launch_run_with_goal(rec.investigation_id, goal,
                                  max_items=12, max_rounds=1,
                                  trigger="explainer_gap")
    return {"run_id": run_id, "status": "running", "goal": goal}


class ManagerParseRequest(BaseModel):
    command: str = ""


class ManagerRunRequest(BaseModel):
    plan: dict = {}
    options: dict = {}
    command: str = ""


@app.post("/api/manager/parse")
def manager_parse(data: ManagerParseRequest):
    """Understand a command: LLM plan first, heuristic splitter on failure.

    No side effects. The returned plan is a preview for the Run step.
    """
    try:
        return manager_mod.parse_command(data.command or "")
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/manager/run")
def manager_run(data: ManagerRunRequest, db: Session = Depends(get_db)):
    """Serve a confirmed plan: N investigations + launches + summary shell."""
    try:
        return manager_mod.run_plan(db, data.plan or {},
                                    data.options or {}, data.command or "")
    except ValueError as e:
        raise HTTPException(422, str(e))


@app.get("/api/manager/runs")
def manager_runs(limit: int = 20, db: Session = Depends(get_db)):
    """Manager runs, newest first, with live child statuses derived on read."""
    from .models import ManagerRun
    recs = (db.query(ManagerRun).order_by(ManagerRun.id.desc())
            .limit(max(1, min(limit, 100))).all())
    return {"runs": [manager_mod._run_row(db, r) for r in recs]}


@app.get("/api/manager/runs/{run_id}")
def manager_run_detail(run_id: int, db: Session = Depends(get_db)):
    from .models import ManagerRun
    rec = db.query(ManagerRun).filter(ManagerRun.id == run_id).first()
    if rec is None:
        raise HTTPException(404, "Manager run not found")
    return manager_mod._run_row(db, rec)


@app.get("/api/manager/runs/{run_id}/summary-report")
def manager_run_summary_report(run_id: int, db: Session = Depends(get_db)):
    """The full run summary report (risks, findings, experiments, hypotheses,
    diagrams, artifact inventory, synthesis) for an agentic-manager run."""
    from . import run_summary as _rs
    try:
        return _rs.manager_run_report(db, run_id)
    except LookupError:
        raise HTTPException(404, "Manager run not found")


@app.get("/api/investigations/{inv_id}/summary-report")
def investigation_summary_report(inv_id: int, db: Session = Depends(get_db)):
    """The full run summary report for one investigation."""
    from . import run_summary as _rs
    try:
        return _rs.investigation_report(db, inv_id)
    except LookupError:
        raise HTTPException(404, "Investigation not found")


@app.get("/api/manager/runs/{run_id}/summary-report/markdown")
def manager_run_summary_report_markdown(run_id: int,
                                        db: Session = Depends(get_db)):
    """Export the run summary report as markdown."""
    from . import run_summary as _rs
    try:
        rep = _rs.manager_run_report(db, run_id)
    except LookupError:
        raise HTTPException(404, "Manager run not found")
    return Response(
        content=rep["markdown"], media_type="text/markdown",
        headers={"Content-Disposition":
                 f'attachment; filename="manager-run-{run_id}-summary.md"'})


@app.get("/api/manager/runs/{run_id}/summary-report/pdf")
def manager_run_summary_report_pdf(run_id: int,
                                   db: Session = Depends(get_db)):
    """Export the run summary report as PDF (requires reportlab)."""
    from . import run_summary as _rs
    try:
        rep = _rs.manager_run_report(db, run_id)
    except LookupError:
        raise HTTPException(404, "Manager run not found")
    try:
        pdf = sec_engine.build_pdf(
            rep["markdown"], title=f"Run summary report — #{run_id}",
            meta={"report_name": "Run summary report",
                  "product": f"Manager run #{run_id}",
                  "highlights_title": "What this run produced"})
    except RuntimeError as e:
        return Response(content=str(e), status_code=501,
                        media_type="text/plain")
    return Response(
        content=pdf, media_type="application/pdf",
        headers={"Content-Disposition":
                 f'attachment; filename="manager-run-{run_id}-summary.pdf"'})


@app.get("/api/investigations/{inv_id}/summary-report/markdown")
def investigation_summary_report_markdown(inv_id: int,
                                          db: Session = Depends(get_db)):
    """Export an investigation's summary report as markdown."""
    from . import run_summary as _rs
    try:
        rep = _rs.investigation_report(db, inv_id)
    except LookupError:
        raise HTTPException(404, "Investigation not found")
    return Response(
        content=rep["markdown"], media_type="text/markdown",
        headers={"Content-Disposition":
                 f'attachment; filename="investigation-{inv_id}-summary.md"'})


@app.get("/api/investigations/{inv_id}/summary-report/pdf")
def investigation_summary_report_pdf(inv_id: int,
                                     db: Session = Depends(get_db)):
    """Export an investigation's summary report as PDF (requires reportlab)."""
    from . import run_summary as _rs
    try:
        rep = _rs.investigation_report(db, inv_id)
    except LookupError:
        raise HTTPException(404, "Investigation not found")
    try:
        pdf = sec_engine.build_pdf(
            rep["markdown"], title=rep["title"],
            meta={"report_name": "Run summary report",
                  "product": rep["title"]})
    except RuntimeError as e:
        return Response(content=str(e), status_code=501,
                        media_type="text/plain")
    return Response(
        content=pdf, media_type="application/pdf",
        headers={"Content-Disposition":
                 f'attachment; filename="investigation-{inv_id}-summary.pdf"'})


@app.post("/api/manager/runs/{run_id}/compile")
def manager_compile(run_id: int, db: Session = Depends(get_db)):
    """Synthesize finished children into the summary investigation.

    409 while anything still runs; idempotent once compiled.
    """
    try:
        return manager_mod.compile_run(db, run_id)
    except LookupError:
        raise HTTPException(404, "Manager run not found")
    except manager_mod.PendingChildren as e:
        raise HTTPException(409, {"pending": e.pending})


@app.get("/api/manager/runs/{run_id}/timeline")
def manager_timeline(run_id: int, db: Session = Depends(get_db)):
    """Execution flow of a run: lanes, timestamped subagent actions, and a
    flow strip for the overview. Pure reads; safe to poll."""
    try:
        return manager_mod.run_timeline(db, run_id)
    except LookupError:
        raise HTTPException(404, "Manager run not found")


@app.get("/api/manager/links")
def manager_links(db: Session = Depends(get_db)):
    """Child investigation -> summary mapping for the AKM sidebar nest."""
    return manager_mod.manager_links(db)


@app.get("/api/security/assessments/{assessment_id}/markdown")
def get_security_markdown(assessment_id: int, db: Session = Depends(get_db)):
    from fastapi.responses import PlainTextResponse

    rec = db.query(SecurityAssessment).filter(
        SecurityAssessment.id == assessment_id).first()
    if not rec:
        raise HTTPException(404, "Assessment not found")
    return PlainTextResponse(rec.markdown, media_type="text/markdown")


@app.get("/api/security/assessments/{assessment_id}/pdf")
def get_security_pdf(assessment_id: int, db: Session = Depends(get_db)):
    from fastapi.responses import Response

    rec = db.query(SecurityAssessment).filter(
        SecurityAssessment.id == assessment_id).first()
    if not rec:
        raise HTTPException(404, "Assessment not found")
    try:
        from datetime import datetime as _dt, timezone as _tz
        try:
            _persp = json.loads(getattr(rec, "perspectives_json", None) or "[]")
            if not isinstance(_persp, list):
                _persp = []
        except Exception:
            _persp = []
        pdf = sec_engine.build_pdf(
            rec.markdown, title=f"AI Security Assessment — {rec.product_name}",
            meta={
                "product": rec.product_name,
                "exposure_label": dict(
                    getattr(sec_engine, "EXPOSURE_META", {}).get(rec.exposure or "", {})
                ).get("label", rec.exposure),
                "overall": rec.overall_pct,
                "posture": rec.posture,
                "perspectives": _persp,
                "task_id": (json.loads(rec.a2a_trace_json or "{}") or {}).get("task_id", ""),
                "date": (rec.created_at.isoformat()[:10] if rec.created_at else
                         _dt.now(_tz.utc).date().isoformat()),
            })
    except RuntimeError as exc:
        raise HTTPException(501, str(exc))
    return Response(
        content=pdf, media_type="application/pdf",
        headers={"Content-Disposition":
                 f"attachment; filename=security-assessment-{rec.id}.pdf"})


@app.post("/api/security/classify-subject")
def classify_security_subject(data: SecuritySubjectRequest):
    """What kind of thing is being assessed, and which paths apply.

    The Security form calls this as the subject is typed so it can offer the
    model mode selector only when the two model questions actually apply. The
    profiler is deterministic, so this is the same function the engine will
    use -- the UI never guesses and then disagrees with the run.
    """
    prof = sec_engine.profile_model_subject(data.product_name or "",
                                            data.use_case or "",
                                            data.focus or [])
    out = {"profile": prof, "is_model_query": prof["is_model_query"],
           "modes": ["target", "adversarial"] if prof["is_model_query"] else []}
    if prof["is_model_query"]:
        out["misuse_intent"] = sec_engine.profile_misuse_intent(
            data.product_name or "", data.use_case or "", data.focus or [],
            subject_profile=prof)
    return out


# --------------------------------------------------------------------------
# model-security knowledge base: landscape, graph, selection
# --------------------------------------------------------------------------

def _landscape_inv(inv_id: int, db: Session) -> int:
    from .models import Investigation as _Inv
    if not db.query(_Inv).filter(_Inv.id == inv_id).first():
        raise HTTPException(404, "Investigation not found")
    return inv_id


@app.get("/api/security/landscape")
def get_landscape(investigation_id: int, db: Session = Depends(get_db)):
    """The model-security landscape for one investigation.

    Inventory, the own/inherited/cascade partition, exploit view, insight
    cards, coverage gaps and catalog context — all derived from stored
    assessment rows. Nothing here re-runs an agent or re-scores anything.
    """
    from . import model_kb as _kb
    return _kb.landscape(db, _landscape_inv(investigation_id, db))


@app.get("/api/security/landscape/graph")
def get_landscape_graph(investigation_id: int,
                        db: Session = Depends(get_db)):
    """Model-security slice of the knowledge graph: KB nodes and edges only.

    A filter over the existing graph rather than a second graph: node kinds and
    relations are the KB's vocabulary, and every risk edge carries the scope
    payload a client needs to label it.
    """
    from . import model_kb as _kb
    return _kb.landscape_graph(db, _landscape_inv(investigation_id, db))


class LandscapeCompareRequest(BaseModel):
    investigation_id: int
    model_keys: Optional[list[str]] = []
    filters: dict = {}
    weights: dict = {}


@app.post("/api/security/landscape/compare")
def post_landscape_compare(data: LandscapeCompareRequest,
                           db: Session = Depends(get_db)):
    """Multi-axis comparison for model selection.

    Returns a comparison, not a winner. A ranked list appears only when the
    caller supplies weights, and the payload says which case it is.
    """
    from . import model_kb as _kb
    try:
        return _kb.compare(db, data.investigation_id, data.model_keys,
                           data.filters, data.weights)
    except ValueError as e:
        # an unknown filter/axis is a caller error, not a silently applied gate
        raise HTTPException(422, str(e))


class LandscapeDecisionRequest(BaseModel):
    investigation_id: int
    model_key: str
    initiative_key: str
    decision: str
    actor: str
    rationale: str = ""
    weights: dict = {}


@app.post("/api/security/landscape/decision")
def post_landscape_decision(data: LandscapeDecisionRequest, request: Request,
                            db: Session = Depends(get_db)):
    """Record a selection decision.

    Writes a ``selected_for`` / ``rejected_for`` edge with actor, rationale and
    timestamp, and logs a ledger human action. It never touches a score: a
    decision is a human judgement about a model, not a new measurement of it.
    """
    from . import model_kb as _kb
    inv = _landscape_inv(data.investigation_id, db)
    try:
        out = _kb.record_decision(db, inv, data.model_key, data.initiative_key,
                                  data.decision, data.actor, data.rationale,
                                  data.weights)
    except ValueError as e:
        raise HTTPException(422, str(e))
    # The audit entry is signed by the request identity, never by a name in the
    # payload: a decision is only attributable if it cannot be signed as
    # somebody else. A payload actor that differs is recorded as declared, so
    # the discrepancy is visible in the trail instead of silently resolved.
    signer = ledger_api.request_actor(request)
    declared = str(data.actor or "").strip()[:64]
    ledger_api.human_action(request, f"model_{data.decision}",
                            {"investigation_id": inv,
                             "model": out["model_key"],
                             "initiative": out["initiative_key"],
                             "rationale": (data.rationale or "")[:300],
                             "declared_actor": declared,
                             "actor_matches_signer": declared == signer})
    return out


@app.post("/api/security/assessments/{assessment_id}/kb/sync")
def post_assessment_kb_sync(assessment_id: int,
                            db: Session = Depends(get_db)):
    """Re-sync one assessment into the knowledge base.

    Idempotent, so this is the safe way to repair a row whose sync failed or to
    pick up a KB change on rows that predate it. Reads stored columns only.
    """
    from . import model_kb as _kb
    rec = db.query(SecurityAssessment).filter(
        SecurityAssessment.id == assessment_id).first()
    if not rec:
        raise HTTPException(404, "Assessment not found")
    try:
        return _kb.sync_model_kb(db, assessment_id)
    except LookupError:
        raise HTTPException(404, "Assessment not found")


@app.post("/api/security/landscape/sync")
def post_landscape_sync(investigation_id: int, db: Session = Depends(get_db)):
    """Sync every model-path assessment in an investigation, oldest first."""
    from . import model_kb as _kb
    return _kb.sync_investigation_kb(db, _landscape_inv(investigation_id, db))


@app.get("/.well-known/agents")
def well_known_agents():
    from .agents import get_agent_cards, PROTOCOL

    return {"protocol": PROTOCOL, "agents": get_agent_cards()}


@app.get("/api/agents/cards")
def agent_cards():
    from .agents import get_agent_cards, PROTOCOL

    return {"protocol": PROTOCOL, "agents": get_agent_cards()}


@app.post("/api/agents/invoke")
def agent_invoke(data: AgentInvokeRequest, db: Session = Depends(get_db)):
    """Invoke one A2A protocol hop directly (debugging / agent-to-agent calls)."""
    from .agents import new_envelope, dispatch

    env = new_envelope("api-caller", data.to, data.intent,
                       data.payload or {}, task_id=data.task_id,
                       note="direct invoke")
    try:
        return dispatch(env, db)
    except ValueError as exc:
        raise HTTPException(400, str(exc))


# ---------- graph ----------
@app.get("/api/investigations/{inv_id}/graph")
def get_graph(inv_id: int, db: Session = Depends(get_db)):
    artifacts = db.query(Artifact).filter(Artifact.investigation_id == inv_id).all()
    relationships = db.query(Relationship).filter(
        Relationship.investigation_id == inv_id).all()
    nodes = [{
        "id": a.id, "label": (a.title or "")[:60], "title": a.title or "",
        "type": a.artifact_type, "relevance": round(a.relevance or 0, 2),
        "sentiment": round(a.sentiment or 0, 2),
        "author": a.author or "", "tags": a.tags or "", "review": a.review,
        "drift": bool(a.drift),
    } for a in artifacts]
    edges = [{
        "id": r.id, "from": r.source_id, "to": r.target_id,
        "label": r.relationship_type,
        "title": r.description or "",
    } for r in relationships]
    return {"nodes": nodes, "edges": edges}


# ---------- known issues (CVEs) ----------
@app.get("/api/investigations/{inv_id}/cves")
def list_cves(inv_id: int, db: Session = Depends(get_db)):
    """Every known CVE for the investigation, newest-published first.

    Unknown-date findings sort last: a missing date is missing metadata, not
    missing importance.
    """
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    rows = db.query(CveFinding).filter(
        CveFinding.investigation_id == inv_id).all()
    dated = sorted((r for r in rows if r.published_date),
                   key=lambda r: r.published_date, reverse=True)
    rows = dated + [r for r in rows if not r.published_date]
    return {"items": [cve.finding_out(r) for r in rows],
            "total": len(rows)}


@app.post("/api/investigations/{inv_id}/cves/collect")
def collect_cves(inv_id: int, db: Session = Depends(get_db)):
    """(Re)collect CVE findings for one investigation. Idempotent.

    Enrichment calls out to NVD/CIRCL, so this takes seconds per new CVE;
    re-running it later only fetches what is new.
    """
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    try:
        out = cve.collect_investigation_cves(db, inv_id)
    except Exception as exc:  # noqa: BLE001 - report, don't 500, a bad sweep
        raise HTTPException(502, f"CVE collection failed: {exc}")
    out["findings"] = [cve.finding_out(r) for r in db.query(CveFinding).filter(
        CveFinding.investigation_id == inv_id).all()]
    return out


@app.post("/api/cves/collect-all")
def collect_cves_everywhere():
    """Sweep every investigation. One bad investigation never stops the rest."""
    return cve.collect_all_investigations()


@app.post("/api/investigations/{inv_id}/known-issues/refresh")
def refresh_known_issues(inv_id: int, product_name: str = "",
                         db: Session = Depends(get_db)):
    """Proactive known-issues pass: search CVEs + advisories for the
    investigation's subject and upsert findings.

    Best-effort and fail-open: a degraded CVE/API source is reported in
    ``degraded_sources``, never turned into a 500. Skips (``skipped: true``)
    when no product/vendor/package subject is identifiable.
    """
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    try:
        out = cve.collect_known_issues(db, inv_id, product_name=product_name)
    except Exception as exc:  # noqa: BLE001 - report, don't 500, a bad pass
        raise HTTPException(502, f"Known-issues pass failed: {exc}")
    out["cve_findings"] = [cve.finding_out(r) for r in db.query(CveFinding).filter(
        CveFinding.investigation_id == inv_id).all()]
    out["known_issue_artifacts"] = [{
        "id": a.id, "title": a.title or "", "url": a.url or "",
        "tags": a.tags or "", "kind": _known_issue_kind(a),
        "review": a.review or "pending",
    } for a in db.query(Artifact).filter(
        Artifact.investigation_id == inv_id,
        Artifact.artifact_type == "known_issue").all()]
    return out


def _known_issue_kind(a) -> str:
    """The issue kind from a known_issue artifact's node_meta, if stored."""
    import json as _json
    try:
        meta = _json.loads(a.node_meta or "{}") or {}
        return meta.get("issue_kind") or ""
    except Exception:
        return ""


@app.get("/api/investigations/{inv_id}/known-issues")
def list_known_issues(inv_id: int, db: Session = Depends(get_db)):
    """CVEs + non-CVE known issues for one investigation, newest first."""
    cves = [cve.finding_out(r) for r in db.query(CveFinding).filter(
        CveFinding.investigation_id == inv_id)
        .order_by(CveFinding.id.desc()).all()]
    issues = [{
        "id": a.id, "title": a.title or "", "url": a.url or "",
        "description": a.description or "", "tags": a.tags or "",
        "kind": _known_issue_kind(a), "review": a.review or "pending",
    } for a in db.query(Artifact).filter(
        Artifact.investigation_id == inv_id,
        Artifact.artifact_type == "known_issue")
        .order_by(Artifact.id.desc()).all()]
    return {"investigation_id": inv_id, "cves": cves,
            "known_issues": issues,
            "total": len(cves) + len(issues)}


def _tag_set(tags: Optional[str]) -> set:
    if not tags:
        return set()
    return set(t.strip().lower() for t in tags.split(",") if t.strip())


@app.get("/api/investigations/{inv_id}/graph/clusters")
def get_clusters(inv_id: int, mode: str = Query("category", pattern="^(category|similarity)$"),
                 threshold: float = Query(0.25, ge=0.0, le=1.0),
                 db: Session = Depends(get_db)):
    artifacts = db.query(Artifact).filter(Artifact.investigation_id == inv_id).all()
    if mode == "category":
        grouped: dict = defaultdict(list)
        for a in artifacts:
            grouped[a.artifact_type or "unknown"].append(a.id)
        clusters = []
        for atype, mids in sorted(grouped.items()):
            counts: dict = defaultdict(int)
            for a in artifacts:
                if a.id in mids:
                    for t in _tag_set(a.tags):
                        counts[t] += 1
            top = sorted(counts, key=lambda t: -counts[t])[:3]
            clusters.append({"id": f"category:{atype}", "label": f"{atype} ({len(mids)})",
                             "mode": "category", "centroid": atype,
                             "centroid_tags": top, "member_ids": sorted(mids),
                             "size": len(mids)})
        return {"mode": mode, "clusters": clusters}

    ids = [a.id for a in artifacts]
    tag_map = {a.id: _tag_set(a.tags) for a in artifacts}
    parent = {i: i for i in ids}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            a, b = tag_map[ids[i]], tag_map[ids[j]]
            union = a | b
            if a and b and union and len(a & b) / len(union) >= threshold:
                ra, rb = find(ids[i]), find(ids[j])
                if ra != rb:
                    parent[rb] = ra

    groups: dict = defaultdict(list)
    for i in ids:
        if tag_map[i]:
            groups[find(i)].append(i)
    clusters = []
    for idx, (root, mids) in enumerate(sorted(groups.items(), key=lambda kv: -len(kv[1]))):
        if len(mids) < 2:
            continue
        sets = [tag_map[m] for m in mids]
        inter = set.intersection(*sets) if sets else set()
        if inter:
            ctags = sorted(inter)
        else:
            counts = defaultdict(int)
            for s in sets:
                for t in s:
                    counts[t] += 1
            ctags = sorted(counts, key=lambda t: (-counts[t], t))[:3]
        label = ", ".join(ctags[:3]) if ctags else f"group {idx + 1}"
        clusters.append({"id": f"similarity:{idx}", "label": f"{label} ({len(mids)})",
                         "mode": "similarity", "centroid": label,
                         "centroid_tags": ctags, "member_ids": sorted(mids),
                         "size": len(mids)})
    return {"mode": mode, "threshold": threshold, "clusters": clusters}


# ---------------------------------------------------------------------------
# portfolio: initiatives, situation, unified register, leakage, advice
# ---------------------------------------------------------------------------

class InitiativeRequest(BaseModel):
    title: str
    business_use_case: str = ""
    owner: str = ""
    data_classes: list[str] = []
    target_users: list[str] = []
    systems: list[str] = []
    obligations: list[str] = []
    control_inventory: list[dict] = []
    status: str = "active"
    review_cadence_days: int = 90
    go_live_at: Optional[str] = None


class SituationRequest(BaseModel):
    investigation_id: int
    assessment_id: int
    situation: dict
    actor: str = ""
    rationale: str = ""


class RiskStateRequest(BaseModel):
    entry_id: int
    status: Optional[str] = None
    owner: Optional[str] = None
    review_by: Optional[str] = None
    residual_note: Optional[str] = None
    mitigation_ids: Optional[list[str]] = None
    accept: bool = False
    accepted_by: Optional[str] = None
    acceptance_note: Optional[str] = None
    rationale: str = ""


class AdvisorRequest(BaseModel):
    investigation_id: int
    initiative_id: Optional[int] = None
    controls_present: Optional[list[str]] = None
    max_burden: Optional[str] = None
    narrative: bool = False


def _load(raw, default=None):
    """Tolerant JSON read: a column holding a half-written or absent value
    reads as the default rather than raising in the middle of a response."""
    if not raw:
        return default
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return default


@app.post("/api/security/assessments/{assessment_id}/pdp/sync")
def post_assessment_pdp_sync(assessment_id: int, request: Request,
                             db: Session = Depends(get_db)):
    """(Re)derive provider-posture findings from accepted evidence.

    Idempotent: findings come from accepted artifacts only, so re-running
    changes nothing unless the evidence did. Deterministic derivation yields
    ``partial`` at best; ``supported`` needs a human override below. Safety
    context derives alongside posture under its own catalog.
    """
    from . import provider_posture as _pp
    from .models import Artifact as _Art
    rec = db.query(SecurityAssessment).filter(
        SecurityAssessment.id == assessment_id).first()
    if not rec:
        raise HTTPException(404, "Assessment not found")
    accepted = [
        {"id": a.id, "title": a.title, "tags": a.tags,
         "artifact_type": a.artifact_type, "review": a.review}
        for a in db.query(_Art).filter(
            _Art.investigation_id == rec.investigation_id,
            _Art.review == "accepted").all()]
    result = _pp.assess_posture(accepted)
    rec.pdp_json = json.dumps(result)
    db.commit()
    ledger_api.human_action(
        request, "provider_posture_synced",
        {"target_type": "assessment", "target_id": rec.id,
         "assessment_id": rec.id, "findings": len(result["findings"]),
         "accepted_sources": len(accepted),
         "catalog": _pp.PDP_ID, "version": _pp.PDP_VERSION})
    return result


class PdpStateRequest(BaseModel):
    assessment_id: int
    dimension_id: str
    standing: str
    summary: str = ""
    evidence_ids: Optional[list[int]] = None
    actor: str = ""
    rationale: str = ""


@app.post("/api/portfolio/pdp/state")
def post_pdp_state(data: PdpStateRequest, request: Request,
                   db: Session = Depends(get_db)):
    """Human override of one PDP dimension. The only path to supported.

    A dimension names tier-specific terms a human verified, so the override
    needs who decided and what they read. Ledgered like any other scope
    decision.
    """
    from . import provider_posture as _pp
    rec = db.query(SecurityAssessment).filter(
        SecurityAssessment.id == data.assessment_id).first()
    if not rec:
        raise HTTPException(404, "Assessment not found")
    try:
        stored = json.loads(rec.pdp_json or "") or {}
    except Exception:
        stored = {}
    findings = stored.get("findings") if isinstance(stored, dict) else None
    if not findings:
        findings = _pp.blank_findings()
    try:
        updated = _pp.set_pdp_finding(
            findings, data.dimension_id, standing=data.standing,
            summary=data.summary, evidence_ids=data.evidence_ids,
            actor=data.actor or ledger_api.request_actor(request))
    except ValueError as e:
        raise HTTPException(422, str(e))
    rec.pdp_json = json.dumps({
        "method": "provider_posture_v1", "version": _pp.PDP_VERSION,
        "catalog": _pp.PDP_ID, "fingerprint": _pp.pdp_fingerprint(),
        "findings": findings,
        "note": "Includes human-overridden standings; see reviewed_by.",
    })
    db.commit()
    ledger_api.human_action(
        request, "provider_posture_override",
        {"target_type": "assessment", "target_id": rec.id,
         "assessment_id": rec.id, "dimension_id": data.dimension_id,
         "standing": data.standing, "actor": data.actor,
         "rationale": data.rationale})
    return updated


@app.get("/api/portfolio/initiatives")
def get_initiatives(investigation_id: int, db: Session = Depends(get_db)):
    """Every initiative in the portfolio, with how far each one is described.

    A field nobody filled in is reported as unknown. An initiative with no
    business use case and no owner is not a plan, and the count of those is
    returned so the gap is visible instead of implied.
    """
    from . import portfolio as _pf
    from .models import Initiative as _Initiative
    inv_id = _landscape_inv(investigation_id, db)
    rows = db.query(_Initiative).filter(
        _Initiative.investigation_id == inv_id).order_by(_Initiative.id).all()
    aggregates = {s["id"]: s for s in _pf.initiative_summaries(db, inv_id)}
    out = []
    for i in rows:
        d = {
            "id": i.id, "title": i.title, "business_use_case": i.business_use_case,
            "owner": i.owner, "data_classes": _load(i.data_classes_json, []),
            "target_users": _load(i.target_users_json, []),
            "systems": _load(i.systems_json, []),
            "obligations": _load(i.obligations_json, []),
            "control_inventory": _pf.normalize_inventory(i.control_inventory_json),
            "status": i.status, "review_cadence_days": i.review_cadence_days,
            "go_live_at": i.go_live_at, "last_reviewed_at": i.last_reviewed_at,
            "aggregate": aggregates.get(i.id, {
                "id": i.id, "assessments": 0,
                "assessments_with_situation": 0, "risks": 0,
                "open_risks": 0, "unowned_risks": 0,
                "risks_with_review_date": 0, "by_layer": {},
                "by_status": {}, "max_severity": None}),
        }
        missing = [f for f in ("business_use_case", "owner") if not d[f]]
        if not d["data_classes"]:
            missing.append("data_classes")
        if not d["obligations"]:
            missing.append("obligations")
        d["missing_fields"] = missing
        d["described"] = not missing
        out.append(d)
    return {"investigation_id": inv_id, "initiatives": out,
            "total": len(out),
            "undescribed": sum(1 for d in out if not d["described"]),
            "note": "An initiative nobody has described yet cannot be assessed "
                    "in context. It is listed, not scored."}


@app.post("/api/portfolio/initiatives")
def post_initiative(investigation_id: int, data: InitiativeRequest,
                    request: Request, db: Session = Depends(get_db)):
    """Create an initiative. Ledgered: an initiative is a scope decision."""
    from . import portfolio as _pf
    from .models import Initiative as _Initiative
    inv_id = _landscape_inv(investigation_id, db)
    if not data.title.strip():
        raise HTTPException(400, "An initiative needs a title to be findable")
    if data.status not in ("active", "paused", "retired"):
        raise HTTPException(400, f"Unknown initiative status: {data.status}")
    rec = _Initiative(
        investigation_id=inv_id, title=data.title.strip(),
        business_use_case=data.business_use_case, owner=data.owner,
        data_classes_json=json.dumps(data.data_classes),
        target_users_json=json.dumps(data.target_users),
        systems_json=json.dumps(data.systems),
        obligations_json=json.dumps(data.obligations),
        control_inventory_json=json.dumps(
            _pf.normalize_inventory(data.control_inventory)),
        status=data.status, review_cadence_days=data.review_cadence_days,
        go_live_at=data.go_live_at)
    db.add(rec)
    db.commit()
    db.refresh(rec)
    ledger_api.human_action(
        request, "portfolio.initiative_created",
        {"target_type": "initiative", "target_id": rec.id,
         "investigation_id": inv_id, "title": rec.title,
         "status": rec.status, "owner": rec.owner,
         "data_classes": data.data_classes,
         "described": bool(rec.business_use_case and rec.owner)})
    return {"id": rec.id, "status": rec.status, "title": rec.title,
            "missing_fields": [f for f in ("business_use_case", "owner")
                               if not getattr(rec, f)]}


@app.post("/api/portfolio/situation")
def post_situation(data: SituationRequest, request: Request,
                   db: Session = Depends(get_db)):
    """Attach a situation profile to a stored assessment.

    Recorded as a versioned snapshot and written to the ledger, because
    "we handle restricted PII in a customer-facing chat" is a decision with a
    date on it. The profile is normalized for reading but stored verbatim: what
    the operator actually said is what gets audited.
    """
    from . import portfolio as _pf
    from .models import SecurityAssessment as _Rec
    rec = db.get(_Rec, data.assessment_id)
    if not rec:
        raise HTTPException(404, "Assessment not found")
    sit = _pf.normalize_situation(data.situation)
    mult = _pf.situation_multiplier(sit)
    prev = _load(rec.situation_json, None)
    snapshot = {
        "situation": data.situation, "normalized": sit,
        "recorded_at": datetime.utcnow().isoformat(), "actor": data.actor,
        "rationale": data.rationale, "supersedes": bool(prev),
    }
    rec.situation_json = json.dumps(snapshot)
    if data.investigation_id:
        rec.investigation_id = data.investigation_id
    db.commit()
    ledger_api.human_action(
        request, "portfolio.situation_recorded",
        {"target_type": "assessment", "target_id": rec.id,
         "assessment_id": rec.id, "investigation_id": rec.investigation_id,
         "channel": sit["channel"], "channel_valid": sit["channel_valid"],
         "tags": sit["tags"], "material_unknown": sit["material_unknown"],
         "unverified_controls": mult["unverified_controls"],
         "multiplier": mult["multiplier"],
         "actor": data.actor, "rationale": data.rationale,
         "supersedes_previous": bool(prev)})
    return {"assessment_id": rec.id, "situation": sit,
            "multiplier": mult,
            "note": "Recorded as a starting point, not a sign-off. Unstated "
                    "fields stay unknown and are listed in unknown_fields."}


@app.get("/api/portfolio/register")
def get_register(investigation_id: int, layer: str = "", status: str = "",
                 tag: str = "", db: Session = Depends(get_db)):
    """The unified register: product, model, privacy and supply-chain rows.

    Every row names the stored assessment it came from and the catalog version
    that produced it, so a row can be traced to the evidence behind it. Rows
    with no owner say so; nothing is silently assigned. ``tag`` filters on
    the row's situation tags (e.g. ``provider_posture``).
    """
    from . import portfolio as _pf
    inv_id = _landscape_inv(investigation_id, db)
    rows = _pf.derive_register(db, inv_id)
    if layer:
        rows = [r for r in rows if r["layer"] == layer]
    if status:
        rows = [r for r in rows if r["status"] == status]
    if tag:
        rows = [r for r in rows if tag in (r.get("situation_tags") or [])]
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["layer"]] = counts.get(r["layer"], 0) + 1
    return {"investigation_id": inv_id, "risks": rows, "total": len(rows),
            "by_layer": counts,
            "unowned": sum(1 for r in rows if r["owner_missing"]),
            "accepted_without_note": sum(
                1 for r in rows
                if r["status"] == "accepted" and not r["acceptance_note"]),
            "note": "Severity is comparable within a layer only; the four "
                    "layers are ranked by evidence and exposure, not by a "
                    "single combined number."}


@app.post("/api/portfolio/register/state")
def post_register_state(data: RiskStateRequest, request: Request,
                        db: Session = Depends(get_db)):
    """Move one register row's human state: owner, status, acceptance.

    Acceptance is separated from a plain status change because accepting a risk
    is a decision someone has to be named for. Policy (and this endpoint)
    requires the accepting person to differ from whoever requested the
    assessment; a gate the requester can pass alone is not a control.
    """
    from . import approvals as _approvals
    from . import portfolio as _pf
    entry = db.get(RiskEntry, data.entry_id)
    if not entry:
        raise HTTPException(404, "Risk entry not found")
    if data.accept and data.status not in (None, "accepted"):
        raise HTTPException(
            400, "accept=true sets status to accepted; do not send both")
    requesters: set[str] = set()
    if data.accept:
        if not data.accepted_by or not data.acceptance_note:
            raise HTTPException(
                400, "Accepting a risk needs accepted_by and acceptance_note: "
                     "who decided, and what they accepted")
        for aid in _load(entry.assessment_ids_json, []) or []:
            try:
                linked = db.get(SecurityAssessment, int(aid))
            except (TypeError, ValueError):
                continue
            requester = getattr(linked, "requested_by", None) if linked else None
            if requester:
                requesters.add(requester)
        for requester in sorted(requesters):
            try:
                _approvals.check_approver(approver=data.accepted_by,
                                          requester=requester)
            except _approvals.ApprovalError as e:
                raise HTTPException(e.status, e.reason)
    row = _pf.set_risk_state(
        db, data.entry_id, status=data.status, owner=data.owner,
        review_by=data.review_by, residual_note=data.residual_note,
        mitigation_ids=data.mitigation_ids, accept=data.accept,
        accepted_by=data.accepted_by,
        acceptance_note=data.acceptance_note)
    ledger_api.human_action(
        request, "portfolio.risk_state_changed",
        {"target_type": "risk_entry", "target_id": data.entry_id,
         "entry_id": data.entry_id, "stable_key": entry.stable_key,
         "from_status": entry.status, "to_status": row["status"],
         "owner": data.owner, "accepted_by": data.accepted_by,
         "acceptance_note": data.acceptance_note,
         "requesters": sorted(requesters),
         "requester_unknown": data.accept and not requesters,
         "rationale": data.rationale,
         "mitigation_ids": data.mitigation_ids})
    return row


@app.get("/api/portfolio/leakage")
def get_leakage(investigation_id: int, db: Session = Depends(get_db)):
    """Which leakage pathways the declared situations actually expose.

    Derived from the situation profiles on stored assessments. Each pathway
    reports its own control coverage, split into evidenced and declared-only,
    because a control nobody can show evidence for is a claim.
    """
    from . import leakage as _lk
    from . import portfolio as _pf
    from .models import SecurityAssessment as _Rec
    inv_id = _landscape_inv(investigation_id, db)
    recs = db.query(_Rec).filter(_Rec.investigation_id == inv_id).all()
    out, tags = [], []
    for rec in recs:
        raw = _pf.stated_situation(rec.situation_json)
        if not raw:
            continue
        sit = _pf.normalize_situation(raw)
        tags.extend(sit["tags"])
        meta = _pf._model_meta(_load(rec.model_json, None))
        rows = _pf.leakage_rows(sit, meta, rec.id, rec.product_name)
        for r in rows:
            r["assessment_id"] = rec.id
            r["product_name"] = rec.product_name
        out.extend(rows)
    counts: dict[str, int] = {}
    for r in out:
        counts[r["source_ref"]] = counts.get(r["source_ref"], 0) + 1
    return {"investigation_id": inv_id, "pathways": out, "total": len(out),
            "by_pathway": counts,
            "catalog_version": _lk.LEAKAGE_VERSION,
            "catalog_fingerprint": _lk.leakage_fingerprint(),
            "playbooks": _lk.select_playbooks(sorted(set(tags))),
            "assessments_with_situation": len({
                r["assessment_id"] for r in out}),
            "note": "Only pathways the situation actually exposes are listed. "
                    "An absent pathway means it was not derived, not that it "
                    "is closed."}


@app.get("/api/portfolio/cascade")
def get_cascade(investigation_id: int, db: Session = Depends(get_db)):
    """Cascade edges between initiatives, including transitive ones.

    An explicit edge is a stated dependency; a transitive edge is one that
    reaches an initiative through a shared model or mechanism. Transitive edges
    carry the path, because a risk you cannot trace is not actionable.
    """
    from . import model_kb as _kb
    from . import portfolio as _pf
    from .models import Initiative as _Initiative
    inv_id = _landscape_inv(investigation_id, db)
    inits = []
    for i in db.query(_Initiative).filter(
            _Initiative.investigation_id == inv_id).all():
        d = {"title": i.title, "business_use_case": i.business_use_case,
             "systems": _load(i.systems_json, []),
             "models": [m.get("model_key") for m in
                        (_kb.landscape(db, inv_id).get("inventory") or [])
                        if i.title and i.title.lower() in
                        (m.get("initiatives") or [""])[0].lower()]}
        inits.append(d)
    land = _kb.landscape(db, inv_id)
    for d in inits:
        d["models"] = [m.get("model_key") for m in (land.get("inventory") or [])
                       if m.get("model_key") and any(
                           d["title"].lower() in (k or "").lower()
                           for k in (m.get("initiative_keys") or []))]
    edges = _pf.portfolio_cascade(land, inits)
    return {"investigation_id": inv_id, "edges": edges, "total": len(edges),
            "initiatives": len(inits),
            "transitive": sum(1 for e in edges if e["basis"] == "transitive"),
            "note": "Cascade edges are inferred from declared systems, models "
                    "and use cases. An edge marked inferred was derived by "
                    "keyword and is not a stated dependency."}


@app.post("/api/portfolio/advisor")
def post_advisor(data: AdvisorRequest, request: Request,
                 db: Session = Depends(get_db)):
    """Mitigation advice for the open rows of one investigation.

    The mapping from risk to control is deterministic and reproducible: the
    same situation yields the same list, with the same reasons for withholding
    anything. No risk is marked secured by having a control attached to it.
    """
    from . import portfolio as _pf
    inv_id = _landscape_inv(data.investigation_id, db)
    try:
        pack = _pf.advise(db, inv_id, controls_present=data.controls_present,
                          max_burden=data.max_burden,
                          initiative_id=data.initiative_id)
    except LookupError as e:
        raise HTTPException(404, str(e))
    ledger_api.human_action(
        request, "portfolio.advice_generated",
        {"target_type": "investigation", "target_id": inv_id,
         "investigation_id": inv_id,
         "advice_count": len(pack["advice"]),
         "quick_wins": sum(1 for a in pack["advice"] if a["quick_win"]),
         "situation_tags": pack["situation"]["tags"],
         "controls_present": data.controls_present})
    return pack


@app.get("/api/portfolio/intel")
def get_intel(investigation_id: int, since_days: int = 30, stale_days: int = 90,
              db: Session = Depends(get_db)):
    """What changed since the last review, and what is going stale.

    Every trigger is derived from stored rows, so the feed cannot report a
    change that did not happen. A quiet feed says what it means.
    """
    from . import portfolio as _pf
    inv_id = _landscape_inv(investigation_id, db)
    return _pf.intel_feed(db, inv_id, since_days=since_days,
                          stale_days=stale_days)


@app.get("/api/portfolio/metrics")
def get_metrics(investigation_id: int, db: Session = Depends(get_db)):
    """Governance counters. No composite score and no letter grade.

    Unknowns are reported as unknown (null), not as zero: "no owner" and "we
    do not know the owner" are different facts, and only one of them is a
    finding.
    """
    from . import model_kb as _kb
    from . import portfolio as _pf
    inv_id = _landscape_inv(investigation_id, db)
    reg = _pf.derive_register(db, inv_id, persist=False)
    return _pf.metrics(reg, _kb.landscape(db, inv_id))


# ---------------------------------------------------------------------------
# executive dashboard: availability, distribution, robustness
# ---------------------------------------------------------------------------

class DashboardScope(BaseModel):
    investigation_id: int
    window_days: int = 90
    initiative_id: Optional[int] = None
    layer: Optional[str] = None
    exposure: Optional[str] = None
    accepted_only: bool = True


def _dashboard_scope(data: DashboardScope, db: Session) -> dict:
    from . import executive as _ex
    inv_id = _landscape_inv(data.investigation_id, db)
    try:
        return _ex.resolve_scope(
            db, inv_id, window_days=data.window_days,
            initiative_id=data.initiative_id, layer=data.layer,
            exposure=data.exposure, accepted_only=data.accepted_only)
    except LookupError as e:
        raise HTTPException(404, str(e))
    except ValueError as e:
        raise HTTPException(422, str(e))


@app.get("/api/dashboard/summary")
def get_dashboard_summary(investigation_id: int, window_days: int = 90,
                          initiative_id: Optional[int] = None,
                          layer: Optional[str] = None,
                          exposure: Optional[str] = None,
                          accepted_only: bool = True,
                          db: Session = Depends(get_db)):
    """Header strip: lights, open High/Critical, approvals, stale.

    Read-only aggregates over stored rows. Every percentage carries its
    sample size; empty denominators read as unknown, never as covered.
    """
    from . import executive as _ex
    scope = _dashboard_scope(DashboardScope(
        investigation_id=investigation_id, window_days=window_days,
        initiative_id=initiative_id, layer=layer, exposure=exposure,
        accepted_only=accepted_only), db)
    return _ex.summary(db, scope["investigation_id"], scope)


@app.get("/api/dashboard/availability")
def get_dashboard_availability(investigation_id: int, window_days: int = 90,
                               initiative_id: Optional[int] = None,
                               layer: Optional[str] = None,
                               exposure: Optional[str] = None,
                               accepted_only: bool = True,
                               db: Session = Depends(get_db)):
    """Coverage, freshness, unknowns, sync health. Lights plus tables."""
    from . import executive as _ex
    scope = _dashboard_scope(DashboardScope(
        investigation_id=investigation_id, window_days=window_days,
        initiative_id=initiative_id, layer=layer, exposure=exposure,
        accepted_only=accepted_only), db)
    return _ex.availability(db, scope["investigation_id"], scope)


@app.get("/api/dashboard/distribution")
def get_dashboard_distribution(investigation_id: int, window_days: int = 90,
                               initiative_id: Optional[int] = None,
                               layer: Optional[str] = None,
                               exposure: Optional[str] = None,
                               accepted_only: bool = True,
                               db: Session = Depends(get_db)):
    """Where risk concentrates. Counts by layer, scope, family, pattern,
    exposure, initiative and status, plus deterministic insight cards. Layers
    stay separate; nothing is averaged."""
    from . import executive as _ex
    scope = _dashboard_scope(DashboardScope(
        investigation_id=investigation_id, window_days=window_days,
        initiative_id=initiative_id, layer=layer, exposure=exposure,
        accepted_only=accepted_only), db)
    return _ex.distribution(db, scope["investigation_id"], scope)


@app.get("/api/dashboard/robustness")
def get_dashboard_robustness(investigation_id: int, window_days: int = 90,
                             initiative_id: Optional[int] = None,
                             layer: Optional[str] = None,
                             exposure: Optional[str] = None,
                             accepted_only: bool = True,
                             db: Session = Depends(get_db)):
    """Process depth: mapping, validation, acceptance, approvals, hygiene.

    Always ships a limitations block. Nothing here claims measured
    production risk."""
    from . import executive as _ex
    scope = _dashboard_scope(DashboardScope(
        investigation_id=investigation_id, window_days=window_days,
        initiative_id=initiative_id, layer=layer, exposure=exposure,
        accepted_only=accepted_only), db)
    return _ex.robustness(db, scope["investigation_id"], scope)


@app.get("/api/dashboard/attention")
def get_dashboard_attention(investigation_id: int, window_days: int = 90,
                            initiative_id: Optional[int] = None,
                            layer: Optional[str] = None,
                            exposure: Optional[str] = None,
                            accepted_only: bool = True,
                            db: Session = Depends(get_db)):
    """Ranked action list with deep links into Landscape and the register."""
    from . import executive as _ex
    scope = _dashboard_scope(DashboardScope(
        investigation_id=investigation_id, window_days=window_days,
        initiative_id=initiative_id, layer=layer, exposure=exposure,
        accepted_only=accepted_only), db)
    return _ex.attention(db, scope["investigation_id"], scope)


@app.get("/api/dashboard/trends")
def get_dashboard_trends(investigation_id: int, days: int = 90,
                         db: Session = Depends(get_db)):
    """Stored daily rollups, oldest first. Gaps stay gaps; nothing is
    interpolated. An empty series means no snapshots yet, not a flat trend."""
    from . import executive as _ex
    inv_id = _landscape_inv(investigation_id, db)
    series = _ex.snapshots(db, inv_id, days=days)
    return {"investigation_id": inv_id, "days": days, "snapshots": series,
            "total": len(series),
            "note": ("Daily rollups written by the scheduler. No snapshots "
                     "yet means the trend is unknown, not flat.")}


@app.post("/api/dashboard/snapshot")
def post_dashboard_snapshot(investigation_id: int, request: Request,
                            db: Session = Depends(get_db)):
    """Write today's rollup now. Ledgered: a snapshot is a dated reading."""
    from . import executive as _ex
    inv_id = _landscape_inv(investigation_id, db)
    out = _ex.write_snapshot(db, inv_id)
    ledger_api.human_action(
        request, "dashboard.snapshot_written",
        {"target_type": "investigation", "target_id": inv_id,
         "investigation_id": inv_id, **out})
    return out


@app.get("/api/dashboard/brief.md")
def get_dashboard_brief_md(investigation_id: int, window_days: int = 90,
                           accepted_only: bool = True,
                           db: Session = Depends(get_db)):
    """Board-safe leadership brief as Markdown, from the same payloads."""
    from . import executive as _ex
    from fastapi.responses import PlainTextResponse
    scope = _dashboard_scope(DashboardScope(
        investigation_id=investigation_id, window_days=window_days,
        accepted_only=accepted_only), db)
    return PlainTextResponse(
        _ex.brief_markdown(db, scope["investigation_id"], scope),
        media_type="text/markdown",
        headers={"Content-Disposition":
                 "attachment; filename=\"leadership-brief-"
                 f"{scope['investigation_id']}.md\""})


@app.get("/api/dashboard/brief.pdf")
def get_dashboard_brief_pdf(investigation_id: int, window_days: int = 90,
                            accepted_only: bool = True,
                            db: Session = Depends(get_db)):
    """The same brief as PDF. Screen and paper agree by construction."""
    from . import executive as _ex
    scope = _dashboard_scope(DashboardScope(
        investigation_id=investigation_id, window_days=window_days,
        accepted_only=accepted_only), db)
    md = _ex.brief_markdown(db, scope["investigation_id"], scope)
    pdf = sec_engine.build_pdf(md, title="Leadership brief",
                               meta={"investigation_id":
                                     scope["investigation_id"]})
    from fastapi.responses import Response
    return Response(
        content=pdf, media_type="application/pdf",
        headers={"Content-Disposition":
                 f'attachment; filename="leadership-brief-'
                 f'{scope["investigation_id"]}.pdf"'})


# ---------------------------------------------------------------------------
# risk scoring + risk management
# ---------------------------------------------------------------------------

class RiskRescoreRequest(BaseModel):
    investigation_id: int | None = None
    initiative_id: int | None = None
    scope: str | None = None


@app.post("/api/risks/rescore")
def post_risks_rescore(data: RiskRescoreRequest, request: Request, db: Session = Depends(get_db)):
    from . import risk_register as rr

    scope = data.scope or "investigation"
    if scope == "all":
        out = rr.rescore_scope(db, None, None)
    elif data.initiative_id:
        out = rr.rescore_scope(db, data.investigation_id, data.initiative_id)
    elif data.investigation_id:
        _landscape_inv(data.investigation_id, db)
        out = rr.rescore_scope(db, data.investigation_id, None)
    else:
        raise HTTPException(400, "investigation_id required")
    ledger_api.human_action(request, "risks_rescored", {"scope": scope, **out})
    return out


@app.post("/api/risks/{risk_id}/rescore")
def post_risk_rescore(risk_id: int, request: Request, db: Session = Depends(get_db)):
    from . import risk_register as rr

    try:
        out = rr.score_and_persist(db, risk_id)
    except LookupError as e:
        raise HTTPException(404, str(e))
    ledger_api.human_action(request, "risk_rescored", {"risk_id": risk_id, **{k: out.get(k) for k in ("band", "residual_score", "priority_score")}})
    return out


@app.get("/api/risks/{risk_id}")
def get_risk(risk_id: int, db: Session = Depends(get_db)):
    from .models import RiskEntry

    r = db.get(RiskEntry, risk_id)
    if not r:
        raise HTTPException(404, "Risk not found")
    return {
        "id": r.id, "risk_id": r.risk_id, "layer": r.layer, "scope": r.scope, "title": r.title,
        "status": r.status, "owner": r.owner, "inherent_score": r.inherent_score, "residual_score": r.residual_score,
        "priority_score": r.priority_score, "band": r.band, "confidence": r.confidence, "scoring_method": r.scoring_method,
        "scoring_fingerprint": r.scoring_fingerprint, "score_rationale": r.score_rationale, "inputs_hash": r.inputs_hash,
        "scored_at": r.scored_at.isoformat() if r.scored_at else None,
        "plain_summary": r.plain_summary, "treatment_plan": json.loads(r.treatment_plan_json or "{}") if r.treatment_plan_json else None,
        "monitor_flags": json.loads(r.monitor_flags_json or "[]") if r.monitor_flags_json else [],
    }


class RiskSyncRequest(BaseModel):
    investigation_id: int


@app.post("/api/risks/sync")
def post_risks_sync(data: RiskSyncRequest, request: Request, db: Session = Depends(get_db)):
    _landscape_inv(data.investigation_id, db)
    from .agents import risk_intake_handle, new_envelope

    env = new_envelope("api-caller", "risk-intake", "ingest_findings", {"investigation_id": data.investigation_id})
    try:
        res = risk_intake_handle(env, db)
    except Exception as e:
        raise HTTPException(500, str(e))
    ledger_api.human_action(request, "risk_sync", {"investigation_id": data.investigation_id, **res.get("payload", {})})
    return res.get("payload", {})


@app.post("/api/risks/review")
def post_risks_review(data: RiskSyncRequest, request: Request, db: Session = Depends(get_db)):
    _landscape_inv(data.investigation_id, db)
    from .agents import risk_orchestrator_handle, new_envelope

    env = new_envelope("api-caller", "risk-orchestrator", "plan_risk_cycle", {"investigation_id": data.investigation_id, "kind": "risk_review"})
    try:
        res = risk_orchestrator_handle(env, db)
    except Exception as e:
        raise HTTPException(500, str(e))
    ledger_api.human_action(request, "risk_review", {"investigation_id": data.investigation_id, **res.get("payload", {})})
    return res.get("payload", {})


class RiskDecideRequest(BaseModel):
    risk_ids: list[str]
    strategy: str = "accept"
    rationale: str = ""


@app.post("/api/risks/decide")
def post_risks_decide(data: RiskDecideRequest, request: Request, db: Session = Depends(get_db)):
    from .agents import risk_governance_handle, new_envelope

    env = new_envelope("api-caller", "risk-governance", "draft_acceptance", {"risk_ids": data.risk_ids, "strategy": data.strategy, "rationale": data.rationale})
    try:
        res = risk_governance_handle(env, db)
    except Exception as e:
        raise HTTPException(400, str(e))
    ledger_api.human_action(request, "risk_decide_drafted", {"risk_ids": data.risk_ids, "strategy": data.strategy})
    return res.get("payload", {})


@app.post("/api/risks/enrich")
def post_risks_enrich(data: RiskSyncRequest, request: Request, db: Session = Depends(get_db)):
    _landscape_inv(data.investigation_id, db)
    from .agents import risk_intake_handle, new_envelope

    env = new_envelope("api-caller", "risk-intake", "ingest_findings", {"investigation_id": data.investigation_id})
    try:
        res = risk_intake_handle(env, db)
    except Exception as e:
        raise HTTPException(500, str(e))
    ledger_api.human_action(request, "risk_enrich", {"investigation_id": data.investigation_id})
    return res.get("payload", {})
