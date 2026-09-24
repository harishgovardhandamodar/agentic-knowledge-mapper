import json
import os
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .database import init_db, get_db
from .models import Investigation, Artifact, Relationship, AgentRun, AgentEvent, Explanation
from . import llm, scheduler
from .agent import launch_run, launch_run_with_goal
from .explainer import (launch_explanation, _extract_concepts, MODES,
                        DEPTH_PLAN, AUDIENCE_HINTS, _question_suggestions,
                        _quiz_from_answer)

os.makedirs("data", exist_ok=True)

app = FastAPI(title="Agentic Knowledge Mapper")

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
        return FileResponse(os.path.join(static_dir, "index.html"))


@app.on_event("startup")
def on_start():
    init_db()
    scheduler.start()
    # Crash recovery: runs stuck in "running" (killed mid-flight) would
    # otherwise block new runs via the 429 guard.
    db = next(get_db())
    try:
        stale = db.query(AgentRun).filter(AgentRun.status == "running").all()
        for r in stale:
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


# ---------- helpers ----------

def _inv_json(inv: Investigation, db: Session) -> dict:
    n_art = db.query(Artifact).filter(Artifact.investigation_id == inv.id).count()
    n_rel = db.query(Relationship).filter(Relationship.investigation_id == inv.id).count()
    n_runs = db.query(AgentRun).filter(AgentRun.investigation_id == inv.id).count()
    return {
        "id": inv.id, "title": inv.title, "keywords": inv.keywords,
        "description": inv.description, "sources": inv.sources,
        "status": inv.status, "artifacts": n_art, "relationships": n_rel,
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
    }


# ---------- health ----------

@app.get("/api/health")
def health():
    return {"status": "ok", "llm": llm.health()}


# ---------- investigations ----------

@app.get("/api/investigations")
def list_investigations(db: Session = Depends(get_db)):
    invs = db.query(Investigation).order_by(Investigation.updated_at.desc()).all()
    return {"items": [_inv_json(i, db) for i in invs]}


@app.post("/api/investigations")
def create_investigation(data: InvestigationCreate, db: Session = Depends(get_db)):
    if not data.title.strip():
        raise HTTPException(400, "Title is required")
    inv = Investigation(title=data.title.strip()[:300],
                        keywords=(data.keywords or "")[:1000],
                        description=(data.description or ""),
                        sources=(data.sources or "rss,arxiv,web")[:200])
    db.add(inv)
    db.commit()
    db.refresh(inv)
    return _inv_json(inv, db)


@app.get("/api/investigations/{inv_id}")
def get_investigation(inv_id: int, db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(404, "Investigation not found")
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


# ---------- agent runs ----------

@app.post("/api/investigations/{inv_id}/run")
def start_run(inv_id: int, req: RunRequest, db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    if db.query(AgentRun).filter(AgentRun.investigation_id == inv_id,
                                 AgentRun.status == "running").first():
        raise HTTPException(429, "A run is already in progress for this investigation")
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

@app.get("/api/investigations/{inv_id}/artifacts")
def list_artifacts(inv_id: int, review: Optional[str] = Query(None),
                   search: Optional[str] = Query(None),
                   limit: int = Query(200, le=500), offset: int = Query(0),
                   db: Session = Depends(get_db)):
    q = db.query(Artifact).filter(Artifact.investigation_id == inv_id)
    if review and review != "all":
        q = q.filter(Artifact.review == review)
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
def review_artifact(artifact_id: int, data: ReviewUpdate, db: Session = Depends(get_db)):
    if data.review not in ("pending", "accepted", "rejected"):
        raise HTTPException(400, "Invalid review state")
    a = db.query(Artifact).filter(Artifact.id == artifact_id).first()
    if not a:
        raise HTTPException(404, "Artifact not found")
    a.review = data.review
    db.commit()
    return _artifact_json(a)


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
def search(q: str = Query(...), investigation_id: int = Query(...),
           db: Session = Depends(get_db)):
    items = (db.query(Artifact)
             .filter(Artifact.investigation_id == investigation_id,
                     Artifact.title.ilike(f"%{q}%")
                     | Artifact.description.ilike(f"%{q}%")
                     | Artifact.tags.ilike(f"%{q}%"))
             .limit(20).all())
    return {"items": [_artifact_json(a) for a in items]}


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
    }


@app.post("/api/investigations/{inv_id}/explain")
def ask_explainer(inv_id: int, req: ExplainRequest, db: Session = Depends(get_db)):
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
    answer = json.loads(e.answer)
    extracted = _extract_concepts(e.question, answer)
    concepts, relations = extracted["concepts"], extracted["relations"]

    # Dedup helpers.
    def norm_title(s):
        return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()

    def find_artifact(title, atype):
        return (db.query(Artifact).filter(
            Artifact.investigation_id == e.investigation_id,
            Artifact.artifact_type == atype,
            Artifact.title == title).first())

    def find_artifact_by_url(url):
        return (db.query(Artifact).filter(
            Artifact.investigation_id == e.investigation_id,
            Artifact.url == url).first())

    root_text = (answer.get("summary") or "") + "\n\n" + "\n\n".join(
        f"## {s.get('heading')}\n{s.get('body')}" for s in answer.get("sections") or [])
    root = find_artifact(e.question[:200], "essay")
    if not root:
        root = Artifact(investigation_id=e.investigation_id, title=e.question[:200],
                        artifact_type="essay", description=(answer.get("summary") or "")[:2000],
                        content=root_text[:6000], author="explainer",
                        tags="explainer," + (e.mode or "explain"),
                        relevance=None, review="pending", origin="agent")
        db.add(root)
        db.flush()

    # Concepts (dedup by normalized title) + Concept nodes.
    concept_ids = {}
    for c in concepts:
        t = c.get("name", "")[:200]
        if not t.strip():
            continue
        existing = None
        for art in db.query(Artifact).filter(
                Artifact.investigation_id == e.investigation_id,
                Artifact.artifact_type == "concept").all():
            if norm_title(art.title) == norm_title(t):
                existing = art
                break
        if existing:
            concept_ids[norm_title(t)] = existing.id
        else:
            a = Artifact(investigation_id=e.investigation_id, title=t[:200],
                         artifact_type="concept",
                         description=(c.get("definition") or "")[:1000],
                         author="explainer", tags="concept,explainer",
                         review="pending", origin="agent")
            db.add(a)
            db.flush()
            concept_ids[norm_title(t)] = a.id

    def add_rel(src, dst, rtype, desc=None):
        if src == dst:
            return False
        exists = (db.query(Relationship).filter(
            Relationship.investigation_id == e.investigation_id,
            Relationship.source_id == src, Relationship.target_id == dst,
            Relationship.relationship_type == rtype).first())
        if exists:
            return False
        db.add(Relationship(investigation_id=e.investigation_id, source_id=src,
                            target_id=dst, relationship_type=rtype,
                            description=desc, origin="agent"))
        return True

    n_rel = 0
    # Root EXPLAINS each concept.
    for nid in concept_ids.values():
        n_rel += add_rel(root.id, nid, "EXPLAINS")
    # Source links: root/explanation cites the web sources as artifacts (url match or new).
    for s in answer.get("sources") or []:
        url = s.get("url") or ""
        if not url.startswith("http"):
            continue
        art = find_artifact_by_url(url)
        if not art:
            art = Artifact(investigation_id=e.investigation_id,
                           title=(s.get("title") or url)[:200], artifact_type="source",
                           url=url, author="explainer",
                           tags="source,explainer", review="pending", origin="agent")
            db.add(art)
            db.flush()
    # Concept <-> source CITES edges where the answer used them.
    for sec in answer.get("sections") or []:
        for c in sec.get("claims") or []:
            for cit in c.get("citations") or []:
                idx = cit.get("sourceIndex")
                if not isinstance(idx, int):
                    continue
                src = (answer.get("sources") or [])[idx] if idx < len(answer.get("sources") or []) else None
                if not src or not (src.get("url") or "").startswith("http"):
                    continue
                art = db.query(Artifact).filter(
                    Artifact.url == src["url"]).first()
                if not art:
                    continue
                # link root EXPLAINS too
                n_rel += add_rel(root.id, art.id, "CITES")
    # Structured relations among concepts.
    n2id = concept_ids
    for r in relations:
        f = n2id.get(norm_title(r.get("from")))
        t = n2id.get(norm_title(r.get("to")))
        if f and t:
            n_rel += add_rel(f, t, r.get("type"))
    db.commit()
    return {"created_artifacts": len(concept_ids) + 1,
            "created_relationships": n_rel, "concepts": list(concept_ids.keys())}


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
    } for a in artifacts]
    edges = [{
        "id": r.id, "from": r.source_id, "to": r.target_id,
        "label": r.relationship_type,
        "title": r.description or "",
    } for r in relationships]
    return {"nodes": nodes, "edges": edges}


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
