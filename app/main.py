import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .database import init_db, get_db
from .models import Investigation, Artifact, Relationship, AgentRun, AgentEvent
from . import llm
from .agent import launch_run

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
