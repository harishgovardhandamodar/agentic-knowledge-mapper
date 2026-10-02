"""mcp-graph — query_artifacts, upsert_node, upsert_edge, subgraph."""

from __future__ import annotations

from typing import Any

from ..database import SessionLocal


def query_artifacts(investigation_id: int, limit: int = 50) -> list[dict[str, Any]]:
    from ..models import Artifact

    db = SessionLocal()
    try:
        rows = db.query(Artifact).filter(Artifact.investigation_id == investigation_id).limit(limit).all()
        return [{"id": r.id, "title": r.title, "artifact_type": r.artifact_type, "tags": r.tags, "review": r.review} for r in rows]
    finally:
        db.close()


def upsert_node(investigation_id: int, title: str, artifact_type: str = "research", stable_key: str | None = None, **meta) -> dict[str, Any]:
    from ..models import Artifact
    import json

    db = SessionLocal()
    try:
        # idempotent on stable_key
        if stable_key:
            existing = db.query(Artifact).filter(Artifact.investigation_id == investigation_id, Artifact.stable_key == stable_key).first()
            if existing:
                return {"id": existing.id, "existing": True}
        art = Artifact(investigation_id=investigation_id, title=title[:500], artifact_type=artifact_type, stable_key=stable_key, node_meta=json.dumps(meta) if meta else None)
        db.add(art)
        db.commit()
        db.refresh(art)
        return {"id": art.id, "existing": False}
    finally:
        db.close()


def upsert_edge(investigation_id: int, source_id: int, target_id: int, relationship_type: str = "related_to", payload: dict | None = None) -> dict[str, Any]:
    from ..models import Relationship
    import json

    db = SessionLocal()
    try:
        stable = f"{source_id}|{relationship_type}|{target_id}"
        existing = db.query(Relationship).filter(Relationship.stable_key == stable, Relationship.investigation_id == investigation_id).first()
        if existing:
            return {"id": existing.id, "existing": True}
        rel = Relationship(investigation_id=investigation_id, source_id=source_id, target_id=target_id, relationship_type=relationship_type, payload_json=json.dumps(payload or {}), stable_key=stable)
        db.add(rel)
        db.commit()
        db.refresh(rel)
        return {"id": rel.id, "existing": False}
    finally:
        db.close()


def subgraph(investigation_id: int, node_types: list[str] | None = None, severity: str | None = None, limit: int = 200) -> dict[str, Any]:
    from ..models import Artifact, Relationship

    db = SessionLocal()
    try:
        q = db.query(Artifact).filter(Artifact.investigation_id == investigation_id)
        if node_types:
            q = q.filter(Artifact.artifact_type.in_(node_types))
        nodes = q.limit(limit).all()
        ids = {n.id for n in nodes}
        edges = db.query(Relationship).filter(Relationship.investigation_id == investigation_id, Relationship.source_id.in_(ids), Relationship.target_id.in_(ids)).limit(limit).all()
        return {
            "nodes": [{"id": n.id, "label": n.title[:40], "type": n.artifact_type} for n in nodes],
            "edges": [{"source": e.source_id, "target": e.target_id, "type": e.relationship_type} for e in edges],
            "counts": {"nodes": len(nodes), "edges": len(edges)},
        }
    finally:
        db.close()
