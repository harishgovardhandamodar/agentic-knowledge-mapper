"""Console BFF aggregators — read-only, compose existing stores.

No new scoring; every number is a count recomputable from rows.
Aggregators are thin: they call executive, portfolio, model_kb, etc., and
shape for the console's persona landings. The classic APIs remain canonical.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from .database import SessionLocal
from .models import Investigation

router = APIRouter(prefix="/api/console", tags=["console"])

PERSONAS = ("researcher", "lead", "privacy", "legal", "executive", "dpo")


def _inv_or_404(db: Session, inv_id: int) -> Investigation:
    inv = db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "Investigation not found")
    return inv


@router.get("/home")
def console_home(
    investigation_id: int = Query(..., description="Scope investigation"),
    persona: str = Query("executive", description="researcher|lead|privacy|legal|executive|dpo"),
    window_days: int = Query(90),
    db: Session = Depends(lambda: SessionLocal()),
):
    """Persona-specific landing payload. Same data, different emphasis."""
    from . import executive as ex
    from . import model_kb as kb

    persona = (persona or "executive").lower()
    if persona not in PERSONAS:
        persona = "executive"
    inv = _inv_or_404(db, investigation_id)
    scope = ex.resolve_scope(db, investigation_id, window_days=window_days)
    summary = ex.summary(db, investigation_id, scope)
    avail = ex.availability(db, investigation_id, scope)
    attn = ex.attention(db, investigation_id, scope)
    # privacy slice
    from . import portfolio as pf
    rows = pf.register_with_state(db, investigation_id)
    privacy_open = [r for r in rows if r.get("layer") == "privacy" and r.get("status") == "open"]
    # provider slice
    try:
        from . import provider_posture as pp

        # count providers with posture
        providers = len({r.get("product_name") for r in rows if r.get("product_name")})
    except Exception:
        providers = 0
    # model slice
    land = kb.landscape(db, investigation_id)
    base = {
        "investigation": {"id": inv.id, "title": inv.title},
        "persona": persona,
        "scope": scope,
        "summary": summary,
        "availability": avail,
        "attention": attn,
        "privacy": {"open_privacy": len(privacy_open), "sample": privacy_open[:5]},
        "providers": providers,
        "landscape": {"inventory": len(land.get("inventory") or []), "counts": land.get("counts", {})},
    }
    # persona emphasis: executive/ciso wants summary+attention, dpo wants privacy, researcher wants model
    if persona in ("executive", "lead"):
        base["emphasis"] = ["summary", "attention", "availability"]
    elif persona in ("privacy", "dpo"):
        base["emphasis"] = ["privacy", "providers", "attention"]
    elif persona == "legal":
        base["emphasis"] = ["attention", "privacy", "summary"]
    else:
        base["emphasis"] = ["landscape", "attention", "privacy"]
    return base


@router.get("/risks")
def console_risks(
    investigation_id: int = Query(...),
    layer: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    tag: str | None = None,
    owner: str | None = None,
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(lambda: SessionLocal()),
):
    """Unified risk register slice for console list."""
    from . import portfolio as pf

    inv = _inv_or_404(db, investigation_id)
    scope = {"investigation_id": investigation_id, "window_days": 90, "layer": layer, "exposure": None, "accepted_only": True, "cutoff": None, "initiative_id": None, "initiative_title": None}
    # Use register_with_state for read-only
    rows = pf.register_with_state(db, investigation_id)
    # apply filters
    if layer:
        rows = [r for r in rows if r.get("layer") == layer]
    if status:
        rows = [r for r in rows if r.get("status") == status]
    if tag:
        rows = [r for r in rows if tag in (r.get("situation_tags") or []) or tag == r.get("subclass")]
    if severity:
        sev = severity.lower()
        # map band names
        def band(r):
            s = r.get("severity")
            if s is None:
                return "unknown"
            try:
                sv = float(s)
                return "critical" if sv >= 80 else "high" if sv >= 60 else "medium" if sv >= 40 else "low"
            except Exception:
                return str(s).lower()

        rows = [r for r in rows if band(r) == sev]
    if owner:
        if owner == "unowned":
            rows = [r for r in rows if not r.get("owner")]
        else:
            rows = [r for r in rows if (r.get("owner") or "").lower() == owner.lower()]
    total = len(rows)
    rows = sorted(rows, key=lambda r: (-(r.get("severity") or 0), r.get("risk_id") or ""))[offset : offset + limit]
    return {"investigation_id": investigation_id, "total": total, "risks": rows, "limit": limit, "offset": offset}


@router.get("/brief")
def console_brief(
    investigation_id: int = Query(...),
    type: str = Query("board", description="board|privacy|counsel|tech"),
    window_days: int = Query(90),
    db: Session = Depends(lambda: SessionLocal()),
):
    """One-click briefs: board, privacy, counsel, tech — same structured payload pattern as dossier."""
    from . import executive as ex

    inv = _inv_or_404(db, investigation_id)
    scope = ex.resolve_scope(db, investigation_id, window_days=window_days)
    md = ex.brief_markdown(db, investigation_id, scope)
    # For now, counsel and tech reuse same markdown with a header note; privacy memo filters to privacy layer
    if type == "privacy":
        md = "# Privacy memo — " + (inv.title or "") + "\n\n" + md
    elif type == "counsel":
        md = "# Counsel pack — " + (inv.title or "") + "\n\n> Stated policy / Independent / Unknown — footnotes are artifact URLs.\n\n" + md
    elif type == "tech":
        md = "# Tech register — " + (inv.title or "") + "\n\n" + md
    return {"investigation_id": investigation_id, "type": type, "markdown": md, "scope": scope}
