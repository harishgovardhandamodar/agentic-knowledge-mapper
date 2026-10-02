"""mcp-brief — render_brief, dossier_slice."""

from __future__ import annotations

from typing import Any

from ..database import SessionLocal


def render_brief(investigation_id: int, type: str = "board") -> dict[str, Any]:
    from .. import executive as ex

    db = SessionLocal()
    try:
        scope = ex.resolve_scope(db, investigation_id)
        md = ex.brief_markdown(db, investigation_id, scope)
        if type == "privacy":
            md = "# Privacy memo — " + md
        elif type == "counsel":
            md = "# Counsel pack — " + md
        return {"investigation_id": investigation_id, "type": type, "markdown": md}
    finally:
        db.close()


def dossier_slice(investigation_id: int, section: str = "executive") -> dict[str, Any]:
    from .. import dossier as d

    db = SessionLocal()
    try:
        dos = d.investigation_dossier(db, investigation_id)
        # return a slice
        if section == "executive":
            return {"executive_summary": dos.get("executive_summary"), "investigation": dos.get("investigation")}
        return dos
    finally:
        db.close()
