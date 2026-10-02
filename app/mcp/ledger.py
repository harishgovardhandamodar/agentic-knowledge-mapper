"""mcp-ledger — append_event, request_approval, verify."""

from __future__ import annotations

from typing import Any

from .. import ledger as L
from ..database import SessionLocal


def append_event(run_id: str, kind: str, actor: str, data: dict | None = None) -> str:
    return L.append(run_id, kind, actor, data=data or {})


def request_approval(run_id: str, kind: str, subject_hash: str, **kwargs) -> int:
    return L.request_approval(run_id, kind, subject_hash, **kwargs)


def verify(run_id: str) -> dict[str, Any]:
    return L.verify(run_id)
