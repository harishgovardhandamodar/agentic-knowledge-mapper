"""Fox Security Research Core — switchable optimized core.

Pairs with Risk Console + Classic, covering collection, assessment,
model/provider/RLHF risk, landscape, scoring, risk management via
MCP tools, A2A, structured swarm (not unbounded chat).

This module is a thin facade over the four swarms and MCP tool layer.
When FOX_CORE_ENABLED and the request selects core=fox, the API routes
through this core's orchestrators; otherwise the classic path runs.
Ledger records core: fox vs classic per run.
"""

from __future__ import annotations

import os
from typing import Any

from . import swarm as swarm_runtime

FOX_CORE_ENABLED = os.getenv("FOX_CORE_ENABLED", "1") != "0"
FOX_CORE_HEADER = "X-Fox-Core"
FOX_CORE_QUERY = "core"


def is_fox_request(request) -> bool:
    if not FOX_CORE_ENABLED:
        return False
    try:
        if (request.headers.get(FOX_CORE_HEADER) or "").lower() == "fox":
            return True
        if (request.query_params.get(FOX_CORE_QUERY) or "").lower() == "fox":
            return True
    except Exception:
        pass
    return False


def core_for_request(request) -> str:
    return "fox" if is_fox_request(request) else "classic"


def swarm_for_task(task: str) -> str | None:
    return swarm_runtime.swarm_for_agent(task)


def mcp_for_intent(intent: str) -> str | None:
    return swarm_runtime.mcp_for_intent(intent)
