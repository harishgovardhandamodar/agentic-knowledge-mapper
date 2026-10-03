"""Swarm runtime — four swarms over shared MCP tools, A2A bus.

GUI → API → Job queue → Swarm (orchestrators → specialists → MCP) → SQLite/Ledger
Orchestrators delegate via A2A envelopes (task_id = ledger run id); specialists
call MCP tools; deterministic core (risk_scoring, pack math, FTS, KB) is never
reimplemented in prompts.
"""

from __future__ import annotations

from typing import Any

from . import agents as A

# Swarm definitions: long-lived agent types, many short-lived tasks
SWARMS = {
    "knowledge": ["collector-orchestrator", "research-collector", "explainer", "drift-judge"],
    "assessment": ["security-orchestrator", "model-eval-orchestrator", "control-analyst",
                   "model-mitigation-analyst", "threat-intel", "model-adv-intel",
                   "provider-posture", "report-writer",
                   # model-assessment workflows (agents.py run_model_a2a_workflow,
                   # run_model_adversarial_a2a_workflow, run_hypothesis_a2a_workflow)
                   "model-orchestrator", "adversary-orchestrator",
                   "model-profiler", "model-internals", "model-privacy",
                   "model-reporter", "model-adversary", "misuse-scout",
                   "model-adoption-analyst", "hypothesis-analyst",
                   "hypothesis-verifier", "hypothesis-reporter",
                   "mitigation-advisor", "experiment-planner"],
    "risk": ["risk-orchestrator", "risk-intake", "risk-triage", "risk-treatment", "risk-monitor", "risk-governance", "risk-reporter"],
    "portfolio": ["manager-orchestrator", "synthesizer"],
}

# Shared tools across swarms
SHARED_TOOLS = ["research-collector", "profiler", "mcp-search"]


def swarm_for_agent(agent: str) -> str | None:
    for swarm, agents in SWARMS.items():
        if agent in agents:
            return swarm
    return None


def mcp_for_intent(intent: str) -> str | None:
    mapping = {
        "collect_research": "mcp-search",
        "map_attacks": "mcp-catalog",
        "ingest_findings": "mcp-register",
        "score_priority": "mcp-score",
        "propose_treatment": "mcp-score",
        "detect_stale": "mcp-register",
        "draft_brief": "mcp-brief",
        "search": "mcp-index",
        "suggest": "mcp-index",
        "upsert_risk": "mcp-register",
        "score_risk": "mcp-score",
    }
    return mapping.get(intent)
