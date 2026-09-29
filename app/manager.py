"""Agentic Manager: one command fans out to N investigations + a summary.

A command like "run detailed security investigations on AI agents in
finance, especially payments / trade / DeFi / crypto" is understood
(LLM first, deterministic splitter when the model is unreachable) and
served: one investigation per topic, each with a research run and a
security assessment launched, plus a summary investigation that compiles
finished children on demand.

Nothing runs in the background: launches are fire-and-forget threads owned
by the agent/security runners, statuses are derived live from their tables
on every read, and the summary compiles only when asked. A restart
mid-flight leaves recoverable rows, never a stuck watcher.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

from . import llm
from .agent import launch_run
from .models import AgentRun, Artifact, Investigation, SecurityAssessment
from .security import EXPOSURE_META
from .security_agent import launch_security_assessment

MAX_TOPICS = 6
SYNTH_TAG = "manager-synthesis"
COMPILE_TRUNC = 1500

_LEAD = re.compile(
    r"^(run|start|launch|do|please\s+)?(a\s+|an\s+)?(detailed\s+)?(new\s+)?"
    r"(security\s+)?(investigations?|investigational|research|study|studies|"
    r"analysis|analyses)\s+(on|about|into|for|of)?\s*",
    re.IGNORECASE)
_SPLIT = re.compile(r"\s*/\s*|\s*;\s*|\n+|\s*\d+[.)]\s+")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def split_command(command: str) -> dict[str, Any]:
    """Deterministic fallback parse: slashes/semicolons/lines split topics.

    "… finance domain, especially A / B / C" yields domain "… finance
    domain" and topics A, B, C; without "especially" the whole (de-verbed)
    command is split. Same shape as the LLM parse, flagged heuristic.
    """
    text = (command or "").strip()
    domain, rest = "", text
    m = re.search(r"\bespecially\b", text, re.IGNORECASE)
    if m:
        domain, rest = text[:m.start()], text[m.end():]
    rest = _LEAD.sub("", rest).strip().rstrip(".")
    if not domain:
        domain = _LEAD.sub("", text).strip().rstrip(".")
    parts = [p.strip().rstrip(".") for p in _SPLIT.split(rest) if p.strip()]
    topics = [{"title": p[:120], "description": p,
               "keywords": p, "focus": []} for p in parts if p]
    domain = re.sub(r"\s+", " ", domain).strip().rstrip(".")[:200]
    return {"domain": domain, "exposure": "confidential_data",
            "topics": topics,
            "summary": {"title": f"Summary: {domain or text[:60]}",
                        "description": f"Synthesis of: {', '.join(t['title'] for t in topics)}"},
            "parsed_by": "heuristic"}


def _llm_parse(command: str) -> dict[str, Any]:
    out = llm.chat_json([
        {"role": "system",
         "content": ("You split a research command into scoped investigations. "
                     "Reply JSON only: {\"domain\": str, "
                     "\"exposure\": one of restricted_data|confidential_data|internal|public, "
                     "\"topics\": [{\"title\": str (<=120 chars), \"description\": str, "
                     "\"keywords\": str, \"focus\": [str]}], "
                     "\"summary\": {\"title\": str, \"description\": str}}. "
                     "Cover each named sub-topic as its own topic; no filler topics.")},
        {"role": "user", "content": command[:2000]}],
        max_tokens=1200, temperature=0.2)
    if not isinstance(out, dict):
        raise ValueError("model did not return a plan object")
    topics = out.get("topics") or []
    norm = []
    for t in topics:
        if not isinstance(t, dict):
            continue
        norm.append({"title": str(t.get("title") or "")[:120],
                     "description": str(t.get("description") or ""),
                     "keywords": str(t.get("keywords") or "")[:1000],
                     "focus": [str(f) for f in (t.get("focus") or [])][:8]})
    summary = out.get("summary") or {}
    return {"domain": str(out.get("domain") or "")[:200],
            "exposure": str(out.get("exposure") or "confidential_data"),
            "topics": norm,
            "summary": {"title": str(summary.get("title") or "")[:300],
                        "description": str(summary.get("description") or "")},
            "parsed_by": "llm"}


def parse_command(command: str) -> dict[str, Any]:
    """Understand a command.

    LLM first; the deterministic splitter whenever the model is unreachable
    *or* its plan validates to nothing. Only raises when both paths fail.
    """
    command = (command or "").strip()
    if not command:
        raise ValueError("command is empty")
    try:
        return validate_plan(_llm_parse(command))
    except Exception:
        pass
    return validate_plan(split_command(command))


def validate_plan(plan: dict[str, Any]) -> dict[str, Any]:
    """Cap, clean and dedupe a plan. Raises ValueError when unusable."""
    if not isinstance(plan, dict):
        raise ValueError("plan must be an object")
    topics = []
    seen = set()
    for t in (plan.get("topics") or []):
        if not isinstance(t, dict):
            continue
        title = str(t.get("title") or "").strip()
        if not title or title.lower() in seen:
            continue
        seen.add(title.lower())
        topics.append({"title": title[:120],
                       "description": str(t.get("description") or title),
                       "keywords": str(t.get("keywords") or title)[:1000],
                       "focus": [str(f) for f in (t.get("focus") or [])][:8]})
    if not topics:
        raise ValueError("no usable topics in command")
    truncated = False
    if len(topics) > MAX_TOPICS:
        topics = topics[:MAX_TOPICS]
        truncated = True
    exposure = str(plan.get("exposure") or "confidential_data")
    if exposure not in EXPOSURE_META:
        exposure = "confidential_data"
    summary = plan.get("summary") or {}
    out = {"domain": str(plan.get("domain") or "")[:200],
           "exposure": exposure,
           "topics": topics,
           "summary": {"title": str(summary.get("title") or
                                   f"Summary: {topics[0]['title']} +{len(topics) - 1}")[:300],
                       "description": str(summary.get("description") or "")},
           "parsed_by": plan.get("parsed_by") or "unknown",
           "truncated": truncated}
    return out


def _run_row(db, run) -> dict[str, Any]:
    plan = {}
    try:
        plan = json.loads(run.plan_json or "{}")
    except Exception:
        plan = {}
    topics = plan.get("topics") or []
    children = []
    all_done = True
    for t in topics:
        inv_id = t.get("investigation_id")
        inv = db.query(Investigation).filter(
            Investigation.id == inv_id).first() if inv_id else None
        runs = (db.query(AgentRun).filter(AgentRun.investigation_id == inv_id)
                .order_by(AgentRun.id.desc()).all()) if inv_id else []
        assessment = None
        if inv_id:
            rec = (db.query(SecurityAssessment)
                   .filter(SecurityAssessment.investigation_id == inv_id)
                   .order_by(SecurityAssessment.id.desc()).first())
            if rec is not None:
                assessment = {"id": rec.id,
                              "overall_pct": rec.overall_pct,
                              "residual_pct": rec.residual_pct,
                              "has_markdown": bool(rec.markdown)}
        research_runs = [r for r in runs if (r.trigger or "manual") != "security"]
        research_done = (inv is not None and inv.status == "ready") or \
            (research_runs and all(r.status in ("done", "error") for r in research_runs)) \
            or (not research_runs and plan.get("options", {}).get("research") is False)
        assess_done = (plan.get("options", {}).get("assessment") is False) or \
            (assessment is not None)
        done = research_done and assess_done
        all_done = all_done and done
        children.append({
            "title": t.get("title"), "investigation_id": inv_id,
            "investigation_status": inv.status if inv else None,
            "research": {"runs": len(research_runs),
                         "done": research_done,
                         "latest": research_runs[0].status if research_runs else None},
            "assessment": assessment,
            "assessment_done": assess_done,
            "done": done,
        })
    compiled = False
    summary_id = run.summary_investigation_id
    if summary_id:
        synth = (db.query(Artifact)
                 .filter(Artifact.investigation_id == summary_id,
                         Artifact.tags.like(f"%{SYNTH_TAG}%"))
                 .order_by(Artifact.id.desc()).first())
        compiled = synth is not None
    return {"id": run.id, "command": run.command, "status": run.status,
            "created_at": run.created_at.isoformat() if run.created_at else None,
            "summary_investigation_id": summary_id,
            "topics": topics, "children": children,
            "all_done": all_done, "compiled": compiled}


def run_plan(db, plan: dict[str, Any], options: dict[str, Any] | None = None) -> dict[str, Any]:
    """Create investigations, launch research + assessments, link a summary."""
    from .models import ManagerRun
    plan = validate_plan(plan)
    options = {"research": True, "assessment": True, **(options or {})}
    plan["options"] = options
    run = ManagerRun(command=plan.get("command") or "",
                     plan_json=json.dumps(plan), status="running")
    db.add(run)
    db.commit()
    db.refresh(run)
    footer = f"\n\nPart of manager run #{run.id}."
    for t in plan["topics"]:
        inv = Investigation(
            title=t["title"][:300],
            keywords=t.get("keywords", "")[:1000],
            description=(t.get("description", "") + footer),
            status="draft")
        db.add(inv)
        db.commit()
        db.refresh(inv)
        t["investigation_id"] = inv.id
        if options.get("research"):
            launch_run(inv.id, trigger=f"manager:{run.id}")
        if options.get("assessment"):
            launch_security_assessment(
                inv.id,
                {"product_name": t["title"][:120],
                 "use_case": t.get("description", ""),
                 "exposure": plan["exposure"],
                 "declared_controls": [],
                 "doc_urls": [],
                 "focus": t.get("focus", [])},
                requested_by=f"manager run {run.id}")
    summary = plan.get("summary") or {}
    names = ", ".join(f"#{t.get('investigation_id')} {t['title']}"
                      for t in plan["topics"])
    summ = Investigation(
        title=(summary.get("title") or f"Manager run #{run.id} summary")[:300],
        keywords=(plan.get("domain") or "")[:1000],
        description=((summary.get("description") or "") +
                     f"\n\nSynthesizes manager run #{run.id}: {names}."
                     f"\nCommand: {run.command}"),
        status="draft")
    db.add(summ)
    db.commit()
    db.refresh(summ)
    run.summary_investigation_id = summ.id
    run.plan_json = json.dumps(plan)
    db.commit()
    return _run_row(db, run)


def compile_run(db, run_id: int) -> dict[str, Any]:
    """Synthesize finished children into the summary investigation.

    409 while anything still runs; idempotent (an existing synthesis is
    returned, never duplicated).
    """
    from .models import ManagerRun
    run = db.query(ManagerRun).filter(ManagerRun.id == run_id).first()
    if run is None:
        raise LookupError("manager run not found")
    row = _run_row(db, run)
    pending = [c["title"] for c in row["children"] if not c["done"]]
    if pending:
        raise PendingChildren(pending)
    summary_id = run.summary_investigation_id
    synth = (db.query(Artifact)
             .filter(Artifact.investigation_id == summary_id,
                     Artifact.tags.like(f"%{SYNTH_TAG}%"))
             .order_by(Artifact.id.desc()).first())
    if synth is not None:
        return {"artifact_id": synth.id, "summary_investigation_id": summary_id,
                "markdown": synth.content, "existing": True}
    briefs = []
    for c in row["children"]:
        inv = db.query(Investigation).filter(
            Investigation.id == c["investigation_id"]).first()
        rec = (db.query(SecurityAssessment)
               .filter(SecurityAssessment.investigation_id == c["investigation_id"])
               .order_by(SecurityAssessment.id.desc()).first())
        md = ""
        if rec is not None and rec.markdown:
            md = rec.markdown[:COMPILE_TRUNC]
        arts = (db.query(Artifact)
                .filter(Artifact.investigation_id == c["investigation_id"]).count())
        briefs.append(
            f"## {c['title']}\n"
            f"Residual {getattr(rec, 'residual_pct', None)} "
            f"(overall {getattr(rec, 'overall_pct', None)}), "
            f"{arts} artifacts.\n{md}")
    plan = {}
    try:
        plan = json.loads(run.plan_json or "{}")
    except Exception:
        plan = {}
    text = llm.chat(
        [{"role": "system",
          "content": ("You synthesize completed security investigations into one "
                      "executive summary. Reply markdown: overall verdict, "
                      "per-topic findings, cross-cutting risks, and next steps. "
                      "Ground every claim in the briefs; invent nothing.")},
         {"role": "user",
          "content": f"Command: {run.command}\n\n" + "\n\n".join(briefs)}],
        max_tokens=3000, temperature=0.2)
    art = Artifact(investigation_id=summary_id,
                   title=f"Manager synthesis (run #{run.id})",
                   artifact_type="research",
                   description=f"Synthesis of {len(briefs)} investigations.",
                   content=text, source="agentic-manager",
                   tags=SYNTH_TAG)
    db.add(art)
    summ = db.query(Investigation).filter(
        Investigation.id == summary_id).first()
    if summ is not None:
        summ.status = "ready"
    run.status = "compiled"
    db.commit()
    db.refresh(art)
    return {"artifact_id": art.id, "summary_investigation_id": summary_id,
            "markdown": text, "existing": False}


class PendingChildren(Exception):
    def __init__(self, pending: list[str]):
        super().__init__("children still running")
        self.pending = pending
