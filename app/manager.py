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
from .models import (AgentEvent, AgentRun, Artifact, Investigation,
                     SecurityAssessment)
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
    synthesis_artifact_id = None
    summary_id = run.summary_investigation_id
    if summary_id:
        synth = (db.query(Artifact)
                 .filter(Artifact.investigation_id == summary_id,
                         Artifact.tags.like(f"%{SYNTH_TAG}%"))
                 .order_by(Artifact.id.desc()).first())
        compiled = synth is not None
        synthesis_artifact_id = synth.id if synth is not None else None
    return {"id": run.id, "command": run.command, "status": run.status,
            "created_at": run.created_at.isoformat() if run.created_at else None,
            "summary_investigation_id": summary_id,
            "synthesis_artifact_id": synthesis_artifact_id,
            "topics": topics, "children": children,
            "all_done": all_done, "compiled": compiled}


def run_plan(db, plan: dict[str, Any], options: dict[str, Any] | None = None,
             command: str = "") -> dict[str, Any]:
    """Create investigations, launch research + assessments, link a summary."""
    from .models import ManagerRun
    plan = validate_plan(plan)
    options = {"research": True, "assessment": True, **(options or {})}
    plan["options"] = options
    run = ManagerRun(command=command or plan.get("command") or "",
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
    topics_risks: list[tuple[str, list[dict[str, Any]]]] = []
    for c in row["children"]:
        inv = db.query(Investigation).filter(
            Investigation.id == c["investigation_id"]).first()
        rec = (db.query(SecurityAssessment)
               .filter(SecurityAssessment.investigation_id == c["investigation_id"])
               .order_by(SecurityAssessment.id.desc()).first())
        md = ""
        threats: list[Any] = []
        if rec is not None:
            if rec.markdown:
                md = rec.markdown[:COMPILE_TRUNC]
            try:
                threats = json.loads(rec.threats_json or "[]")
            except Exception:
                threats = []
        arts = (db.query(Artifact)
                .filter(Artifact.investigation_id == c["investigation_id"]).count())
        risks = topic_top_risks(threats)
        topics_risks.append((c["title"], risks))
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
    overlaps = find_overlaps(topics_risks)
    lapses = find_lapses(topics_risks)
    tables = render_summary_tables(topics_risks, overlaps, lapses)
    text = llm.chat(
        [{"role": "system",
          "content": ("You are given fact tables (top risks, overlaps, lapses) "
                      "plus assessment briefs. Do NOT repeat the tables. Reply "
                      "markdown with: overall verdict in two sentences, "
                      "cross-cutting patterns across topics, what the evidence "
                      "does not cover, and concrete next steps. Ground every "
                      "claim in the briefs; invent nothing.")},
         {"role": "user",
          "content": f"Command: {run.command}\n\n{tables}\n\n" + "\n\n".join(briefs)}],
        max_tokens=3000, temperature=0.2)
    markdown = tables + "\n## Synthesis\n\n" + (text or "").strip() + "\n"
    art = Artifact(investigation_id=summary_id,
                   title=f"Manager synthesis (run #{run.id})",
                   artifact_type="research",
                   description=f"Synthesis of {len(briefs)} investigations.",
                   content=markdown, source="agentic-manager",
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
            "markdown": markdown, "existing": False}


class PendingChildren(Exception):
    def __init__(self, pending: list[str]):
        super().__init__("children still running")
        self.pending = pending


TOP_RISKS_PER_TOPIC = 5
LAPSE_COVERAGE_PCT = 50.0


def topic_top_risks(threats: list[Any], n: int = TOP_RISKS_PER_TOPIC) -> list[dict[str, Any]]:
    """Worst-first threat rows, trimmed to the fields the summary needs."""
    rows = [t for t in (threats or []) if isinstance(t, dict) and t.get("id")]
    rows.sort(key=lambda t: -(t.get("residual_score") or 0)
              if isinstance(t.get("residual_score"), (int, float)) else -1)
    return [{"id": t.get("id"), "title": t.get("title", ""),
             "residual_severity": t.get("residual_severity"),
             "residual_score": t.get("residual_score"),
             "coverage": t.get("coverage"),
             "controls": t.get("controls") or []} for t in rows[:n]]


def find_overlaps(topics_risks: list[tuple[str, list[dict[str, Any]]]]) -> list[dict[str, Any]]:
    """Threat ids striking in 2+ topics: the common risks. Sorted by reach,
    then worst residual."""
    by_id: dict[str, dict[str, Any]] = {}
    for topic, risks in topics_risks:
        for r in risks:
            cell = by_id.setdefault(r["id"], {"id": r["id"], "title": r["title"],
                                              "topics": [], "residuals": []})
            cell["topics"].append(topic)
            if isinstance(r.get("residual_score"), (int, float)):
                cell["residuals"].append(r["residual_score"])
    out = [c for c in by_id.values() if len(c["topics"]) >= 2]
    for c in out:
        c["max_residual"] = max(c["residuals"]) if c["residuals"] else None
    out.sort(key=lambda c: (-len(c["topics"]),
                            -(c["max_residual"] or 0)))
    return out


def find_lapses(topics_risks: list[tuple[str, list[dict[str, Any]]]]) -> list[dict[str, Any]]:
    """High/Critical residuals with less than half coverage: the lapses."""
    out = []
    for topic, risks in topics_risks:
        for r in risks:
            cov = r.get("coverage")
            cov = float(cov) if isinstance(cov, (int, float)) else 100.0
            if r.get("residual_severity") in ("Critical", "High") \
                    and cov < LAPSE_COVERAGE_PCT:
                out.append({"topic": topic, **r})
    out.sort(key=lambda r: (-(r.get("residual_score") or 0)))
    return out


def render_summary_tables(topics_risks: list[tuple[str, list[dict[str, Any]]]],
                          overlaps: list[dict[str, Any]],
                          lapses: list[dict[str, Any]]) -> str:
    """Deterministic fact sections: present even when the model is terse."""
    L = ["## Top risks by topic", ""]
    for topic, risks in topics_risks:
        L.append(f"### {topic}")
        L.append("")
        L.append("| Threat | Severity | Residual | Coverage | Controls |")
        L.append("|---|---|---|---|---|")
        for r in risks:
            cov = r.get("coverage")
            cov_s = f"{cov:g}%" if isinstance(cov, (int, float)) else "–"
            res = r.get("residual_score")
            res_s = f"{res:g}" if isinstance(res, (int, float)) else "–"
            ctls = ", ".join(r.get("controls") or []) or "–"
            L.append(f"| {r['id']} {r['title']} | {r.get('residual_severity') or '–'} "
                     f"| {res_s} | {cov_s} | {ctls} |")
        L.append("")
    L += ["## Overlaps — common risks", ""]
    if overlaps:
        L.append("| Threat | Topics | Worst residual |")
        L.append("|---|---|---|")
        for o in overlaps:
            mr = f"{o['max_residual']:g}" if isinstance(o.get("max_residual"), (int, float)) else "–"
            L.append(f"| {o['id']} {o['title']} | {len(o['topics'])}: "
                     f"{', '.join(o['topics'])} | {mr} |")
    else:
        L.append("No threat id strikes in more than one topic.")
    L += ["", "## Lapses", ""]
    if lapses:
        L.append("| Topic | Threat | Severity | Residual | Coverage |")
        L.append("|---|---|---|---|---|")
        for r in lapses:
            res = r.get("residual_score")
            res_s = f"{res:g}" if isinstance(res, (int, float)) else "–"
            cov = r.get("coverage")
            cov_s = f"{cov:g}%" if isinstance(cov, (int, float)) else "–"
            L.append(f"| {r['topic']} | {r['id']} {r['title']} | "
                     f"{r.get('residual_severity') or '–'} | {res_s} | {cov_s} |")
    else:
        L.append("No High/Critical residual under half coverage.")
    L.append("")
    return "\n".join(L)


# Stage -> subagent role, per runner kind. Unknown stages fall through to
# the stage name itself so a new event never renders blank.
SUBAGENTS = {
    "manager": {"command": "orchestrator", "plan": "orchestrator",
                "create": "orchestrator", "launch": "orchestrator",
                "compile": "synthesizer"},
    "research": {"plan": "planner", "search": "research-collector",
                 "analyze": "analyzer", "map": "mapper",
                 "summary": "writer", "cve": "cve-sweeper",
                 "queue": "queue"},
    "security": {"plan": "security-orchestrator", "gate": "control-analyst",
                 "controls": "control-analyst", "score": "scoring",
                 "search": "research-collector", "analyze": "threat-intel",
                 "map": "mapper", "summary": "report-writer",
                 "queue": "queue", "cve": "cve-sweeper"},
}

MAX_EVENTS_PER_LANE = 50


def subagent(kind: str, stage: Any) -> str:
    stage = str(stage or "")
    return SUBAGENTS.get(kind, {}).get(stage, stage or "unknown")


def _iso(ts: Any) -> str | None:
    """ISO timestamp, normalized to naive UTC so DB rows and fresh markers
    sort and subtract comparably (SQLite returns naive datetimes)."""
    try:
        if ts is None:
            return None
        if getattr(ts, "tzinfo", None) is not None:
            ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
        return ts.isoformat()
    except Exception:
        return None


def run_timeline(db, run_id: int) -> dict[str, Any]:
    """Execution flow of a manager run: lanes, timestamped subagent actions,
    and a flow strip for the overview. Pure reads; safe to poll."""
    from .models import ManagerRun
    run = db.query(ManagerRun).filter(ManagerRun.id == run_id).first()
    if run is None:
        raise LookupError("manager run not found")
    row = _run_row(db, run)
    try:
        plan = json.loads(run.plan_json or "{}")
    except Exception:
        plan = {}
    topics = plan.get("topics") or []

    lanes = [{"id": "manager", "label": "Manager", "kind": "manager"}]
    for i, t in enumerate(topics):
        lanes.append({"id": f"topic-{t.get('investigation_id') or i}",
                      "label": t.get("title") or f"Topic {i + 1}",
                      "kind": "topic",
                      "investigation_id": t.get("investigation_id")})
    summary_title = ((plan.get("summary") or {}).get("title")
                     or "Summary")
    lanes.append({"id": "summary", "label": summary_title, "kind": "summary",
                  "investigation_id": run.summary_investigation_id})

    events: list[dict[str, Any]] = []

    def ev(ts, lane, agent, stage, label, status="done", ref=None):
        if ts is None:
            return
        events.append({"t": _iso(ts), "lane": lane, "agent": agent,
                       "stage": stage, "label": str(label or "")[:280],
                       "status": status, "ref": ref or {}})

    ev(run.created_at, "manager", "orchestrator", "command",
       f"Command received ({len(run.command or '')} chars)", "done",
       {"type": "run", "id": run.id})
    ev(run.created_at, "manager", "orchestrator", "plan",
       f"Plan: {len(topics)} topics "
       f"({(plan.get('parsed_by') or 'unknown')})", "done",
       {"type": "run", "id": run.id})

    for i, t in enumerate(topics):
        inv_id = t.get("investigation_id")
        lane = f"topic-{inv_id or i}"
        inv = db.query(Investigation).filter(
            Investigation.id == inv_id).first() if inv_id else None
        if inv is not None:
            ev(inv.created_at, lane, "orchestrator", "create",
               f"Investigation #{inv.id} created", "done",
               {"type": "investigation", "id": inv.id})
        if not inv_id:
            continue
        runs = (db.query(AgentRun)
                .filter(AgentRun.investigation_id == inv_id)
                .order_by(AgentRun.id).all())
        for r in runs:
            kind = "security" if (r.trigger or "") == "security" \
                else "research"
            agent = ("security-agent" if kind == "security"
                     else "investigation-agent")
            ev(r.started_at or (r.events[0].created_at if r.events else None),
               lane, agent, "run",
               f"{agent} run #{r.id} started"
               + (f" ({r.trigger})" if r.trigger else ""), "done",
               {"type": "run", "id": r.id})
            for e in (db.query(AgentEvent)
                      # Join, don't just filter by run_id: bulk deletes elsewhere
                      # (query.delete() skips ORM cascades) can orphan events
                      # whose run is gone, and rowid reuse would then attach
                      # ghosts to a later run with the same id.
                      .join(AgentRun, AgentEvent.run_id == AgentRun.id)
                      .filter(AgentEvent.run_id == r.id)
                      .order_by(AgentEvent.id).all()):
                ev(e.created_at, lane, subagent(kind, e.stage), e.stage,
                   e.message, "done", {"type": "run", "id": r.id})
            if (r.status or "") not in ("done", "error"):
                ev(_now(), lane, agent, "run",
                   f"Run #{r.id} {r.status}…", "running",
                   {"type": "run", "id": r.id})
            else:
                ev(r.finished_at, lane, agent, "run",
                   f"Run #{r.id} {r.status}", "done",
                   {"type": "run", "id": r.id})
        rec = (db.query(SecurityAssessment)
               .filter(SecurityAssessment.investigation_id == inv_id)
               .order_by(SecurityAssessment.id.desc()).first())
        if rec is not None:
            ev(rec.created_at, lane, "scoring", "score",
               f"Assessment #{rec.id}: residual {rec.residual_pct}/100", "done",
               {"type": "assessment", "id": rec.id})

    if run.summary_investigation_id:
        synth = (db.query(Artifact)
                 .filter(Artifact.investigation_id == run.summary_investigation_id,
                         Artifact.tags.like(f"%{SYNTH_TAG}%"))
                 .order_by(Artifact.id.desc()).first())
        if synth is not None:
            ev(synth.created_at, "summary", "synthesizer", "compile",
               f"Summary compiled (artifact #{synth.id})", "done",
               {"type": "artifact", "id": synth.id})

    events.sort(key=lambda e: (e["t"] or "", e["lane"]))
    by_lane: dict[str, list] = {}
    for e in events:
        by_lane.setdefault(e["lane"], []).append(e)
    truncated: dict[str, int] = {}
    capped: list[dict[str, Any]] = []
    for lane_id, evs in by_lane.items():
        if len(evs) > MAX_EVENTS_PER_LANE:
            half = MAX_EVENTS_PER_LANE // 2
            truncated[lane_id] = len(evs) - MAX_EVENTS_PER_LANE
            evs = evs[:half] + evs[-(MAX_EVENTS_PER_LANE - half):]
        capped.extend(evs)
    capped.sort(key=lambda e: (e["t"] or "", e["lane"]))

    options = plan.get("options", {})
    children = row.get("children") or []
    r_done = sum(1 for c in children if (c.get("research") or {}).get("done"))
    r_total = sum(1 for _ in children) if options.get("research", True) else 0
    a_done = sum(1 for c in children if c.get("assessment_done"))
    a_total = sum(1 for _ in children) if options.get("assessment", True) else 0
    summ_state = "done" if row.get("compiled") else (
        "active" if row.get("all_done") else "pending")
    flow = [
        {"key": "command", "label": "Command", "state": "done",
         "detail": f"{len(run.command or '')} chars"},
        {"key": "plan", "label": "Plan",
         "state": "done",
         "detail": f"{len(topics)} topics ({plan.get('parsed_by') or '?'})"},
        {"key": "topics", "label": "Investigations",
         "state": "done" if children else "pending",
         "detail": f"{len(children)} created"},
        {"key": "research", "label": "Research",
         "state": ("done" if r_total and r_done >= r_total else
                   "active" if r_done else "pending") if r_total else "pending",
         "detail": f"{r_done}/{r_total} done" if r_total else "skipped"},
        {"key": "assessment", "label": "Assessments",
         "state": ("done" if a_total and a_done >= a_total else
                   "active" if a_done else "pending") if a_total else "pending",
         "detail": f"{a_done}/{a_total} done" if a_total else "skipped"},
        {"key": "summary", "label": "Summary", "state": summ_state,
         "detail": ("compiled" if row.get("compiled") else
                    "ready to compile" if row.get("all_done") else "waiting")},
    ]
    return {"run_id": run.id, "t0": _iso(run.created_at),
            "lanes": lanes, "events": capped, "flow": flow,
            "truncated": truncated}
