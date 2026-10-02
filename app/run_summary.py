"""Run summary report — one markdown report per run, everywhere.

Every run (an investigation, or an agentic-manager fan-out) gets a single
summary report that aggregates what the run produced: security & privacy
risks, findings, experiments, hypotheses, every stored mermaid diagram, and
the full collected-artifact inventory. The same markdown renders in the
Classic GUI, the Risk Console reader, and the agentic-manager panel, so the
three surfaces agree on what a run produced.

Everything here reads stored rows; nothing re-runs agents or the LLM.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from . import dossier as _dossier
from .models import Artifact, Investigation, ManagerRun, SecurityAssessment


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _loads(raw, default):
    try:
        return json.loads(raw) if raw else default
    except Exception:
        return default


def latest_assessment(db, inv_id: int):
    return (db.query(SecurityAssessment)
            .filter(SecurityAssessment.investigation_id == inv_id)
            .order_by(SecurityAssessment.id.desc()).first())


def _f(value, default="—") -> str:
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return f"{value:g}" if float(value).is_integer() else f"{value:.1f}"
    return str(value)


# --------------------------------------------------------------------------
# Section builders (per assessment)
# --------------------------------------------------------------------------

def _risks_section(rec) -> list[str]:
    """Top security & privacy risks from the stored threat set (includes
    model RM*/privacy PDP* rows for model subjects)."""
    threats = _loads(getattr(rec, "threats_json", None), []) or []
    if isinstance(threats, dict):
        threats = threats.get("threats") or []
    rows = []
    for t in threats:
        if not isinstance(t, dict):
            continue
        rows.append({
            "id": t.get("id") or t.get("threat_id") or "?",
            "title": t.get("title") or t.get("name") or "",
            "severity": t.get("severity") or t.get("level") or "",
            "residual": t.get("residual_score"),
            "inherent": t.get("inherent_score") or t.get("score"),
            "coverage": t.get("coverage"),
            "dimension": t.get("dimension") or "",
        })
    rows.sort(key=lambda r: -(float(r["residual"] or -1)))
    out: list[str] = []
    if not rows:
        return out
    out.append("| ID | Risk | Severity | Inherent | Residual | Coverage |")
    out.append("|---|---|---|---|---|---|")
    for r in rows:
        cov = f"{r['coverage']:.0f}%" if isinstance(r["coverage"], (int, float)) else "—"
        out.append(
            f"| {r['id']} | {str(r['title'])[:72]} | {r['severity'] or '—'} | "
            f"{_f(r['inherent'])} | {_f(r['residual'])} | {cov} |")
    return out


def _findings_section(rec) -> list[str]:
    """Findings: model-attack findings when present, else the catalog threats
    already surfaced in the risks table (kept distinct for model rows)."""
    out: list[str] = []
    model_json = _loads(getattr(rec, "model_json", None), {}) or {}
    if not isinstance(model_json, dict):
        model_json = {}
    findings = model_json.get("attacks") or model_json.get("findings") or []
    if findings:
        out.append("| ID | Finding | Severity | Residual |")
        out.append("|---|---|---|---|")
        for f in findings:
            if not isinstance(f, dict):
                continue
            out.append(
                f"| {f.get('id') or '?'} | {str(f.get('title') or f.get('name') or '')[:72]} | "
                f"{f.get('severity') or '—'} | {_f(f.get('residual_score'))} |")
        return out
    # Non-model rows: findings are the threat set; the risk table above is the
    # same set, so say so rather than duplicating it.
    threats = _loads(getattr(rec, "threats_json", None), []) or []
    if threats:
        out.append(f"_Findings are the {len(threats)} risks listed in "
                   "“Security & privacy risks” — a catalog threat set, not a "
                   "model-attack register._")
    return out


def _experiments_section(rec) -> list[str]:
    """Ranked experiments + roadmap planned against what is still open."""
    out: list[str] = []
    model_json = _loads(getattr(rec, "model_json", None), {}) or {}
    hyp_json = _loads(getattr(rec, "hypothesis_json", None), {}) or {}
    if not isinstance(model_json, dict):
        model_json = {}
    if not isinstance(hyp_json, dict):
        hyp_json = {}
    experiments = (model_json.get("experiments")
                   or hyp_json.get("experiments") or [])
    roadmap = (model_json.get("experiments_roadmap")
               or hyp_json.get("experiments_roadmap") or {})
    method = (model_json.get("experiment_method")
              or hyp_json.get("experiment_method") or "")
    if not experiments:
        return out
    out.append(f"_{method or 'Experiment plan'}._")
    out.append("| ID | Experiment |")
    out.append("|---|---|")
    for e in experiments:
        if not isinstance(e, dict):
            continue
        title = e.get("title") or e.get("objective") or e.get("hypothesis") or ""
        if not title and e.get("id"):
            title = f"Experiment {e['id']}"
        out.append(f"| {e.get('id') or '?'} | {str(title)[:110]} |")
    if isinstance(roadmap, dict) and any(roadmap.values()):
        out.append("")
        out.append("**Roadmap**")
        for bucket, items in roadmap.items():
            names = [str(i).strip() for i in (items or []) if str(i).strip()]
            if not names:
                continue
            out.append(f"- **{bucket}:** " + "; ".join(n[:90] for n in names))
    return out


def _hypotheses_section(rec) -> list[str]:
    """The claim register for model_hypothesis rows."""
    out: list[str] = []
    claims = _dossier.hypothesis_register(rec)
    if not claims:
        return out
    out.append("| ID | Claim | Confidence | Status | Falsifiers |")
    out.append("|---|---|---|---|---|")
    for c in claims:
        fals = "; ".join(str(x) for x in (c.get("falsifiers") or [])[:3])
        out.append(
            f"| {c.get('hypothesis_id') or '?'} | "
            f"{str(c.get('claim') or c.get('title') or '')[:80]} | "
            f"{_f(c.get('confidence'))} | {c.get('status') or 'untested'} | "
            f"{fals[:60]} |")
    return out


def _diagrams_for(rec) -> list[dict[str, str]]:
    return _dossier._assessment_diagrams(rec)


def _diagrams_section(diagrams: list[dict[str, str]]) -> list[str]:
    """Every stored mermaid figure, embedded so the report renders diagrams."""
    out: list[str] = []
    for d in diagrams:
        src = str(d.get("source") or "").strip()
        if not src:
            continue
        out.append(f"### {d.get('caption') or d.get('key') or 'Diagram'}")
        out.append("")
        out.append("```mermaid")
        out.append(src)
        out.append("```")
        out.append("")
    return out


def _artifacts_section(artifacts: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    if not artifacts:
        out.append("_No artifacts recorded for this run._")
        return out
    out.append(f"**{len(artifacts)} collected artifact(s).**")
    out.append("")
    out.append("| # | Type | Title | Source | Review |")
    out.append("|---|---|---|---|---|")
    for a in artifacts:
        out.append(
            f"| {a['id']} | {a.get('artifact_type') or '—'} | "
            f"{str(a.get('title') or '')[:64]} | {a.get('source') or '—'} | "
            f"{a.get('review') or '—'} |")
    return out


def _artifacts_for(db, inv_id: int) -> list[dict[str, Any]]:
    arts = (db.query(Artifact)
            .filter(Artifact.investigation_id == inv_id)
            .order_by(Artifact.id.asc()).all())
    return [{
        "id": a.id, "title": a.title or "", "artifact_type": a.artifact_type,
        "source": a.source or "", "review": a.review or "",
        "relevance": a.relevance, "url": a.url or "",
    } for a in arts]


def _inv_section(db, inv_id: int) -> dict[str, Any]:
    """One investigation's contribution to a report: risks, findings,
    experiments, hypotheses, diagrams and artifact inventory."""
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    rec = latest_assessment(db, inv_id) if inv_id else None
    diagrams = _diagrams_for(rec) if rec is not None else []
    scoring = _loads(getattr(rec, "scoring_json", None), {}) or {}
    path = (scoring.get("assessment_path") or "standard") \
        if isinstance(scoring, dict) else "standard"
    return {
        "investigation_id": inv_id,
        "title": inv.title if inv else "Unknown investigation",
        "status": inv.status if inv else None,
        "assessment_id": rec.id if rec is not None else None,
        "assessment_path": path,
        "residual_pct": rec.residual_pct if rec is not None else None,
        "overall_pct": rec.overall_pct if rec is not None else None,
        "risks": _risks_section(rec) if rec is not None else [],
        "findings": _findings_section(rec) if rec is not None else [],
        "experiments": _experiments_section(rec) if rec is not None else [],
        "hypotheses": _hypotheses_section(rec) if rec is not None else [],
        "diagrams": diagrams,
        "artifacts": _artifacts_for(db, inv_id),
    }


# --------------------------------------------------------------------------
# Public reports
# --------------------------------------------------------------------------

def investigation_report(db, inv_id: int) -> dict[str, Any]:
    """Full summary report for one investigation."""
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if inv is None:
        raise LookupError("investigation not found")
    sec = _inv_section(db, inv_id)
    L: list[str] = []
    A = L.append
    A(f"# Run summary report — {inv.title}")
    A("")
    A(f"_Investigation #{inv.id} · status {inv.status or 'unknown'} · "
      f"generated {_now_iso()[:19]} UTC · assessment "
      f"#{sec['assessment_id'] or 'none'}_")
    A("")
    if sec["residual_pct"] is not None:
        A(f"**Residual {_f(sec['residual_pct'])} / overall "
          f"{_f(sec['overall_pct'])}** · "
          f"path `{sec['assessment_path'] or 'standard'}`")
        A("")

    def _sec(title: str, lines: list[str]) -> None:
        if not lines:
            return
        A(f"## {title}")
        A("")
        A("\n".join(lines))
        A("")

    _sec("Security & privacy risks", sec["risks"])
    _sec("Findings", sec["findings"])
    _sec("Experiments", sec["experiments"])
    _sec("Hypotheses", sec["hypotheses"])
    _sec("Diagrams", _diagrams_section(sec["diagrams"]))
    _sec("Collected artifacts", _artifacts_section(sec["artifacts"]))
    markdown = "\n".join(L).strip() + "\n"
    return {
        "kind": "investigation",
        "investigation_id": inv_id,
        "title": inv.title,
        "generated": _now_iso(),
        "markdown": markdown,
        "diagrams": sec["diagrams"],
        "artifacts": sec["artifacts"],
        "counts": {
            "risks": len(sec["risks"]) - 2 if sec["risks"] else 0,
            "findings": 0,
            "experiments": len(sec["experiments"]) - 2 if sec["experiments"] else 0,
            "hypotheses": len(sec["hypotheses"]) - 2 if sec["hypotheses"] else 0,
            "diagrams": len(sec["diagrams"]),
            "artifacts": len(sec["artifacts"]),
        },
    }


def manager_run_report(db, run_id: int) -> dict[str, Any]:
    """Full summary report for an agentic-manager run: every child plus the
    compiled synthesis, one report."""
    run = db.query(ManagerRun).filter(ManagerRun.id == run_id).first()
    if run is None:
        raise LookupError("manager run not found")
    plan = _loads(run.plan_json, {}) or {}
    topics = plan.get("topics") or []
    child_ids = [t.get("investigation_id") for t in topics
                 if t.get("investigation_id")]
    sections = [_inv_section(db, inv_id) for inv_id in child_ids]
    summary_id = run.summary_investigation_id

    synthesis_md = ""
    if summary_id:
        synth = (db.query(Artifact)
                 .filter(Artifact.investigation_id == summary_id,
                         Artifact.tags.like("%manager-synthesis%"))
                 .order_by(Artifact.id.desc()).first())
        if synth is not None and synth.content:
            synthesis_md = synth.content

    L: list[str] = []
    A = L.append
    A(f"# Run summary report — #{run.id}")
    A("")
    A(f"_Manager run #{run.id} · status {run.status or 'unknown'} · "
      f"created {(run.created_at or '').strftime('%Y-%m-%d %H:%M') if run.created_at else '—'} "
      f"UTC · {len(child_ids)} investigation(s) · summary "
      f"#{summary_id or '—'}_")
    A("")
    if run.command:
        A(f"**Command:** {run.command}")
        A("")

    for s in sections:
        label = s["title"]
        A(f"## {label}  _(investigation #{s['investigation_id']})_")
        A("")
        if s["residual_pct"] is not None:
            A(f"**Residual {_f(s['residual_pct'])} / overall "
              f"{_f(s['overall_pct'])}** · path "
              f"`{s['assessment_path'] or 'standard'}`")
            A("")
        A("\n".join(s["risks"]) if s["risks"] else "_No risks recorded._")
        A("")
        if s["findings"]:
            A("**Findings**")
            A("")
            A("\n".join(s["findings"]))
            A("")
        if s["experiments"]:
            A("**Experiments**")
            A("")
            A("\n".join(s["experiments"]))
            A("")
        if s["hypotheses"]:
            A("**Hypotheses**")
            A("")
            A("\n".join(s["hypotheses"]))
            A("")

    all_diagrams: list[dict[str, str]] = []
    for s in sections:
        all_diagrams.extend(s["diagrams"])
    if all_diagrams:
        A("## Diagrams")
        A("")
        A("\n".join(_diagrams_section(all_diagrams)))
        A("")

    all_artifacts: list[dict[str, Any]] = []
    for s in sections:
        all_artifacts.extend(s["artifacts"])
    if summary_id:
        all_artifacts.extend(_artifacts_for(db, summary_id))
    A("## Collected artifacts")
    A("")
    A("\n".join(_artifacts_section(all_artifacts)))
    A("")

    if synthesis_md:
        A("## Synthesis")
        A("")
        A(synthesis_md.strip())
        A("")

    markdown = "\n".join(L).strip() + "\n"
    return {
        "kind": "manager",
        "run_id": run_id,
        "title": f"Manager run #{run_id}",
        "command": run.command,
        "status": run.status,
        "summary_investigation_id": summary_id,
        "generated": _now_iso(),
        "markdown": markdown,
        "diagrams": all_diagrams,
        "artifacts": all_artifacts,
        "counts": {
            "investigations": len(sections),
            "diagrams": len(all_diagrams),
            "artifacts": len(all_artifacts),
        },
    }