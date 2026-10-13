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
from datetime import UTC, datetime
from typing import Any

from . import dossier as _dossier
from .models import (
    AgentRun,
    Artifact,
    Explanation,
    Investigation,
    ManagerRun,
    Relationship,
    SecurityAssessment,
)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


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


def _council_section(db, inv_id: int) -> list[str]:
    """The council review across ALL assessments of one investigation.

    A model investigation holds three assessments (internals, misuse,
    hypothesis synthesis); reporting only the latest row's path hides two of
    them. This section names every flow, then renders the hypothesis
    assessment(s) the way the council reported them: panel, analytics,
    coverage, claims with seats and objections, and standing decisions.

    Everything reads stored rows. A flow that never ran is absent, not
    zeroed -- a missing assessment is a gap in the run, and the report says
    which flows are missing rather than implying they scored nothing.
    """
    from . import council as _council
    recs = (db.query(SecurityAssessment)
            .filter(SecurityAssessment.investigation_id == inv_id)
            .order_by(SecurityAssessment.id).all())
    if not recs:
        return []
    out: list[str] = []

    # The flows that ran, in order. Each row names its own path so a reader
    # can see at a glance whether the synthesis read two priors or ran alone.
    out.append("| # | Flow | Score |")
    out.append("|---|---|---|")
    for r in recs:
        scoring = _loads(getattr(r, "scoring_json", None), {}) or {}
        path = scoring.get("assessment_path") or "standard"
        if path == "model_hypothesis":
            score = scoring.get("confidence_pct")
            label = f"{_f(score)}/100 confidence"
        else:
            score = r.overall_pct
            label = f"{_f(score)}"
        out.append(f"| {r.id} | `{path}` | {label} |")
    out.append("")

    for r in recs:
        scoring = _loads(getattr(r, "scoring_json", None), {}) or {}
        if scoring.get("assessment_path") != "model_hypothesis":
            continue
        claims = _dossier.hypothesis_register(r)
        council = (_loads(getattr(r, "a2a_trace_json", None), {}) or {}
                   ).get("council") or {}
        panel = council.get("panel") or {}
        an = _council.run_analytics(claims, council.get("coverage"),
                                    panel)
        out.append(f"### Assessment #{r.id} — hypothesis synthesis "
                   f"({an['n_claims']} claims, "
                   f"{an['n_contested']} contested)")
        out.append("")
        seats = ", ".join(f"{s_} ({st['filed']} filed)"
                          for s_, st in sorted(an["by_seat"].items())
                          if st["filed"]) or "none filed"
        cov = an["coverage_pct"]
        cov_str = f"{cov}%" if cov is not None else "—"
        unex = ", ".join(f"`{c}`" for c in an["unexamined_classes"]) or "none"
        out.append(f"Seats filing claims: {seats}. Coverage {cov_str} of the "
                   f"classes the corpus speaks to; unexamined: {unex}.")
        out.append("")
        if an["grounds"]:
            out.append("Objections concentrated on: " +
                       ", ".join(f"{g} ({n})"
                                 for g, n in an["grounds"].items()) + ".")
            out.append("")
        out.append("| ID | Claim | Seat | Conf | Status | Objections | Refuted by |")
        out.append("|---|---|---|---|---|---|---|")
        for c in claims:
            cc = c.get("council") or {}
            chs = cc.get("challenges") or []
            grounds = "; ".join(sorted({str(ch.get("ground") or "")
                                        for ch in chs if isinstance(ch, dict)}))
            out.append(
                f"| {c.get('hypothesis_id') or c.get('id') or '?'} | "
                f"{str(c.get('claim') or '')[:72]} | "
                f"{cc.get('seat') or '—'} | "
                f"{_f(c.get('confidence'))} | "
                f"{c.get('status') or 'untested'} | "
                f"{grounds or '—'} | "
                f"{str(c.get('falsifier') or '')[:60]} |")
        out.append("")
        if r.assurance_decision:
            by = f" by {r.assurance_decided_by}" if r.assurance_decided_by else ""
            why = (f" — {r.assurance_decision_note}"
                   if r.assurance_decision_note else "")
            out.append(f"Standing decision: **{r.assurance_decision}**{by}{why}.")
            out.append("")
    return out


def _diagrams_for(rec) -> list[dict[str, str]]:
    return _dossier._assessment_diagrams(rec)


def _latest_explanations(db, inv_id: int, limit: int = 3) -> list:
    try:
        return (db.query(Explanation)
                .filter(Explanation.investigation_id == inv_id)
                .order_by(Explanation.id.desc()).limit(limit).all())
    except Exception:
        return []


def _writeup_section(db, inv_id: int) -> list[str]:
    """The detailed write-up: latest explanations with their summaries,
    key points, and provenance. The report leads with prose here, not
    scores: for a write-up investigation this section IS the summary."""
    out: list[str] = []
    for exp in _latest_explanations(db, inv_id):
        ans = _loads(getattr(exp, "answer", None), {}) or {}
        if not isinstance(ans, dict):
            ans = {}
        trace = _loads(getattr(exp, "trace", None), {}) or {}
        if not isinstance(trace, dict):
            trace = {}
        out.append(f"**Q: {getattr(exp, 'question', '')}** "
                   f"({getattr(exp, 'mode', '')}/"
                   f"{getattr(exp, 'depth', '')} · "
                   f"{getattr(exp, 'status', '')})")
        out.append("")
        if ans.get("summary"):
            out.append(str(ans["summary"]))
            out.append("")
        for kp in (ans.get("key_points") or [])[:8]:
            out.append(f"- {kp}")
        if ans.get("key_points"):
            out.append("")
        queries = trace.get("queries") or []
        hits = trace.get("hits") or []
        fetched = trace.get("fetched") or []
        if queries or hits or fetched:
            out.append(f"_Provenance: {len(queries)} queries, "
                       f"{len(hits)} hits, {len(fetched)} pages "
                       f"fetched._")
            out.append("")
    return out


def _writeup_diagrams(db, inv_id: int) -> list[dict[str, str]]:
    """Explainer figures (answer diagram, maps, prose fences)."""
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for exp in _latest_explanations(db, inv_id, limit=3):
        for d in _dossier._explainer_diagrams(exp):
            src = str(d.get("source") or "").strip()
            if not src or src in seen:
                continue
            seen.add(src)
            d = dict(d)
            d["origin"] = f"write-up #{exp.id}"
            out.append(d)
            if len(out) >= 6:
                return out
    return out


def _day(value) -> str:
    try:
        return value.date().isoformat() if hasattr(value, "date") \
            else str(value)[:10]
    except Exception:
        return "undated"


def _process_figures(db, inv_id: int) -> list[dict[str, str]]:
    """Workflow, activity, and interaction figures from stored rows.

    All three derive from what actually ran (no model involved): stage
    readiness, action counts, and dated actor exchanges. Labels carry
    counts and dates only, never free text, so the figures stay inside
    the parser-safe subset.
    """
    try:
        runs = (db.query(AgentRun)
                .filter(AgentRun.investigation_id == inv_id).all())
    except Exception:
        runs = []
    research = [r for r in runs if (r.trigger or "manual") != "security"]
    r_done = sum(1 for r in research if r.status == "done")
    try:
        assessments = (db.query(SecurityAssessment)
                       .filter(SecurityAssessment.investigation_id
                               == inv_id)
                       .order_by(SecurityAssessment.id.desc()).all())
    except Exception:
        assessments = []
    try:
        exps = (db.query(Explanation)
                .filter(Explanation.investigation_id == inv_id).all())
    except Exception:
        exps = []
    e_done = sum(1 for e in exps if e.status == "done")
    decided = [a for a in assessments if getattr(a, "assurance_decision",
                                                 None)]
    latest = assessments[0] if assessments else None
    a_state = ("none yet" if not assessments
               else f"scored {latest.residual_pct}"
               if latest.residual_pct is not None else "running")
    r_state = ("not started" if not research
               else f"{r_done}/{len(research)} done")
    w_state = ("none yet" if not exps else f"{e_done} answer(s)")
    v_state = (f"decided ({decided[0].assurance_decision})" if decided
               else "open")
    workflow = ("\n".join([
        "flowchart LR",
        f'    R["research: {r_state}"]',
        f'    A["assessment: {a_state}"]',
        f'    W["write-up: {w_state}"]',
        f'    V["review: {v_state}"]',
        "    R --> A --> W --> V"]) + "\n")
    rounds = 0
    kept = 0
    for r in research:
        try:
            stats = json.loads(r.stats or "{}") or {}
        except Exception:
            stats = {}
        if isinstance(stats, dict):
            rounds += int(stats.get("rounds") or 0)
            kept += int(stats.get("artifacts_kept") or 0)
    try:
        rels = db.query(Relationship).filter(
            Relationship.investigation_id == inv_id).count()
    except Exception:
        rels = 0
    activity = ("\n".join([
        "stateDiagram-v2",
        "    [*] --> Research",
        f"    Research --> Assessment : {rounds} rounds, {kept} kept",
        f"    Assessment --> Writeup : {len(assessments)} assessment(s)",
        f"    Writeup --> Review : {len(exps)} write-up(s)",
        f"    Review --> [*] : {rels} relationships mapped"]) + "\n")
    msgs = []
    try:
        inv = db.query(Investigation).filter(
            Investigation.id == inv_id).first()
    except Exception:
        inv = None
    if inv is not None and getattr(inv, "created_at", None) is not None:
        msgs.append((getattr(inv, "created_at", None),
                     "User->>Research: brief opened"))
    for r in sorted(research,
                    key=lambda r: getattr(r, "started_at", None) or "")[:4]:
        if getattr(r, "started_at", None) is not None:
            msgs.append((r.started_at,
                         f"Research->>Research: round results "
                         f"({r.status})"))
    for a in assessments[:2]:
        if getattr(a, "created_at", None) is not None:
            msgs.append((a.created_at, "Research->>Security: assess"))
    for e in sorted(exps, key=lambda e: e.id)[:3]:
        if getattr(e, "created_at", None) is not None:
            msgs.append((e.created_at, "User->>Explainer: question asked"))
            if e.status == "done":
                msgs.append((getattr(e, "finished_at", None)
                             or e.created_at,
                             "Explainer->>User: answer delivered"))
    seq = []
    for d, m in sorted(
            [(d, m) for d, m in msgs if d is not None],
            key=lambda t: str(t[0]))[:8]:
        # Dates ride inside the message text: a second colon would split
        # the statement, so the day goes in parentheses.
        head, _, tail = m.partition(": ")
        seq.append(f"{head}: {tail} ({_day(d)})" if tail
                   else f"{m} ({_day(d)})")
    lines = ["sequenceDiagram",
             "    participant User",
             "    participant Research",
             "    participant Security",
             "    participant Explainer"]
    for m in seq:
        lines.append(f"    {m}")
    if not seq:
        lines.append("    Note over User,Explainer: no exchanges recorded yet")
    interaction = "\n".join(lines) + "\n"
    return [
        {"key": "workflow", "caption": "Investigation workflow",
         "source": workflow, "origin": "process"},
        {"key": "activity", "caption": "Agent activity",
         "source": activity, "origin": "process"},
        {"key": "interaction", "caption": "Actor interactions",
         "source": interaction, "origin": "process"},
    ]


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
    writeup = _writeup_section(db, inv_id) if inv_id else []
    if inv_id:
        diagrams = (list(diagrams) + _writeup_diagrams(db, inv_id)
                    + _process_figures(db, inv_id))
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
        "council": _council_section(db, inv_id),
        "writeup": writeup,
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
    _sec("Council review", sec["council"])
    _sec("Write-up", sec["writeup"])
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
            "writeups": len(sec["writeup"]) - 2 if sec["writeup"] else 0,
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
        if s.get("council"):
            A("**Council review**")
            A("")
            A("\n".join(s["council"]))
            A("")

    all_diagrams: list[dict[str, str]] = []
    for s in sections:
        all_diagrams.extend(s["diagrams"])
    for inv_id in child_ids:
        # Incident reconstructions store their timeline/causal figures as
        # fenced markdown in a per-topic artifact, not on the assessment
        # row: collect them so the report diagrams cover what happened,
        # not only the risk scoring.
        try:
            art = (db.query(Artifact)
                   .filter(Artifact.investigation_id == inv_id,
                           Artifact.tags.like("%incident-reconstruction%"))
                   .order_by(Artifact.id.desc()).first())
        except Exception:
            art = None
        if art is None or not art.content:
            continue
        for key, src in _dossier._mermaid_fences(art.content):
            if any(d.get("source") == src for d in all_diagrams):
                continue
            all_diagrams.append(
                {"key": key or "(unlabelled)",
                 "caption": (key.replace("_", " ") if key
                             else f"incident figure (#{inv_id})"),
                 "source": src,
                 "origin": "incident reconstruction"})
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
