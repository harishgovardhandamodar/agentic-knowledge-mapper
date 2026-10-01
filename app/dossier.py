"""Investigation dossier: the whole audit write-up of one investigation.

The executive summary answers "what do we have". This module answers the
question behind it -- "how did we get here, and can I check it?" -- in four
parts, in the order the work actually happened:

1. **The request.** What was asked, verbatim, with the sources it was allowed
   to use. Not a paraphrase: the same strings the planner read.
2. **What was investigated.** Every run's plan and rationale, the queries it
   actually issued and where it sent them, how many rounds it spent, what the
   query-shape ledger says each *kind* of question has cost and returned, and
   the event trail it left.
3. **What was collected.** Every artifact with its type, source, collecting
   actor, why it was kept, review flag and drift flag; the known issues; the
   questions that were answered and what each answer stood on.
4. **How the scores were applied, and what moved them.** Per assessment: the
   inputs it was given, the arithmetic in full (each dimension's weight x
   score, or each threat's likelihood x impact and its control coverage), the
   items that drove each dimension, and the difference between the numbers.

Everything here is read from stored rows. No LLM call, no invention: a dossier
that cannot be rebuilt from the database is not an audit record, it is a
second opinion. The markdown writer is the same data as prose, so the PDF and
the on-screen preview cannot drift apart.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any

# Path -> (section label, what the headline number means, which scoring
# dimension table describes it). Same three flows the summary reports, plus
# the catalog path, so a dossier covers every stored assessment.
_PATH_META: dict[str, tuple[str, str]] = {
    "standard": ("Catalog assessment", "residual risk"),
    "model": ("Workflow 1 · Model internals", "model risk"),
    "model_adversarial": ("Workflow 2 · Adversarial misuse", "misuse potential"),
    "model_hypothesis": ("Hypothesis synthesis", "mean confidence"),
}
_PATH_ORDER = ("standard", "model", "model_adversarial", "model_hypothesis")


def _load(raw: Any, default: Any = None) -> Any:
    try:
        val = json.loads(raw) if raw else None
    except Exception:
        return default
    return default if val is None else val


def _f(val: Any, default: float = 0.0) -> float:
    try:
        return float(val)
    except (TypeError, ValueError):
        return default


def _iso(dt: Any) -> str | None:
    return dt.isoformat() if dt else None


def _pct(part: float, whole: float) -> str:
    return f"{100.0 * part / whole:.0f}%" if whole else "0%"


def _short(text: str, limit: int = 240) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _demote_headings(md: str) -> str:
    """Push an embedded report's headings down one level so its ``#`` title
    cannot restart the dossier's own outline or hijack the PDF's table of
    contents. Nothing else is touched: the text stays verbatim."""
    return "\n".join(_one(ln) for ln in (md or "").splitlines())


def _one(ln: str) -> str:
    """Add one # to an ATX heading, saturating at h6. A leading '#' with no
    space (a code fence marker) is left alone."""
    if not ln.startswith("#") or len(ln) > 1 and ln[1] not in " #":
        return ln
    level = len(ln) - len(ln.lstrip("#"))
    if level >= 6:
        return ln
    return "#" + ln


# --------------------------------------------------------------------------
# provenance helpers (moved here so the dossier and the API read alike)
# --------------------------------------------------------------------------

def artifact_actor(a, run) -> str:
    """Who/what brought this artifact in, as one honest label."""
    if (a.origin or "") == "manual":
        return "human"
    if (a.author or "") == "explainer":
        return "explainer"
    if run is not None:
        trig = run.trigger or "manual"
        return {"manual": "agent · manual run",
                "schedule": "agent · scheduled"}.get(trig, f"agent · {trig}")
    return "agent"


def artifact_purpose(a, run) -> str:
    """Why this artifact was collected, best available evidence first."""
    if a.relevance_reason:
        return a.relevance_reason
    if (a.author or "") == "explainer":
        return "saved from an explanation"
    if (a.origin or "") == "manual":
        return "added by hand"
    if run is not None:
        plan = _load(run.plan, {}) or {}
        goal = plan.get("goal")
        if goal:
            return f"agent run goal: {goal}"[:300]
        return f"collected by agent run #{run.id} ({run.trigger or 'manual'})"
    return "collected by agent"


# --------------------------------------------------------------------------
# part 2 + 3: what was investigated, what was collected
# --------------------------------------------------------------------------

def _runs_section(db, inv_id: int) -> list[dict[str, Any]]:
    from .models import AgentEvent, AgentRun
    runs = (db.query(AgentRun).filter(AgentRun.investigation_id == inv_id)
            .order_by(AgentRun.id).all())
    out: list[dict[str, Any]] = []
    for r in runs:
        plan = _load(r.plan, {}) or {}
        stats = _load(r.stats, {}) or {}
        events = (db.query(AgentEvent).filter(AgentEvent.run_id == r.id)
                  .order_by(AgentEvent.id).all())
        by_stage = Counter(e.stage for e in events)
        out.append({
            "id": r.id,
            "trigger": r.trigger or "manual",
            "status": r.status,
            "goal": plan.get("goal") or "",
            "rationale": plan.get("rationale") or "",
            "queries": [{"text": q.get("text") or "",
                         "sources": list(q.get("sources") or [])}
                        for q in (plan.get("queries") or [])
                        if isinstance(q, dict)],
            "stats": stats if isinstance(stats, dict) else {},
            "events": [{"stage": e.stage, "message": _short(e.message, 200),
                        "at": _iso(e.created_at)} for e in events],
            "stages": [{"stage": k, "count": v}
                       for k, v in sorted(by_stage.items())],
            "error": _short(r.error or "", 400),
            "started_at": _iso(r.started_at),
            "finished_at": _iso(r.finished_at),
        })
    return out


def _collection_section(db, inv_id: int) -> dict[str, Any]:
    from .explainer import _answer_excerpt, _supporting_for
    from .models import (AgentRun, Artifact, CveFinding, Explanation,
                         Relationship)
    runs = {r.id: r for r in
            db.query(AgentRun).filter(AgentRun.investigation_id == inv_id).all()}
    arts = (db.query(Artifact).filter(Artifact.investigation_id == inv_id)
            .order_by(Artifact.relevance.desc(), Artifact.id).all())
    items = []
    for a in arts:
        run = runs.get(a.run_id) if a.run_id else None
        items.append({
            "id": a.id,
            "title": a.title or "",
            "artifact_type": a.artifact_type or "",
            "source": a.source or "",
            "url": a.url or "",
            "author": a.author or "",
            "tags": a.tags or "",
            "relevance": round(_f(a.relevance), 3),
            "relevance_reason": a.relevance_reason or "",
            "review": a.review or "pending",
            "drift": bool(a.drift),
            "origin": a.origin or "agent",
            "run_id": a.run_id,
            "actor": artifact_actor(a, run),
            "purpose": artifact_purpose(a, run),
            "date_published": _iso(a.date_published),
            "collected_at": _iso(a.created_at),
            "excerpt": _short(a.description or a.content or "", 240),
        })
    usable = [a for a in arts if (a.review or "") != "rejected"]
    flags = {"accepted": sum(1 for a in arts if (a.review or "") == "accepted"),
             "pending": sum(1 for a in arts if (a.review or "") not in
                            ("accepted", "rejected")),
             "rejected": sum(1 for a in arts if (a.review or "") == "rejected"),
             "drift": sum(1 for a in arts if a.drift)}
    rels = (db.query(Relationship).filter(Relationship.investigation_id == inv_id)
            .all())
    cves = (db.query(CveFinding).filter(CveFinding.investigation_id == inv_id)
            .all())
    exps = (db.query(Explanation)
            .filter(Explanation.investigation_id == inv_id)
            .order_by(Explanation.id.desc()).all())
    answers = []
    for e in exps:
        ans = _load(e.answer, {}) or {}
        answers.append({
            "id": e.id,
            "question": e.question or "",
            "status": e.status,
            "mode": e.mode or "explain",
            "depth": e.depth or "balanced",
            "audience": e.audience or "intermediate",
            "hops": e.hops or 0,
            "excerpt": _answer_excerpt(e),
            "key_points": [str(k) for k in (ans.get("key_points") or [])][:6]
                          if isinstance(ans, dict) else [],
            "sources": [str(s) for s in (ans.get("sources") or [])][:12]
                       if isinstance(ans, dict) else [],
            # _supporting_for already returns plain dicts, and rejects
            # artifacts a reviewer rejected.
            "supporting": [{"id": s.get("id"), "title": s.get("title") or "",
                            "artifact_type": s.get("artifact_type") or "",
                            "url": s.get("url") or "",
                            "relevance": round(_f(s.get("relevance")), 3)}
                           for s in _supporting_for(e.question or "", usable)],
            "created_at": _iso(e.created_at),
        })
    by_type = Counter(i["artifact_type"] or "item" for i in items)
    by_source = Counter((i["source"] or "unspecified") for i in items)
    by_actor = Counter(i["actor"] for i in items)
    by_day = Counter((i["collected_at"] or "")[:10] for i in items if i["collected_at"])
    return {
        "totals": {
            "artifacts": len(items),
            "usable": len(usable),
            "relationships": len(rels),
            "relationship_types": dict(Counter(
                r.relationship_type or "related_to" for r in rels)),
            "known_issues": len(cves),
            "answers": len(answers),
            "answered": sum(1 for a in answers if a["status"] == "done"),
        },
        "flags": flags,
        "by_type": sorted(({"name": k, "count": v} for k, v in by_type.items()),
                          key=lambda d: (-d["count"], d["name"])),
        "by_source": sorted(({"name": k, "count": v}
                             for k, v in by_source.items()),
                            key=lambda d: (-d["count"], d["name"]))[:12],
        "by_actor": sorted(({"name": k, "count": v}
                            for k, v in by_actor.items()),
                           key=lambda d: (-d["count"], d["name"])),
        "by_day": [{"day": k, "count": by_day[k]} for k in sorted(by_day)],
        "artifacts": items,
        "known_issues": [{
            "cve_id": c.cve_id, "title": c.title or "",
            "severity": c.severity or "unknown", "cvss": c.cvss,
            "status": c.status or "unknown",
            "published": _iso(c.published_date),
            "impact": _short(c.impact or c.description or "", 300),
            "url": c.source_url or "",
        } for c in cves],
        "answers": answers,
    }


# --------------------------------------------------------------------------
# part 4: how the scores were applied, and what moved them
# --------------------------------------------------------------------------

def _dimension_table(scoring: dict) -> list[dict[str, Any]]:
    """Weight x score = contribution, per dimension, with the items that drove
    each one. ``contribution`` is the stored arithmetic, not a recomputation,
    so the dossier reports the number that produced the headline."""
    from . import security as sec
    tables = {"model": sec.MODEL_DIMENSIONS,
              "adversarial": sec.ADVERSARIAL_DIMENSIONS,
              "hypothesis": sec.HYPOTHESIS_DIMENSIONS}
    rows = scoring.get("dimensions") or []
    out = []
    for row in rows:
        did = row.get("id")
        weight = _f(row.get("weight"))
        score = _f(row.get("score"))
        contrib = row.get("contribution")
        out.append({
            "id": did,
            "weight": weight,
            "score": round(score, 1),
            "contribution": round(_f(contrib, score * weight), 2),
            "percent_of_total": weight,
        })
    return out


def _drivers_for(items: list[dict], dim_id: str) -> list[dict]:
    got = [i for i in items
           if isinstance(i, dict) and str(i.get("dimension") or "") == str(dim_id)]
    return sorted(got, key=lambda i: -_f(i.get("inherent_score",
                                              i.get("confidence"))))


def _model_inputs(rec, scoring: dict) -> dict[str, Any]:
    from .security import EXPOSURE_META
    exposure = rec.exposure or ""
    return {
        "exposure": exposure,
        # The stored value is the tier key ("confidential_data"); a reader needs
        # the label the assessment actually scored against, plus its weight,
        # since exposure scales every inherent likelihood on the catalog path.
        "exposure_label": EXPOSURE_META.get(exposure, {}).get("label", exposure),
        "exposure_weight": EXPOSURE_META.get(exposure, {}).get("weight"),
        "focus": _load(rec.focus_json, []) or [],
        "doc_urls": _load(rec.doc_urls_json, []) or [],
        "use_case": _short(rec.use_case or "", 400),
        "workflow_text": _short(rec.workflow_text or "", 400),
        "declared_controls": (_load(rec.controls_json, {}) or {}).get(
            "declared_controls", []) or [],
    }


def _catalog_scoring(scoring: dict, rows: list[dict]) -> dict[str, Any]:
    """Catalog path: the aggregate is a weighted worst-case plus breadth, and
    every threat's residual is its inherent likelihood after control coverage."""
    bd = scoring.get("breakdown") or {}
    dist = scoring.get("distribution") or {}
    top = sorted(rows, key=lambda r: -_f(r.get("residual_score")))[:5]
    return {
        "kind": "catalog",
        "method": scoring.get("method") or "catalog-lx-i",
        "aggregate_note": bd.get("method") or "",
        "parameters": {k: bd.get(k) for k in
                       ("worst_weight", "breadth_weight", "top_n",
                        "min_residual_floor", "min_applicability",
                        "exposure", "exposure_weight") if k in bd},
        "inherent_pct": _f(scoring.get("inherent_pct")),
        "residual_pct": _f(scoring.get("residual_pct")),
        "delta": _f(scoring.get("delta")),
        "posture": scoring.get("posture") or "",
        "inherent_posture": scoring.get("inherent_posture") or "",
        "distribution": dist,
        "active_controls": scoring.get("active_controls") or [],
        "items": rows,
        "top_threats": [{"id": t.get("id"), "title": _short(t.get("title", ""), 90),
                         "residual": _f(t.get("residual_score")),
                         "coverage": _f(t.get("coverage"))} for t in top],
    }


def _dimension_scoring(path: str, scoring: dict, items: list[dict]) -> dict[str, Any]:
    """Model/misuse/hypothesis paths: weighted dimensions, each driven by the
    items mapped onto it. Residual equals inherent -- no control mapping."""
    dims = _dimension_table(scoring)
    for d in dims:
        d["drivers"] = _drivers_for(items, d["id"])
    excl = [i for i in items if i.get("excluded")]
    scored = [i for i in items if not i.get("excluded")]
    return {
        "kind": "dimensions",
        "method": scoring.get("method") or "",
        "dimensions": dims,
        "items": scored,
        "excluded": excl,
        "total_contribution": round(sum(d["contribution"] for d in dims), 2),
        "inherent_pct": _f(scoring.get("inherent_pct")),
        "residual_pct": _f(scoring.get("residual_pct")),
        "delta": _f(scoring.get("delta")),
        "posture": scoring.get("posture") or "",
        "score_meaning": scoring.get("score_meaning") or "",
        "residual_equals_inherent": abs(_f(scoring.get("delta"))) < 1e-9,
    }


def _hypothesis_scoring(scoring: dict, items: list[dict]) -> dict[str, Any]:
    """Hypothesis path: confidence in the drafted claims, not risk. Higher is
    better-evidenced. The claim rows carry their own per-claim confidence."""
    dims = _dimension_table(scoring)
    for d in dims:
        d["drivers"] = []
    return {
        "kind": "hypothesis",
        "method": scoring.get("method") or "",
        "dimensions": dims,
        "score_meaning": scoring.get("score_meaning") or
            "confidence in the drafted claims, not risk",
        "claims": items,
        "mean_confidence": _f(scoring.get("overall_pct",
                                         scoring.get("confidence_pct"))),
        "residual_equals_inherent": True,
    }


def _score_audit(db, inv_id: int) -> dict[str, Any]:
    """Per-assessment score audit: inputs, arithmetic, and what moved the
    number. ``latest`` marks the row that currently stands for each path."""
    from .models import SecurityAssessment
    recs = (db.query(SecurityAssessment)
            .filter(SecurityAssessment.investigation_id == inv_id)
            .order_by(SecurityAssessment.id.desc()).all())
    rows_out: list[dict[str, Any]] = []
    latest: set[int] = set()
    seen_paths: set[str] = set()
    for rec in recs:
        scoring = _load(rec.scoring_json, {}) or {}
        path = scoring.get("assessment_path")
        if path not in _PATH_META:
            # Same re-derivation rule as the summary: an unmarked row can only
            # be target or standard; the profiler is deterministic.
            try:
                from . import security as sec
                focus = _load(rec.focus_json, []) or []
                prof = sec.profile_model_subject(rec.product_name or "",
                                                 rec.use_case or "", focus)
                path = "model" if prof["is_model_query"] else "standard"
            except Exception:
                path = "standard"
        items = _load(rec.threats_json, []) or []
        if not isinstance(items, dict):
            items = [i for i in items if isinstance(i, dict)]
        else:
            # A stored dict here means a legacy row shaped {threats: [...]};
            # reading it as a list of rows would silently produce an empty
            # table and look like "no findings mapped".
            items = [i for i in (items.get("threats") or [])
                     if isinstance(i, dict)]
        ev = _load(rec.evidence_json, {}) or {}
        if not isinstance(ev, dict):
            ev = {}
        trace = _load(rec.a2a_trace_json, {}) or {}
        if not isinstance(trace, dict):
            trace = {}
        label, meaning = _PATH_META[path]
        is_latest = path not in seen_paths
        if is_latest:
            seen_paths.add(path)
            latest.add(rec.id)
        if path == "standard":
            detail = _catalog_scoring(scoring, items)
        elif path == "model_hypothesis":
            detail = _hypothesis_scoring(scoring, items)
        else:
            detail = _dimension_scoring(path, scoring, items)
        rows_out.append({
            "id": rec.id,
            "path": path,
            "label": label,
            "score_meaning": meaning,
            "score": _f(scoring.get("overall_pct", rec.overall_pct)),
            "inherent": _f(scoring.get("inherent_pct", rec.inherent_pct)),
            "residual": _f(scoring.get("residual_pct", rec.residual_pct)),
            "delta": _f(scoring.get("delta")),
            "exposure": rec.exposure,
            "product_name": rec.product_name,
            "created_at": _iso(rec.created_at),
            "run_id": rec.run_id,
            "is_latest": is_latest,
            "threat_pack_version": rec.threat_pack_version,
            "threat_pack_fingerprint": rec.threat_pack_fingerprint,
            "inputs": _model_inputs(rec, scoring),
            # The stored report, verbatim. Section 4 explains how the numbers
            # were reached; this is the report the user actually read, kept
            # unedited so the two can be compared rather than reconciled.
            "report_markdown": rec.markdown or "",
            "provenance": {
                "a2a_task_id": trace.get("task_id") or "",
                "hops": [h for h in (trace.get("trace") or [])
                         if isinstance(h, dict)],
                "scope": ev.get("scope") or "",
                "queries": [str(q) for q in (ev.get("queries_run") or [])][:12]
                           if isinstance(ev.get("queries_run"), list) else [],
                "evidence": [e for e in (ev.get("evidence") or [])
                             if isinstance(e, dict)][:12]
                            if isinstance(ev.get("evidence"), list) else [],
                "known_exploits": [str(e) for e in
                                   (ev.get("known_exploits") or [])][:8]
                                  if isinstance(ev.get("known_exploits"), list)
                                  else [],
            },
            "detail": detail,
        })
    rows_out.sort(key=lambda r: (r["created_at"] or "", r["id"]), reverse=True)
    return {"rows": rows_out,
            "latest_ids": sorted(latest, reverse=True),
            "paths_present": [p for p in _PATH_ORDER if p in seen_paths]}


def investigation_dossier(db, inv_id: int) -> dict[str, Any]:
    """Assemble the full dossier for one investigation. Raises LookupError
    when the investigation does not exist."""
    from .models import Investigation
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if inv is None:
        raise LookupError("investigation not found")
    from . import yield_ as yld
    runs = _runs_section(db, inv_id)
    collection = _collection_section(db, inv_id)
    scores = _score_audit(db, inv_id)
    shapes = yld.shape_stats(db, inv_id)
    return {
        "investigation": {
            "id": inv.id, "title": inv.title or "Untitled",
            "status": inv.status, "keywords": inv.keywords or "",
            "description": inv.description or "", "sources": inv.sources or "",
            "created_at": _iso(inv.created_at),
            "updated_at": _iso(inv.updated_at),
            "schedule": {
                "enabled": bool(inv.schedule_enabled),
                "cron": inv.schedule_cron or "",
                "max_items": inv.schedule_max_items,
                "max_rounds": inv.schedule_rounds,
            },
        },
        "generated": datetime.now(timezone.utc).isoformat(),
        "runs": runs,
        "query_shapes": shapes,
        "collection": collection,
        "scores": scores,
        "novel_areas": [],
    }


# --------------------------------------------------------------------------
# the write-up: markdown (and hence the PDF)
# --------------------------------------------------------------------------

def dossier_markdown(db, inv_id: int, dossier: dict | None = None) -> str:
    """The complete write-up of every part of the dossier, as markdown. This
    is the same data the preview renders, so PDF and screen agree.

    ``dossier`` lets a caller that already holds a payload pass it in, so the
    PDF's cover block and its body come from one read of the database."""
    d = dossier or investigation_dossier(db, inv_id)
    inv = d["investigation"]
    col = d["collection"]
    L: list[str] = []
    A = L.append

    A(f"# Investigation dossier — {inv['title']}")
    A("")
    A(f"_Investigation #{inv['id']} · generated {d['generated'][:19]} UTC · "
      f"status {inv['status'] or 'unknown'} · "
      f"created {(inv['created_at'] or '')[:10]}_")
    A("")

    # --- part 1: the request ---
    A("## 1. The request")
    A("")
    A(f"**Title.** {inv['title']}")
    if inv["keywords"]:
        A("")
        A(f"**Keywords.** {inv['keywords']}")
    if inv["description"]:
        A("")
        A(f"**Description.** {inv['description']}")
    A("")
    A(f"**Sources enabled.** {inv['sources'] or 'none recorded'}")
    sch = inv.get("schedule") or {}
    if sch.get("enabled"):
        A("")
        A(f"**Schedule.** {sch.get('cron') or 'custom'} · up to "
          f"{sch.get('max_items')} items · {sch.get('max_rounds')} rounds")
    A("")

    # --- part 2: what was investigated ---
    A("## 2. What was investigated")
    A("")
    runs = d["runs"]
    if not runs:
        A("No agent run has been recorded for this investigation. Nothing was "
          "searched, so every number below comes from what was entered by hand "
          "or supplied to an assessment directly.")
        A("")
    for r in runs:
        stats = r.get("stats") or {}
        A(f"### Run #{r['id']} — {r['trigger']} run, {r['status']}")
        A("")
        if r.get("goal"):
            A(f"**Goal.** {r['goal']}")
            A("")
        if r.get("rationale"):
            A(f"**Planner's rationale.** {r['rationale']}")
            A("")
        if r["queries"]:
            A("| Query | Sources searched |")
            A("|---|---|")
            for q in r["queries"]:
                A(f"| {q['text']} | {', '.join(q['sources']) or 'default'} |")
            A("")
        bits = []
        for key, label in (("rounds", "rounds"), ("artifacts_kept", "artifacts kept"),
                           ("relationships", "relationships"),
                           ("llm_calls", "analysis calls"),
                           ("query_shapes", "query shapes")):
            if key in stats:
                bits.append(f"{stats[key]} {label}")
        A(f"**Cost and yield.** {' · '.join(bits) if bits else 'no stats recorded'}"
          + (f" · {(r['started_at'] or '')[:19]} → {(r['finished_at'] or '')[:19]}"
             if r.get("started_at") else ""))
        A("")
        if r["stages"]:
            A("**Stages.** " + " · ".join(f"{s['stage']} ×{s['count']}"
                                           for s in r["stages"]))
            A("")
        if r.get("error"):
            A(f"**Error.** {r['error']}")
            A("")

    shapes = d.get("query_shapes") or []
    if shapes:
        A("### Query shapes: what each kind of question has cost and returned")
        A("")
        A("The agent re-plans from scratch every round, so this ledger is its "
          "only memory of which question shapes paid off.")
        A("")
        A("| Shape | Example | Attempts | Found | Kept | Yield |")
        A("|---|---|---|---|---|---|")
        for s in shapes[:15]:
            A(f"| {s['shape']} | {_short(s.get('example') or '', 48)} | "
              f"{s.get('attempts', 0)} | {s.get('found', 0)} | "
              f"{s.get('kept', 0)} | {_pct(s.get('kept', 0), s.get('found', 0))} |")
        A("")

    # --- part 3: what was collected ---
    A("## 3. What was collected")
    A("")
    tot = col["totals"]
    fl = col["flags"]
    A(f"**Totals.** {tot['artifacts']} artifacts "
      f"({tot['usable']} usable after review) · {tot['relationships']} relationships · "
      f"{tot['known_issues']} known issues · {tot['answered']}/{tot['answers']} "
      f"questions answered.")
    A("")
    A(f"**Review state.** {fl['accepted']} accepted · {fl['pending']} pending · "
      f"{fl['rejected']} rejected"
      + (f" · {fl['drift']} drift-flagged" if fl["drift"] else "")
      + ". Rejected artifacts stand in no score: they are listed here for the "
        "record and excluded everywhere else.")
    A("")
    if col["by_type"] or col["by_actor"]:
        A("**Composition.** "
          + " · ".join(f"{c['count']} {c['name']}" for c in col["by_type"][:8])
          + " | by actor: "
          + " · ".join(f"{c['count']} {c['name']}" for c in col["by_actor"]))
        A("")
    if col["by_day"]:
        A("**Collection timeline.** "
          + " · ".join(f"{c['day']}: {c['count']}" for c in col["by_day"]))
        A("")
    if col["artifacts"]:
        A("### Every artifact, with why it was kept")
        A("")
        A("| ID | Type | Title | Relevance | Why it was collected | Actor | Review |")
        A("|---|---|---|---|---|---|---|")
        for a in col["artifacts"]:
            A(f"| A{a['id']} | {a['artifact_type']} | {_short(a['title'], 60)} | "
              f"{a['relevance']:.2f} | {_short(a['purpose'], 48)} | "
              f"{a['actor']} | {a['review']}"
              + (" (drift)" if a["drift"] else "") + " |")
        A("")
    if col["known_issues"]:
        A("### Known issues")
        A("")
        A("| CVE | Title | Severity | CVSS | Standing |")
        A("|---|---|---|---|---|")
        for c in col["known_issues"]:
            A(f"| {c['cve_id']} | {_short(c['title'], 52)} | {c['severity']} | "
              f"{c['cvss'] if c['cvss'] is not None else '—'} | {c['status']} |")
        A("")
    if col["answers"]:
        A("### Questions answered")
        A("")
        for ans in col["answers"]:
            A(f"**{ans['question']}** "
              f"_({ans['status']}, {ans['mode']}/{ans['depth']}/{ans['audience']}, "
              f"{ans['hops']} hops)_")
            A("")
            if ans["excerpt"]:
                A(_short(ans["excerpt"], 400))
                A("")
            for kp in ans["key_points"]:
                A(f"- {kp}")
            if ans["key_points"]:
                A("")
            if ans["supporting"]:
                A("Stands on: "
                  + ", ".join(f"A{s['id']} {_short(s['title'], 40)}"
                              for s in ans["supporting"][:8]) + ".")
                A("")

    # --- part 4: scores ---
    A("## 4. How each score was applied, and what moved it")
    A("")
    scores = d["scores"]
    if not scores["rows"]:
        A("No security assessment has been run for this investigation.")
        A("")
    paths = scores["paths_present"]
    if len(paths) > 1:
        A("These numbers do not share a scale and are never averaged: "
          + "; ".join(f"{_PATH_META[p][0]} reports {_PATH_META[p][1]}"
                      for p in paths) + ".")
        A("")
    for row in scores["rows"]:
        det = row["detail"]
        mark = " _(current)_" if row["is_latest"] else " _(superseded)_"
        A(f"### {row['label']}{mark} — assessment #{row['id']}")
        A("")
        A(f"**Score.** {row['score']:g}/100 ({row['score_meaning']}). "
          + (f"Inherent {row['inherent']:g} → residual {row['residual']:g} "
             f"(delta {row['delta']:g})."
             if row["path"] != "model_hypothesis"
             else f"Mean confidence across {len(det.get('claims', []))} claims."))
        A("")
        inp = row["inputs"]
        A(f"**Inputs.** Exposure tier {inp['exposure_label'] or row['exposure']}"
          + (f" (weight {inp['exposure_weight']:g})"
             if inp.get("exposure_weight") is not None else "")
          + (f"; focus {', '.join(inp['focus'])}" if inp.get("focus") else "")
          + (f"; use case {_short(inp['use_case'], 120)}"
             if inp.get("use_case") else "")
          + (f"; {len(inp['doc_urls'])} doc URL(s)" if inp.get("doc_urls") else "")
          + (f"; declared controls {', '.join(inp['declared_controls'])}"
             if inp.get("declared_controls") else "")
          + ".")
        A("")
        if det["kind"] == "catalog":
            A(f"**Method.** {_short(det['aggregate_note'], 300)}")
            A("")
            params = det.get("parameters") or {}
            if params:
                A("**Scoring parameters.** "
                  + " · ".join(f"{k} = {v}" for k, v in params.items()) + ".")
                A("")
            # Always stated, including the empty case: "no controls declared"
            # is the single most load-bearing input on the catalog path, since
            # it is why residual equals inherent on a fresh assessment.
            ctl = det.get("active_controls") or []
            A(f"**Controls applied.** "
              + (", ".join(ctl) + ". " if ctl
                 else "None declared. ")
              + "Controls reduce likelihood by coverage, never below the "
                "residual floor.")
            A("")
            A("| Threat | Likelihood | Impact | Inherent | Coverage | "
              "Residual likelihood | Residual | Severity |")
            A("|---|---|---|---|---|---|---|---|")
            for t in det["items"]:
                A(f"| {t['id']} {_short(t.get('title', ''), 40)} | "
                  f"{_f(t.get('likelihood')):.1f} | {_f(t.get('impact')):.1f} | "
                  f"{_f(t.get('inherent_score')):.1f} | "
                  f"{_f(t.get('coverage')):.0f}% | "
                  f"{_f(t.get('residual_likelihood')):.1f} | "
                  f"{_f(t.get('residual_score')):.1f} | "
                  f"{t.get('residual_severity') or '—'} |")
            A("")
            dist = det.get("distribution") or {}
            if dist:
                A("**Severity distribution.** inherent "
                  + ", ".join(f"{k} {v}" for k, v in
                              (dist.get("inherent") or {}).items())
                  + " → residual "
                  + ", ".join(f"{k} {v}" for k, v in
                              (dist.get("residual") or {}).items()) + ".")
                A("")
            A(f"**Posture.** {det['posture']} "
              f"(before controls: {det['inherent_posture']}).")
            A("")
        elif det["kind"] == "dimensions":
            A(f"**Method.** {_short(det['method'], 120)}. Each dimension's score "
              "comes from the findings mapped onto it; contribution = score × "
              "weight. Residual equals inherent: no control mapping is defined "
              "on this path.")
            A("")
            A("| Dimension | Weight | Score | Contribution | Driven by |")
            A("|---|---|---|---|---|")
            for d_ in det["dimensions"]:
                drivers = ", ".join(
                    f"{it.get('id')} {_short(it.get('title', ''), 40)} "
                    f"({_f(it.get('inherent_score')):.0f})"
                    for it in d_["drivers"][:3])
                A(f"| {d_['id']} | {_pct(d_['weight'], 1.0)} | {d_['score']:.0f}/100 "
                  f"| {d_['contribution']:.2f} | {drivers or 'no item mapped'} |")
            A("")
            if det["excluded"]:
                A("**Ruled out.** "
                  + "; ".join(f"{it.get('id')} {_short(it.get('title', ''), 50)}"
                              for it in det["excluded"][:8]) + ".")
                A("")
            A("**Every finding.**")
            A("")
            for it in det["items"]:
                A(f"- **{it.get('id')} {_short(it.get('title', ''), 80)}** "
                  f"— {_f(it.get('inherent_score')):.0f}/100 on "
                  f"{it.get('dimension') or 'unmapped'}"
                  + (f" — {_short(it.get('rationale', ''), 120)}"
                     if it.get("rationale") else "") + ".")
            A("")
        elif det["kind"] == "hypothesis":
            A(f"**Method.** {_short(det['method'], 120)}. "
              f"{det['score_meaning']}. Higher is better-evidenced, not more "
              "dangerous, so it is not comparable with the risk numbers above.")
            A("")
            A("| Dimension | Weight | Score | Contribution |")
            A("|---|---|---|---|")
            for d_ in det["dimensions"]:
                A(f"| {d_['id']} | {_pct(d_['weight'], 1.0)} | {d_['score']:.0f}/100 "
                  f"| {d_['contribution']:.2f} |")
            A("")
            A("**Every claim.**")
            A("")
            for c in det["claims"]:
                contra = c.get("contradicted_by") or []
                A(f"- **{c.get('id')} {_short(c.get('claim', ''), 90)}** "
                  f"— confidence {_f(c.get('confidence')):.0f}/100, impact "
                  f"{c.get('impact', '—')}/5"
                  + (f"; corroborated by both flows" if c.get("cross_flow") else "")
                  + (f"; counter-evidence: {', '.join(c.get('counter_evidence', []))}"
                     if c.get("counter_evidence") else "")
                  + (f"; in tension with flow 1: {', '.join(contra)}"
                     if contra else "")
                  + f". Refuted by: {_short(c.get('falsifier', ''), 100)}")
            A("")
        prov = row.get("provenance") or {}
        if prov.get("scope") or prov.get("queries") or prov.get("evidence"):
            A("**Scope and evidence for this assessment.**")
            A("")
            if prov.get("scope"):
                A(_short(prov["scope"], 500))
                A("")
            if prov.get("queries"):
                A("Queries run: "
                  + "; ".join(f"“{_short(q, 90)}”" for q in prov["queries"]) + ".")
                A("")
            for e in prov.get("evidence") or []:
                A(f"- **{_short(str(e.get('title') or e.get('source') or ''), 90)}**"
                  + (f" — {_short(str(e.get('summary') or e.get('excerpt') or ''), 200)}"
                     if (e.get("summary") or e.get("excerpt")) else "")
                  + (f" [{e['url']}]" if e.get("url") else ""))
            if prov.get("evidence"):
                A("")
            if prov.get("known_exploits"):
                A("Known exploits referenced: "
                  + "; ".join(prov["known_exploits"]) + ".")
                A("")
        if row.get("threat_pack_version"):
            A(f"**Threat pack.** {row['threat_pack_version']} "
              f"({row.get('threat_pack_fingerprint') or 'no fingerprint'}) — "
              "the exact catalogue these numbers were computed against.")
            A("")
        if prov.get("a2a_task_id") or prov.get("hops"):
            A("**Agent chain.** "
              + (f"task {prov['a2a_task_id']}" if prov.get("a2a_task_id")
                 else "task id not recorded")
              + " · " + (" → ".join(
                  f"{h.get('from') or '?'}→{h.get('to') or '?'}"
                  for h in prov.get("hops") or []
                  if h.get("from") or h.get("to"))
                  or "hop trace not recorded")
              + ".")
            A("")

    # --- appendix: each current assessment's own report, verbatim ---
    current = [r for r in scores["rows"] if r["is_latest"] and r.get("report_markdown")]
    if current:
        A("## 5. The assessment reports as written")
        A("")
        A("Section 4 explains how each score was reached; this appendix is each "
          "current assessment's stored report, unedited. It is here so the two "
          "can be compared rather than reconciled.")
        A("")
        for row in current:
            A(f"### {row['label']} — assessment #{row['id']}")
            A("")
            A(_demote_headings(row["report_markdown"]))
            A("")

    A("---")
    A("")
    A("_Every number in this dossier is read from stored rows; none is "
      "recomputed or estimated at render time. Re-running an assessment writes "
      "a new row and leaves the superseded one above._")
    return "\n".join(L)