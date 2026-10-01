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
import re
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


def _mermaid_fences(md: str) -> list[tuple[str, str]]:
    """Every ```mermaid block in a report, as (key, source).

    A fence's key rides in its info string -- ```` ```mermaid workflow ```` --
    and tells the PDF renderer which figure to draw. A bare ```` ```mermaid ````
    is an unlabelled block: equally real, and it must not be skipped just
    because no label was written.
    """
    out: list[tuple[str, str]] = []
    key, buf, inside = "", [], False
    for raw in (md or "").splitlines():
        line = raw.rstrip()
        s = line.strip()
        if s.startswith("```"):
            if not inside:
                info = s[3:].strip().split()
                key = info[1] if len(info) > 1 and info[0] == "mermaid" else ""
                buf = []
            else:
                src = "\n".join(buf).strip()
                if src and _looks_mermaid(src):
                    out.append((key, src))
                buf = []
            inside = not inside
            continue
        if inside:
            buf.append(line)
    return out


def _looks_mermaid(src: str) -> bool:
    """A mermaid block opens with a diagram-type keyword."""
    return bool(re.match(
        r"\s*(graph|flowchart|sequenceDiagram|classDiagram|stateDiagram|erDiagram"
        r"|journey|gantt|pie|mindmap|timeline|quadrantChart|C4Context)\b", src,
        re.IGNORECASE))


def _assessment_diagrams(rec: Any) -> list[dict[str, str]]:
    """All mermaid for one assessment: the stored figure set plus anything
    fenced inside its own report.

    Both are read from the row, never regenerated: the diagram a reader saw is
    the one in the report."""
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    stored = _load(getattr(rec, "diagrams_json", None), {}) or {}
    if isinstance(stored, dict):
        for key, src in stored.items():
            src = str(src or "").strip()
            if src:
                out.append({"key": str(key), "caption": str(key).replace("_", " "),
                            "source": src, "origin": "stored figure set"})
                seen.add(str(key))
    for key, src in _mermaid_fences(getattr(rec, "markdown", "") or ""):
        if key in seen and src == next(
                (d["source"] for d in out if d["key"] == key), None):
            continue          # same figure as the stored set: one copy only
        out.append({"key": key or "(unlabelled)",
                    "caption": (key.replace("_", " ") if key
                                else _first_line(src)),
                    "source": src,
                    "origin": "report body" if key else "report body (unlabelled)"})
        if key:
            seen.add(key)
    return out


def _first_line(src: str, limit: int = 60) -> str:
    line = next((l.strip() for l in (src or "").splitlines() if l.strip()), "")
    return line if len(line) <= limit else line[: limit - 1] + "…"


def _source_refs(ans: dict) -> list[dict[str, str]]:
    """An answer's citations, as title plus whatever link it carries.

    The explainer writes sources as dicts, but the URL is often an internal
    ``graph://artifact/N`` handle rather than a web address, so it is kept as
    a separate field instead of being flattened into ``url`` and read as a
    broken link."""
    out: list[dict[str, str]] = []
    for s in (ans.get("sources") or []):
        if isinstance(s, dict):
            out.append({"title": str(s.get("title") or "").strip(),
                        "url": str(s.get("url") or "").strip(),
                        "kind": str(s.get("kind") or s.get("source") or "").strip()})
        elif isinstance(s, str):
            out.append({"title": s.strip(), "url": "", "kind": ""})
    return out[:12]


def _explainer_diagrams(exp: Any) -> list[dict[str, str]]:
    """Mermaid an explainer produced.

    The explainer stores its figure under ``answer.diagram`` -- a single
    object of ``mermaid``/``title``/``caption``, not a keyed collection. It
    also accepts a ``diagrams`` map and fenced blocks in the prose, so all
    three are read: a deep-dive whose figure only exists in the prose would
    otherwise leave the report claiming it has no diagrams at all.
    """
    out: list[dict[str, str]] = []
    ans = _load(getattr(exp, "answer", None), {}) or {}
    meta = _load(getattr(exp, "meta", None), {}) or {}
    if not isinstance(ans, dict):
        ans = {}
    packs: list[tuple[str, Any]] = [("explainer payload", meta.get("diagrams"))]

    one = ans.get("diagram")
    if isinstance(one, dict):
        packs.append(("explainer figure", one))
    figs = ans.get("figures")
    if isinstance(figs, list):
        packs.append(("explainer figures", figs))
    elif isinstance(one, str) and one.strip():
        packs.append(("explainer figure", one))
    if isinstance(ans.get("diagrams"), dict):
        packs.append(("answer diagrams", ans["diagrams"]))

    for origin, pack in packs:
        if isinstance(pack, str):
            if pack.strip():
                out.append({"key": "", "caption": _first_line(pack),
                            "source": pack.strip(), "origin": origin,
                            "note": ""})
            continue
        if isinstance(pack, list):
            for val in pack:
                if isinstance(val, dict) and str(val.get("mermaid") or "").strip():
                    note = " ".join(str(val.get(k) or "").strip()
                                    for k in ("title", "caption")).strip()
                    out.append({"key": "", "caption": note or _first_line(
                        str(val["mermaid"])), "source": str(val["mermaid"]).strip(),
                        "origin": origin, "note": note})
            continue
        if not isinstance(pack, dict):
            continue
        if "mermaid" in pack:
            items = [(None, pack)]
        else:
            items = list(pack.items())
        for key, val in items:
            src = ""
            note = ""
            if isinstance(val, dict):
                src = str(val.get("mermaid") or "").strip()
                note = " ".join(str(val.get(k) or "").strip()
                                for k in ("title", "caption")).strip()
            else:
                src = str(val or "").strip()
            if not src or not _looks_mermaid(src):
                continue
            label = str(key or "").strip()
            out.append({
                "key": label,
                "caption": (label.replace("_", " ") if label
                            else note or _first_line(src)),
                "source": src,
                "origin": origin,
                "note": note,
            })
    for key, src in _mermaid_fences(
            str(ans.get("summary") or "") + "\n" + "\n".join(
                str(s.get("body") or "")
                for s in (ans.get("sections") or []) if isinstance(s, dict))):
        out.append({"key": key, "caption": key.replace("_", " ") if key
                    else _first_line(src), "source": src,
                    "origin": "answer prose", "note": ""})
    return out


def _iso(dt: Any) -> str | None:
    return dt.isoformat() if dt else None


def _pct(part: float, whole: float) -> str:
    return f"{100.0 * part / whole:.0f}%" if whole else "0%"


def _short(text: str, limit: int = 240) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _flatten_headings(md: str) -> str:
    """Compress a report's heading levels into the dossier's own band.

    An appended report may nest four or five levels deep; demoting each one
    saturates at h6, where a run of claims and threats all read as the same
    depth and the structure is lost. Mapping the report's shallowest heading
    to ``###`` and everything below it proportionally keeps the internal
    hierarchy visible while leaving the dossier's ``##`` outline untouched."""
    def _level(ln: str) -> int:
        return len(ln) - len(ln.lstrip("#"))

    lines = (md or "").splitlines()

    def _is_heading(ln: str) -> bool:
        # ATX: hashes then a space. The old test only checked ln[1], which
        # recognises `# title` and nothing else -- every `##` section was
        # treated as body text and left its level untouched.
        rest = ln.lstrip("#")
        return ln.startswith("#") and (rest == "" or rest.startswith(" "))

    levels = sorted({_level(l) for l in lines if _is_heading(l)})
    if not levels:
        return md or ""
    # Land the report's *shallowest* heading on h3 and keep every step below it
    # in proportion, so the report's own title lands at h3 while its `## 6.
    # Known exploits` sits at h4 -- inside the dossier's section 5 rather than
    # beside it, competing with the dossier's own numbered outline.
    base = levels[0]
    depth = min(3, len(levels))          # at most three visible levels
    span = max(1, levels[-1] - base)
    out = []
    for ln in lines:
        if _is_heading(ln):
            lvl = _level(ln)
            rel = min(1 + int(round((lvl - base) / span * (depth - 1))),
                      depth)
            out.append("#" * (2 + rel) + ln.lstrip("#"))
        else:
            out.append(ln)
    return "\n".join(out)


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
    # "Usable" means a reviewer accepted it. Pending artifacts -- however
    # relevant -- have not been judged yet, and counting them as evidence
    # inflates the base the findings stand on.
    usable = [a for a in arts if (a.review or "") == "accepted"]
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
            "diagrams": _explainer_diagrams(e),
            "excerpt": _answer_excerpt(e),
            "key_points": [str(k) for k in (ans.get("key_points") or [])][:6],
            # The explainer's own narrative, read from the stored answer so the
            # dossier shows the finding rather than only the question. The
            # summary is what a reader needs before the full sections.
            "summary": str(ans.get("summary") or "").strip(),
            "mechanism_steps": (
                [str(s) for s in (ans.get("mechanism_steps") or [])
                 if isinstance(s, (str, int, float))][:12]
                if isinstance(ans.get("mechanism_steps"), list) else []),
            "tradeoffs": (
                [str(s) for s in (ans.get("tradeoffs") or [])
                 if isinstance(s, (str, int, float))][:10]
                if isinstance(ans.get("tradeoffs"), list) else []),
            "as_of": str(ans.get("as_of") or ""),
            "conflicts": ([str(c) for c in (ans.get("conflicts") or [])
                           if isinstance(c, str)][:8]
                          if isinstance(ans.get("conflicts"), list) else []),
            # Each section heading and body, so an export can carry the whole
            # deep-dive rather than a truncated excerpt.
            "sections": ([{"heading": str(s.get("heading") or ""),
                           "body": str(s.get("body") or "")}
                          for s in (ans.get("sections") or [])
                          if isinstance(s, dict)][:40]
                         if isinstance(ans.get("sections"), list) else []),
            "documents": ([str(s) for s in (ans.get("documents") or [])
                           if isinstance(s, str)][:10]
                          if isinstance(ans.get("documents"), list) else []),
            "sources": _source_refs(ans),
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
    rank = {"accepted": 0, "pending": 1, "rejected": 2}
    items.sort(key=lambda i: (rank.get(i["review"], 1),
                              -i["relevance"], i["id"]))
    return {
        "totals": {
            "artifacts": len(items),
            "usable": len(usable),
            "rel_high": sum(1 for i in items if i["relevance"] >= 0.4),
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


def _figure_label(key: str, src: str, product: str = "") -> str:
    """The figure key only when the source really is that figure.

    Every path stores its diagrams under the same three names -- ``dataflow``,
    ``threat_paths``, ``workflow`` -- but a model path's ``dataflow`` is a model
    flow or a hypothesis map, not the catalogue data-flow. Trusting the key
    alone hands the PDF renderer a catalogue figure to draw over an unrelated
    diagram, so the label is only honoured when the source matches the figure
    the renderer can actually draw.
    """
    from .security import mermaid_dataflow, mermaid_threat_paths, mermaid_workflow
    canon = {
        "dataflow": mermaid_dataflow(product),
        "threat_paths": mermaid_threat_paths(),
        "workflow": mermaid_workflow(product),
    }
    wanted = canon.get(key)
    if wanted and _norm_mermaid(wanted) == _norm_mermaid(src):
        return key
    return ""


def _norm_mermaid(src: str) -> str:
    """Collapse whitespace so an exact-source comparison is not defeated by
    re-indentation alone."""
    return re.sub(r"\s+", " ", (src or "")).strip()


def _diagram_index(rows: list[dict], answers: list[dict]) -> list[dict]:
    """Every diagram the investigation produced, deduplicated by source.

    One product's figure set is repeated verbatim by every assessment that
    shares it, and the report body fences the same figures again. Listing each
    copy would pad the PDF with identical drawings and read as a bug, so a
    source appears once with the places it came from recorded beside it. The
    catalogue is otherwise unaltered -- nothing is dropped, only repeated.
    """
    order = list(_PATH_ORDER)
    ordered = sorted(
        [r for r in rows if r.get("diagrams")],
        key=lambda r: (order.index(r["path"]) if r["path"] in order
                       else len(order),
                       not r.get("is_latest"), r.get("id") or 0))
    seen: dict[str, dict] = {}
    groups: list[dict] = []

    def _add(grp_title: str, src: str, cap: str, key: str, label: str,
             origin: str, where: str) -> None:
        sig = _norm_mermaid(src)
        if not sig:
            return
        if sig in seen:
            entry = seen[sig]
            if where not in entry["seen_in"]:
                entry["seen_in"].append(where)
            return
        entry = {"key": key, "caption": cap, "source": src, "origin": origin,
                 "label": label, "seen_in": [where]}
        seen[sig] = entry
        groups.append({"title": grp_title, "diagrams": [entry]})

    for r in ordered:
        title = f"{r['label']} — assessment #{r['id']}"
        for d in r["diagrams"]:
            key = d["key"] if d["key"] not in ("", "(unlabelled)") else ""
            label = _figure_label(key, d["source"],
                                  r.get("product_name") or "") if key else ""
            cap = (key.replace("_", " ") if key else _first_line(d["source"]))
            _add(title, d["source"], cap, key, label, d["origin"],
                 f"assessment #{r['id']}")
    for a in answers:
        if not a.get("diagrams"):
            continue
        title = f"Explainer #{a['id']} — {a.get('status') or 'unknown'}"
        for d in a["diagrams"]:
            key = d["key"] if d["key"] not in ("", "(unlabelled)") else ""
            cap = (key.replace("_", " ") if key else _first_line(d["source"]))
            _add(title, d["source"], cap, key, "", d["origin"],
                 f"explainer #{a['id']}")
    # One flat section: the heading per source is the caption, so the grouping
    # titles are dropped and every figure sits in a single ordered list.
    return [{"title": "", "diagrams": [d for g in groups for d in g["diagrams"]]}] \
        if any(g["diagrams"] for g in groups) else []


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
            "diagrams": _assessment_diagrams(rec),
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

    # --- executive summary: the whole point of the document, first ---
    A("## Executive summary")
    A("")
    tot, fl = col["totals"], col["flags"]
    rows = d["scores"]["rows"]
    latest = [r for r in rows if r.get("is_latest")]
    parts = [
        f"**{inv['title']}** was investigated against "
        f"{inv['sources'] or 'no recorded sources'}, collecting "
        f"{tot.get('artifacts', 0)} artifact(s) and answering "
        f"{tot.get('answered', 0)} of {tot.get('answers', 0)} question(s).",
    ]
    if latest:
        # One line per path, each naming what its number means. A dossier that
        # lists the scores without their meanings invites reading one as the
        # answer to a question it does not answer.
        parts.append("")
        parts.append("| Path | Score | What it means |")
        parts.append("|---|---|---|")
        for r in latest:
            parts.append(f"| {r['label']} | {r['score']}/100 | "
                         f"{r['score_meaning']} |")
    else:
        parts.append("")
        parts.append("No security assessment has been run for this "
                     "investigation, so there is no score to report.")
    answered = [a for a in col["answers"] if a.get("status") == "done"]
    if answered:
        top = answered[0].get("summary") or answered[0].get("excerpt") or ""
        if top:
            parts.append("")
            parts.append("**Lead finding.** " + _short(top, 420))
    heat: list[tuple[str, dict]] = []
    for r in latest:
        for t in ((r.get("detail") or {}).get("items") or []):
            if isinstance(t, dict) and t.get("residual_score") is not None:
                heat.append((r["label"], t))
    heat.sort(key=lambda e: -_f(e[1].get("residual_score")))
    if heat:
        # The headline score is an aggregate; the threats below are what is
        # still standing after controls. A reader who stops at the number
        # never learns that T12-class items barely moved.
        parts.append("")
        parts.append("**Highest residual threats.**")
        parts.append("")
        parts.append("| Threat | Residual | Coverage | Path |")
        parts.append("|---|---|---|---|")
        for label, t in heat[:6]:
            cov = t.get("coverage")
            cov_s = f"{cov:.0f}%" if isinstance(cov, (int, float)) else "—"
            weak = " *(lowest coverage)*" \
                if isinstance(cov, (int, float)) and cov < 70 else ""
            res = t.get("residual_score")
            res_s = f"{res:g}/100" if isinstance(res, (int, float)) else "—"
            parts.append(f"| {t.get('id')} {_short(str(t.get('title') or ''), 48)} "
                         f"| {res_s} | {cov_s}{weak} | {_short(label, 40)} |")
        weakest = sorted(
            ((t.get("coverage"), t.get("id")) for _, t in heat
             if isinstance(t.get("coverage"), (int, float))),
            key=lambda e: e[0])[:2]
        if weakest and weakest[0][0] < 70:
            parts.append("")
            parts.append("Lowest coverage: "
                         + ", ".join(f"{i} ({c:.0f}%)" for c, i in weakest)
                         + " — the LOW headline does not cover these; "
                         "see section 8 before relying on it in a regulated "
                         "environment.")
    gaps = []
    if tot.get("known_issues"):
        gaps.append(f"{tot['known_issues']} known issue(s) surfaced")
    unanswered = tot.get("answers", 0) - tot.get("answered", 0)
    if unanswered > 0:
        gaps.append(f"{unanswered} question(s) still unanswered")
    if fl.get("duplicates"):
        gaps.append(f"{fl['duplicates']} duplicate artifact(s)")
    if gaps:
        parts.append("")
        parts.append("**Open items.** " + "; ".join(gaps) + ".")
    # Confidence up front: the headline score means little without knowing
    # how much was answered, what failed, and how much evidence is reviewed.
    conf = [f"{tot.get('answered', 0)}/{tot.get('answers', 0)} questions answered",
            f"{fl.get('accepted', 0)} accepted · "
            f"{fl.get('pending', 0)} pending artifacts"]
    failed = [r for r in (d.get("runs") or [])
              if (r.get("status") or "") not in ("done",)]
    if failed:
        conf.append(f"{len(failed)} run(s) failed or interrupted")
    if latest:
        conf.append(f"last assessment "
                    f"#{max(r['id'] for r in latest)}")
    parts.append("")
    parts.append("**Confidence.** " + "; ".join(conf) + ".")
    gap_runs = [r for r in (d.get("runs") or [])
                if (r.get("trigger") or "") == "explainer_gap"
                and (r.get("status") or "") != "done" and r.get("goal")]
    if gap_runs:
        parts.append("")
        parts.append("**Open questions.** Follow-up research that never "
                     "finished; its goals are still unanswered:")
        for r in gap_runs:
            parts.append(f"- Run #{r['id']} ({r.get('status')}): "
                         f"{_short(r['goal'], 160)}")
    parts.append("")
    parts.append("Read section 2 for what was asked, section 3 for what came "
                 "back, section 4 for how each score was reached, section 5 "
                 "for the current assessment reports, section 6 for every "
                 "diagram, section 7 for the deep-dives behind each answer, "
                 "and section 8 for what was not closed.")
    for p in parts:
        A(p)
    A("")
    A("---")
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
        if stats.get("assessment_id"):
            # Security runs record assessment stats, not search counts: show
            # what the run produced so short runs still leave a trace.
            abits = [f"assessment #{stats['assessment_id']}"]
            if stats.get("residual_pct") is not None:
                try:
                    abits.append(f"residual {float(stats['residual_pct']):g}/100")
                except (TypeError, ValueError):
                    pass
            if stats.get("posture"):
                abits.append(_short(str(stats["posture"]), 80))
            for key, label in (("threats", "threats"),
                               ("evidence", "evidence items"),
                               ("control_count", "controls"),
                               ("known_exploits", "known exploits")):
                if stats.get(key) is not None:
                    abits.append(f"{stats[key]} {label}")
            if stats.get("duration_ms") is not None:
                try:
                    abits.append(f"{float(stats['duration_ms']) / 1000:.0f}s")
                except (TypeError, ValueError):
                    pass
            if stats.get("failed"):
                abits.append(f"failed: {_short(str(stats['failed']), 120)}")
            A("**Assessment.** " + " · ".join(abits) + ".")
            A("")
        if r["stages"]:
            A("**Stages.** " + " · ".join(f"{s['stage']} ×{s['count']}"
                                           for s in r["stages"]))
            A("")
        if r.get("error"):
            # A past run's failure is a historical record, not a live fault:
            # label it as an outcome and point at the gaps register instead
            # of printing a bare "Error." that reads as if the report broke.
            A(f"**Outcome.** {r['status']}: {r['error']} — recorded "
              f"{(r.get('finished_at') or r.get('started_at') or '')[:10]}; "
              f"what it left missing is tracked in section 8.")
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
      f"({fl['accepted']} accepted · {fl['pending']} pending · "
      f"{fl['rejected']} rejected; {tot['usable']} usable after review — "
      f"accepted only) · {tot['relationships']} relationships · "
      f"{tot['known_issues']} known issues · {tot['answered']}/{tot['answers']} "
      f"questions answered.")
    A("")
    low = tot['artifacts'] - tot.get('rel_high', tot['artifacts'])
    if low:
        A(f"**Relevance note.** {low} artifact(s) sit below 0.40 relevance, "
          f"mostly explainer-derived concepts: they inform questions, not "
          f"findings, and appear at the end of the table.")
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
    cur_by_path = {r.get("path"): r for r in scores["rows"]
                   if r["is_latest"]}
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
        if not row["is_latest"]:
            # A superseded assessment keeps its score and its delta, not its
            # arithmetic: reprinting every table triples the section for
            # numbers no decision should use.
            cur = cur_by_path.get(row.get("path"))
            if cur is not None:
                try:
                    delta = float(cur["score"]) - float(row["score"])
                    delta_s = f"{delta:+.1f} vs current (#{cur['id']})"
                except (TypeError, ValueError):
                    delta_s = "current unreadable"
            else:
                delta_s = "path retired, no current version"
            A(f"Superseded {(row.get('created_at') or '')[:10]} — {delta_s}. "
              f"See the §5 change log for the version history.")
            A("")
            continue
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

    # --- appendix: the current reports verbatim, older ones as a log ---
    # Reprinting every superseded assessment roughly triples this section
    # without adding information: the numbers that changed are the scores and
    # the dates, and those fit in a table.
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
            A(_flatten_headings(row["report_markdown"]))
            A("")
    earlier = [r for r in scores["rows"] if not r["is_latest"]]
    if earlier:
        if not current:
            A("## 5. The assessment reports as written")
            A("")
        cur_by_path = {r.get("path"): r for r in scores["rows"]
                       if r["is_latest"]}
        A("### Earlier versions (change log)")
        A("")
        A("Superseded assessments are summarised, not reprinted: the report "
          "that changed is above, and what moved between versions is below.")
        A("")
        A("| Assessment | Created | Score | Inherent → residual | Δ vs current |")
        A("|---|---|---|---|---|")
        for row in earlier:
            cur = cur_by_path.get(row.get("path"))
            if cur is not None:
                try:
                    delta = float(cur["score"]) - float(row["score"])
                    delta_s = f"{delta:+.1f}"
                except (TypeError, ValueError):
                    delta_s = "—"
            else:
                delta_s = "— (path retired)"
            inh = row.get("inherent")
            res = row.get("residual")
            span = (f"{inh:g} → {res:g}"
                    if isinstance(inh, (int, float))
                    and isinstance(res, (int, float)) else "—")
            A(f"| {row['label']} — assessment #{row['id']} "
              f"| {(row.get('created_at') or '')[:10]} | {row['score']}/100 "
              f"| {span} | {delta_s} |")
        A("")

    # --- every mermaid source the investigation produced ---
    figs = _diagram_index(scores["rows"], col.get("answers") or [])
    flat = [d for g in figs for d in g["diagrams"]]
    if flat:
        A("## 6. Diagrams")
        A("")
        A(f"{len(flat)} distinct diagram source"
          f"{'s' if len(flat) != 1 else ''} across this investigation. The stored "
          "figure set, anything fenced inside a report, and anything an "
          "explainer produced are all included; a source shared by several "
          "assessments is listed once with where it appears. Sources are "
          "reproduced verbatim so each figure can be re-rendered elsewhere.")
        A("")
        # NOTE: the loop variable must not be `d` -- that name holds the
        # whole dossier payload, and later sections read runs/scores from it.
        for i, fig in enumerate(flat, 1):
            A(f"### {i}. {fig['caption']}")
            A("")
            where = ", ".join(fig["seen_in"][:8])
            more = (f" (+{len(fig['seen_in']) - 8} more)"
                    if len(fig["seen_in"]) > 8 else "")
            A(f"*{fig['origin']} — appears in {where}{more}.*")
            A("")
            # A label the PDF figure specs recognise is drawn as a vector
            # figure; anything else is shown as source, so no diagram is
            # silently dropped or drawn as the wrong figure.
            A(f"```mermaid {fig['label']}" if fig.get("label") else "```mermaid")
            A(fig["source"])
            A("```")
            A("")

    # --- support material: every answer in full ---
    deep = [a for a in col["answers"] if a.get("status") == "done"
            and (a.get("sections") or a.get("summary"))]
    if deep:
        A("## 7. The deep-dives, in full")
        A("")
        A("Each question that was answered, with its finding, its diagram and "
          "its sources. Section 3 lists them; this is the material itself, so "
          "an exported report carries the whole investigation rather than a "
          "pointer to it.")
        A("")
        for ans in deep:
            A(f"### {ans['question']}")
            A("")
            A(f"_explainer #{ans['id']} · {ans['mode']}/{ans['depth']}/"
              f"{ans['audience']} · {ans['hops']} hops"
              + (f" · as of {ans['as_of']}" if ans.get("as_of") else "")
              + "_")
            A("")
            if ans.get("summary"):
                A(ans["summary"])
                A("")
            for dg in ans.get("diagrams") or []:
                A(f"**Diagram — {dg['caption']}**  ")
                A(f"_{dg['origin']}_")
                A("")
                A("```mermaid")
                A(dg["source"])
                A("```")
                A("")
            if ans.get("mechanism_steps"):
                A("**How it works.**")
                A("")
                for i, step in enumerate(ans["mechanism_steps"], 1):
                    A(f"{i}. {step}")
                A("")
            if ans.get("tradeoffs"):
                A("**Trade-offs.**")
                A("")
                for t in ans["tradeoffs"]:
                    A(f"- {t}")
                A("")
            for sec in ans.get("sections") or []:
                if sec["heading"]:
                    A(f"#### {sec['heading']}")
                    A("")
                if sec["body"]:
                    A(sec["body"])
                    A("")
            if ans.get("key_points"):
                A("**Key points.**")
                A("")
                for kp in ans["key_points"]:
                    A(f"- {kp}")
                A("")
            if ans.get("conflicts"):
                A("**Conflicts noted.** "
                  + "; ".join(ans["conflicts"]) + ".")
                A("")
            if ans.get("supporting"):
                A("**Grounded in.** "
                  + "; ".join(f"{s.get('title') or s.get('url') or 'source'}"
                              + (f" [{s['url']}]" if s.get("url") else "")
                              for s in ans["supporting"][:12])
                  + ".")
                A("")
            elif ans.get("sources"):
                A("**Grounded in.** "
                  + "; ".join(
                      f"{s['title'] or 'source'}"
                      + (f" ({s['url']})" if s.get("url") else "")
                      for s in ans["sources"][:12])
                  + ".")
                A("")
            if ans.get("documents"):
                A("**Documents referenced.** " + ", ".join(ans["documents"]) + ".")
                A("")

    # --- what was not closed ---
    # A report that only states conclusions invites treating declared
    # controls as tested ones and a LOW headline as covering every threat.
    # This register names each gap, why it matters, and where it surfaced.
    A("## 8. Open questions and evidence gaps")
    A("")
    A("What the investigation did not close. Work through this section before "
      "acting on the headline score: every item is something the next run, "
      "review, or vendor conversation still has to verify.")
    A("")
    bad_runs = [r for r in (d.get("runs") or [])
                if (r.get("status") or "") != "done"]
    if bad_runs:
        A("### Interrupted runs")
        A("")
        for r in bad_runs:
            A(f"- **Run #{r['id']}** ({r.get('trigger') or 'manual'}): "
              f"{r.get('error') or 'did not finish'}. Whatever it was "
              f"collecting or answering is missing below unless a later run "
              f"repeated it.")
        A("")
    stuck = [a for a in (col.get("answers") or [])
             if (a.get("status") or "") != "done"]
    if stuck:
        A("### Unanswered questions")
        A("")
        for a in stuck:
            A(f"- **Explainer #{a['id']}** ({a.get('mode') or 'answer'}): "
              f"status {a.get('status') or 'unknown'} — "
              f"“{_short(str(a.get('question') or ''), 100)}”.")
        A("")
    weak: list[tuple[str, dict]] = []
    for r in [x for x in scores["rows"] if x["is_latest"]]:
        for t in ((r.get("detail") or {}).get("items") or []):
            cov = t.get("coverage") if isinstance(t, dict) else None
            if isinstance(cov, (int, float)) and cov < 70:
                weak.append((r["label"], t))
    weak.sort(key=lambda e: _f(e[1].get("coverage")))
    if weak:
        A("### Weakest coverage")
        A("")
        A("These threats moved the least under controls. The aggregate "
          "headline does not describe them; in a regulated environment they "
          "are the residual risk.")
        A("")
        A("| Threat | Coverage | Residual | Path |")
        A("|---|---|---|---|")
        for label, t in weak:
            res = t.get("residual_score")
            res_s = f"{res:g}/100" if isinstance(res, (int, float)) else "—"
            A(f"| {t.get('id')} {_short(str(t.get('title') or ''), 48)} "
              f"| {t.get('coverage'):.0f}% | {res_s} "
              f"| {_short(label, 40)} |")
        A("")
    ctrl_ids: list[str] = []
    for r in [x for x in scores["rows"] if x["is_latest"]]:
        for t in ((r.get("detail") or {}).get("items") or []):
            for c in (t.get("controls") or []):
                if c and c not in ctrl_ids:
                    ctrl_ids.append(c)
    if ctrl_ids:
        try:
            from .security import _CONTROL_CATALOG
            catalog = {c["id"]: c for c in _CONTROL_CATALOG}
        except Exception:
            catalog = {}
        A("### Controls relied upon")
        A("")
        A("Every control below is **as-declared**: its efficacy is the value "
          "the assessment computed with, not a measured result. Treat the "
          "residual as provisional until each control is independently "
          "tested — configuration samples, log evidence, or red-team "
          "results — and confirmed in the vendor contract where it depends "
          "on one (retention, residency, sub-processors).")
        A("")
        A("| Control | Efficacy | Standard | Status |")
        A("|---|---|---|---|")
        for cid in ctrl_ids:
            c = catalog.get(cid, {})
            eff = c.get("efficacy")
            eff_s = f"{eff:.0%}" if isinstance(eff, (int, float)) else "—"
            name = _short(str(c.get("name") or cid), 52)
            A(f"| {cid} {name} | {eff_s} "
              f"| {_short(str(c.get('standard') or '—'), 40)} | declared |")
        A("")
    if fl.get("pending"):
        A(f"**Evidence still under review.** {fl['pending']} artifact(s) are "
          f"pending review; findings resting on them should be re-checked "
          f"after triage.")
        A("")
    A("**Blast radius not quantified.** Counts of reachable Restricted "
      "assets, typical context sizes, and steward populations were not "
      "recorded, so residual risk is a score, not an exposure estimate.")
    A("")

    A("---")
    A("")
    A("_Every number in this dossier is read from stored rows; none is "
      "recomputed or estimated at render time. Re-running an assessment writes "
      "a new row and leaves the superseded one above. “Usable after review” "
      "means accepted by a reviewer: pending artifacts are unjudged, not "
      "evidence._")
    return "\n".join(L)


def dossier_bundle(db, inv_id: int, dossier: dict | None = None) -> bytes:
    """A ZIP: ``dossier.md`` plus every diagram as ``images/*.png``.

    Each mermaid fence keeps its source -- it renders natively on GitHub and
    keeps the report reproducible -- and gains a picture link above it, so
    the same file also shows figures in viewers with no diagram plugin. A
    fence with no rendered picture stays exactly as the plain Markdown
    export has it.
    """
    import io as _io
    import zipfile as _zf
    from .mermaid_png import collect_sources, render_sources
    md = dossier_markdown(db, inv_id, dossier=dossier)
    try:
        pngs = render_sources(collect_sources(md))
    except Exception:
        pngs = {}
    numbering: dict[str, tuple[int, str]] = {}
    files: dict[str, bytes] = {}
    out: list[str] = []
    buf: list[str] = []
    in_fence = False
    code: list[str] = []

    def _flush_fence() -> None:
        src = "\n".join(code).strip()
        blob = pngs.get(src)
        if blob:
            if src not in numbering:
                head = next((l.strip() for l in code if l.strip()),
                            "diagram")
                slug = re.sub(r"[^a-z0-9]+", "-", head.lower()
                              ).strip("-")[:40] or "diagram"
                n = len(numbering) + 1
                numbering[src] = (n, f"images/fig-{n:02d}-{slug}.png")
                files[numbering[src][1]] = blob
            n, arc = numbering[src]
            head = next((l.strip() for l in code if l.strip()),
                        "diagram")[:80].replace("[", "(").replace("]", ")")
            out.append(f"![Figure {n}: {head}]({arc})")
            out.append("")
        out.extend(buf)

    for raw in md.splitlines():
        line = raw.rstrip()
        if line.strip().startswith("```"):
            if not in_fence:
                buf = [line]
                code = []
            else:
                buf.append(line)
                _flush_fence()
                buf = []
                code = []
            in_fence = not in_fence
            continue
        if in_fence:
            buf.append(line)
            code.append(line)
        else:
            out.append(line)
    bundle = _io.BytesIO()
    with _zf.ZipFile(bundle, "w", _zf.ZIP_DEFLATED) as zf:
        zf.writestr("dossier.md", "\n".join(out) + "\n")
        for arc, blob in files.items():
            zf.writestr(arc, blob)
    return bundle.getvalue()