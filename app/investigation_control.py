"""Investigation control: what can be run, what is running, rerun all or parts.

The Agentic Manager composes investigations from a command. This module is the
other half: the control surface for an investigation that already exists --
which parts of its work can be invoked again, which are already in flight, and
what a re-run would actually do.

A "part" is a unit of work that already has an endpoint and an owner module:
research collection, security assessment, gap research, the CVE sweep, the
explainer, hypothesis evidence, the summary recompute, drift detection. The
investigation-type *plugins* are deliberately not parts: they route and read
back, they do not execute (``app/plugins.py``).

Two rules make the control surface honest, and both are load-bearing:

* **The parts' own guards are reused, never re-implemented.** Each part is
  dispatched by calling the endpoint function that already owns its validation,
  busy lock and audit entry. Copying those guards into a second caller would
  make the two drift, and the copy is the one nobody tests.
* **One part failing never abandons the rest.** A re-run reports per-part
  ``launched`` / ``skipped`` / ``failed`` with the reason, so "rerun everything"
  on a six-part investigation is still useful when the CVE sweep is slow and
  the explainer is busy. Aborting on the first error would report a partial
  action as a total failure.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

# Part catalog. ``requires`` names another part whose output this one reads, so
# "rerun everything" can be ordered and a lone part can be refused with a reason
# instead of silently producing nothing.
PARTS: list[dict[str, Any]] = [
    {
        "key": "research",
        "label": "Research collection",
        "blurb": "Re-plan and collect fresh evidence across the seats.",
        "endpoint": "POST /api/investigations/{id}/run",
        "requires": None,
        "blocking": True,
    },
    {
        "key": "assess",
        "label": "Security assessment",
        "blurb": "Run the AI Security Engineering & Evaluation Agent "
                 "(one assessment, or three for a model subject).",
        "endpoint": "POST /api/investigations/{id}/security/assess",
        "requires": None,
        "blocking": False,
    },
    {
        "key": "gaps",
        "label": "Gap research",
        "blurb": "Paper-first collection on the least-covered open questions.",
        "endpoint": "POST /api/investigations/{id}/research-gaps/run",
        "requires": "research",
        "blocking": True,
    },
    {
        "key": "cves",
        "label": "CVE sweep",
        "blurb": "Re-collect known vulnerabilities from NVD/CIRCL. Only fetches "
                 "what is new; slow and synchronous.",
        "endpoint": "POST /api/investigations/{id}/cves",
        "requires": None,
        "blocking": False,
    },
    {
        "key": "explain",
        "label": "Explainer write-up",
        "blurb": "Answer one question about this investigation and store it.",
        "endpoint": "POST /api/investigations/{id}/explain",
        "requires": None,
        "blocking": False,
    },
    {
        "key": "hypotheses",
        "label": "Hypothesis evidence",
        "blurb": "Collect evidence for the falsifiers of the strongest stored "
                 "hypotheses.",
        "endpoint": "POST /api/security/assessments/{id}/hypotheses/"
                    "{hypothesis_id}/collect-evidence",
        "requires": "assess",
        "blocking": False,
    },
    {
        "key": "summary",
        "label": "Summary recompute",
        "blurb": "Recompute the executive summary from the current review "
                 "flags. Synchronous.",
        "endpoint": "POST /api/investigations/{id}/summary/regenerate",
        "requires": None,
        "blocking": False,
    },
    {
        "key": "drift",
        "label": "Drift detection",
        "blurb": "Re-check stored findings against current sources. "
                 "Synchronous.",
        "endpoint": "POST /api/investigations/{id}/detect-drift",
        "requires": None,
        "blocking": False,
    },
]

PART_BY_KEY = {p["key"]: p for p in PARTS}

# Launch order. A part that reads another part's output runs after it, so a
# full re-run collects evidence before the assessment scores it.
_ORDER = ["research", "assess", "gaps", "cves", "hypotheses", "explain",
          "summary", "drift"]

_LIVE_RUN_STATES = ("running", "awaiting_approval")


def _iso(value: Any) -> str | None:
    return value.isoformat() if value is not None else None


def _counts(db: Session, inv_id: int) -> dict[str, int]:
    from .models import AgentRun, Artifact, CveFinding, Explanation, SecurityAssessment

    def n(model, **filters) -> int:
        return db.query(model).filter(
            model.investigation_id == inv_id, **filters).count()

    return {
        "artifacts": n(Artifact),
        "assessments": n(SecurityAssessment),
        "explanations": n(Explanation),
        "cve_findings": n(CveFinding),
        "runs": n(AgentRun),
    }


def _last_run(db: Session, inv_id: int, triggers: tuple[str, ...]) -> dict | None:
    from .models import AgentRun
    q = db.query(AgentRun).filter(AgentRun.investigation_id == inv_id)
    if triggers:
        q = q.filter(AgentRun.trigger.in_(triggers))
    r = q.order_by(AgentRun.id.desc()).first()
    if r is None:
        return None
    return {"id": r.id, "status": r.status, "trigger": r.trigger or "manual",
            "started_at": _iso(r.started_at), "finished_at": _iso(r.finished_at),
            "error": (r.error or "")[:300] or None}


def _research_busy(db: Session, inv_id: int) -> bool:
    from .models import AgentRun
    return db.query(AgentRun).filter(
        AgentRun.investigation_id == inv_id,
        AgentRun.status.in_(_LIVE_RUN_STATES)).first() is not None


def _explain_busy(db: Session, inv_id: int) -> bool:
    from .models import Explanation
    return db.query(Explanation).filter(
        Explanation.investigation_id == inv_id,
        Explanation.status == "running").first() is not None


def _assess_busy(db: Session, inv_id: int, product: str, use_case: str) -> bool:
    from . import security_agent
    try:
        return security_agent.security_run_busy(
            db, inv_id, assessment_mode="", product_name=product,
            use_case=use_case, focus=[])
    except Exception:
        # An unknown subject profile must not read as "free to launch": the
        # honest answer is that the state could not be determined.
        return True


# --------------------------------------------------------------------------
# State: what each part could do right now, and why not when it could not
# --------------------------------------------------------------------------

def part_state(db: Session, inv_id: int,
               product: str = "", use_case: str = "") -> dict[str, Any]:
    """Per-part availability, busy state and last run. No side effects.

    ``available`` is False when the part has nothing to read yet -- reporting
    it as merely "busy" would send the operator chasing a lock that does not
    exist, when the real answer is "run research first".
    """
    counts = _counts(db, inv_id)
    busy_research = _research_busy(db, inv_id)
    busy_explain = _explain_busy(db, inv_id)
    busy_assess = _assess_busy(db, inv_id, product, use_case)

    blockers = {
        "research": (busy_research,
                     "a run is already in progress for this investigation"),
        "gaps": (busy_research or counts["artifacts"] == 0,
                 "a run is already in progress" if busy_research
                 else "nothing collected yet — run research first"),
        "explain": (busy_explain, "an explanation is already in progress"),
        "assess": (busy_assess,
                   "a security assessment of this kind is already running here"),
        "hypotheses": (counts["assessments"] == 0,
                       "no stored assessment — run the security assessment first"),
    }

    last = {
        "research": _last_run(db, inv_id, ()),
        "gaps": _last_run(db, inv_id, ("research_gaps",)),
        "assess": _last_run(db, inv_id, ("security",)),
        "hypotheses": _last_run(db, inv_id, ("explainer_gap",)),
    }
    from .models import CveFinding, Explanation
    cve_last = (db.query(CveFinding)
                .filter(CveFinding.investigation_id == inv_id)
                .order_by(CveFinding.id.desc()).first())
    if cve_last is not None:
        last["cves"] = {"id": cve_last.id, "status": "collected",
                        "trigger": "cve_sweep",
                        "started_at": _iso(cve_last.created_at),
                        "finished_at": _iso(cve_last.created_at), "error": None}
    exp_last = (db.query(Explanation)
                .filter(Explanation.investigation_id == inv_id)
                .order_by(Explanation.id.desc()).first())
    if exp_last is not None:
        last["explain"] = {"id": exp_last.id, "status": exp_last.status,
                           "trigger": "explainer", "started_at": _iso(exp_last.created_at),
                           "finished_at": _iso(exp_last.finished_at), "error": None}

    parts = []
    for spec in PARTS:
        busy, reason = blockers.get(spec["key"], (False, None))
        parts.append({
            **spec,
            "available": not busy,
            # Only when blocked: a reason shown next to an available part
            # reads as "something is wrong" when nothing is.
            "blocked_reason": None if not busy else reason,
            "last": last.get(spec["key"]),
        })
    return {"investigation_id": inv_id, "counts": counts, "parts": parts,
            "order": _ORDER,
            "full_set": [p["key"] for p in parts if p["available"]]}


# --------------------------------------------------------------------------
# Launch
# --------------------------------------------------------------------------

def _dispatch(db: Session, inv_id: int, key: str, params: dict[str, Any],
              request: Any) -> dict[str, Any]:
    """Call the endpoint function that owns this part.

    Importing ``main`` here (not at module scope) is deliberate: main imports
    this module for its routes, so a top-level import would be circular. The
    alternative -- re-implementing the busy locks -- is worse: the copy would
    drift from the endpoint it shadows and nothing would notice.
    """
    from . import main as main_mod

    if key == "research":
        main_mod.start_run(inv_id, main_mod.RunRequest(
            max_items=int(params.get("max_items", 25)),
            max_rounds=int(params.get("max_rounds", 2))), request, db)
        return {"status": "launched", "run_id": None}

    if key == "assess":
        payload = main_mod.SecurityAssessRequest(
            product_name=params.get("product_name") or "Target product",
            product_url=params.get("product_url") or "",
            exposure=params.get("exposure") or "confidential_data",
            use_case=params.get("use_case") or "",
            focus=params.get("focus") or [],
            assessment_mode=params.get("assessment_mode") or "",
            allow_partial=bool(params.get("allow_partial", True)))
        out = main_mod.start_security_assessment(inv_id, payload, request, db)
        return {"status": "launched", "run_id": out.get("run_id")}

    if key == "gaps":
        out = main_mod.investigation_gaps_run(
            inv_id, main_mod.GapResearchRequest(
                top_n=int(params.get("top_n", 3)),
                max_items=int(params.get("max_items", 12))), db)
        launched = out.get("launched") or {}
        # "No open gaps" is a real answer, not a failure: the part ran and the
        # investigation has nothing left to collect. Report it as such.
        if not launched:
            return {"status": "nothing_to_do", "run_id": None,
                    "detail": out.get("message") or "no open gaps"}
        return {"status": "launched", "run_id": launched.get("run_id"),
                "detail": out.get("message")}

    if key == "cves":
        out = main_mod.collect_cves(inv_id, db)
        return {"status": "collected",
                "detail": f"{len(out.get('findings') or [])} CVE finding(s) stored",
                "raw": {"cve_artifacts": out.get("artifacts"),
                        "findings": len(out.get("findings") or [])}}

    if key == "explain":
        from .models import Investigation
        inv = db.query(Investigation).filter(
            Investigation.id == inv_id).first()
        subject = getattr(inv, "title", "") or "this investigation"
        question = (params.get("question")
                    or f"What is the current state and main risk of {subject}?")
        out = main_mod.ask_explainer(inv_id, main_mod.ExplainRequest(
            question=question, mode=params.get("mode") or "explain",
            depth=params.get("explain_depth") or "balanced",
            audience=params.get("audience") or "intermediate",
            max_pages=int(params.get("max_pages", 6))), request, db)
        return {"status": "launched", "run_id": out.get("id"),
                "detail": f"explanation #{out.get('id')}"}

    if key == "hypotheses":
        return _dispatch_hypotheses(db, inv_id, params, request)

    if key == "summary":
        out = main_mod.regenerate_summary(inv_id, request, db)
        return {"status": "computed",
                "detail": (out.get("synthesis") or "")[:200] or "summary recomputed"}

    if key == "drift":
        out = main_mod.detect_investigation_drift(
            inv_id, main_mod.DetectDriftRequest(), request, db)
        return {"status": "computed",
                "detail": f"{(out.get('drifted') or out.get('checked') or 0)} finding(s) checked"}

    raise ValueError(f"unknown part: {key}")


def _dispatch_hypotheses(db: Session, inv_id: int, params: dict[str, Any],
                         request: Any) -> dict[str, Any]:
    """Collect evidence for the top falsifiable hypotheses on the newest row."""
    from . import dossier as _dossier
    from . import main as main_mod
    from .models import SecurityAssessment
    rec = (db.query(SecurityAssessment)
           .filter(SecurityAssessment.investigation_id == inv_id)
           .order_by(SecurityAssessment.id.desc()).first())
    if rec is None:
        return {"status": "nothing_to_do",
                "detail": "no stored assessment to read hypotheses from"}
    register = _dossier.hypothesis_register(rec)
    wanted = str(params.get("hypothesis_id") or "").strip()
    claims = (register if wanted else [
        c for c in register
        if (c.get("status") or "untested") in ("untested", "contested")])
    if wanted:
        claims = [c for c in register
                  if (c.get("hypothesis_id") or c.get("id")) == wanted]
    claims = claims[:max(1, min(int(params.get("top_n", 2)), 5))]
    launched = []
    for c in claims:
        hid = c.get("hypothesis_id") or c.get("id")
        if not hid:
            continue
        out = main_mod.collect_hypothesis_evidence(rec.id, hid, db)
        launched.append(out.get("run_id"))
    if not launched:
        return {"status": "nothing_to_do",
                "detail": "no open hypotheses with falsifiers to test"}
    return {"status": "launched", "run_id": launched[0],
            "detail": f"{len(launched)} hypothesis run(s)",
            "run_ids": launched}


def launch(db: Session, inv_id: int, parts: list[str] | None = None,
           params: dict[str, Any] | None = None, request: Any = None,
           actor: str = "") -> dict[str, Any]:
    """Re-run the selected parts, or every available part when none are given.

    Returns one outcome per requested part. A part that raises is recorded and
    the next one still runs: a re-run is a fan-out, and reporting only the
    first failure would hide the five parts that did launch.
    """
    params = params or {}
    state = part_state(db, inv_id, product=params.get("product_name") or "",
                       use_case=params.get("use_case") or "")
    available = {p["key"]: p for p in state["parts"]}

    if not parts or (len(parts) == 1 and parts[0] in ("*", "all")):
        wanted = [k for k in _ORDER if available.get(k, {}).get("available")]
    else:
        wanted = []
        for key in parts:
            if key not in PART_BY_KEY:
                raise ValueError(f"unknown part: {key}")
            if key not in wanted:
                wanted.append(key)
        wanted.sort(key=_ORDER.index)

    outcomes = []
    for key in wanted:
        spec = available.get(key)
        if spec is None:
            outcomes.append({"part": key, "status": "failed",
                             "detail": "unknown part"})
            continue
        if not spec["available"]:
            outcomes.append({"part": key, "label": spec["label"],
                             "status": "skipped",
                             "detail": spec["blocked_reason"]})
            continue
        try:
            result: dict[str, Any] = _dispatch(db, inv_id, key, params, request)
            outcomes.append({"part": key, "label": spec["label"], **result})
        except Exception as exc:  # noqa: BLE001 - one part must not stop the rest
            status = _http_status(exc)
            outcomes.append({
                "part": key, "label": spec["label"], "status": "failed",
                "detail": _clean(exc), "http_status": status,
                # A 429 or 409 means the part's own guard refused it, which is
                # a normal outcome of a fan-out, not an error to surface red.
                "refused": status in (409, 422, 429)})
    launched = [o for o in outcomes if o.get("status") in ("launched",
                                                            "collected",
                                                            "computed")]
    return {
        "investigation_id": inv_id,
        "requested": wanted,
        "outcomes": outcomes,
        "counts": {
            "launched": len(launched),
            "skipped": sum(1 for o in outcomes if o.get("status") == "skipped"),
            "failed": sum(1 for o in outcomes if o.get("status") == "failed"),
            "nothing_to_do": sum(1 for o in outcomes
                                 if o.get("status") == "nothing_to_do"),
        },
        "actor": actor or None,
        "state": part_state(db, inv_id, product=params.get("product_name") or "",
                            use_case=params.get("use_case") or ""),
    }


def _http_status(exc: Exception) -> int | None:
    status = getattr(exc, "status_code", None)
    return status if isinstance(status, int) else None


def _clean(exc: Exception) -> str:
    detail = getattr(exc, "detail", None)
    text = detail if isinstance(detail, str) else str(exc)
    return text[:300]
