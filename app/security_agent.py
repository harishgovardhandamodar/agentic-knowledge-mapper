"""AI Security Engineering & Evaluation Agent runner.

A run is an AgentRun (trigger="security") with AgentEvent progress the GUI
polls, and the finished product is a SecurityAssessment row scoped to the
investigation. Work is dispatched through the persisted job queue rather than a
bare thread, so a restart mid-assessment does not leave the run stuck with
nothing to retry.

Inside, the assessment itself runs the agent-to-agent workflow from
app/agents.py (orchestrator → research-collector → threat-intel →
report-writer), where research-collector searches THIS app's knowledge graph
(artifacts of the investigation) for related research papers and known-attack
evidence.
"""
import json
import contextvars
import threading
import traceback
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from .database import SessionLocal
from .models import Investigation, AgentRun, AgentEvent, SecurityAssessment
from . import security as sec_engine
from . import threatpack
from . import approvals
from . import jobqueue
from . import obs

#: Job kind for security assessments. The queue is shared, so every enqueue
#: names its kind and the worker can be pointed at a subset.
KIND_SECURITY = "security_assessment"

_worker = None
_worker_lock = threading.Lock()


def _handle_security_job(job, payload) -> bool:
    """Queue handler: run one security assessment.

    Returns True for "done". ``run_security_assessment`` handles its own errors
    by writing them onto the run, so a failure here is a bug in the handler
    itself and is left to the queue to retry.

    The trace is re-bound from the payload rather than inherited: a queued job
    outlives the request that created it and is executed by the worker thread,
    whose context is the worker's own. Copying the context at claim time used to
    be enough when the job *was* the request's thread, and silently stopped
    being true the moment a queue got involved.
    """
    run_id = payload.get("run_id")
    if not run_id:
        return False
    with obs.trace_scope(payload.get("trace")):
        run_security_assessment(run_id, payload.get("params") or {})
    return True


def recover_jobs() -> list:
    """Re-queue jobs a dead worker left behind. Returns the recovered run ids.

    Called from application startup, before the interrupted-run sweep, so the two
    agree about which runs are actually lost.
    """
    db = SessionLocal()
    try:
        stale = jobqueue.recover_orphans(db)
        run_ids = [j.run_id for j in stale if j.run_id]
        if run_ids:
            # Notified on one of the recovered runs, not on ``stale[0]``: a job
            # need not belong to a run at all, and an event with a null run_id is
            # a NOT NULL violation, not a notification.
            _event(db, run_ids[0], "queue",
                   f"Re-queued {len(stale)} job(s) left running by a previous "
                   f"process.", {"jobs": [j.id for j in stale]})
        return run_ids
    finally:
        db.close()


def _ensure_worker():
    """Start the shared worker once, if it is not already polling.

    Recovery is *not* done here. Doing it on first launch meant a process that
    restarted with nothing queued never looked at the job its own crash left
    behind; :func:`recover_jobs` runs at startup instead, where a restart is
    actually noticed.
    """
    global _worker
    with _worker_lock:
        if _worker is None:
            _worker = jobqueue.start_worker(_handle_security_job,
                                            kinds=[KIND_SECURITY])
    return _worker


def start_worker():
    """Begin polling, after recovery has had its chance to re-queue work."""
    return _ensure_worker()


def _event(db: Session, run_id: int, stage: str, message: str, data: dict | None = None):
    db.add(AgentEvent(run_id=run_id, stage=stage, message=message,
                      data=json.dumps(data or {})))
    db.commit()


def security_run_stats(result: dict, assessment_id: int,
                       duration_ms: int | None) -> dict:
    """The measurable trace every security run leaves in ``agent_runs.stats``.

    Posture, pack identity and duration are pinned here (not just the score)
    so the dossier can show cost and provenance even for short or failed runs
    instead of printing "no stats recorded".
    """
    return {"assessment_id": assessment_id,
            "overall_pct": result.get("overall_pct"),
            "inherent_pct": result.get("inherent_pct"),
            "residual_pct": result.get("residual_pct"),
            "delta": result.get("delta"),
            "posture": result.get("posture", ""),
            "pack_version": threatpack.PACK_VERSION,
            "pack_fingerprint": threatpack.pack_fingerprint(),
            "active_controls": result.get("active_controls", []),
            "control_count": len(result.get("active_controls", [])),
            "confidence": result.get("confidence"),
            "threats": len(result.get("threats", [])),
            "evidence": len(result.get("evidence", [])),
            "known_exploits": len(result.get("known_exploits", [])),
            "collector_cache_hits": result.get("collector_cache_hits", 0),
            "duration_ms": duration_ms}


def run_security_assessment(run_id: int, params: dict):
    db = SessionLocal()
    try:
        run = db.query(AgentRun).filter(AgentRun.id == run_id).first()
        if not run:
            return
        inv = db.query(Investigation).filter(
            Investigation.id == run.investigation_id).first()
        if not inv:
            raise RuntimeError("investigation not found")

        _mode = params.get("assessment_mode") or ""
        _prof = sec_engine.profile_model_subject(
            params.get("product_name") or "", params.get("use_case") or "",
            params.get("focus") or [])
        # One resolver, shared with the route's busy check and the engine, so
        # the mode the lock protects is the mode the run will take.
        _resolved = sec_engine.resolve_model_mode(
            params.get("product_name") or "", params.get("use_case") or "",
            params.get("focus") or [], _mode, subject_profile=_prof)
        if _mode == "hypothesis":
            _event(db, run.id, "plan",
                   f"Hypothesis synthesis for '{params.get('product_name') or 'model'}': "
                   "reads the stored internals and misuse assessments and "
                   "drafts falsifiable claims with refutation tests. "
                   "A2A: hypothesis-analyst → research-collector → "
                   "hypothesis-verifier → scoring (confidence) → "
                   "hypothesis-reporter. No standards mapping.")
        elif _prof["is_model_query"]:
            _event(db, run.id, "plan",
                   f"Model subject: {(_prof.get('summary') or 'model')} → "
                   f"{_resolved} path "
                   f"({'adversarial misuse: what can be built with this model' if _resolved == 'adversarial' else 'internals/privacy: is this model sound'}). "
                   "No AI-standards mapping on either model path.")
        else:
            _event(db, run.id, "plan",
                   f"Security assessment planned for '{params.get('product_name') or 'product'}' "
                   f"(exposure: {params.get('exposure')}). "
                   "A2A: orchestrator → control-analyst → research-collector → threat-intel → "
                   "scoring → report-writer.")

        # ---- approval gate: run the control-analyst stage only, then pause for
        # ---- the operator to confirm the control plan before the rest proceeds.
        #
        # An approved plan is honoured ONLY when it carries an approver. A plan
        # arriving on the original request used to skip the gate entirely, which
        # made the gate a field the requester set for themselves; now a plan
        # without a recorded approver is ignored and the run parks as designed.
        approved_plan = params.get("approved_control_plan") or None
        if approved_plan is not None and not (
                params.get("approved_by")
                and params.get("approved_at")):
            _event(db, run.id, "gate",
                   "Ignored an approved control plan with no recorded approver; "
                   "parking at the gate instead.")
            approved_plan = None
        approved_mplan = params.get("approved_mitigation_plan") or None
        if approved_mplan is not None and not (
                params.get("approved_by")
                and params.get("approved_at")):
            _event(db, run.id, "gate",
                   "Ignored an approved mitigation plan with no recorded "
                   "approver; parking at the gate instead.")
            approved_mplan = None
        if params.get("require_approval") and not approved_plan:
            # The gate approves a catalog control plan, so a model subject has
            # nothing to park on: its path scores dimension weights and maps no
            # controls. Parking there would ask an operator to approve a plan
            # the run then ignores. Say so in the event and run straight
            # through -- the model path's own review is the report.
            from . import security as _sec
            _gate_profile = _sec.profile_model_subject(
                params.get("product_name") or "", params.get("use_case") or "",
                params.get("focus") or [])
            if _mode == "model_engineering" and (
                    params.get("model_meta") or {}).get("workflows") and \
                    "mitigation_controls" in (
                        params.get("model_meta") or {}).get("workflows") and \
                    not approved_mplan:
                # W3 proposes a real MM* plan, so there IS something to park
                # on: run through the mitigation analyst, then wait for a
                # human. Other model paths still skip (nothing to approve).
                from .agents import run_model_engineering_a2a_workflow
                preview = run_model_engineering_a2a_workflow(
                    params.get("model_meta") or {},
                    use_case=params.get("use_case") or "",
                    db=db, investigation_id=inv.id,
                    exposure=params.get("exposure") or "confidential_data",
                    stop_after="analyst")
                plan = preview.get("mitigation") or {}
                run.status = "awaiting_approval"
                run.stats = json.dumps({"pending_gate": "model_mitigation_plan",
                                        "mitigation_plan": plan,
                                        "params": params})
                db.commit()
                _event(db, run.id, "gate",
                       f"Awaiting approval: mitigation-analyst proposes "
                       f"{len(plan.get('plan', []))} control(s), "
                       f"{len(plan.get('deferred', []))} deferred. "
                       f"Approve or reject in the Security tab to continue.",
                       {"mitigation_plan": plan})
                return
            if _gate_profile["is_model_query"] or _mode == "hypothesis" or \
                    _mode == "model_engineering":
                _event(db, run.id, "gate",
                       "Approval gate skipped: no catalog control plan exists "
                       "on this path (dimension weights / hypotheses instead). "
                       "Review the report instead.")
            else:
                from .agents import new_envelope, dispatch
                gate_env = new_envelope(
                    "security-orchestrator", "control-analyst", "analyse_controls",
                    {"product_name": params.get("product_name") or "Target product",
                     "use_case": params.get("use_case") or "",
                     "exposure": params.get("exposure") or "confidential_data",
                     "declared_controls": params.get("declared_controls") or []})
                gate_res = dispatch(gate_env, db)
                plan = gate_res.get("payload", {})
                run.status = "awaiting_approval"
                run.stats = json.dumps({"pending_gate": "control_plan",
                                        "control_plan": plan,
                                        "params": params})
                db.commit()
                _event(db, run.id, "gate",
                       f"Awaiting approval: control-analyst proposes "
                       f"{len(plan.get('declared_controls', []))} active + "
                       f"{len(plan.get('proposed_controls', []))} recommended control(s) "
                       f"(confidence {plan.get('confidence', 0):.0%}). "
                       f"Approve or reject in the Security tab to continue.",
                       {"control_plan": plan})
                return

        result = sec_engine.build_assessment(
            product_name=params.get("product_name") or "Target product",
            product_url=params.get("product_url") or "",
            exposure=params.get("exposure") or "confidential_data",
            use_case=params.get("use_case") or "",
            workflow_text=params.get("workflow_text") or "",
            doc_urls=params.get("doc_urls") or [],
            focus=params.get("focus") or [],
            db=db,
            investigation_id=inv.id,
            declared_controls=params.get("declared_controls") or [],
            control_plan_override=approved_plan,
            assessment_mode=params.get("assessment_mode") or "",
            model_meta=params.get("model_meta") or {},
        )

        plan = result.get("control_plan", {})
        _path = (result.get("scoring", {}).get("assessment_path") or "standard")
        if _path == "model_adversarial":
            # Named per-hop, not per-catalog-agent: on this path no
            # control-analyst and no threat-intel ran, and an event log that
            # claims they did is a false audit trail.
            _adv = next((h for h in result.get("a2a_trace", [])
                         if h.get("intent") == "derive_capabilities"), {})
            _scout = next((h for h in result.get("a2a_trace", [])
                           if h.get("intent") == "engineer_scenarios"), {})
            _event(db, run.id, "analyze",
                   f"model-adversary: {_adv.get('note', 'capabilities derived')}.",
                   {"hop": _adv})
            _event(db, run.id, "map",
                   f"misuse-scout: {_scout.get('note', 'scenarios engineered')}.",
                   {"hop": _scout})
        elif _path == "model":
            _event(db, run.id, "analyze",
                   f"model-internals + model-privacy: "
                   f"{len(result.get('threats', []))} model findings across "
                   f"{len(result.get('scoring', {}).get('dimensions', []))} "
                   "weighted dimensions.")
        elif _path == "model_hypothesis":
            h = next((x for x in result.get("a2a_trace", [])
                      if x.get("intent") == "draft_hypotheses"), {})
            v = next((x for x in result.get("a2a_trace", [])
                      if x.get("intent") == "verify_hypotheses"), {})
            _event(db, run.id, "analyze",
                   f"hypothesis-analyst: {h.get('note', 'claims drafted')}.",
                   {"hop": h})
            _event(db, run.id, "map",
                   f"hypothesis-verifier/reporter: {v.get('note', 'claims verified')}.",
                   {"hop": v})
        elif _path == "model_engineering":
            _w1 = (result.get("scoring", {}) or {}).get("w1", {}) or {}
            _w2 = (result.get("scoring", {}) or {}).get("w2", {}) or {}
            _event(db, run.id, "analyze",
                   f"model-adv-intel: {len(result.get('model_attacks', []))} "
                   f"W1 attack findings "
                   f"(coverage {_w1.get('coverage_pct', 0):g}%).",
                   {"findings": [f.get("attack_id")
                                 for f in result.get("model_attacks", [])]})
            _event(db, run.id, "map",
                   f"model-adoption-analyst: "
                   f"{sum(1 for d in result.get('adoption_dimensions', []) if d.get('rating') != 'unknown')}/"
                   f"{len(result.get('adoption_dimensions', []))} W2 dimensions rated "
                   f"(uncertainty {_w2.get('uncertainty_pct', 0):g}%).")
        else:
            _event(db, run.id, "controls",
                   f"control-analyst: {len(plan.get('declared_controls', []))} declared control(s), "
                   f"{len(plan.get('proposed_controls', []))} proposed, "
                   f"confidence {plan.get('confidence', 0):.0%} ({plan.get('source', 'n/a')}).",
                   {"declared": plan.get("declared_controls", []),
                    "proposed": plan.get("proposed_controls", []),
                    "confidence": plan.get("confidence", 0)})
            _event(db, run.id, "analyze",
                   f"threat-intel: {len(result.get('known_exploits', []))} known attacks mapped "
                   f"onto {len(result.get('threats', []))} threats.",
                   {"exploits": [k["id"] for k in result.get("known_exploits", [])]})
            _event(db, run.id, "map",
                   f"report-writer: Known Exploits section + executive summary drafted "
                   f"(A2A task {result.get('a2a_task_id')}).")
        if _path == "model_engineering":
            _w1s = (result.get("scoring", {}) or {}).get("w1", {}) or {}
            _w2s = (result.get("scoring", {}) or {}).get("w2", {}) or {}
            _event(db, run.id, "score",
                   f"Deterministic scoring: W1 "
                   f"{_w1s.get('overall_pct', '—')}/100 "
                   f"(coverage {_w1s.get('coverage_pct', 0):g}%) · W2 "
                   f"{_w2s.get('overall_pct', '—')}/100 "
                   f"(uncertainty {_w2s.get('uncertainty_pct', 0):g}%) — "
                   f"{result.get('posture', '')[:60]}.",
                   {"w1": _w1s, "w2": _w2s})
        else:
            _event(db, run.id, "score",
                   f"Deterministic scoring: inherent {result.get('inherent_pct', 0):g}/100 → "
                   f"residual {result.get('residual_pct', 0):g}/100 "
                   f"({result.get('delta', 0):+g}) — {result.get('posture', '')[:60]}.",
                   {"inherent_pct": result.get("inherent_pct"),
                    "residual_pct": result.get("residual_pct"),
                    "active_controls": result.get("active_controls", []),
                    "breakdown": result.get("scoring", {}).get("breakdown", {})})
        _event(db, run.id, "search",
               f"research-collector: {len(result.get('evidence', []))} evidence items "
               f"({result.get('queries_run') and len(result['queries_run'])} queries).",
               {"evidence": [e["title"][:80] for e in result.get("evidence", [])[:10]]})

        rec = SecurityAssessment(
            investigation_id=inv.id,
            run_id=run.id,
            requested_by=params.get("requested_by"),
            product_name=result["product_name"],
            product_url=result["product_url"],
            exposure=result["exposure"],
            use_case=params.get("use_case") or "",
            workflow_text=params.get("workflow_text") or "",
            doc_urls_json=json.dumps(params.get("doc_urls") or []),
            focus_json=json.dumps(params.get("focus") or []),
            require_approval=1 if params.get("require_approval") else 0,
            overall_pct=result["overall_pct"],
            inherent_pct=result.get("inherent_pct", result["overall_pct"]),
            residual_pct=result.get("residual_pct", result["overall_pct"]),
            controls_json=json.dumps({
                "active_controls": result.get("active_controls", []),
                "control_plan": result.get("control_plan", {}),
                "openshell": result.get("openshell", {}),
            }),
            scoring_json=json.dumps(result.get("scoring", {})),
            situation_json=json.dumps(params["situation"])
            if params.get("situation") else None,
            initiative_id=params.get("initiative_id"),
            perspectives_json=json.dumps(result.get("perspectives", [])),
            posture=result["posture"],
            markdown=result["markdown"],
            diagrams_json=json.dumps(result["diagrams"]),
            threats_json=json.dumps(result["threats"]),
            evidence_json=json.dumps({
                "evidence": result.get("evidence", []),
                "queries_run": result.get("queries_run", []),
                "known_exploits": result.get("known_exploits", []),
                "scope": result.get("scope", ""),
                "exec_paragraph": result.get("exec_paragraph", ""),
            }),
            a2a_trace_json=json.dumps({
                "task_id": result.get("a2a_task_id", ""),
                "trace": result.get("a2a_trace", []),
            }),
            threat_pack_version=threatpack.PACK_VERSION,
            threat_pack_fingerprint=threatpack.pack_fingerprint(),
            model_json=json.dumps({
                "meta": result.get("model_meta") or {},
                "attacks": result.get("model_attacks") or [],
                "dimensions": result.get("adoption_dimensions") or [],
                "mitigation": result.get("mitigation") or {},
                "experiments": result.get("experiments") or [],
                "w1": (result.get("scoring", {}) or {}).get("w1", {}),
                "w2": (result.get("scoring", {}) or {}).get("w2", {}),
                "w3": (result.get("scoring", {}) or {}).get("w3", {}),
                "approved_mitigation_plan":
                    params.get("approved_mitigation_plan"),
                "approved_by": params.get("approved_by"),
                "approved_at": params.get("approved_at"),
                "model_adv_version": (result.get("scoring", {}) or {}).get(
                    "model_adv_version"),
                "model_adv_fingerprint": (result.get("scoring", {}) or {}).get(
                    "model_adv_fingerprint"),
                "adoption_version": (result.get("scoring", {}) or {}).get(
                    "adoption_version"),
                "adoption_fingerprint": (result.get("scoring", {}) or {}).get(
                    "adoption_fingerprint"),
            }) if result.get("model_meta") else None,
        )
        db.add(rec)
        db.commit()
        db.refresh(rec)

        # Sync the model-security knowledge base. Assessment -> graph nodes,
        # edges and stored registers, idempotently: a second run on the same
        # model enriches the same nodes instead of adding near-duplicates. A
        # product assessment is skipped by the sync itself; a KB failure must
        # never cost the operator their assessment, so it is reported as an
        # event and the row stands.
        try:
            from . import model_kb as _kb
            _kbres = _kb.sync_model_kb(db, rec.id)
            if not _kbres.get("skipped"):
                _event(db, run.id, "map",
                       f"Knowledge base synced: {_kbres['nodes_created']} new "
                       f"node(s), {_kbres['nodes_updated']} enriched, "
                       f"{_kbres['edges_created']} new edge(s) "
                       f"(fingerprint {_kbres['fingerprint']}).",
                       {k: v for k, v in _kbres.items()
                        if k not in ("skipped", "reason")})
        except Exception as _kb_err:
            _event(db, run.id, "map",
                   f"Knowledge base sync failed ({_kb_err}); the assessment "
                   f"itself is unaffected and can be re-synced from the "
                   f"Landscape tab.", {"error": str(_kb_err)[:200]})

        # Mitigation-advisor hop: the same deterministic pack the Portfolio
        # tab shows, recorded on the run so the pipeline and the tab cannot
        # disagree about what was advised. Fail-open like the KB sync: advice
        # is derived from stored rows and versioned catalogs, never a
        # re-score, so it must never fail the run.
        try:
            from .agents import new_envelope as _new_env, dispatch as _dispatch
            _adv_res = _dispatch(_new_env(
                "security-orchestrator", "mitigation-advisor",
                "advise_portfolio_risks",
                {"investigation_id": inv.id,
                 "initiative_id": params.get("initiative_id")}), db)
            _adv_payload = _adv_res.get("payload", {}) or {}
            _adv_items = _adv_payload.get("advice", []) or []
            _event(db, run.id, "advise",
                   f"mitigation-advisor: {len(_adv_items)} advice item(s), "
                   f"{sum(1 for a in _adv_items if a.get('quick_win'))} "
                   f"quick win(s) ({_adv_payload.get('method')} "
                   f"v{_adv_payload.get('version')}, deterministic).",
                   {"advice_count": len(_adv_items),
                    "initiative_id": params.get("initiative_id")})
        except Exception as _adv_err:
            _event(db, run.id, "advise",
                   f"mitigation-advisor unavailable ({_adv_err}); advice "
                   f"remains available from the Portfolio tab.",
                   {"error": str(_adv_err)[:200]})

        # NOTE: build_assessment ran the A2A workflow on this same session;
        # expire everything so later reads see fresh state.
        db.expire_all()
        run = db.query(AgentRun).filter(AgentRun.id == run_id).first()
        finished = datetime.now(timezone.utc)
        try:
            duration_ms = int((finished - run.started_at).total_seconds()
                              * 1000) if run.started_at else None
        except Exception:
            duration_ms = None
        stats = security_run_stats(result, rec.id, duration_ms)
        run.stats = json.dumps(stats)
        run.status = "done"
        run.finished_at = finished
        db.commit()
        _event(db, run.id, "summary",
               f"Done: {result['product_name']} — residual risk "
               f"{result['overall_pct']}/100 ({result['posture'][:60]}…).",
               stats)
    except Exception as e:
        try:
            run = db.query(AgentRun).filter(AgentRun.id == run_id).first()
            if run:
                run.status = "error"
                run.error = f"{e}\n{traceback.format_exc()[-2000:]}"
                run.finished_at = datetime.now(timezone.utc)
                # A failed assessment still leaves measurable stats: the pack
                # it ran against and how long it lived are known even when the
                # score is not, so the dossier can show cost and provenance
                # instead of "no stats recorded".
                try:
                    prior = json.loads(run.stats or "{}")
                    if not isinstance(prior, dict):
                        prior = {}
                except Exception:
                    prior = {}
                prior.setdefault("pack_version", threatpack.PACK_VERSION)
                prior.setdefault("pack_fingerprint",
                                 threatpack.pack_fingerprint())
                try:
                    prior.setdefault(
                        "duration_ms",
                        int((run.finished_at - run.started_at)
                            .total_seconds() * 1000)
                        if run.started_at else None)
                except Exception:
                    pass
                prior["failed"] = str(e)[:200]
                run.stats = json.dumps(prior)
                db.commit()
                _event(db, run.id, "summary", f"Security assessment failed: {e}")
        except Exception:
            db.rollback()
    finally:
        db.close()


def launch_security_assessment(investigation_id: int, params: dict,
                               requested_by: str = "") -> int:
    """Create the run row, queue the work, and start a worker. Returns run_id.

    The work goes through the queue rather than straight into a thread: the run
    row alone is not a record of a job, and a thread's memory is not either. A
    restart between here and the end of the assessment used to leave the run
    stuck at "running" with nothing to retry.
    """
    db = SessionLocal()
    try:
        run = AgentRun(investigation_id=investigation_id, status="running",
                       trigger="security",
                       plan=json.dumps({"goal": "AI security assessment",
                                        "product": params.get("product_name", ""),
                                        "exposure": params.get("exposure", ""),
                                        "controls": params.get("declared_controls", []),
                                        "assessment_mode": params.get("assessment_mode", ""),
                                        "model_meta": params.get("model_meta") or {},
                                        "require_approval": bool(params.get("require_approval"))}))
        db.add(run)
        db.commit()
        db.refresh(run)
        run_id = run.id
        # Recorded at creation, not at approval time: the approver check needs
        # to know who asked, and by the time they approve that is not otherwise
        # recoverable.
        params = dict(params or {})
        params["requested_by"] = requested_by or approvals.UNKNOWN_ACTOR
        jobqueue.enqueue(db, KIND_SECURITY, {"run_id": run_id, "params": params},
                         key=f"security:{run_id}", run_id=run_id)
    finally:
        db.close()
    _ensure_worker()
    return run_id


def resume_security_assessment(run_id: int, *, approved_by: str = "",
                               note: str = "") -> bool:
    """Resume a run parked at an approval gate. Returns True if resumed.

    ``approved_by`` is required to be a real identity: the caller is expected to
    have run it past :func:`app.approvals.check_approver` first, and the stamp
    it writes is what :func:`run_security_assessment` later checks before
    honouring the plan. Without the stamp the run re-parks at the gate, so a
    resume that skipped the check cannot slip through.
    """
    db = SessionLocal()
    try:
        run = db.query(AgentRun).filter(AgentRun.id == run_id).first()
        if not run or run.status != "awaiting_approval":
            return False
        try:
            stats = json.loads(run.stats or "{}")
        except Exception:
            stats = {}
        gate = stats.get("pending_gate") or "control_plan"
        plan = stats.get("control_plan" if gate == "control_plan"
                         else "mitigation_plan", {})
        # Restore the original request params (use_case, workflow, docs, focus)
        # so the resumed run is identical apart from the approved plan.
        params = dict(stats.get("params") or {})
        try:
            run_plan = json.loads(run.plan or "{}")
        except Exception:
            run_plan = {}
        params.setdefault("product_name", run_plan.get("product", ""))
        params.setdefault("exposure", run_plan.get("exposure", "confidential_data"))
        if gate == "model_mitigation_plan":
            params["approved_mitigation_plan"] = plan
        else:
            params["declared_controls"] = plan.get("declared_controls", [])
            params["approved_control_plan"] = plan
        params["require_approval"] = False
        params["approved_by"] = approvals.normalise_actor(approved_by)
        params["approved_at"] = datetime.now(timezone.utc).isoformat()
        params["approval_note"] = note[:500]
        # The approval has already happened, so this is a re-queue rather than a
        # new run: the same key keeps a double-click from starting a second one.
        jobqueue.enqueue(db, KIND_SECURITY, {"run_id": run_id, "params": params},
                         key=f"security:{run_id}", run_id=run_id)
        run.status = "running"
        run.stats = None
        db.commit()
    finally:
        db.close()
    _ensure_worker()
    return True


def security_run_busy(db: Session, investigation_id: int,
                      assessment_mode: str = "",
                      product_name: str = "",
                      use_case: str = "",
                      focus: Optional[list] = None) -> bool:
    """Is a duplicate of THIS assessment already in flight?

    Scoped by mode on purpose. A model subject legitimately has three
    assessments -- soundness, misuse, and the hypothesis synthesis over the
    other two -- and they must be able to run together; blocking the second one
    because the first is running would make the set impossible to produce. A
    second run of the same resolved mode is still a double-submit and still
    refused.

    Compares the RESOLVED mode, not the requested string. Without that, an
    auto-mode request that resolves to ``adversarial`` sails past the lock held
    by the explicit ``adversarial`` run it actually duplicates, and the user
    ends up with two concurrent runs writing two reports of the same thing.
    """
    q = db.query(AgentRun).filter(
        AgentRun.investigation_id == investigation_id,
        AgentRun.status.in_(["running", "awaiting_approval"]),
        AgentRun.trigger == "security")
    runs = q.all()
    if not runs:
        return False
    from . import security as _sec
    prof = _sec.profile_model_subject(product_name or "", use_case or "",
                                      focus or [])
    wanted = _sec.resolve_model_mode(product_name or "", use_case or "",
                                     focus or [], assessment_mode or "",
                                     subject_profile=prof)
    for run in runs:
        try:
            existing = json.loads(run.plan or "{}").get("assessment_mode", "")
        except Exception:
            existing = ""
        if not existing:
            # A plan written before the mode existed: fall back to the params
            # it stored when it parked at the approval gate, which is the
            # only place they are persisted.
            try:
                existing = (json.loads(run.stats or "{}")
                            .get("params", {}).get("assessment_mode", ""))
            except Exception:
                existing = ""
        if not existing:
            # Its own mode is unknown -- a run queued before modes were
            # recorded, whose subject text was not stored either. There is no
            # honest way to tell whether it duplicates this request, so refuse:
            # this is the blanket block that predates mode scoping, and a
            # wrongly-admitted run would write a second report of a question
            # that may already be in flight.
            return True
        resolved_existing = _sec.resolve_model_mode(
            product_name or "", use_case or "", focus or "",
            existing, subject_profile=prof)
        if resolved_existing == wanted:
            return True
    return False
