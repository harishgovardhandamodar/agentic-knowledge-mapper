"""AI Security Engineering & Evaluation Agent runner.

Background-thread runner following the conventions of app/agent.py: a run is an
AgentRun (trigger="security") with AgentEvent progress the GUI polls, and the
finished product is a SecurityAssessment row scoped to the investigation.

Inside, the assessment itself runs the agent-to-agent workflow from
app/agents.py (orchestrator → research-collector → threat-intel →
report-writer), where research-collector searches THIS app's knowledge graph
(artifacts of the investigation) for related research papers and known-attack
evidence.
"""
import json
import threading
import traceback
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .database import SessionLocal
from .models import Investigation, AgentRun, AgentEvent, SecurityAssessment
from . import security as sec_engine


def _event(db: Session, run_id: int, stage: str, message: str, data: dict | None = None):
    db.add(AgentEvent(run_id=run_id, stage=stage, message=message,
                      data=json.dumps(data or {})))
    db.commit()


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

        _event(db, run.id, "plan",
               f"Security assessment planned for '{params.get('product_name') or 'product'}' "
               f"(exposure: {params.get('exposure')}). "
               "A2A: orchestrator → control-analyst → research-collector → threat-intel → "
               "scoring → report-writer.")

        # ---- approval gate: run the control-analyst stage only, then pause for
        # ---- the operator to confirm the control plan before the rest proceeds.
        approved_plan = params.get("approved_control_plan") or None
        if params.get("require_approval") and not approved_plan:
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
        )

        plan = result.get("control_plan", {})
        _event(db, run.id, "controls",
               f"control-analyst: {len(plan.get('declared_controls', []))} declared control(s), "
               f"{len(plan.get('proposed_controls', []))} proposed, "
               f"confidence {plan.get('confidence', 0):.0%} ({plan.get('source', 'n/a')}).",
               {"declared": plan.get("declared_controls", []),
                "proposed": plan.get("proposed_controls", []),
                "confidence": plan.get("confidence", 0)})
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
        _event(db, run.id, "analyze",
               f"threat-intel: {len(result.get('known_exploits', []))} known attacks mapped "
               f"onto {len(result.get('threats', []))} threats.",
               {"exploits": [k["id"] for k in result.get("known_exploits", [])]})
        _event(db, run.id, "map",
               f"report-writer: Known Exploits section + executive summary drafted "
               f"(A2A task {result.get('a2a_task_id')}).")

        rec = SecurityAssessment(
            investigation_id=inv.id,
            run_id=run.id,
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
            }),
            scoring_json=json.dumps(result.get("scoring", {})),
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
        )
        db.add(rec)
        db.commit()
        db.refresh(rec)

        # NOTE: build_assessment ran the A2A workflow on this same session;
        # expire everything so later reads see fresh state.
        db.expire_all()
        run = db.query(AgentRun).filter(AgentRun.id == run_id).first()
        stats = {"assessment_id": rec.id,
                 "overall_pct": result["overall_pct"],
                 "inherent_pct": result.get("inherent_pct"),
                 "residual_pct": result.get("residual_pct"),
                 "delta": result.get("delta"),
                 "active_controls": result.get("active_controls", []),
                 "confidence": result.get("confidence"),
                 "threats": len(result.get("threats", [])),
                 "evidence": len(result.get("evidence", [])),
                 "known_exploits": len(result.get("known_exploits", []))}
        run.stats = json.dumps(stats)
        run.status = "done"
        run.finished_at = datetime.now(timezone.utc)
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
                db.commit()
                _event(db, run.id, "summary", f"Security assessment failed: {e}")
        except Exception:
            db.rollback()
    finally:
        db.close()


def launch_security_assessment(investigation_id: int, params: dict) -> int:
    """Create the run row and start the background thread. Returns run_id."""
    db = SessionLocal()
    try:
        run = AgentRun(investigation_id=investigation_id, status="running",
                       trigger="security",
                       plan=json.dumps({"goal": "AI security assessment",
                                        "product": params.get("product_name", ""),
                                        "exposure": params.get("exposure", ""),
                                        "controls": params.get("declared_controls", []),
                                        "require_approval": bool(params.get("require_approval"))}))
        db.add(run)
        db.commit()
        db.refresh(run)
        run_id = run.id
    finally:
        db.close()
    t = threading.Thread(target=run_security_assessment,
                         args=(run_id, params), daemon=True)
    t.start()
    return run_id


def resume_security_assessment(run_id: int) -> bool:
    """Resume a run parked at an approval gate. Returns True if resumed."""
    db = SessionLocal()
    try:
        run = db.query(AgentRun).filter(AgentRun.id == run_id).first()
        if not run or run.status != "awaiting_approval":
            return False
        try:
            stats = json.loads(run.stats or "{}")
        except Exception:
            stats = {}
        plan = stats.get("control_plan", {})
        # Restore the original request params (use_case, workflow, docs, focus)
        # so the resumed run is identical apart from the approved control plan.
        params = dict(stats.get("params") or {})
        try:
            run_plan = json.loads(run.plan or "{}")
        except Exception:
            run_plan = {}
        params.setdefault("product_name", run_plan.get("product", ""))
        params.setdefault("exposure", run_plan.get("exposure", "confidential_data"))
        params["declared_controls"] = plan.get("declared_controls", [])
        params["approved_control_plan"] = plan
        params["require_approval"] = False
        run.status = "running"
        run.stats = None
        db.commit()
    finally:
        db.close()
    t = threading.Thread(target=run_security_assessment,
                         args=(run_id, params), daemon=True)
    t.start()
    return True


def security_run_busy(db: Session, investigation_id: int) -> bool:
    return db.query(AgentRun).filter(
        AgentRun.investigation_id == investigation_id,
        AgentRun.status.in_(["running", "awaiting_approval"]),
        AgentRun.trigger == "security").first() is not None
