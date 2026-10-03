"""Agentic Payments Security & Privacy Evaluation.

A structured questionnaire run against a payment-capable agent, managed by the
Agentic Manager. Operators answer a versioned catalog, the run is scored
deterministically (pass/partial/fail/na), and a residual-risk summary plus
Markdown/JSON reports are produced.

Design rules:

- **Stable keys** everywhere: section keys + question keys identify a question
  across catalog versions, so a re-seed can never duplicate or orphan rows.
- **Idempotent seed**: ``seed_catalog_v1`` upserts by version + (section,
  question) keys.
- **Deterministic scoring**: pass = 1.0*weight, partial = 0.5*weight,
  fail = 0, na excluded from the denominator.
- **No payment credentials / PANs in answers or notes** — answers are evidence
  of controls, never the data itself (enforced by guidance + report language).

Every write goes through the API layer, which requires a named operator and
records each action on the audit ledger.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from .models import (EvaluationAnswer, EvaluationCatalog, EvaluationQuestion,
                     EvaluationRun, EvaluationSection)

CATALOG_VERSION = "v1"
CATALOG_NAME = "Agentic Payments Security & Privacy Evaluation"

RATINGS = ("pass", "partial", "fail", "na")
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, None: 4}

# Defaults per the domain contract.
_DEFAULT_TYPE = "text"
_DEFAULT_WEIGHT = 1.0

# Severity hints per the spec: high/critical on binding, intent integrity,
# kill-switch, prompt injection, and exposure.
_HI = "high"
_CRIT = "critical"


def _q(key: str, prompt: str, *, guidance: str = "",
       qtype: str = _DEFAULT_TYPE, options: list[str] | None = None,
       weight: float = _DEFAULT_WEIGHT,
       severity: str | None = None) -> dict[str, Any]:
    return {"key": key, "prompt": prompt, "guidance": guidance,
            "question_type": qtype, "options": options,
            "weight": weight, "severity_hint": severity}


# The v1 catalog: 12 sections, 53 questions, stable keys.
CATALOG_V1: list[dict[str, Any]] = [
    {"key": "identity_auth", "title": "Identity, Authentication & Binding",
     "questions": [
        _q("agent_user_binding", "How is the agent cryptographically bound to a user/org before initiating payments?",
           guidance="Name the binding primitive (key ownership, session, attestation) and who proves it.", severity=_HI),
        _q("agent_authn", "What authenticates the agent (API keys, mTLS, signed assertions, hardware keys, short-lived tokens)?",
           guidance="List the mechanisms actually in use, not the ones documented as available."),
        _q("compromised_creds_impact", "Can compromised agent credentials initiate payments without the user? Residual risk?",
           guidance="Describe the blast radius of a single stolen credential."),
        _q("cred_lifecycle", "How are credentials rotated, revoked, scoped (least privilege)?",
           guidance="Rotation cadence, revocation path, per-scope credential isolation."),
        _q("instrument_binding", "Hard binding between agent identity and payment instrument? Auditable?",
           guidance="Is the instrument bound to the agent identity, and can that binding be audited?", severity=_HI),
    ]},
    {"key": "consent_scope", "title": "Consent, Authorization & Scope",
     "questions": [
        _q("explicit_consent", "Explicit granular consent (amount, MCC, time, frequency)?",
           guidance="Is consent per-payment and parameterized, or a blanket approval?"),
        _q("hard_limits", "User hard limits enforced at payment rail, not only in agent?",
           guidance="Are caps enforced downstream of the agent so a compromised agent cannot exceed them?"),
        _q("authz_properties", "Authorizations single-use, time-bound, non-transferable?",
           guidance="One-time, expiring, and non-replayable authorizations."),
        _q("step_up_auth", "Step-up auth for high-risk / out-of-policy payments?",
           guidance="What triggers step-up, and what factor is required?"),
        _q("standing_vs_oneshot", "Standing vs one-shot auth; revocation path?",
           guidance="Can a standing authorization be revoked quickly, and does the agent honor revocation?"),
    ]},
    {"key": "intent_integrity", "title": "Payment Intent Integrity",
     "questions": [
        _q("intent_protection", "Intent (amount, payee, currency, purpose) protected from tampering?",
           guidance="How is the intent payload integrity-protected between user and rail?", severity=_CRIT),
        _q("intent_signing", "Intent signed / integrity-protected end-to-end?",
           guidance="Signing scope: user → agent → rail. Who can sign and what is covered?", severity=_CRIT),
        _q("post_approval_mutation", "Can compromised agent alter payee/amount after approval?",
           guidance="Is the approved payload immutable after the user confirms?", severity=_CRIT),
        _q("independent_policy_check", "Independent policy/risk/human check before funds move?",
           guidance="Is there a check that is not under the agent's control before settlement?", severity=_HI),
    ]},
    {"key": "data_privacy", "title": "Data Minimization & Privacy",
     "questions": [
        _q("data_received", "What personal/financial data does the agent receive/store/transmit?",
           guidance="Inventory the data elements and their flows."),
        _q("tokenized_credentials", "PANs/account numbers exposed to agent, or only tokens?",
           guidance="Does the agent ever see raw card/account numbers, or only tokens?", severity=_HI),
        _q("logging_scope", "What is logged per payment, retention, who can access?",
           guidance="Log fields, retention window, access control to the logs."),
        _q("log_redaction", "Logs free of unnecessary PII/secrets? Redaction policy?",
           guidance="Is redaction applied before logs are written or only on read?"),
        _q("model_retention", "Agent/model provider retain prompts/tool outputs that could reconstruct transactions?",
           guidance="Does the model provider keep prompts/outputs that could rebuild a payment?"),
    ]},
    {"key": "autonomy", "title": "Agent Autonomy Boundaries",
     "questions": [
        _q("autonomy_level", "Max autonomy (fully autonomous / propose-and-confirm / draft-only)?",
           qtype="select", options=["fully_autonomous", "propose_and_confirm", "draft_only"]),
        _q("non_overridable_policy", "Non-overridable constraints (new merchants, caps)?",
           guidance="Constraints the agent cannot relax or override."),
        _q("ambiguous_instructions", "Handling of ambiguous/conflicting user instructions?",
           guidance="Does the agent ask or guess when instructions conflict?"),
        _q("chaining_escalation", "Can agent chain payments or escalate privileges without new authz?",
           guidance="Multi-hop escalation must re-authorize."),
        _q("kill_switch", "Immediate freeze/kill-switch for payment capability?",
           guidance="How fast and how broad is the kill-switch?", severity=_CRIT),
    ]},
    {"key": "fraud_adversarial", "title": "Fraud, Abuse & Adversarial Resilience",
     "questions": [
        _q("anomaly_detection", "Detects anomalous agent payment behavior?",
           guidance="Behavioral detection on the agent's payment patterns."),
        _q("prompt_injection", "Defense against prompt injection / tool manipulation aimed at payments?",
           guidance="Isolate untrusted content from the payment execution path.", severity=_CRIT),
        _q("third_party_tool_risk", "Malicious tool the agent calls can trigger/redirect payment?",
           guidance="Can a compromised external tool redirect funds or forge an intent?", severity=_HI),
        _q("fraud_response", "Response process when fraud is suspected?",
           guidance="Who is paged, what is frozen, what is the SL."),
        _q("rate_limits", "Agent-specific rate limits, circuit breakers, thresholds?",
           guidance="Per-agent velocity controls at the rail or gateway."),
    ]},
    {"key": "audit", "title": "Auditability & Forensics",
     "questions": [
        _q("attribution", "Every payment attributable to user, agent, grant, intent, execution path?",
           guidance="Full attribution chain from user intent to settled payment.", severity=_HI),
        _q("immutable_logs", "Audit logs immutable, timestamped, retained as required?",
           guidance="Append-only storage, tamper evidence, retention policy."),
        _q("reasoning_reconstruction", "Sanitized decision chain reconstructable without excess private data?",
           guidance="Can a reviewer see why the agent paid, without raw PII?"),
        _q("audit_access_control", "Who can access audit data, under what controls?",
           guidance="Access model for the audit store."),
    ]},
    {"key": "errors_remediation", "title": "Error Handling & Remediation",
     "questions": [
        _q("failed_partial", "Handling of failed, partial, or reversed agentic payments?",
           guidance="Idempotency and settlement-failure handling."),
        _q("duplicate_prevention", "Duplicate/retried payments prevented?",
           guidance="Idempotency keys, dedup on retry."),
        _q("user_remedies", "User remedies (dispute, refund, chargeback)?",
           guidance="What can the user do after an unwanted payment?"),
        _q("revoke_after_incident", "How fast can user revoke agent payment authority?",
           guidance="Time-to-revoke after an incident."),
    ]},
    {"key": "third_parties", "title": "Third Parties & Models",
     "questions": [
        _q("third_party_inventory", "Which third parties process data/instructions for agentic payments?",
           guidance="Inventory of processors with a stake in the payment path."),
        _q("contracts_controls", "Contractual/technical controls governing them?",
           guidance="DPA terms, sub-processor limits, technical controls."),
        _q("model_provider_visibility", "What payment-related data can a hosted model provider see/retain?",
           guidance="Prompts, tool outputs, and retention the provider holds.", severity=_HI),
        _q("execution_without_plaintext", "Payment execute without model provider seeing plaintext credentials/full details?",
           guidance="Is the sensitive portion executed outside the model's view?", severity=_HI),
    ]},
    {"key": "regulatory", "title": "Regulatory Alignment",
     "questions": [
        _q("sca_psd2", "SCA / equivalent strong customer authentication addressed?",
           guidance="SCA triggers and how the agent satisfies them."),
        _q("aml_sanctions", "AML/KYC and sanctions screening applied?",
           guidance="Screening on the agent's payment path."),
        _q("consumer_protection", "Unauthorized-transaction liability and automated-decision disclosures?",
           guidance="Liability model and disclosure obligations."),
        _q("jurisdiction_constraints", "Data residency and local payment rules enforced?",
           guidance="Where data sits and which rules apply."),
    ]},
    {"key": "threat_model", "title": "Threat Model & Residual Risk",
     "questions": [
        _q("threat_model_doc", "Explicit threat model for agentic payments?",
           guidance="A written model, not an implicit one.", severity=_HI),
        _q("accepted_residual_risk", "Accepted residual risks and sign-off owner?",
           guidance="Named owner per accepted risk."),
        _q("adversarial_testing", "Tested against prompt-injection→payment, credential theft, intent tampering, replay?",
           guidance="Evidence of red-team / adversarial testing.", severity=_HI),
        _q("worst_case_exposure", "Worst-case financial exposure per user and aggregate if agent fully compromised?",
           guidance="Quantify per-user and aggregate loss given full compromise.", severity=_CRIT),
    ]},
    {"key": "ops", "title": "Operational Readiness",
     "questions": [
        _q("production_monitoring", "Production monitoring of agent payment capability?",
           guidance="Metrics, alerts, SLAs on the payment capability."),
        _q("incident_playbook", "Incident playbook for agentic payment abuse?",
           guidance="Runbook with roles and freeze steps."),
        _q("policy_propagation", "How fast do limit/consent/revocation changes take effect?",
           guidance="Propagation latency of policy changes to the rail."),
        _q("break_glass", "Documented break-glass for emergency suspension?",
           guidance="Who can suspend, and under what process."),
    ]},
]


def seed_catalog_v1(db: Session) -> dict[str, int]:
    """Idempotently seed catalog v1 (upsert by version + section/question key).

    Re-runs update titles/guidance but never duplicate rows. Returns counts.
    """
    cat = (db.query(EvaluationCatalog)
           .filter(EvaluationCatalog.version == CATALOG_VERSION).first())
    if cat is None:
        cat = EvaluationCatalog(version=CATALOG_VERSION, name=CATALOG_NAME,
                                description="Agentic-initiated payments "
                                            "security & privacy evaluation")
        db.add(cat)
        db.flush()
    for si, section in enumerate(CATALOG_V1):
        sec = (db.query(EvaluationSection)
               .filter(EvaluationSection.catalog_id == cat.id,
                       EvaluationSection.key == section["key"]).first())
        if sec is None:
            sec = EvaluationSection(catalog_id=cat.id,
                                    key=section["key"],
                                    title=section["title"],
                                    order_index=si)
            db.add(sec)
            db.flush()
        else:
            sec.title = section["title"]
            sec.order_index = si
        for qi, q in enumerate(section["questions"]):
            qrow = (db.query(EvaluationQuestion)
                    .filter(EvaluationQuestion.section_id == sec.id,
                            EvaluationQuestion.key == q["key"]).first())
            opts = json.dumps(q.get("options") or []) if q.get("options") else None
            if qrow is None:
                qrow = EvaluationQuestion(
                    section_id=sec.id, key=q["key"], prompt=q["prompt"],
                    guidance=q.get("guidance") or "",
                    question_type=q.get("question_type", _DEFAULT_TYPE),
                    options_json=opts, weight=q.get("weight", _DEFAULT_WEIGHT),
                    severity_hint=q.get("severity_hint"),
                    order_index=qi, is_active=1)
                db.add(qrow)
            else:
                qrow.prompt = q["prompt"]
                qrow.guidance = q.get("guidance") or ""
                qrow.question_type = q.get("question_type", _DEFAULT_TYPE)
                qrow.options_json = opts
                qrow.weight = q.get("weight", _DEFAULT_WEIGHT)
                qrow.severity_hint = q.get("severity_hint")
                qrow.order_index = qi
                qrow.is_active = 1
    db.commit()
    sections = db.query(EvaluationSection).filter(
        EvaluationSection.catalog_id == cat.id).count()
    questions = (db.query(EvaluationQuestion)
                 .join(EvaluationSection)
                 .filter(EvaluationSection.catalog_id == cat.id).count())
    return {"catalog_id": cat.id, "version": cat.version,
            "sections": sections, "questions": questions}


def get_catalog(db: Session, catalog_id: int) -> dict[str, Any]:
    cat = db.query(EvaluationCatalog).filter(
        EvaluationCatalog.id == catalog_id).first()
    if cat is None:
        raise LookupError("catalog not found")
    sections = (db.query(EvaluationSection)
                .filter(EvaluationSection.catalog_id == cat.id)
                .order_by(EvaluationSection.order_index).all())
    return {
        "id": cat.id, "version": cat.version, "name": cat.name,
        "description": cat.description,
        "sections": [{
            "id": s.id, "key": s.key, "title": s.title,
            "order_index": s.order_index,
            "questions": [{
                "id": q.id, "key": q.key, "prompt": q.prompt,
                "guidance": q.guidance, "question_type": q.question_type,
                "options": json.loads(q.options_json) if q.options_json else [],
                "weight": q.weight, "severity_hint": q.severity_hint,
                "order_index": q.order_index, "is_active": bool(q.is_active),
            } for q in sorted(s.questions, key=lambda x: x.order_index)],
        } for s in sections],
    }


# --------------------------------------------------------------------------
# Runs & scoring
# --------------------------------------------------------------------------

def create_run(db: Session, target_agent_id: str, title: str = "",
               catalog_id: int | None = None, actor: str = "") -> EvaluationRun:
    """Create a draft evaluation run against a payment-capable agent."""
    if not target_agent_id or not str(target_agent_id).strip():
        raise ValueError("target_agent_id is required")
    if catalog_id is None:
        cat = db.query(EvaluationCatalog).filter(
            EvaluationCatalog.version == CATALOG_VERSION).first()
        if cat is None:
            seed_catalog_v1(db)
            cat = db.query(EvaluationCatalog).filter(
                EvaluationCatalog.version == CATALOG_VERSION).first()
        catalog_id = cat.id
    run = EvaluationRun(
        catalog_id=catalog_id, target_agent_id=str(target_agent_id).strip(),
        title=(title or "").strip() or f"Evaluation of {target_agent_id}",
        status="draft", created_by=actor or None)
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def _qrow(db: Session, run: EvaluationRun, question_id: int) -> EvaluationQuestion:
    q = db.query(EvaluationQuestion).filter(
        EvaluationQuestion.id == question_id).first()
    if q is None:
        raise LookupError("question not found")
    sec = db.query(EvaluationSection).filter(
        EvaluationSection.id == q.section_id).first()
    if sec is None or sec.catalog_id != run.catalog_id:
        raise LookupError("question not in this run's catalog")
    return q


def upsert_answer(db: Session, run: EvaluationRun, question_id: int, *,
                  answer_value: Any = None, risk_rating: str = "",
                  evidence_url: str = "", notes: str = "",
                  actor: str = "") -> EvaluationAnswer:
    """Set one answer. ``risk_rating`` must be pass|partial|fail|na."""
    if run.status == "completed":
        raise ValueError("run is already completed")
    if run.status == "archived":
        raise ValueError("run is archived")
    rating = (risk_rating or "").strip().lower()
    if rating not in RATINGS:
        raise ValueError(f"risk_rating must be one of: {', '.join(RATINGS)}")
    _qrow(db, run, question_id)
    answer = (db.query(EvaluationAnswer)
              .filter(EvaluationAnswer.run_id == run.id,
                      EvaluationAnswer.question_id == question_id).first())
    av = json.dumps(answer_value) if answer_value is not None else None
    if answer is None:
        answer = EvaluationAnswer(run_id=run.id, question_id=question_id,
                                  answer_value=av, risk_rating=rating,
                                  evidence_url=(evidence_url or "")[:1000],
                                  notes=notes or None,
                                  answered_by=actor or None,
                                  answered_at=datetime.now(timezone.utc))
        db.add(answer)
    else:
        answer.answer_value = av
        answer.risk_rating = rating
        answer.evidence_url = (evidence_url or "")[:1000]
        answer.notes = notes or None
        answer.answered_by = actor or None
        answer.answered_at = datetime.now(timezone.utc)
    if run.status == "draft":
        run.status = "in_progress"
    db.commit()
    db.refresh(answer)
    return answer


def _scored_answers(db: Session, run: EvaluationRun) -> list[dict[str, Any]]:
    """Answers joined to their questions, with computed score contribution."""
    answers = {a.question_id: a for a in db.query(EvaluationAnswer).filter(
        EvaluationAnswer.run_id == run.id).all()}
    questions = (db.query(EvaluationQuestion)
                 .join(EvaluationSection)
                 .filter(EvaluationSection.catalog_id == run.catalog_id,
                         EvaluationQuestion.is_active == 1)
                 .order_by(EvaluationSection.order_index,
                           EvaluationQuestion.order_index).all())
    out = []
    for q in questions:
        a = answers.get(q.id)
        rating = a.risk_rating if a else None
        w = float(q.weight or 0)
        score = 0.0
        if rating == "pass":
            score = 1.0 * w
        elif rating == "partial":
            score = 0.5 * w
        elif rating == "fail":
            score = 0.0
        # na: excluded from denominator (score contributes nothing)
        out.append({
            "question_id": q.id, "key": q.key, "prompt": q.prompt,
            "section_key": None,  # filled below
            "section_title": None,  # filled below
            "weight": w, "severity_hint": q.severity_hint,
            "risk_rating": rating, "answer_value": a.answer_value if a else None,
            "evidence_url": a.evidence_url if a else None,
            "notes": a.notes if a else None,
            "answered_by": a.answered_by if a else None,
            "score": score,
        })
    # attach section context
    sec_by_q = {q.id: s for s in db.query(EvaluationSection).all()
                for q in s.questions}
    for row in out:
        s = sec_by_q.get(row["question_id"])
        if s:
            row["section_key"] = s.key
            row["section_title"] = s.title
    return out


def complete_run(db: Session, run: EvaluationRun, actor: str = "") -> dict[str, Any]:
    """Score a run and lock it. Returns the scoring summary."""
    if run.status in ("completed", "archived"):
        raise ValueError(f"run is already {run.status}")
    rows = _scored_answers(db, run)
    # Only questions that received a rating count toward the denominator:
    # unanswered questions are "not assessed", not silently failed. na is
    # excluded too, per the domain contract.
    rows = [r for r in rows if r["risk_rating"]]
    denom = sum(r["weight"] for r in rows if r["risk_rating"] != "na")
    numer = sum(r["score"] for r in rows if r["risk_rating"] != "na")
    overall = round(100.0 * numer / denom, 1) if denom else None
    counts = {"pass": 0, "partial": 0, "fail": 0, "na": 0, "answered": 0}
    for r in rows:
        if r["risk_rating"]:
            counts[r["risk_rating"]] += 1
            counts["answered"] += 1
    gaps = [r for r in rows if r["risk_rating"] in ("fail", "partial")]
    gaps.sort(key=lambda r: (SEVERITY_ORDER.get(r["severity_hint"], 4),
                             -r["weight"], r["key"]))
    run.overall_score = overall
    run.status = "completed"
    run.completed_by = actor or None
    run.completed_at = datetime.now(timezone.utc)
    run.residual_risk_summary = _residual_summary(rows, gaps)
    db.commit()
    return {"run_id": run.id, "overall_score": overall, "counts": counts,
            "denominator_weight": denom, "earned_weight": numer,
            "gaps": [{"key": g["key"], "section_key": g["section_key"],
                      "prompt": g["prompt"], "risk_rating": g["risk_rating"],
                      "severity_hint": g["severity_hint"]} for g in gaps]}


def _residual_summary(rows: list[dict[str, Any]],
                      gaps: list[dict[str, Any]]) -> str:
    if not rows:
        return "No questions answered."
    lines = [f"{sum(1 for r in rows if r['risk_rating'] == 'pass')} pass, "
             f"{sum(1 for r in rows if r['risk_rating'] == 'partial')} partial, "
             f"{sum(1 for r in rows if r['risk_rating'] == 'fail')} fail, "
             f"{sum(1 for r in rows if r['risk_rating'] == 'na')} n/a"]
    if gaps:
        lines.append("Open gaps: " + ", ".join(
            f"{g['key']} ({g['severity_hint'] or 'medium'})" for g in gaps[:12]))
    return "\n".join(lines)


def run_payload(db: Session, run: EvaluationRun) -> dict[str, Any]:
    """Full run state (answers + catalog) for the JSON report and API."""
    cat = get_catalog(db, run.catalog_id)
    rows = _scored_answers(db, run)
    by_q = {r["question_id"]: r for r in rows}
    sections = []
    for s in cat["sections"]:
        qs = []
        for q in s["questions"]:
            r = by_q.get(q["id"]) or {}
            qs.append({
                "question_id": q["id"], "key": q["key"], "prompt": q["prompt"],
                "guidance": q["guidance"], "question_type": q["question_type"],
                "options": q["options"], "weight": q["weight"],
                "severity_hint": q["severity_hint"],
                "risk_rating": r.get("risk_rating"),
                "answer_value": json.loads(r["answer_value"]) if r.get("answer_value") else None,
                "evidence_url": r.get("evidence_url"),
                "notes": r.get("notes"), "answered_by": r.get("answered_by"),
                "score": r.get("score", 0.0),
            })
        sections.append({"key": s["key"], "title": s["title"],
                         "questions": qs})
    gaps = [q for sec in sections for q in sec["questions"]
            if q["risk_rating"] in ("fail", "partial")]
    gaps.sort(key=lambda q: (SEVERITY_ORDER.get(q["severity_hint"], 4),
                             -q["weight"], q["key"]))
    return {
        "run": {
            "id": run.id, "target_agent_id": run.target_agent_id,
            "title": run.title, "status": run.status,
            "catalog_version": cat["version"],
            "overall_score": run.overall_score,
            "residual_risk_summary": run.residual_risk_summary,
            "created_by": run.created_by, "completed_by": run.completed_by,
            "created_at": run.created_at.isoformat() if run.created_at else None,
            "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        },
        "catalog": {"id": cat["id"], "version": cat["version"], "name": cat["name"]},
        "sections": sections,
        "gaps": gaps,
    }


def report_json(db: Session, run: EvaluationRun) -> dict[str, Any]:
    return run_payload(db, run)


def report_markdown(db: Session, run: EvaluationRun) -> str:
    p = run_payload(db, run)
    run_ = p["run"]
    L: list[str] = []
    A = L.append
    A(f"# Agentic Payments Security & Privacy Evaluation")
    A("")
    A(f"_Run #{run_['id']} · {run_['title']} · target agent "
      f"`{run_['target_agent_id']}`_")
    A(f"_Catalog {run_['catalog_version']} · status {run_['status']} · "
      f"created by {run_['created_by'] or '—'}"
      f"{' · completed by ' + run_['completed_by'] if run_['completed_by'] else ''}_")
    A("")
    if run_["overall_score"] is not None:
        A(f"## Overall score: **{run_['overall_score']:g}/100**")
        A("")
        if run_["residual_risk_summary"]:
            A("### Residual risk")
            A("")
            A(run_["residual_risk_summary"])
            A("")
    else:
        A("_Run not yet scored._")
        A("")
    for s in p["sections"]:
        A(f"## {s['title']}")
        A("")
        A("| Question | Rating | Evidence | Notes |")
        A("|---|---|---|---|")
        for q in s["questions"]:
            rating = q["risk_rating"] or "—"
            ev = q["evidence_url"] or "—"
            notes = str(q["notes"] or "")[:80] or "—"
            A(f"| {q['key']} — {str(q['prompt'])[:60]} | {rating} | "
              f"{ev} | {notes} |")
        A("")
    if p["gaps"]:
        A("## Gap list (sorted by severity)")
        A("")
        for g in p["gaps"]:
            A(f"- **{g['key']}** ({g['risk_rating']}, "
              f"{g['severity_hint'] or 'medium'}): {str(g['prompt'])[:90]}")
        A("")
    return "\n".join(L).strip() + "\n"