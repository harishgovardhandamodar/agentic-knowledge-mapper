"""HTTP surface for the audit ledger.

Deliberately a separate router rather than more of ``app/main.py``: the audit
surface has a different audience (auditors, reviewers, compliance) than the
product API, and a route that can read every actor's prompt hash and every
verdict is worth being able to review on its own.

Three read shapes, matching the three questions an auditor asks:

1. *What happened?*      ``/runs/{id}/timeline``   -- ordered, filterable
2. *Did it check out?*   ``/runs/{id}/verify``     -- chain + proof integrity
3. *What if it didn't?*  ``/runs/{id}/drift``, ``/contamination`` -- blast radius
"""
import json
import sys
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Body, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy import func

from . import ledger as L
from .database import SessionLocal
from .ledger_models import LedgerApproval, LedgerClaim, LedgerEvent, LedgerRun

router = APIRouter(prefix="/api/ledger", tags=["ledger"])

_CSV = "text/csv"


def _csv(rows: list, columns: list) -> str:
    def cell(v) -> str:
        s = "" if v is None else str(v)
        return '"' + s.replace('"', '""') + '"'
    out = [",".join(columns)]
    out += [",".join(cell(r.get(c)) for c in columns) for r in rows]
    return "\n".join(out)


def _require_run(run_id: str) -> None:
    db = SessionLocal()
    try:
        if db.get(LedgerRun, run_id) is None:
            raise HTTPException(404, f"no ledger run {run_id}")
    finally:
        db.close()


# ------------------------------------------------------------------- runs --

@router.post("/runs")
def open_run(payload: dict = Body(...)):
    """Open an audited run. The mandate is fixed here and hashed, so the policy
    in force at the time of an action is provable afterwards."""
    run_id = (payload.get("id") or "").strip()
    if not run_id:
        raise HTTPException(400, "id is required")
    mandate = L.Mandate.from_dict(payload.get("mandate"))
    if L.get_run(run_id) is not None:
        raise HTTPException(409, f"run {run_id} already exists")
    L.ensure_run(run_id, mandate, payload.get("label"))
    h = L.append(run_id, "run.start", "ledger", actor_type="system",
                 intent="run_start", verdict="allow", severity="info",
                 data={"label": payload.get("label"),
                       "mandate": mandate.as_dict(),
                       "mandate_hash": mandate.hash}, checked=False)
    return {"run_id": run_id, "mandate_hash": mandate.hash, "head": h,
            "mandate": mandate.as_dict()}


@router.get("/timeline")
def ledger_timeline(limit: int = Query(200, le=2000)):
    """The whole ledger as one chronological stream, newest first. Same shape
    as a session timeline so the UI renders both with one renderer."""
    return L.global_timeline(limit)


@router.get("/runs")
def list_runs(limit: int = Query(50, le=500), status: str = Query(None)):
    db = SessionLocal()
    try:
        q = db.query(LedgerRun)
        if status:
            q = q.filter(LedgerRun.status == status)
        rows = q.order_by(LedgerRun.created_at.desc()).limit(limit).all()
        out = []
        for r in rows:
            events = (db.query(func.count(LedgerEvent.id))
                      .filter(LedgerEvent.run_id == r.id).scalar() or 0)
            out.append({"run_id": r.id, "label": r.label, "status": r.status,
                        "kind": r.kind, "session_id": r.session_id,
                        "mandate_hash": r.mandate_hash, "head_hash": r.head_hash,
                        "head_seq": r.head_seq, "events": events,
                        "created_at": str(r.created_at), "closed_at": str(r.closed_at)})
        return {"runs": out, "total": len(out)}
    finally:
        db.close()


@router.get("/runs/{run_id}")
def get_run(run_id: str):
    _require_run(run_id)
    return L.summary(run_id)


@router.post("/runs/{run_id}/close")
def close_run(run_id: str, payload: dict = Body(default={})):
    _require_run(run_id)
    status = payload.get("status", "closed")
    if status not in ("closed", "aborted"):
        raise HTTPException(400, "status must be 'closed' or 'aborted'")
    h = L.append(run_id, "run.end", "ledger", actor_type="system", intent="run_end",
                 verdict="allow", severity="info", data={"status": status}, checked=False)
    db = SessionLocal()
    try:
        row = db.get(LedgerRun, run_id)
        row.status, row.closed_at = status, datetime.now(timezone.utc)
        db.commit()
    finally:
        db.close()
    return {"run_id": run_id, "status": status, "head": h}


# --------------------------------------------------------------- timeline --

@router.get("/runs/{run_id}/timeline")
def get_timeline(
    run_id: str,
    kind: str = Query(None, description="comma-separated event kinds"),
    actor_type: str = Query(None, description="comma-separated: agent,llm,mcp,a2a,human,system"),
    actor: str = Query(None),
    verdict: str = Query(None),
    min_severity: str = Query(None, description="info|warn|block"),
    since_seq: int = Query(0, ge=0),
    limit: int = Query(200, le=2000),
    offset: int = Query(0, ge=0),
    include_data: bool = Query(True),
):
    """The transparency view: one ordered stream of every actor's actions.

    ``min_severity=warn`` is the useful default for a reviewer -- it drops the
    routine steps and leaves only what deviated.
    """
    _require_run(run_id)
    split = lambda v: [x.strip() for x in v.split(",") if x.strip()] if v else None  # noqa: E731
    try:
        return L.timeline(run_id, kinds=split(kind), actor_types=split(actor_type),
                          actors=split(actor), verdict=verdict,
                          min_severity=min_severity, since_seq=since_seq,
                          limit=limit, offset=offset, include_data=include_data)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/runs/{run_id}/timeline.csv")
def get_timeline_csv(run_id: str, min_severity: str = Query(None)):
    """Spreadsheet-friendly export for review and sign-off workflows."""
    _require_run(run_id)
    cols = ["seq", "ts", "actor_type", "actor", "kind", "intent", "verdict",
            "severity", "hash", "prev_hash"]
    rows = [{c: e.get(c) for c in cols} for e in
            L.timeline(run_id, min_severity=min_severity, limit=2000,
                       include_data=False)["events"]]
    return Response(_csv(rows, cols), media_type=_CSV,
                    headers={"Content-Disposition":
                             f'attachment; filename="ledger-{run_id}.csv"'})


@router.get("/runs/{run_id}/violations")
def get_violations(run_id: str):
    """Just the bad news: every block/warn, in order. This is the view a human
    approver should be shown before signing off."""
    _require_run(run_id)
    return L.timeline(run_id, min_severity="warn", limit=2000)


# ----------------------------------------------------------------- proofs --

@router.get("/runs/{run_id}/proofs")
def get_proofs(run_id: str, verify: bool = Query(False,
                                                 description="re-derive each proof now")):
    _require_run(run_id)
    events = L.timeline(run_id, limit=2000, include_data=False)["events"]
    proofs = [{"seq": e["seq"], "kind": e["kind"], "actor": e["actor"],
               "hash": e["hash"], "proof": e["proof"]}
              for e in events if e.get("proof")]
    if verify:
        for p in proofs:
            p["verification"] = L.verify_proof(run_id, p["seq"])
    return {"run_id": run_id, "proofs": proofs, "total": len(proofs)}


@router.get("/runs/{run_id}/events/{seq}/proof")
def get_proof(run_id: str, seq: int, verify: bool = Query(True)):
    """Proof-of-Work for one step, re-derived from the ledger by default.

    Passing ``verify=false`` returns the stored artifact without checking it --
    useful for display, but the re-derived answer is the one that counts.
    """
    _require_run(run_id)
    res = L.verify_proof(run_id, seq)
    if "checks" not in res or len(res["checks"]) == 1:
        raise HTTPException(404, f"no event {run_id}#{seq}")
    if not verify:
        db = SessionLocal()
        try:
            ev = (db.query(LedgerEvent)
                  .filter(LedgerEvent.run_id == run_id, LedgerEvent.seq == seq)
                  .first())
            return {"run_id": run_id, "seq": seq, "hash": ev.hash,
                    "stored_proof": json.loads(ev.proof_json) if ev.proof_json else None}
        finally:
            db.close()
    return res


# ----------------------------------------------------------------- claims --

@router.get("/runs/{run_id}/claims")
def get_claims(run_id: str, verdict: str = Query(None),
               ungrounded_only: bool = Query(False)):
    _require_run(run_id)
    db = SessionLocal()
    try:
        q = db.query(LedgerClaim).filter(LedgerClaim.run_id == run_id)
        if verdict:
            q = q.filter(LedgerClaim.verdict == verdict)
        if ungrounded_only:
            q = q.filter(LedgerClaim.n_sources == 0)
        return {"run_id": run_id, "claims": [{
            "claim_hash": c.claim_hash, "seq": c.seq, "actor": c.actor,
            "text": c.text, "citations": json.loads(c.citations_json or "[]"),
            "n_sources": c.n_sources, "confidence": c.confidence,
            "verdict": c.verdict, "verifier": c.verifier,
            "created_at": str(c.created_at)} for c in q.order_by(LedgerClaim.id).all()]}
    finally:
        db.close()


@router.post("/runs/{run_id}/claims/{claim_hash}/verify")
def verify_claim(run_id: str, claim_hash: str, payload: dict = Body(...)):
    """Record a verification verdict against a claim. The verdict itself becomes
    a chained event, so a later reviewer can see when the doubt arose."""
    _require_run(run_id)
    verdict = payload.get("verdict")
    if verdict not in L.CLAIM_VERDICTS:
        raise HTTPException(400, f"verdict must be one of {sorted(L.CLAIM_VERDICTS)}")
    h = L.verify_claim(run_id, claim_hash, verdict,
                       method=payload.get("method", "reviewer"),
                       note=payload.get("note", ""),
                       actor=payload.get("actor", "verifier"),
                       actor_type=payload.get("actor_type", "agent"))
    return {"claim_hash": claim_hash, "verdict": verdict, "event": h}


@router.get("/runs/{run_id}/contamination/{ref}")
def get_contamination(run_id: str, ref: str):
    """Everything downstream of one event hash or claim hash.

    The core anti-hallucination query: if a piece of evidence turns out to be
    fabricated, this is every conclusion it now taints.
    """
    _require_run(run_id)
    if not L.is_hash(ref):
        raise HTTPException(400, "ref must be a 64-char sha256 hex digest")
    return L.contamination(run_id, ref)


# ----------------------------------------------------------------- audits --

@router.get("/runs/{run_id}/verify")
def verify_run(run_id: str, deep: bool = Query(True)):
    """Full audit: chain integrity, head anchoring, proof re-derivation and
    claim content-addresses. ``ok: false`` means the record cannot be trusted."""
    _require_run(run_id)
    report = L.verify_chain(run_id)
    if deep:
        report["drift"] = L.detect_drift(run_id)
    return report


@router.get("/runs/{run_id}/drift")
def get_drift(run_id: str):
    """Behaviour vs mandate: unplanned work, scope creep, budget overruns, retry
    loops, blocked-then-continued, and unverified claims kept propagating."""
    _require_run(run_id)
    return L.detect_drift(run_id)


@router.get("/runs/{run_id}/export")
def export_run(run_id: str, download: bool = Query(False)):
    """Self-contained audit bundle. Verifiable offline with no database, no app
    and no network -- ``verify_export`` in ``app.ledger`` is the checker."""
    _require_run(run_id)
    doc = L.export_run(run_id)
    if download:
        return Response(json.dumps(doc, indent=2), media_type="application/json",
                        headers={"Content-Disposition":
                                 f'attachment; filename="ledger-{run_id}.json"'})
    return doc


@router.get("/audit-drops")
def list_audit_drops(limit: int = Query(100, ge=1, le=1000)):
    """Audit records this deployment failed to write -- the dead letters.

    The ledger is fail-open by design: a failing database must not stop the
    agents. The cost is that a lost record is invisible, and a trail with
    invisible holes is worse than one that visibly failed. This is where the
    holes are listed, with the process-wide drop count so a reader can tell
    "nothing lost" from "lost so much it stopped being written down".
    """
    return {"drops": L.audit_drops(limit=limit),
            "process_dropped_total": L.dropped_audit_count()}


@router.post("/verify-export")
def verify_export(payload: dict = Body(...)):
    """Verify a bundle uploaded from elsewhere. Lets a reviewer check a run they
    have no access to this deployment."""
    try:
        return L.verify_export(payload)
    except ValueError as e:
        raise HTTPException(400, str(e))


# -------------------------------------------------------------- approvals --

@router.get("/runs/{run_id}/approvals")
def get_approvals(run_id: str, pending_only: bool = Query(False)):
    _require_run(run_id)
    db = SessionLocal()
    try:
        q = db.query(LedgerApproval).filter(LedgerApproval.run_id == run_id)
        if pending_only:
            q = q.filter(LedgerApproval.decision.is_(None))
        return {"run_id": run_id, "approvals": [{
            "id": a.id, "seq": a.seq, "kind": a.kind,
            "subject_hash": a.subject_hash, "summary": a.summary,
            "requested_by": a.requested_by, "requested_at": str(a.requested_at),
            "decision": a.decision, "decided_by": a.decided_by,
            "decided_at": str(a.decided_at), "note": a.note,
            "event_hash": a.event_hash} for a in q.order_by(LedgerApproval.id).all()]}
    finally:
        db.close()


@router.post("/runs/{run_id}/approvals")
def request_approval(run_id: str, payload: dict = Body(...)):
    _require_run(run_id)
    kind = payload.get("kind")
    if not kind:
        raise HTTPException(400, "kind is required")
    aid = L.request_approval(run_id, kind, payload.get("subject_hash", ""),
                             summary=payload.get("summary", ""),
                             requested_by=payload.get("requested_by", "system"))
    return {"approval_id": aid, "run_id": run_id, "kind": kind}


@router.post("/approvals/{approval_id}/decide")
def decide_approval(approval_id: int, payload: dict = Body(...)):
    """A human decision. Recorded as a chained event signed by the deciding
    identity, so an approval cannot be back-dated into the record."""
    decision = payload.get("decision")
    if decision not in ("grant", "deny"):
        raise HTTPException(400, "decision must be 'grant' or 'deny'")
    decided_by = payload.get("decided_by")
    if not decided_by:
        raise HTTPException(400, "decided_by is required: a human decision needs an actor")
    try:
        h = L.decide_approval(approval_id, decision, decided_by=decided_by,
                              note=payload.get("note", ""))
    except KeyError:
        raise HTTPException(404, f"no approval {approval_id}")
    return {"approval_id": approval_id, "decision": decision, "event": h}


@router.get("/approvals/pending")
def pending_approvals(limit: int = Query(50, le=200)):
    """Cross-run approval queue: everything waiting on a human, oldest first."""
    db = SessionLocal()
    try:
        rows = (db.query(LedgerApproval)
                .filter(LedgerApproval.decision.is_(None))
                .order_by(LedgerApproval.id).limit(limit).all())
        return {"approvals": [{
            "id": a.id, "run_id": a.run_id, "kind": a.kind,
            "subject_hash": a.subject_hash, "summary": a.summary,
            "requested_by": a.requested_by, "requested_at": str(a.requested_at),
        } for a in rows], "total": len(rows)}
    finally:
        db.close()


# ------------------------------------------------------------- live hooks --

@router.post("/runs/{run_id}/actions")
def record_action(run_id: str, payload: dict = Body(...)):
    """Append an action from an external actor (an MCP server, a human clicking
    something, a peer agent over A2A). Lets actors outside this process land on
    the same chain, so there is one timeline rather than several.
    """
    _require_run(run_id)
    kind = payload.get("kind")
    actor = payload.get("actor")
    if not kind or not actor:
        raise HTTPException(400, "kind and actor are required")
    actor_type = payload.get("actor_type", "system")
    if actor_type not in L.ACTOR_TYPES:
        raise HTTPException(400, f"actor_type must be one of {sorted(L.ACTOR_TYPES)}")
    mandate = L.summary(run_id)["mandate"]
    ctx = L.RunCtx(run_id, L.Mandate.from_dict(mandate))
    try:
        h = ctx._event(kind, actor, actor_type=actor_type,
                       intent=payload.get("intent"),
                       data=payload.get("data") or {},
                       input_refs=payload.get("input_refs"),
                       tool=payload.get("tool"), domain=payload.get("domain"))
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"run_id": run_id, "event": h}


# --------------------------------------------------------------- sessions --

SESSION_HEADER = "X-AKM-Session"
ACTOR_HEADER = "X-AKM-Actor"
DEFAULT_ACTOR = "user"


def session_key(request: Request) -> Optional[str]:
    """The browser's stable key for "this sitting".

    Header first, cookie second: the SPA sends the header from JS, but a curl
    or a server-side proxy can carry the cookie without touching JS.
    """
    key = (request.headers.get(SESSION_HEADER)
           or request.cookies.get("akm_session")
           or "").strip()
    return key[:64] or None


def request_actor(request: Request) -> str:
    return (request.headers.get(ACTOR_HEADER) or DEFAULT_ACTOR).strip()[:64]


async def open_session(request: Request):
    """FastAPI dependency: make the caller's session current for the request.

    A dependency with a ``yield`` runs in the same context as the endpoint, so
    the contextvar set here is visible to the handler *and* to any background
    thread it starts (those copy the context explicitly). A request with no
    session key behaves exactly as it did before sessions existed.

    This runs for *every* product request, which is precisely why it has to be
    fail-open: a browser always sends the header, so letting a ledger error
    propagate here would turn an audit-trail outage into a total application
    outage. If the trail cannot be opened, the request proceeds unaudited.
    """
    key = session_key(request)
    if not key:
        request.state.ledger_session = None
        yield None
        return
    session_id = L._safe("resolve_session", L.resolve_session, key)
    if not session_id:
        request.state.ledger_session = None
        yield None
        return
    request.state.ledger_session = session_id
    request.state.ledger_client_key = key
    try:
        with L.session(session_id, client_key=key):
            yield session_id
    except Exception as exc:  # noqa: BLE001 - the trail is never load-bearing
        print(f"[ledger] session context failed: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        yield session_id


def human_action(request: Request, action: str,
                 detail: dict | None = None) -> Optional[str]:
    """Record a human action against whatever is current: the open run if the
    handler scoped one, otherwise the session. Fail-open lives in the ledger, so
    product handlers can call this without a try/except."""
    return L.record_human(request_actor(request), action, detail)


def _require_session(session_id: str) -> None:
    db = SessionLocal()
    try:
        row = db.get(LedgerRun, session_id)
    finally:
        db.close()
    if row is None or row.kind != "session":
        raise HTTPException(404, f"no session {session_id}")


@router.get("/sessions")
def list_sessions(limit: int = Query(50, le=200)):
    return {"sessions": L.list_sessions(limit=limit)}


@router.get("/sessions/{session_id}")
def get_session(session_id: str):
    _require_session(session_id)
    db = SessionLocal()
    try:
        row = db.get(LedgerRun, session_id)
    finally:
        db.close()
    return {"session_id": session_id, "label": row.label, "status": row.status,
            "client_key": row.client_key,
            "created_at": str(row.created_at), "last_seen_at": str(row.last_seen_at),
            "head_hash": row.head_hash,
            "tasks": L.session_tasks(session_id)}


@router.get("/sessions/{session_id}/timeline")
def session_timeline(session_id: str, limit: int = Query(2000, le=20000)):
    _require_session(session_id)
    return L.session_timeline(session_id, limit=limit)


@router.get("/sessions/{session_id}/verify")
def verify_session(session_id: str):
    _require_session(session_id)
    return L.verify_session(session_id)


@router.get("/sessions/{session_id}/insights")
def session_insights(session_id: str):
    # An existing but empty session is a real session with nothing in it, so it
    # gets an empty summary rather than a 404. Only a missing one is a 404.
    _require_session(session_id)
    return L.session_insights(session_id)


@router.post("/sessions")
def start_session(payload: dict = Body(default={})):
    """Explicitly begin a new sitting. The UI calls this for its "New session"
    button; without one, sessions roll over on the idle timeout instead."""
    key = (payload.get("client_key") or "").strip()[:64] or None
    session_id = (payload.get("id") or "").strip() or None
    if session_id is None:
        import uuid
        session_id = f"ses-{uuid.uuid4().hex[:12]}"
    L.ensure_session(session_id, client_key=key,
                     label=payload.get("label") or "session")
    return {"session_id": session_id, "client_key": key}
