"""Who is allowed to approve a control plan.

The gate exists so a human confirms the control set before the assessment
proceeds. As written it did not: the approver was whoever held the request, the
run recorded no approver at all, and the request that opened the run could also
carry ``approved_control_plan`` -- which is the same person approving their own
request and skipping the gate in one call.

Two rules now, both of which are about attribution rather than permission:

* **The approver must not be the requester.** Separating these is the entire
  point of a gate; a self-approval is a rubber stamp with a click in it. The
  requester's identity is recorded when the run is created, and the approval
  refuses to match it.
* **The approver is recorded, always.** Approve, reject, or edit-then-approve,
  the decision names who made it, and goes on the ledger. An approval nobody can
  be named against is not a control.

One deliberate exception: when no requester identity was captured at all, the
gate compares against the fallback actor rather than waving the check through.
Failing closed on a missing identity is the point -- a gate that opens when it
cannot identify anyone is a gate that is off.
"""
import json

#: Actor name used when a request carried no identity header. Kept distinct from
#: any real name so it is visible in the approval record rather than looking
#: like a person.
UNKNOWN_ACTOR = "unknown"


def normalise_actor(actor) -> str:
    a = (actor or "").strip()[:64]
    return a or UNKNOWN_ACTOR


def same_actor(a, b) -> bool:
    """Case-insensitive, whitespace-tolerant identity comparison.

    Identity strings arrive from headers, so ``"Alice"`` and ``"alice "`` are
    the same person; treating them as two would let a self-approval through by
    changing case.
    """
    return normalise_actor(a).lower() == normalise_actor(b).lower()


class ApprovalError(Exception):
    """The approval is not allowed. ``reason`` is user-facing."""

    def __init__(self, reason, *, status: int = 409, detail=None):
        super().__init__(reason)
        self.reason = reason
        self.status = status
        self.detail = detail or {}


def check_approver(*, approver: str, requester: str, run_id=None) -> str:
    """Raise unless ``approver`` may approve work requested by ``requester``.

    Returns the normalised approver name on success, so the caller records
    exactly what it checked.
    """
    who = normalise_actor(approver)
    asked_by = normalise_actor(requester)
    if who == UNKNOWN_ACTOR:
        raise ApprovalError(
            "approval requires an identified approver; send X-AKM-Actor",
            status=403,
            detail={"approver": who, "requester": asked_by})
    if same_actor(who, asked_by):
        raise ApprovalError(
            "the person who requested this run cannot approve it; a second "
            "person must confirm the control plan",
            status=403,
            detail={"approver": who, "requester": asked_by, "run_id": run_id})
    return who


def decision_record(*, run_id, decision, approver, requester, plan=None,
                    edited=False, note="") -> dict:
    """The audit row for an approval decision.

    Written to the ledger by the caller. Carries the full control set that was
    approved, because "approved" is only meaningful next to *what* was
    approved -- a later reader has to be able to tell whether the plan changed
    between proposal and sign-off.
    """
    plan = plan or {}
    return {
        "run_id": run_id,
        "decision": decision,
        "approver": normalise_actor(approver),
        "requester": normalise_actor(requester),
        "edited": bool(edited),
        "active_controls": list(plan.get("declared_controls") or []),
        "proposed_controls": list(plan.get("proposed_controls") or []),
        "note": note[:500],
    }


def requester_of(stats) -> str:
    """The requester's identity from a run's stored gate state."""
    try:
        data = json.loads(stats or "{}")
    except Exception:
        data = {}
    if not isinstance(data, dict):
        return UNKNOWN_ACTOR
    params = data.get("params")
    if isinstance(params, dict):
        return normalise_actor(params.get("requested_by"))
    return normalise_actor(data.get("requested_by"))
