"""Assurance layer: what has to be true before a residual score means anything.

:mod:`app.security` answers "what is the residual risk given the controls we
say we have". That question is answerable in a lab and misleading in a
regulated review, because "we say we have" is exactly the thing under dispute.

This module answers the harder question -- "can anyone prove it" -- and it does
so by refusing to reduce risk on assertion. Eight checks, each deterministic
and each able to *raise* a score back to its inherent value:

1. **Control attestation** (:func:`control_attestation`). A declared control is
   not a control. It only reduces residual risk once an *accepted primary*
   artifact names it. The result is two numbers, not one: a *declared*
   residual (planning view, current behaviour) and a *verified* residual
   (assurance view). The headline always states which one it is printing.
2. **Architecture completeness gate** (:func:`architecture_gate`). Inference
   topology, retention, subprocessors and AI-interaction logging are not
   details; they *are* the determinants of T02/T07/T11. On a Restricted or
   Confidential tier an unknown item forces those threats back to inherent and
   raises a blocking finding.
3. **Evidence acceptance gate** (:func:`evidence_gate`). Residual may only be
   reduced for a top threat that has a minimum count of high-relevance
   *accepted* artifacts behind it. Pending research is research.
4. **Blast radius** (:func:`blast_radius`). "Residual 25" is abstract; "25
   across 4,000 restricted assets x 300 privileged users" is a decision.
5. **Forensics readiness** (:func:`forensics_readiness`). Can a responder
   reconstruct who sent what context to which model? If not, T01/T02/T06/T08
   cannot claim low residual -- the absence of logging *is* the exposure.
6. **Semantic-gap hardening** (:func:`detect_chains`, :func:`injection_cap`).
   Concatenating untrusted catalog content with system instructions is LLM01
   exposure by construction, so KE-01 -> KE-06 is modelled as one chained path
   rather than two independent threats.
7. **Decision frame** (:func:`decision_frame`). Accept / Accept with mandatory
   guardrails / Reject until the architecture gate closes, with the actions
   that would change the answer.
8. **Vendor questionnaire** (:func:`vendor_questionnaire`). Unresolved
   architecture items become a structured artefact to send the vendor, not an
   open question nobody owns.

Everything here is a pure function over stored rows -- no LLM, no database, no
network. The dossier reads the same block the API returns, so the PDF and the
screen cannot disagree about whether a control was evidenced.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable, Optional

from . import security as sec

ASSURANCE_METHOD = "akm-assurance"
ASSURANCE_VERSION = "1.0.0"

#: Tiers where an unresolved architecture question is a *blocking* condition
#: rather than a caveat. Below these, an unknown inference topology is a
#: finding, not a stopper: an internal wiki assistant has no residency posture
#: to violate.
RESTRICTED_TIERS = frozenset({"restricted_data", "confidential_data"})

#: The mandatory pre-scoring checklist. Each item names the threats it
#: determines, so an unknown item can force exactly those threats back to
#: inherent instead of blanketing the whole assessment.
ARCHITECTURE_ITEMS: tuple[dict[str, Any], ...] = (
    {
        "key": "inference_topology",
        "label": "Inference endpoint (SaaS / VPC / on-prem)",
        "why": "Determines whether data crosses the trust boundary at all, and "
               "under whose contract.",
        "blocks": ("T07", "T11"),
        "question": "Where does inference actually run — the vendor's public "
                    "SaaS API, a dedicated VPC endpoint, or fully on-premises? "
                    "Name the endpoint and the region it terminates in.",
    },
    {
        "key": "retention_training",
        "label": "Retention window + training use",
        "why": "Retention is what turns a one-off submission into a durable "
               "copy. Training use makes it a corpus.",
        "blocks": ("T02",),
        "question": "What is the contractual retention window for prompts and "
                    "responses, is zero-retention / no-training in place, and "
                    "is it enforceable (audit right, DPA clause) or best-effort?",
    },
    {
        "key": "subprocessor_flowdown",
        "label": "Subprocessor list + contractual flow-down",
        "why": "A subprocessor receiving Restricted metadata inherits every "
               "obligation you accepted, or none of them.",
        "blocks": ("T07", "T11"),
        "question": "Provide the current subprocessor register, the regions "
                    "each operates in, and the flow-down clause binding them "
                    "to your data-protection terms.",
    },
    {
        "key": "ai_interaction_logging",
        "label": "AI-interaction logging (identity + asset + model)",
        "why": "Without it there is no reconstructability, so no incident "
               "response and no audit.",
        "blocks": ("T08",),
        "question": "Does an immutable log record, per AI interaction: user "
                    "identity, asset/record context, prompt hash, model id and "
                    "version, and timestamp? Provide the schema and retention "
                    "period, and the SIEM export path.",
    },
)

#: Threats whose architecture items are unknown, aggregated into one gate.
GATE_BLOCKED_THREATS = ("T02", "T07", "T11")

#: Threats that cannot claim low residual without reconstructable AI-interaction
#: logging. The principal-architect rule: an assessment that cannot demonstrate
#: reconstructability must not underwrite a low number here.
FORENSICS_GATED_THREATS = ("T01", "T02", "T06", "T08")

#: Minimum accepted, high-relevance artifacts before a top residual threat may
#: be reduced at all. Tunable; the value ships in the fingerprint.
MIN_ACCEPTED_PER_TOP_THREAT = 3
MIN_ACCEPTED_RELEVANCE = 0.6
TOP_THREAT_GATE_N = 5

#: Cap on prompt-injection coverage when no adversarial test result has been
#: accepted. Delimiters and instruction hierarchy reduce LLM01; they do not
#: remove it, and a control with no test evidence cannot claim full efficacy.
INJECTION_COVERAGE_CAP = 0.35
INJECTION_CONTROLS = ("C05", "C13")
INJECTION_GATED_THREAT = "T05"

#: Prompt-injection controls that stay above the cap *because* an adversarial
#: test artifact was accepted.
ADVERSARIAL_TEST_TERMS = (
    "adversarial", "red team", "red-team", "prompt injection test",
    "injection suite", "jailbreak test", "fuzz", "penetration test",
)

#: Weight of each reconstructability element. 100 = a responder can fully
#: reconstruct who sent what, to which model, and what came back.
FORENSICS_ELEMENTS: tuple[dict[str, Any], ...] = (
    {"key": "user_identity", "label": "User identity per AI interaction",
     "weight": 20, "terms": ("user id", "user identity", "actor id", "subject id",
                             "who sent", "per-user log", "identity on")},
    {"key": "asset_context", "label": "Asset / record context captured",
     "weight": 15, "terms": ("asset id", "record context", "catalog id", "table id",
                             "object context", "resource id", "asset context")},
    {"key": "prompt_hash", "label": "Prompt hash (content-minimised)",
     "weight": 15, "terms": ("prompt hash", "prompt_hash", "hash of prompt",
                             "prompt digest", "hashed prompt")},
    {"key": "model_id", "label": "Model id + version per call",
     "weight": 15, "terms": ("model id", "model version", "model_id", "model name",
                             "endpoint model", "model fingerprint")},
    {"key": "timestamp", "label": "Immutable timestamp",
     "weight": 10, "terms": ("timestamp", "immutable", "append-only",
                             "write-once", "non-repudiable")},
    {"key": "response_recorded", "label": "Returned content recorded or hashable",
     "weight": 10, "terms": ("response logged", "response recorded", "completion log",
                             "output logged", "response hash", "full transcript")},
    {"key": "log_schema", "label": "Documented log schema",
     "weight": 7, "terms": ("log schema", "schema documented", "field reference",
                            "logging specification", "schema v")},
    {"key": "siem_integration", "label": "SIEM / export integration point",
     "weight": 8, "terms": ("siem", "splunk", "sentinel", "elastic", "qradar",
                            "syslog", "export endpoint", "streaming export")},
)

FORENSICS_RECONSTRUCTABLE_AT = 70

#: Exposure bands keyed to the same thresholds :func:`app.security._posture`
#: uses, so "elevated" means the same thing in both places.
EXPOSURE_BANDS = ((75.0, "critical"), (50.0, "elevated"),
                  (30.0, "moderate"), (0.0, "low"))

DECISION_ACCEPT = "accept"
DECISION_GUARDRAILS = "accept_with_mandatory_guardrails"
DECISION_REJECT = "reject_until_architecture_gate_closed"

TERMINAL_DECISIONS = (DECISION_ACCEPT, DECISION_GUARDRAILS, DECISION_REJECT)

_PRIMARY_TYPES = frozenset({
    "vendor_doc", "vendor_documents", "documentation", "dpa", "contract",
    "config", "config_log", "log_sample", "screenshot", "test_result",
    "red_team", "penetration_test", "audit", "attestation",
})


# ------------------------------------------------------------------ helpers --

def _fingerprint(payload: Any) -> str:
    canon = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()[:12]


def assurance_fingerprint() -> str:
    """Content hash of every constant that can change an assurance verdict.

    Covers the thresholds and checklists as well as the catalog ids they refer
    to, so a retune is detectable the same way a catalog edit is.
    """
    return _fingerprint({
        "id": ASSURANCE_METHOD,
        "version": ASSURANCE_VERSION,
        "restricted_tiers": sorted(RESTRICTED_TIERS),
        "architecture": [[i["key"], sorted(i["blocks"])] for i in ARCHITECTURE_ITEMS],
        "gate_blocked": list(GATE_BLOCKED_THREATS),
        "forensics_gated": list(FORENSICS_GATED_THREATS),
        "forensics": [[e["key"], e["weight"]] for e in FORENSICS_ELEMENTS],
        "forensics_at": FORENSICS_RECONSTRUCTABLE_AT,
        "min_accepted": MIN_ACCEPTED_PER_TOP_THREAT,
        "min_relevance": MIN_ACCEPTED_RELEVANCE,
        "top_n": TOP_THREAT_GATE_N,
        "injection_cap": INJECTION_COVERAGE_CAP,
        "injection_controls": list(INJECTION_CONTROLS),
        "adversarial_terms": list(ADVERSARIAL_TEST_TERMS),
        "bands": EXPOSURE_BANDS,
        "decisions": list(TERMINAL_DECISIONS),
        "pack": [sec._WORST_WEIGHT, sec._BREADTH_WEIGHT, sec._TOP_N],
    })


def _get(a: Any, *names: str, default: Any = None) -> Any:
    """First present key from ``names``.

    Artifact dicts arrive from several loaders (``app.security`` keys them
    ``type``/``snippet``; ``app.dossier`` keys them ``artifact_type``/``excerpt``
    and adds ``review``). Reading one shape and assuming the other is how an
    attestation silently reports "declared" on a row that *was* accepted.
    """
    if isinstance(a, dict):
        for n in names:
            if a.get(n) not in (None, ""):
                return a[n]
    else:
        for n in names:
            v = getattr(a, n, None)
            if v not in (None, ""):
                return v
    return default


def _blob(a: Any) -> str:
    """All searchable text of an artifact, lowercased."""
    parts = [
        _get(a, "title", default=""),
        _get(a, "description", "snippet", "content", "excerpt", default=""),
        _get(a, "tags", default=""),
        _get(a, "url", default=""),
        _get(a, "source", default=""),
        _get(a, "artifact_type", "type", default=""),
        _get(a, "author", default=""),
    ]
    return " ".join(str(p) for p in parts if p).lower()


def _num(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _accepted(a: Any) -> bool:
    return str(_get(a, "review", default="pending") or "pending") == "accepted"


def _rejected(a: Any) -> bool:
    return str(_get(a, "review", default="pending") or "pending") == "rejected"


def _iso(v: Any) -> str:
    if v is None:
        return ""
    if hasattr(v, "isoformat"):
        try:
            return v.isoformat()
        except Exception:
            return ""
    return str(v)


# --------------------------------------------------- evidence provenance ---

#: Artifact kinds that are the operator's own assertion rather than a document
#: someone else stands behind. A vendor's public security page is a marketing
#: surface: it is external text, but it is the same party asserting its own
#: controls, so it cannot verify them.
_SELF_ASSERTED_KINDS = frozenset({
    "vendor_web", "vendor_webpage", "marketing", "homepage", "trust_center",
    "self_attested", "assertion", "claim", "questionnaire_response",
    "internal_note", "note",
})


def source_class(artifact: Any) -> str:
    """Classify an artifact's provenance: vendor_docs | contract | arxiv |
    news | research | self_attested.

    The distinction that matters for assurance is the last one. A vendor
    document and a press item are both external text; an operator's own
    assertion is not evidence of anything except that they asserted it.
    """
    atype = str(_get(artifact, "artifact_type", "type", default="") or "").lower()
    url = str(_get(artifact, "url", default="") or "").lower()
    source = str(_get(artifact, "source", default="") or "").lower()
    origin = str(_get(artifact, "origin", default="") or "").lower()
    blob = _blob(artifact)

    if (origin in ("self", "self_attested") or atype in _SELF_ASSERTED_KINDS):
        return "self_attested"
    if not url and atype not in _PRIMARY_TYPES:
        # No URL and not a declared primary kind: an internal note.
        return "self_attested"
    # Contract language is checked before the generic primary-kind branch: a
    # DPA is a binding commitment and a security whitepaper is not, and
    # collapsing both to "vendor_docs" would lose the distinction the class
    # exists to make.
    if "dpa" in blob or "data processing agreement" in blob or \
            atype in ("dpa", "contract", "msa", "sow"):
        return "contract"
    if atype in _PRIMARY_TYPES:
        return "vendor_docs"
    if "arxiv" in url or "arxiv" in source or atype == "paper":
        return "arxiv"
    if atype in ("news", "tweet", "interview", "book", "projection", "cve"):
        return "news"
    if atype in ("research", "essay"):
        return "research"
    if any(d in url for d in ("docs.", "developer.", "/docs", "documentation")):
        return "vendor_docs"
    return "research"


def artifact_provenance(artifact: Any) -> dict[str, Any]:
    """The stamp that must travel with every citation used for scoring.

    Source class, fetch date, review status and whether the artifact counts as
    primary evidence. A citation without this stamp is indistinguishable from
    one a reviewer has judged, which is precisely the failure the two observed
    dossiers exhibited (0 accepted / 48 pending, findings still resting on
    pending material).
    """
    review = str(_get(artifact, "review", default="pending") or "pending")
    cls = source_class(artifact)
    fetched = _iso(_get(artifact, "created_at", "collected_at", "fetched_at"))
    published = _iso(_get(artifact, "date_published", "published"))
    atype = str(_get(artifact, "artifact_type", "type", default="") or "")
    is_primary = (atype.lower() in _PRIMARY_TYPES) or cls in ("vendor_docs", "contract")
    return {
        "artifact_id": _get(artifact, "id"),
        "title": str(_get(artifact, "title", default="") or "")[:200],
        "source_class": cls,
        "artifact_type": atype,
        "review": review,
        "fetched_at": fetched,
        "published_at": published,
        "relevance": round(_num(_get(artifact, "relevance"), 0.0), 3),
        "drift": bool(_get(artifact, "drift", default=False)),
        "origin": str(_get(artifact, "origin", default="agent") or "agent"),
        "is_primary": is_primary,
        "usable_for_reduction": _accepted(artifact) and is_primary and not _rejected(artifact),
    }


def pending_evidence_weight(artifacts: Optional[list[Any]] = None) -> dict[str, Any]:
    """How much of the collected base is still provisional.

    Read by the executive summary so a reader knows what share of the score
    could still move on review.
    """
    arts = list(artifacts or [])
    total = len(arts)
    accepted = sum(1 for a in arts if _accepted(a))
    rejected = sum(1 for a in arts if _rejected(a))
    pending = total - accepted - rejected
    usable = sum(1 for a in arts if artifact_provenance(a)["usable_for_reduction"])
    high = sum(1 for a in arts
               if _accepted(a) and _num(_get(a, "relevance")) >= MIN_ACCEPTED_RELEVANCE)
    weight = (pending / total) if total else 0.0
    return {
        "artifacts": total,
        "accepted": accepted,
        "pending": pending,
        "rejected": rejected,
        "accepted_high_relevance": high,
        "usable_for_reduction": usable,
        "pending_weight": round(weight, 3),
        "verdict": ("no_pending_evidence" if not pending else
                    "mostly_provisional" if weight >= 0.5 else "partly_provisional"),
        "note": ("Share of collected artifacts a reviewer has not yet judged. "
                 "Pending artifacts never reduce residual in the verified "
                 "layer."),
    }


def review_queue(artifacts: Optional[list[Any]] = None, *,
                 now: Any = None, timeout_days: int = 14,
                 high_relevance: float = MIN_ACCEPTED_RELEVANCE,
                 ) -> dict[str, Any]:
    """Age pending artifacts into a human-in-the-loop queue with a recommendation.

    A pending artifact is not a neutral holding state: it silently inflates the
    apparent base and, before this change, fed scoring. Every pending item past
    ``timeout_days`` is surfaced with a suggested action (promote when it is
    high-relevance and unflagged, reject when it drifted or is off-brief) so
    the backlog cannot grow unbounded without a decision.
    """
    from datetime import datetime, timedelta, timezone

    ref = now or datetime.now(timezone.utc)
    if isinstance(ref, str):
        try:
            ref = datetime.fromisoformat(ref.replace("Z", "+00:00"))
        except Exception:
            ref = datetime.now(timezone.utc)
    if ref.tzinfo is None:
        ref = ref.replace(tzinfo=timezone.utc)

    items: list[dict[str, Any]] = []
    overdue = 0
    for a in (artifacts or []):
        if str(_get(a, "review", default="pending") or "pending") != "pending":
            continue
        created = _get(a, "created_at", "collected_at", "fetched_at")
        age_days = 0
        if created:
            raw = _iso(created)
            try:
                dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                age_days = max(0, (ref - dt).days)
            except Exception:
                age_days = 0
        rel = _num(_get(a, "relevance"))
        drift = bool(_get(a, "drift", default=False))
        overdue_flag = age_days >= timeout_days
        if overdue_flag:
            overdue += 1
        if drift:
            action, why = "reject", "flagged off-brief (drift)"
        elif rel >= high_relevance:
            action, why = "accept", f"high relevance {rel:.2f} >= {high_relevance:g}"
        elif rel and rel < 0.3:
            action, why = "reject", f"low relevance {rel:.2f}"
        else:
            action, why = "review", "relevance inconclusive"
        items.append({
            "artifact_id": _get(a, "id"),
            "title": str(_get(a, "title", default="") or "")[:160],
            "source_class": source_class(a),
            "relevance": round(rel, 3),
            "age_days": age_days,
            "drift": drift,
            "recommended_action": action,
            "reason": why,
            "overdue": overdue_flag,
        })
    items.sort(key=lambda i: (-int(i["overdue"]), -i["relevance"]))
    return {
        "timeout_days": timeout_days,
        "pending": len(items),
        "overdue": overdue,
        "items": items,
        "auto_apply": False,
        "note": ("Recommendation only: acceptance is a human decision and is "
                 "recorded as a ledger event when taken."),
    }


# ----------------------------------------------------- control attestation --

def control_attestation(declared_controls: Optional[Iterable[str]] = None,
                        artifacts: Optional[list[Any]] = None,
                        ) -> dict[str, Any]:
    """Per-control evidence standing with the provenance behind it.

    ``evidenced`` requires an **accepted primary** artifact naming the control
    id. A pending vendor PDF is not evidence yet, and a self-attested note is
    not evidence at all -- that distinction is the whole point of the split.
    Ids outside the catalogue are ``unknown``, never quietly ``declared``.
    """
    arts = list(artifacts or [])
    out: dict[str, dict[str, Any]] = {}
    for cid in declared_controls or []:
        cid = str(cid).strip().upper()
        if not cid:
            continue
        known = cid in sec._CONTROL_BY_ID
        supporting: list[dict[str, Any]] = []
        for a in arts:
            if cid.lower() not in _blob(a):
                continue
            prov = artifact_provenance(a)
            if prov["usable_for_reduction"]:
                supporting.append(prov)
        supporting.sort(key=lambda p: (-p["relevance"], str(p["artifact_id"])))
        if not known:
            status = "unknown"
        elif supporting:
            status = "evidenced"
        else:
            status = "declared"
        out[cid] = {
            "control_id": cid,
            "status": status,
            "in_catalog": known,
            "efficacy": sec._CONTROL_BY_ID[cid]["efficacy"] if known else None,
            "evidence": supporting[:6],
            "evidence_count": len(supporting),
            "source_classes": sorted({s["source_class"] for s in supporting}),
            "coverage_effect": 1.0 if status == "evidenced" else 0.0,
        }
    return out


def verified_control_ids(attestation: dict[str, Any]) -> list[str]:
    """Only ``evidenced`` controls may reduce residual risk in the verified layer."""
    return sorted(cid for cid, a in (attestation or {}).items()
                  if (a or {}).get("status") == "evidenced")


def _threat_evidence_index(threat_ids: Optional[Iterable[str]] = None,
                           known_exploits: Optional[list[dict]] = None,
                           ) -> dict[str, set[str]]:
    """Map each threat to the artifact ids that speak to it.

    An artifact speaks to a threat when it names the threat id directly, or when
    it names a known-exploit id (KE-xx) mapped to that threat in the catalogue.
    Anything else is not evidence *for that threat*, however relevant it is to
    the product.
    """
    wanted = {str(t).upper() for t in (threat_ids or [])}
    ke_map: dict[str, set[str]] = {}
    for ke in (known_exploits or []):
        if not isinstance(ke, dict):
            continue
        ke_id = str(ke.get("id") or "").upper()
        if not ke_id:
            continue
        for tid in ke.get("threat_ids") or []:
            wanted.add(str(tid).upper())
            ke_map.setdefault(str(tid).upper(), set()).add(ke_id)
    index: dict[str, set[str]] = {}
    if not wanted:
        return index
    from .agents import KNOWN_ATTACKS

    for ke in KNOWN_ATTACKS:
        for tid in ke.get("threat_ids") or []:
            if str(tid).upper() in wanted:
                ke_map.setdefault(str(tid).upper(), set()).add(str(ke.get("id") or "").upper())
    return ke_map if ke_map else {t: set() for t in wanted}


# ------------------------------------------------------ architecture gate --

def architecture_gate(checklist: Optional[dict[str, Any]] = None,
                      exposure: str = "confidential_data",
                      ) -> dict[str, Any]:
    """Mandatory data-flow completeness gate.

    ``checklist`` maps an :data:`ARCHITECTURE_ITEMS` key to either a status
    string (``known`` / ``partial`` / ``unknown``) or a dict with ``status``,
    ``value`` and ``source_id``. Absent key = unknown; that is the honest
    reading of a question nobody answered.

    On a Restricted/Confidential tier the gate is *required*: any open item
    forces the threats it determines back to inherent and raises a blocking
    finding. Below that tier the same items are reported as gaps without
    blocking, because a public-data assistant has no residency obligation to
    breach.
    """
    supplied = checklist or {}
    required = str(exposure or "").lower() in RESTRICTED_TIERS

    def _status(entry: Any) -> str:
        if entry is None:
            return "unknown"
        if isinstance(entry, dict):
            st = str(entry.get("status") or "unknown").lower()
            value = entry.get("value")
            if st == "known" and not str(value or "").strip():
                # "known" with nothing recorded is a claim, not a fact.
                return "unknown"
            return st
        st = str(entry).lower()
        if st in ("known", "answered", "yes", "complete", "confirmed"):
            return "known"
        if st in ("partial", "partly", "assumed"):
            return "partial"
        return "unknown"

    items: list[dict[str, Any]] = []
    blocked: set[str] = set()
    open_items: list[str] = []
    for spec in ARCHITECTURE_ITEMS:
        entry = supplied.get(spec["key"])
        st = _status(entry)
        rec: dict[str, Any] = {
            "key": spec["key"],
            "label": spec["label"],
            "status": st,
            "blocks": list(spec["blocks"]),
            "why": spec["why"],
        }
        if isinstance(entry, dict):
            rec["value"] = str(entry.get("value") or "")[:400]
            rec["source_id"] = entry.get("source_id")
        elif entry is not None:
            rec["value"] = str(entry)[:400]
        items.append(rec)
        if st != "known":
            open_items.append(spec["key"])
            blocked.update(spec["blocks"])

    complete = not open_items
    findings = []
    if required and open_items:
        findings.append({
            "id": "ARCH-GAP",
            "severity": "blocking",
            "title": "Architecture gap — scoring incomplete",
            "open_items": open_items,
            "blocked_threats": sorted(blocked),
            "detail": ("Residual scoring for "
                       + ", ".join(sorted(blocked))
                       + " is held at inherent until the data-flow checklist "
                         "is complete. The headline residual is therefore a "
                         "floor, not an estimate."),
        })
    return {
        "required": required,
        "tier": exposure,
        "complete": complete,
        "items": items,
        "open_items": open_items,
        "blocked_threats": sorted(blocked) if (required and open_items) else [],
        "gate_blocked_applied": bool(required and open_items),
        "findings": findings,
        "banner": ("Architecture Gap — scoring incomplete" if required and open_items
                   else "Architecture checklist complete" if required
                   else f"Architecture checklist not required at tier {exposure}"),
    }


# ---------------------------------------------------------- evidence gate --

def evidence_gate(threats: Optional[list[dict[str, Any]]] = None,
                  artifacts: Optional[list[Any]] = None,
                  known_exploits: Optional[list[dict]] = None,
                  *, min_accepted: int = MIN_ACCEPTED_PER_TOP_THREAT,
                  min_relevance: float = MIN_ACCEPTED_RELEVANCE,
                  top_n: int = TOP_THREAT_GATE_N,
                  ) -> dict[str, Any]:
    """Minimum accepted-evidence threshold before residual may be reduced.

    For each of the top ``top_n`` residual threats, count the *accepted*,
    high-relevance artifacts that speak to it. Below ``min_accepted`` the
    threat's verified residual is held at inherent. This is what stops a
    dossier resting on 48 pending artifacts from reporting a reduction.
    """
    rows = sorted(threats or [],
                  key=lambda r: -_num(r.get("residual_score")))
    top = rows[:top_n]
    ke_map = _threat_evidence_index([r.get("id") for r in rows], known_exploits)
    arts = list(artifacts or [])
    usable = [a for a in arts
              if _accepted(a)
              and _num(_get(a, "relevance")) >= min_relevance
              and artifact_provenance(a)["is_primary"]
              and not bool(_get(a, "drift", default=False))]

    per_threat: list[dict[str, Any]] = []
    gated: list[str] = []
    for r in top:
        tid = str(r.get("id") or "").upper()
        needles = {tid.lower()} | {k.lower() for k in ke_map.get(tid, set())}
        hits = [a for a in usable
                if any(n and n in _blob(a) for n in needles)]
        ok = len(hits) >= min_accepted
        if not ok:
            gated.append(tid)
        per_threat.append({
            "threat_id": tid,
            "title": str(r.get("title") or "")[:80],
            "residual_score": r.get("residual_score"),
            "accepted_evidence": len(hits),
            "required": min_accepted,
            "met": ok,
            "evidence_ids": [_get(a, "id") for a in hits[:6]],
        })
    return {
        "min_accepted_per_threat": min_accepted,
        "min_relevance": min_relevance,
        "top_n": top_n,
        "usable_evidence_pool": len(usable),
        "per_threat": per_threat,
        "gated_threats": gated,
        "applied": bool(gated),
        "note": ("Residual is held at inherent for any top threat without the "
                 "minimum accepted primary evidence behind it."),
    }


# ------------------------------------------------------ exposure / radius --

def blast_radius(residual_pct: Optional[float] = None,
                 inventory: Optional[dict[str, Any]] = None,
                 exposure: str = "confidential_data",
                 ) -> dict[str, Any]:
    """Turn a residual score into an approximate exposure estimate.

    A 0-100 residual is abstract. "Residual 25 across 4,000 restricted assets,
    300 privileged users, 2 MB mean context" is a materiality conversation. The
    inventory is optional in the API and *required* for any go/no-go on a
    restricted tier -- reported here rather than assumed.
    """
    inv = inventory or {}
    restricted = int(_num(inv.get("restricted_assets"), 0))
    confidential = int(_num(inv.get("confidential_assets"), 0))
    users = int(_num(inv.get("privileged_users"), 0))
    avg_kb = _num(inv.get("avg_context_kb"), 0.0)
    max_kb = _num(inv.get("max_context_kb"), 0.0)
    records = restricted + confidential

    def _band(pct: float) -> str:
        for thresh, name in EXPOSURE_BANDS:
            if pct >= thresh:
                return name
        return "low"

    pct = _num(residual_pct, 0.0)
    band = _band(pct)
    quantified = bool(records and users)
    payload_mb = (records * max_kb / 1024.0) if (records and max_kb) else 0.0
    required = str(exposure or "").lower() in RESTRICTED_TIERS
    missing = [k for k, v in (("restricted_assets", restricted),
                              ("confidential_assets", confidential),
                              ("privileged_users", users),
                              ("avg_context_kb", avg_kb),
                              ("max_context_kb", max_kb)) if not v]
    return {
        "residual_pct": pct,
        "band": band,
        "required_for_tier": required,
        "quantified": quantified,
        "inventory": {
            "restricted_assets": restricted,
            "confidential_assets": confidential,
            "records_in_scope": records,
            "privileged_users": users,
            "avg_context_kb": round(avg_kb, 1),
            "max_context_kb": round(max_kb, 1),
        },
        "records_at_risk": records * users if quantified else None,
        "max_payload_mb": round(payload_mb, 1) if payload_mb else None,
        "summary": (
            f"{band} residual {pct:g}% × {records} record(s) × {users} privileged "
            f"user(s)" if quantified
            else f"{band} residual {pct:g}% — exposure not quantified"),
        "missing_inputs": missing,
        "blocks_decision": bool(required and not quantified),
        "note": ("Blast-radius quantification is a required input for any "
                 "go/no-go on a restricted or confidential tier."),
    }


# -------------------------------------------------------------- forensics --

def forensics_readiness(artifacts: Optional[list[Any]] = None,
                        attestation: Optional[dict[str, Any]] = None,
                        checklist: Optional[dict[str, Any]] = None,
                        ) -> dict[str, Any]:
    """Can an incident responder reconstruct an AI interaction end to end?

    Each element is located either in an accepted primary artifact that names
    it, or in the operator's own architecture checklist (a schema pasted into
    the checklist is evidence of the same standing as a vendor document). An
    element that cannot be located is reported as **not found** rather than
    assumed absent-but-fine: the spec requires the agent to look, and to say so.
    """
    arts = [a for a in (artifacts or [])
            if _accepted(a) and not _rejected(a)]
    att = attestation or {}
    log_controls = [c for c in ("C07", "C08")
                    if (att.get(c) or {}).get("status") == "evidenced"]
    corpus = " ".join(_blob(a) for a in arts) + " " + " ".join(
        str(v.get("value") or "") for v in (checklist or {}).values()
        if isinstance(v, dict))

    found: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    score = 0.0
    for el in FORENSICS_ELEMENTS:
        hit = any(t in corpus for t in el["terms"])
        if not hit and el["key"] == "log_schema" and log_controls:
            # An evidenced immutable-audit control implies a schema exists.
            hit = True
        rec = {
            "key": el["key"],
            "label": el["label"],
            "weight": el["weight"],
            "status": "found" if hit else "not_found",
        }
        if hit:
            score += el["weight"]
            found.append(rec)
        else:
            missing.append(rec)
    score = round(score, 1)
    return {
        "score": score,
        "max_score": sum(e["weight"] for e in FORENSICS_ELEMENTS),
        "reconstructable": score >= FORENSICS_RECONSTRUCTABLE_AT,
        "threshold": FORENSICS_RECONSTRUCTABLE_AT,
        "elements": found + missing,
        "not_found": [m["key"] for m in missing],
        "gated_threats": list(FORENSICS_GATED_THREATS),
        "evidenced_log_controls": log_controls,
        "band": ("reconstructable" if score >= FORENSICS_RECONSTRUCTABLE_AT
                 else "partial" if score >= 40 else "not_demonstrated"),
        "note": ("An assessment that cannot demonstrate reconstructability of "
                 "AI interactions must not claim low residual on "
                 + ", ".join(FORENSICS_GATED_THREATS) + "."),
    }


# ------------------------------------------------- injection / chain model --

def adversarial_test_evidenced(artifacts: Optional[list[Any]] = None) -> bool:
    """Has an accepted primary artifact recorded an adversarial test result?"""
    for a in (artifacts or []):
        if not _accepted(a):
            continue
        if not artifact_provenance(a)["is_primary"]:
            continue
        blob = _blob(a)
        if any(t in blob for t in ADVERSARIAL_TEST_TERMS):
            return True
    return False


def injection_cap(threats: Optional[list[dict[str, Any]]] = None,
                  artifacts: Optional[list[Any]] = None,
                  *, cap: float = INJECTION_COVERAGE_CAP,
                  ) -> dict[str, Any]:
    """Cap prompt-injection coverage at ``cap`` unless an adversarial test exists.

    Delimiters, escaping and instruction hierarchy reduce LLM01; they do not
    remove it. A control claiming full efficacy with no test result behind it
    is a claim, so its coverage is capped -- which pushes residual back up
    rather than leaving an optimistic headline.
    """
    tested = adversarial_test_evidenced(artifacts)
    applied: list[str] = []
    for r in threats or []:
        if str(r.get("id") or "").upper() != INJECTION_GATED_THREAT:
            continue
        cov = _num(r.get("coverage")) / 100.0
        r["coverage"] = round(min(cov, cap if not tested else max(cov, cap)) * 100, 1)
        applied.append(INJECTION_GATED_THREAT)
    return {
        "threat_id": INJECTION_GATED_THREAT,
        "cap": cap,
        "adversarial_test_evidenced": tested,
        "applied_to": applied,
        "active": bool(applied) and not tested,
        "note": ("Coverage for prompt-injection controls is capped at "
                 f"{cap:.0%} until an accepted adversarial test result exists."),
    }


def detect_chains(threats: Optional[list[dict[str, Any]]] = None,
                  artifacts: Optional[list[Any]] = None,
                  *,
                  full_metadata_context: Optional[bool] = None,
                  ) -> list[dict[str, Any]]:
    """Model KE-01 -> KE-06 as one composite path, not two independent threats.

    Fires when full-metadata context is confirmed (explicitly, or inferred from
    T01 and T05 both being in scope): an injected instruction in retrieved
    catalog content that then exfiltrates context is a *single* exploit chain
    with one mitigation set, and scoring the halves independently lets a reader
    believe one of them is covered.
    """
    rows = {str(r.get("id") or "").upper(): r for r in (threats or [])}
    t01, t05 = rows.get("T01"), rows.get("T05")
    if full_metadata_context is None:
        full_metadata_context = bool(t01 and t05)
    if not full_metadata_context:
        return []
    res = max(_num((t05 or {}).get("residual_score")),
              _num((t01 or {}).get("residual_score")))
    return [{
        "id": "KE-01->KE-06",
        "title": "Indirect injection chained to context disclosure",
        "path": ["KE-01", "KE-06"],
        "threats": ["T05", "T01"],
        "composite_residual": round(res, 1),
        "exploit": ("Instructions planted in untrusted catalog content are "
                    "followed by the assistant, which then discloses system "
                    "prompt and retrieved context in its output."),
        "mitigations": [
            "Delimiter/escape untrusted catalog content and enforce an "
            "instruction hierarchy",
            "Adversarial prompt-injection suite with recorded results",
            "Output review before publication + downstream ACL sync",
        ],
        "note": ("Scored as one path: covering KE-01 without covering the "
                 "disclosure step leaves the chain open."),
    }]


# ---------------------------------------------------------- decision frame --

def decision_frame(*, verified_residual_pct: Optional[float],
                   declared_residual_pct: Optional[float],
                   gate: dict[str, Any],
                   ev_gate: dict[str, Any],
                   forensics: dict[str, Any],
                   radius: dict[str, Any],
                   evidence_confidence: float,
                   exposure: str = "confidential_data",
                   ) -> dict[str, Any]:
    """Accept / Accept with mandatory guardrails / Reject, with the reasons.

    The decision is derived, never asked for: a reader can replay it from the
    gates. Below the restricted tier the decision frame is advisory, because
    the gates that block are the ones a public-data deployment cannot fail.
    """
    v = _num(verified_residual_pct, 100.0)
    reasons: list[str] = []
    actions: list[dict[str, Any]] = []

    if gate.get("gate_blocked_applied"):
        decision = DECISION_REJECT
        reasons.append(
            "Architecture completeness gate failed on a "
            f"{exposure} tier: {', '.join(gate.get('open_items') or [])}")
        for item in gate.get("items") or []:
            if item.get("status") != "known":
                actions.append({
                    "action": f"Close architecture item: {item['label']}",
                    "owner": "vendor + architecture",
                    "window_days": 30,
                    "unblocks": item.get("blocks") or [],
                })
    elif radius.get("blocks_decision"):
        decision = DECISION_REJECT
        reasons.append(
            "Blast radius is unquantified on a restricted tier: missing "
            + ", ".join(radius.get("missing_inputs") or []))
        actions.append({
            "action": "Record the exposure inventory (assets, privileged users, "
                      "context size)",
            "owner": "product owner",
            "window_days": 30,
            "unblocks": ["materiality"],
        })
    elif (not forensics.get("reconstructable")
          and str(exposure or "").lower() in RESTRICTED_TIERS):
        decision = DECISION_GUARDRAILS
        reasons.append(
            "Forensics readiness is "
            f"{forensics.get('score')}/{forensics.get('max_score')} "
            f"({forensics.get('band')}); not reconstructable")
        for key in (forensics.get("not_found") or [])[:4]:
            el = next((e for e in FORENSICS_ELEMENTS if e["key"] == key), None)
            actions.append({
                "action": f"Evidence for {el['label'] if el else key}",
                "owner": "security engineering",
                "window_days": 30,
                "unblocks": list(FORENSICS_GATED_THREATS),
            })
    elif _num(evidence_confidence) < 0.5:
        decision = DECISION_GUARDRAILS
        reasons.append(
            f"Evidence confidence {evidence_confidence:.0%}: most of the "
            "residual reduction rests on unevidenced controls")
        actions.append({
            "action": "Attach accepted primary evidence to every declared control",
            "owner": "control owner",
            "window_days": 30,
            "unblocks": ["evidence_confidence"],
        })
    elif v >= 50.0:
        decision = DECISION_GUARDRAILS
        reasons.append(f"Verified residual {v:g}% is elevated")
    else:
        decision = DECISION_ACCEPT
        reasons.append(
            f"Verified residual {v:g}% with evidence confidence "
            f"{evidence_confidence:.0%} and all gates satisfied")

    for tid in (ev_gate.get("gated_threats") or [])[:3]:
        actions.append({
            "action": f"Accept >= {ev_gate.get('min_accepted_per_threat')} "
                      f"primary artifacts for {tid}",
            "owner": "reviewer",
            "window_days": 30,
            "unblocks": [tid],
        })
    if not reasons:
        reasons.append("No assurance view computed")
    return {
        "decision": decision,
        "headline": {
            DECISION_ACCEPT: "Accept",
            DECISION_GUARDRAILS: "Accept with mandatory guardrails",
            DECISION_REJECT: "Reject until the architecture gate closes",
        }[decision],
        "advisory_only": str(exposure or "").lower() not in RESTRICTED_TIERS,
        "reasons": reasons,
        "actions_0_30_days": actions[:10],
        "verified_residual_pct": v,
        "declared_residual_pct": declared_residual_pct,
    }


# ---------------------------------------------------- vendor questionnaire --

def vendor_questionnaire(gate: Optional[dict[str, Any]] = None,
                         forensics: Optional[dict[str, Any]] = None,
                         chains: Optional[list[dict[str, Any]]] = None,
                         ) -> dict[str, Any]:
    """Turn unresolved architecture items into a sendable artefact.

    An open architecture question with no owner is a question nobody will ever
    answer. This renders one structured questionnaire the vendor can answer in
    a single pass, each item naming the threats it unblocks so the reader can
    price the answer.
    """
    g = gate or {}
    f = forensics or {}
    items: list[dict[str, Any]] = []
    for spec in ARCHITECTURE_ITEMS:
        rec = next((i for i in (g.get("items") or []) if i.get("key") == spec["key"]), None)
        st = (rec or {}).get("status") or "unknown"
        if st == "known":
            continue
        items.append({
            "id": f"VQ-{spec['key']}",
            "section": spec["label"],
            "question": spec["question"],
            "why_it_matters": spec["why"],
            "blocks": list(spec["blocks"]),
            "current_status": st,
            "recorded_value": (rec or {}).get("value") or "",
        })
    for key in (f.get("not_found") or []):
        el = next((e for e in FORENSICS_ELEMENTS if e["key"] == key), None)
        if not el:
            continue
        items.append({
            "id": f"VQ-forensics-{key}",
            "section": f"AI-interaction logging — {el['label']}",
            "question": (f"Provide evidence that {el['label'].lower()} is "
                         "recorded per AI interaction, with the field name, "
                         "schema location and retention period."),
            "why_it_matters": ("Without it, an incident responder cannot "
                               "reconstruct what left the boundary."),
            "blocks": list(FORENSICS_GATED_THREATS),
            "current_status": "not_found",
            "recorded_value": "",
        })
    for ch in (chains or []):
        items.append({
            "id": "VQ-injection-testing",
            "section": "Prompt-injection assurance",
            "question": ("Provide the results of adversarial prompt-injection "
                         "testing against untrusted retrieved content, "
                         "including the delimiter and instruction-hierarchy "
                         "design and the pass rate on the test suite."),
            "why_it_matters": ("Prompt-injection controls cannot be credited "
                               "at full efficacy without recorded test results."),
            "blocks": [INJECTION_GATED_THREAT],
            "current_status": "unevidenced",
            "recorded_value": "",
        })
    return {
        "items": items,
        "count": len(items),
        "markdown": _questionnaire_markdown(items),
        "note": ("Generated from unresolved architecture and forensics items. "
                 "Send to the vendor as a single questionnaire."),
    }


def _questionnaire_markdown(items: list[dict[str, Any]]) -> str:
    if not items:
        return ("_No open vendor questions: the architecture checklist and "
                "forensics elements are all evidenced._")
    out = ["## Vendor Assurance Questionnaire", ""]
    for i, it in enumerate(items, 1):
        out.append(f"**{i}. {it['section']}** — status: {it['current_status']}")
        out.append("")
        out.append(it["question"])
        out.append("")
        out.append(f"_Why: {it['why_it_matters']}_")
        out.append("")
        out.append(f"_Unblocks: {', '.join(it['blocks']) or 'materiality'}_")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


# ------------------------------------------------------------ entry point --

def assess(*, exposure: str, inherent_threats: list[dict[str, Any]],
           declared_controls: Optional[Iterable[str]] = None,
           applicability: Optional[dict[str, float]] = None,
           artifacts: Optional[list[Any]] = None,
           architecture_checklist: Optional[dict[str, Any]] = None,
           exposure_inventory: Optional[dict[str, Any]] = None,
           known_exploits: Optional[list[dict]] = None,
           full_metadata_context: Optional[bool] = None,
           score_fn=None) -> dict[str, Any]:
    """The full assurance pass over one threat set. Pure; no DB, no LLM.

    Returns the declared *and* verified layers side by side plus every gate,
    so a caller can print either without recomputing anything.
    """
    from .security import _aggregate_pct, score_assessment

    score_fn = score_fn or score_assessment
    arts = list(artifacts or [])

    # ---- 1. attestation: which controls may reduce risk at all --------------
    declared = sorted({str(c).strip().upper() for c in (declared_controls or []) if str(c).strip()})
    att = control_attestation(declared, arts)
    verified = verified_control_ids(att)

    # ---- 2. declared layer: current behaviour ------------------------------
    declared_scoring = score_fn(exposure, inherent_threats,
                                active_controls=declared,
                                applicability=applicability)
    declared_threats = [dict(r) for r in declared_scoring.get("threats") or []]

    # ---- 3. verified layer: only evidenced controls ------------------------
    verified_scoring = score_fn(exposure, inherent_threats,
                                active_controls=verified,
                                applicability=applicability)
    verified_threats = [dict(r) for r in verified_scoring.get("threats") or []]
    v_by_id = {str(r["id"]).upper(): r for r in verified_threats}

    # ---- 4. architecture gate ----------------------------------------------
    gate = architecture_gate(architecture_checklist, exposure)

    # ---- 5. evidence gate, measured on the declared (planning) order -------
    ev_gate = evidence_gate(declared_threats, arts, known_exploits)

    # ---- 6. forensics readiness -------------------------------------------
    forensics = forensics_readiness(arts, att, architecture_checklist)

    # ---- 7. semantic-gap hardening ----------------------------------------
    injection = injection_cap(verified_threats, arts)
    chains = detect_chains(declared_threats, arts, full_metadata_context=full_metadata_context)

    # ---- 8. force residual back to inherent wherever a gate says so --------
    forced: dict[str, str] = {}
    if gate.get("gate_blocked_applied"):
        for tid in gate.get("blocked_threats") or []:
            forced[tid] = "architecture gate: unknown data-flow item"
    for tid in (forensics.get("gated_threats") or []) if not forensics.get("reconstructable") else ():
        forced.setdefault(tid, "forensics readiness not demonstrated")
    for tid in ev_gate.get("gated_threats") or []:
        forced.setdefault(tid, "insufficient accepted evidence")
    if injection.get("active"):
        forced.setdefault(INJECTION_GATED_THREAT, "prompt-injection coverage capped: no adversarial test")

    for tid, reason in forced.items():
        r = v_by_id.get(tid)
        if not r:
            continue
        r["residual_score"] = r["inherent_score"]
        r["coverage"] = 0.0
        r["residual_severity"] = r.get("inherent_severity")
        r["forced_to_inherent"] = True
        r["forced_reason"] = reason

    inh_pct, ver_pct, _ = _aggregate_pct(verified_threats, applicability)

    # ---- 9. evidence confidence: share of reduction that is evidenced ------
    def _reduction(rows: list[dict[str, Any]]) -> float:
        return sum(_num(r.get("inherent_score")) - _num(r.get("residual_score")) for r in rows)

    d_red, v_red = _reduction(declared_threats), _reduction(verified_threats)
    evidence_confidence = round(max(0.0, min(1.0, v_red / d_red)), 3) if d_red > 0 else 0.0

    coverage_confidence: dict[str, Any] = {}
    d_by_id = {str(r["id"]).upper(): r for r in declared_threats}
    for tid, vr in v_by_id.items():
        dc = _num((d_by_id.get(tid) or {}).get("coverage"))
        vc = _num(vr.get("coverage"))
        coverage_confidence[tid] = {
            "declared_coverage": round(dc, 1),
            "verified_coverage": round(vc, 1),
            "coverage_confidence_pct": round((vc / dc) * 100, 0) if dc > 0 else 0.0,
        }

    # ---- 10. exposure / blast radius --------------------------------------
    radius = blast_radius(ver_pct, exposure_inventory, exposure)

    # ---- 11. decision ------------------------------------------------------
    decision = decision_frame(
        verified_residual_pct=ver_pct,
        declared_residual_pct=declared_scoring.get("residual_pct"),
        gate=gate, ev_gate=ev_gate, forensics=forensics,
        radius=radius, evidence_confidence=evidence_confidence,
        exposure=exposure)

    unverified = sorted(cid for cid, a in att.items() if a.get("status") != "evidenced")
    from .security import _posture

    merged = []
    for d in sorted(declared_threats, key=lambda r: (-_num(r.get("residual_score")), r.get("id"))):
        tid = str(d.get("id") or "").upper()
        v = v_by_id.get(tid) or {}
        merged.append({
            **{k: d.get(k) for k in (
                "id", "title", "stride", "owasp", "inherent_score",
                "inherent_severity", "impact", "likelihood", "controls",
                "applicability", "applicable")},
            "declared_residual": d.get("residual_score"),
            "declared_coverage": d.get("coverage"),
            "verified_residual": v.get("residual_score"),
            "verified_coverage": v.get("coverage"),
            "coverage_confidence_pct": coverage_confidence.get(tid, {}).get("coverage_confidence_pct", 0.0),
            "forced_to_inherent": bool(v.get("forced_to_inherent")),
            "forced_reason": v.get("forced_reason") or "",
        })

    return {
        "method": ASSURANCE_METHOD,
        "version": ASSURANCE_VERSION,
        "fingerprint": assurance_fingerprint(),
        "headline_layer": "verified",
        "headline_residual_pct": ver_pct,
        "declared": {
            "inherent_pct": declared_scoring.get("inherent_pct"),
            "residual_pct": declared_scoring.get("residual_pct"),
            "posture": declared_scoring.get("posture"),
            "active_controls": declared,
            "mean_coverage": (declared_scoring.get("breakdown") or {}).get("mean_coverage"),
        },
        "verified": {
            "inherent_pct": inh_pct,
            "residual_pct": ver_pct,
            "posture": _posture(ver_pct),
            "active_controls": verified,
            "mean_coverage": (verified_scoring.get("breakdown") or {}).get("mean_coverage"),
        },
        "evidence_confidence": evidence_confidence,
        "evidence_confidence_pct": round(evidence_confidence * 100),
        "control_attestation": att,
        "unverified_controls": unverified,
        "coverage_confidence": coverage_confidence,
        "architecture_gate": gate,
        "evidence_gate": ev_gate,
        "forensics": forensics,
        "injection": injection,
        "chains": chains,
        "blast_radius": radius,
        "decision": decision,
        "vendor_questionnaire": vendor_questionnaire(gate, forensics, chains),
        "pending_evidence": pending_evidence_weight(arts),
        "threats": merged,
        "forced_to_inherent": sorted(forced),
        "gates_open": sorted(set(
            list(gate.get("open_items") or [])
            + list(ev_gate.get("gated_threats") or [])
            + (["forensics"] if not forensics.get("reconstructable") else [])
            + (["injection"] if injection.get("active") else [])
            + (["blast_radius"] if radius.get("blocks_decision") else []))),
        "note": ("Declared residual is a planning view. Verified residual "
                 "only credits controls backed by accepted primary evidence "
                 "and is held at inherent wherever a gate fails."),
    }


def pack_supersession(threat_version: Optional[str] = None,
                      threat_fp: Optional[str] = None) -> dict[str, Any]:
    """Has a newer threat pack shipped since this row was scored?

    Reported, never acted on: re-scoring an assessment somebody already signed
    is a decision for whoever owns it, not a side effect of a read.
    """
    try:
        from . import threatpack as tp

        current_v, current_fp = tp.PACK_VERSION, tp.pack_fingerprint()
        newer = []
        if threat_version and threat_version != current_v:
            newer.append(f"pack version {threat_version} → {current_v}")
        if threat_fp and threat_fp != current_fp:
            newer.append(f"catalog fingerprint {threat_fp} → {current_fp}")
        return {
            "threat_pack_used": threat_version,
            "current_version": current_v,
            "fingerprint_used": threat_fp,
            "current_fingerprint": current_fp,
            "stale": bool(newer),
            "newer_pack_available": bool(newer),
            "recommendation": ("Re-score recommended: a newer threat pack is "
                               "available." if newer else "Up to date."),
            "deltas": newer,
        }
    except Exception as exc:  # pragma: no cover - defensive
        return {"threat_pack_used": threat_version, "stale": None,
                "newer_pack_available": None,
                "recommendation": f"Pack comparison unavailable: {exc}"}


def canonical_register_key(product_family: Optional[str], layer: str,
                           source_ref: str, scope: str = "own") -> str:
    """Stable key for the canonical threat register, per product family.

    Two runs of the same product family must land on the same row so the
    second run updates evidence and coverage instead of adding a
    slightly-different threat list. This is the fix for "multiple overlapping
    assessments with slight threat-list drift".
    """
    fam = " ".join(str(product_family or "").lower().split()) or "unassigned"
    return ":".join([fam, str(layer or "unknown").lower(),
                     str(source_ref or "?").upper(), str(scope or "own").lower()])