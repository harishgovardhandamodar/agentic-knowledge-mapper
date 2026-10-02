"""Agent-to-Agent (A2A) protocol for the AI Security assessment workflow.

Protocol ``a2a/1.0``: every inter-agent call is a JSON envelope routed through
``dispatch()`` (the protocol bus), not a bare function call. Each hop appends
an auditable trace entry, persisted with the assessment and rendered in the UI.

The bus is also the audit checkpoint: every hop, and every model call made inside
a handler, lands on one hash-chained ledger timeline per task (see ``app.ledger``
and ``/api/ledger``). The in-envelope ``trace`` stays as the lightweight
protocol-level record; the ledger is the tamper-evident one.

Agents (cards at ``GET /api/agents/cards`` and ``GET /.well-known/agents``):

- ``security-orchestrator`` — plans the workflow, fans out collection tasks.
- ``research-collector``    — agentic search *within this app*: multi-query
  search over the investigation's knowledge graph (Artifact rows scoped by
  ``investigation_id``, falling back to all investigations).
- ``threat-intel``          — maps a curated known-attack catalogue onto the
  assessment's threat IDs (T01..T12) and joins entries with locally-found
  evidence.
- ``report-writer``         — drafts the "Known Exploits & Research Evidence"
  markdown section, executive-summary bullets, and (via the fox-services LLM
  gateway, with deterministic fallback) a grounded executive paragraph.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from . import grounding
from . import ledger
from . import obs

PROTOCOL = "a2a/1.0"


# ------------------------------------------------------------- agent cards ---

AGENT_CARDS: list[dict[str, Any]] = [
    {
        "name": "security-orchestrator",
        "protocol": PROTOCOL,
        "description": "Plans and orchestrates the AI security assessment workflow.",
        "skills": ["plan_assessment", "delegate_collection", "assemble_report"],
        "endpoint": "/api/investigations/{id}/security/assess",
    },
    {
        "name": "control-analyst",
        "protocol": PROTOCOL,
        "description": (
            "Reads the declared security-control coverage and the product context, "
            "then proposes per-threat applicability and the controls worth enabling. "
            "Arithmetic is done deterministically by the scoring engine, not here."
        ),
        "skills": ["analyse_controls", "judge_applicability", "propose_control_plan"],
        "endpoint": "/api/agents/invoke",
    },
    {
        "name": "research-collector",
        "protocol": PROTOCOL,
        "description": (
            "Agentic search within this app: multi-query search over the "
            "investigation knowledge graph, ranked evidence out."
        ),
        "skills": ["agentic_search", "rank_evidence"],
        "endpoint": "/api/agents/invoke",
    },
    {
        "name": "threat-intel",
        "protocol": PROTOCOL,
        "description": (
            "Maps curated known attacks onto threat IDs, cites local evidence, and "
            "returns per-threat applicability and evidence confidence."
        ),
        "skills": ["map_attacks", "cite_evidence", "score_evidence_confidence"],
        "endpoint": "/api/agents/invoke",
    },
    {
        "name": "report-writer",
        "protocol": PROTOCOL,
        "description": "Drafts the Known Exploits section + executive bullets/paragraph.",
        "skills": ["write_exploits_section", "write_exec_bullets"],
        "endpoint": "/api/agents/invoke",
    },
    {
        "name": "mitigation-advisor",
        "protocol": PROTOCOL,
        "description": (
            "Maps the open rows of the unified portfolio register to controls, "
            "deterministically, from stored rows and versioned catalogs. No "
            "model call: the same situation always yields the same list, "
            "withheld controls are reported rather than dropped, and no risk "
            "is ever marked secured."
        ),
        "skills": ["advise_portfolio_risks"],
        "endpoint": "/api/agents/invoke",
    },
    {
        "name": "model-profiler",
        "protocol": PROTOCOL,
        "description": (
            "Deterministically profiles the assessment subject (nature, "
            "architecture, class, family, data, interface). No model call."
        ),
        "skills": ["profile_model"],
        "endpoint": "/api/agents/invoke",
    },
    {
        "name": "model-internals",
        "protocol": PROTOCOL,
        "description": (
            "Reviews a model's architecture, training and inference surface; "
            "deterministic profile rules when the model is unreachable."
        ),
        "skills": ["review_internals"],
        "endpoint": "/api/agents/invoke",
    },
    {
        "name": "model-privacy",
        "protocol": PROTOCOL,
        "description": (
            "Assesses data minimization, retention and personal-data handling "
            "across collect, train, serve, log and delete."
        ),
        "skills": ["assess_model_privacy"],
        "endpoint": "/api/agents/invoke",
    },
    {
        "name": "model-reporter",
        "protocol": PROTOCOL,
        "description": "Drafts the model report sections + executive paragraph.",
        "skills": ["write_model_report"],
        "endpoint": "/api/agents/invoke",
    },
    {
        "name": "model-adv-intel",
        "protocol": PROTOCOL,
        "description": (
            "Maps published attacks onto a model or family from collected "
            "evidence, with class, scope, confidence and prerequisites. "
            "Evidence-keyed rules when the model is unreachable."
        ),
        "skills": ["map_model_attacks"],
        "endpoint": "/api/agents/invoke",
    },
    {
        "name": "model-adoption-analyst",
        "protocol": PROTOCOL,
        "description": (
            "Rates engineering adoption dimensions from primary sources; "
            "missing evidence rates unknown, never safe."
        ),
        "skills": ["rate_adoption"],
        "endpoint": "/api/agents/invoke",
    },
    {
        "name": "model-eval-reporter",
        "protocol": PROTOCOL,
        "description": "Drafts the dual-section model evaluation report.",
        "skills": ["write_model_eval_report"],
        "endpoint": "/api/agents/invoke",
    },
    {
        "name": "experiment-planner",
        "protocol": PROTOCOL,
        "description": (
            "Plans ranked experiments that settle open questions: unknown "
            "dimensions, confident attacks, open falsifiers, MM validations. "
            "Plan only — nothing here executes anything."
        ),
        "skills": ["plan_experiments"],
        "endpoint": "/api/agents/invoke",
    },
    {
        "name": "model-adversary",
        "protocol": PROTOCOL,
        "description": (
            "Turns a model profile into the capabilities an attacker would "
            "use: what the model lets someone build, infer, or launder. "
            "Deterministic capability rules when the model is unreachable."
        ),
        "skills": ["derive_capabilities"],
        "endpoint": "/api/agents/invoke",
    },
    {
        "name": "misuse-scout",
        "protocol": PROTOCOL,
        "description": (
            "Engineers adversarial scenarios from the derived capabilities: "
            "attack chains, prerequisites, and what each one would achieve."
        ),
        "skills": ["engineer_scenarios"],
        "endpoint": "/api/agents/invoke",
    },
    {
        "name": "misuse-reporter",
        "protocol": PROTOCOL,
        "description": (
            "Drafts the misuse report: ranked scenarios, abuse-chain "
            "diagram, and a grounded executive paragraph."
        ),
        "skills": ["write_misuse_report"],
        "endpoint": "/api/agents/invoke",
    },
    # --- flow 3: hypothesis synthesis. Reads the other two flows' output and
    # turns it into falsifiable claims rather than another score.
    {
        "name": "hypothesis-analyst",
        "protocol": PROTOCOL,
        "description": (
            "Reads the internals findings and misuse scenarios and drafts "
            "falsifiable claims from them: premise, mechanism, consequence, "
            "and the observation that would refute each one. Deterministic "
            "cross-flow rules when no model is reachable."
        ),
        "skills": ["draft_hypotheses"],
        "endpoint": "/api/agents/invoke",
    },
    {
        "name": "hypothesis-verifier",
        "protocol": PROTOCOL,
        "description": (
            "Challenges each drafted claim: which evidence supports it, which "
            "argues against it, and how well-specified its refutation test is. "
            "A claim with no counter-evidence is flagged, not rewarded."
        ),
        "skills": ["verify_hypotheses"],
        "endpoint": "/api/agents/invoke",
    },
    {
        "name": "hypothesis-reporter",
        "protocol": PROTOCOL,
        "description": (
            "Drafts the hypothesis report: claims with confidence and "
            "falsifiers, an evidence map, per-claim chain diagrams, and the "
            "observations that would settle the open questions."
        ),
        "skills": ["write_hypothesis_report"],
        "endpoint": "/api/agents/invoke",
    },
]


def get_agent_cards() -> list[dict[str, Any]]:
    return [dict(c) for c in AGENT_CARDS]


# --------------------------------------------------------------- envelopes ---

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_task_id(prefix: str = "sec") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def new_envelope(
    sender: str,
    recipient: str,
    intent: str,
    payload: Optional[dict[str, Any]] = None,
    task_id: Optional[str] = None,
    trace: Optional[list[dict[str, Any]]] = None,
    trace_id: Optional[str] = None,
    note: str = "",
) -> dict[str, Any]:
    env: dict[str, Any] = {
        "protocol": PROTOCOL,
        "task_id": task_id or new_task_id(),
        "from": sender,
        "to": recipient,
        "intent": intent,
        "payload": payload or {},
        # ``trace`` is the hop log -- a list of the agents this task passed
        # through. The *id* of the correlated trace is a different thing and has
        # its own key, because one name for both means whichever is read first
        # wins and the other is silently wrong.
        "trace": list(trace or []),
        "trace_id": trace_id or None,
    }
    env["trace"].append({"agent": sender, "intent": intent, "at": _now(), "note": note})
    return env


def reply_envelope(
    request_env: dict[str, Any],
    sender: str,
    intent: str,
    payload: Optional[dict[str, Any]] = None,
    note: str = "",
) -> dict[str, Any]:
    return new_envelope(
        sender=sender,
        recipient=request_env.get("from", "security-orchestrator"),
        intent=intent,
        payload=payload,
        task_id=request_env.get("task_id"),
        trace=request_env.get("trace", []),
        trace_id=request_env.get("trace_id"),
        note=note,
    )


# -------------------------------------------------- control-analyst agent ---

# Threat -> keyword hits for the deterministic applicability heuristic.
# The base lists describe the AI writing-assistant threat model; the
# domain bridges extend it to adjacent products (finance, payments) so
# assessments outside the original vocabulary still differentiate instead
# of collapsing every threat to the floor.
APPLICABILITY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "T01": ("paste", "prompt", "free text", "user", "employee", "assistant",
            "customer", "client", "pii"),
    "T02": ("retain", "train", "logging", "debug", "vendor",
            "transaction", "financial", "memoriz", "membership", "inversion",
            "extract"),
    "T03": ("classif", "label", "metadata", "catalog", "ledger"),
    "T04": ("schema", "description", "semantic", "field", "column",
            "balance", "ledger", "account", "tabular", "dataframe", "csv"),
    "T05": ("import", "inject", "instruction", "external", "linked doc",
            "payment", "transfer", "transaction"),
    "T06": ("insider", "export", "share", "exfil", "abuse",
            "customer", "fund", "account"),
    "T07": ("vendor", "subprocessor", "saas", "third-party", "external model",
            "payment", "processor", "bank"),
    "T08": ("audit", "provenance", "lineage", "log", "who",
            "transaction", "journal"),
    "T09": ("hallucinat", "stale", "accuracy", "trust", "quality",
            "amount", "balance"),
    "T10": ("role", "permission", "admin", "privilege", "least-privilege"),
    "T11": ("region", "residency", "gdpr", "transfer", "cross-border", "eu"),
    "T12": ("compliance", "dpia", "iso", "soc 2", "gdpr", "audit",
            "financial", "bank", "pci", "finance"),
}

APPLICABILITY_FLOOR = 0.45
APPLICABILITY_HIT = 0.18
# Deliberately below security._MIN_APPLICABILITY (0.3): a threat set here is
# reported with its rationale but excluded from the aggregate score.
APPLICABILITY_EXCLUDED = 0.25


def heuristic_applicability(product: str, use_case: str = "",
                            evidence: list[dict[str, Any]] | None = None,
                            focus: list[str] | None = None,
                            model_profile: dict[str, Any] | None = None) -> dict[str, float]:
    """Keyword-driven applicability: a threat counts when the product, use
    case, focus areas or evidence plausibly exercise it. The floor keeps
    catalog-inherent threats visible; keyword hits lift toward 1.0.

    ``model_profile`` (from security.profile_model_subject) adjusts for what
    kind of subject this is: a model with no conversational surface cannot
    exercise chat-shaped threats, so T01/T05 drop below the scoring floor
    (still reported, never silently gone). The exclusion stands through the
    evidence re-judge too: collected artifacts describe the domain, and domain
    chatter must not re-animate a threat the assessment's own charter
    excludes. Without a profile the numbers are exactly as before.
    """
    ev_blob = " ".join(
        f"{e.get('title', '')} {e.get('tags', '')} {e.get('snippet', '')}"
        for e in (evidence or []) if isinstance(e, dict))
    blob = (f"{product or ''} {use_case or ''} {ev_blob} "
            f"{' '.join(focus or [])}").lower()
    app: dict[str, float] = {}
    for tid, terms in APPLICABILITY_KEYWORDS.items():
        hits = sum(1 for t in terms if t in blob)
        # base floor keeps catalog-inherent threats visible; keywords lift them
        app[tid] = round(min(1.0, APPLICABILITY_FLOOR + APPLICABILITY_HIT * hits), 2)
    if model_profile and model_profile.get("is_model_query"):
        if model_profile.get("interface") == "non_conversational":
            # No prompt box, no pasted-into-assistant: the chat-surface
            # threats below score nothing here. They stay in the report,
            # marked below the scoring floor -- exclusion survives the
            # evidence re-judge by design (see below).
            for tid in ("T01", "T05"):
                app[tid] = min(app.get(tid, APPLICABILITY_FLOOR),
                               APPLICABILITY_EXCLUDED)
        if model_profile.get("trains_on_data") and model_profile.get("personal_data"):
            app["T02"] = round(min(1.0, app.get("T02", APPLICABILITY_FLOOR) + 0.2), 2)
    return app


def control_analyst_handle(env: dict[str, Any]) -> dict[str, Any]:
    """Intent ``analyse_controls``: control coverage + per-threat applicability.

    The LLM proposes applicability and extra controls worth enabling; if it is
    unavailable the deterministic heuristic below still returns a usable plan.
    """
    from . import security as sec

    payload = env.get("payload", {})
    product = payload.get("product_name", "the product")
    use_case = payload.get("use_case", "")
    exposure = payload.get("exposure", "confidential_data")
    declared = [str(c).strip().upper() for c in (payload.get("declared_controls") or [])]
    declared = [c for c in declared if c in sec._CONTROL_BY_ID]
    evidence = payload.get("evidence", []) or []
    focus = payload.get("focus") or []
    ev_blob = " ".join(
        f"{e.get('title', '')} {e.get('tags', '')} {e.get('snippet', '')}"
        for e in evidence if isinstance(e, dict))
    profile = sec.profile_model_subject(product, use_case, focus)
    applicability = heuristic_applicability(
        product, use_case, evidence, focus, model_profile=profile)
    proposed_extra: list[dict[str, Any]] = []
    confidence = 0.5
    source = "deterministic heuristic (no LLM)"

    try:
        from . import llm as _llm
        cat_lines = "\n".join(
            f"- {c['id']} {c['name']} (efficacy {c['efficacy']})" for c in sec._CONTROL_CATALOG)
        threat_lines = "\n".join(
            f"- {tid}: {dict(sec._THREAT_BY_ID[tid])}" for tid in sec._THREAT_IDS
            if tid in getattr(sec, "_THREAT_BY_ID", {}))
        sys_p = (
            "You are a security controls analyst. Judge, for the product "
            "described below"
            f"{' (' + profile['summary'] + ')' if profile.get('summary') else ''}, "
            "how applicable each threat is (0.0-1.0) and which additional "
            "controls from the catalogue should be enabled. Judge what is in "
            "front of you -- a model, a dataset and an interface each carry "
            "different threats than a conversational assistant. "
            "Reply with STRICT JSON only."
        )
        user_p = (
            f"Product: {product}\nUse case: {use_case}\nExposure tier: {exposure}\n"
            f"Subject profile: {profile['summary'] or 'no model-specific signals; assess as described'}\n"
            f"Declared controls already in place: {', '.join(declared) or 'none'}\n"
            f"Evidence snippets: {ev_blob[:1500] or 'none'}\n\n"
            f"Control catalogue:\n{cat_lines}\n\n"
            f"Threats:\n{threat_lines or '- T01..T12 (catalog AI metadata-writing threats)'}\n\n"
            'Return JSON: {"applicability": {"T01": 0.8, ...}, '
            '"extra_controls": ["C03", ...], "confidence": 0.0-1.0, '
            '"rationale": "one short sentence"}'
        )
        raw = _llm.chat([{"role": "system", "content": sys_p},
                         {"role": "user", "content": user_p}],
                        temperature=0.1, max_tokens=600).strip()
        m = re.search(r"\{.*\}", raw, re.S)
        if m:
            data = json.loads(m.group(0))
            llm_app = data.get("applicability") or {}
            for tid, val in llm_app.items():
                tid = str(tid).upper()
                if tid in sec._THREAT_IDS:
                    try:
                        applicability[tid] = max(0.0, min(1.0, float(val)))
                    except (TypeError, ValueError):
                        pass
            extra = [str(c).strip().upper() for c in (data.get("extra_controls") or [])
                     if str(c).strip().upper() in sec._CONTROL_BY_ID]
            # never recommend something already declared
            proposed_extra = [{"id": c, "name": sec._CONTROL_BY_ID[c]["name"]}
                              for c in dict.fromkeys(extra) if c not in declared]
            try:
                confidence = max(0.0, min(1.0, float(data.get("confidence", 0.6))))
            except (TypeError, ValueError):
                confidence = 0.6
            source = "control-analyst via LLM gateway"
    except Exception as exc:
        source = f"deterministic heuristic (LLM unavailable: {exc})"

    return reply_envelope(
        env, "control-analyst", "control_plan",
        {
            "declared_controls": declared,
            "applicability": applicability,
            "proposed_controls": proposed_extra,
            "confidence": confidence,
            "source": source,
        },
        note=(f"{len(declared)} declared control(s), "
              f"{len(proposed_extra)} proposed, confidence {confidence:.2f} ({source})"),
    )


# ----------------------------------------------- mitigation-advisor agent ---

def mitigation_advisor_handle(env: dict[str, Any]) -> dict[str, Any]:
    """Intent ``advise_portfolio_risks``: the deterministic advice pack.

    The mapping itself lives in :mod:`app.portfolio` and makes no model call,
    so this role is the one agent in the system that cannot hallucinate a
    control: the same stored register and situation always yield the same
    list. It opens its own session because the bus only passes ``db`` to the
    research-collector; everything it reads is a stored row, and everything
    it returns is the same pack the Portfolio tab shows, so the pipeline, a
    peer agent and the UI cannot disagree about what was advised.
    """
    from . import portfolio as _pf
    from .database import SessionLocal

    payload = env.get("payload", {}) or {}
    try:
        inv_id = int(payload.get("investigation_id"))
    except (TypeError, ValueError):
        raise ValueError("advise_portfolio_risks needs an investigation_id")
    db = SessionLocal()
    try:
        try:
            pack = _pf.advise(
                db, inv_id,
                initiative_id=payload.get("initiative_id"),
                controls_present=payload.get("controls_present"),
                max_burden=payload.get("max_burden"))
        except LookupError as exc:
            raise ValueError(str(exc))
    finally:
        db.close()
    return reply_envelope(
        env, "mitigation-advisor", "portfolio_advice",
        {
            "investigation_id": pack["investigation_id"],
            "initiative_id": pack["initiative_id"],
            "method": pack["method"],
            "version": pack["version"],
            "advice": pack["advice"],
            "playbooks": [{"id": p["id"], "title": p["name"]}
                          for p in pack["playbooks"]],
            "limitations": pack["limitations"],
            "catalogs": pack["catalogs"],
        },
        note=(f"{len(pack['advice'])} advice item(s), "
              f"{sum(1 for a in pack['advice'] if a['quick_win'])} quick win(s) "
              f"({pack['method']} v{pack['version']}, deterministic)"),
    )


# ------------------------------------------------- research-collector agent ---

_SEARCH_GROUPS: list[tuple[str, list[str]]] = [
    ("prompt_injection", ["prompt injection", "indirect prompt", "instruction hijack"]),
    ("jailbreak", ["jailbreak", "safety training bypass", "refusal bypass"]),
    ("data_extraction", ["training data extraction", "data leakage", "memorization", "membership inference"]),
    ("sensitive_disclosure", ["sensitive information disclosure", "PII leak", "privacy leak", "confidential leak"]),
    ("backdoor", ["backdoor", "sleeper agent", "deceptive alignment", "trojan"]),
    ("adversarial", ["adversarial", "red team", "benchmark", "WMDP", "dual-use"]),
    ("misclassification", ["misclassif", "mislabel", "label noise", "data quality"]),
    ("governance", ["governance", "DPIA", "audit", "provenance", "lineage"]),
]


def _derive_queries(product_name: str, use_case: str, threat_titles: list[str]) -> list[tuple[str, list[str]]]:
    queries = list(_SEARCH_GROUPS)
    blob = f"{product_name} {use_case} {' '.join(threat_titles)}".lower()
    extra = [kw for kw in ("metadata", "catalog", "assistant", "copilot", "RAG", "exfiltration", "DLP")
             if kw.lower() in blob]
    if extra:
        queries.append(("context", extra))
    return queries


def _score_artifact(artifact: Any, terms: list[str]) -> tuple[float, list[str]]:
    title = (artifact.title or "").lower()
    tags = (artifact.tags or "").lower()
    desc = (artifact.description or "").lower()
    content = (artifact.content or "")[:4000].lower()
    author = (artifact.author or "").lower()
    score = 0.0
    hits: list[str] = []
    for term in terms:
        t = term.lower()
        if t in title:
            score += 3.0
            hits.append(f"title:{term}")
        if t in tags:
            score += 2.0
            hits.append(f"tag:{term}")
        if t in desc:
            score += 1.0
            hits.append(f"desc:{term}")
        if t in content:
            score += 0.7
            hits.append(f"content:{term}")
        if t in author:
            score += 0.5
            hits.append(f"author:{term}")
    atype = (artifact.artifact_type or "").lower()
    if score > 0 and atype in ("paper", "research"):
        score += 2.0
        hits.append("type:paper/research boost")
    try:
        rel = float(artifact.relevance or 0)
    except (TypeError, ValueError):
        rel = 0.0
    if score > 0 and rel > 0:
        score += rel  # agent-curated relevance nudges ranking
        hits.append(f"agent-relevance:{rel:.2f}")
    return score, hits


def _audit_evidence(ranked: list[dict[str, Any]], artifacts: list[Any]) -> None:
    """Bind each evidence item to a content-addressed claim.

    This is where the pipeline's grounding guarantee is established: the snippet
    is checked verbatim against the artifact it was taken from, and the claim
    hash is attached to the item itself. Because the orchestrator forwards the
    same evidence list to threat-intel and report-writer, those hops inherit the
    refs and the whole assessment becomes traceable back to an artifact id.

    No-ops when no ledger run is open, so the collector is unchanged in tests
    and one-off calls.
    """
    if not ledger.current_run():
        return
    by_id = {a.id: a for a in artifacts if a is not None}
    for e in ranked:
        art = by_id.get(e.get("artifact_id"))
        source_text = ((art.description or art.content or "") if art else "")
        source_key = e.get("url") or f"artifact:{e.get('artifact_id')}"
        res = ledger.record_claim(
            e.get("title") or "",
            [{"source": source_key, "quote": e.get("snippet") or ""}],
            {source_key: source_text},
            actor="research-collector")
        if res:
            e["claim_hash"] = res["claim_hash"]
            e["grounded"] = not res["violation"]


def collector_subject_key(mode: str, name: str, family: str = "",
                          focus: tuple = ()) -> str:
    """Stable subject identity for the research cache: same subject asking
    the same question family must hit the same cache entry across runs and
    parallel manager jobs. Hash, not text, so keys stay fixed-width."""
    canon = json.dumps({"mode": mode or "", "name": name or "",
                        "family": family or "",
                        "focus": sorted(str(f) for f in (focus or []))},
                       sort_keys=True, separators=(",", ":"))
    return hashlib.sha1(canon.encode("utf-8")).hexdigest()[:16]


_COLLECTOR_CACHE: dict[tuple, dict] = {}
_COLLECTOR_CACHE_MAX = 64


def _collector_cache_lookup(investigation_id: Any, subject_key: str,
                            threat_titles: list, db: Any) -> dict | None:
    """A cached collection is only valid while the corpus is unchanged: the
    entry records artifact count + max id, and any drift means a miss, never
    a stale hit."""
    from .models import Artifact
    key = (investigation_id,
           subject_key or "",
           hashlib.sha1(json.dumps(sorted(str(t) for t in
                                           (threat_titles or [])),
                                   separators=(",", ":")).encode("utf-8")
                        ).hexdigest()[:16])
    entry = _COLLECTOR_CACHE.get(key)
    if not entry:
        return None
    try:
        current = db.query(Artifact).filter(
            Artifact.investigation_id == int(investigation_id)).all()
    except (TypeError, ValueError):
        return None
    ids = [a.id for a in current]
    if len(ids) != entry.get("artifact_count") or \
            (max(ids) if ids else 0) != entry.get("max_artifact_id", -1):
        _COLLECTOR_CACHE.pop(key, None)
        return None
    return {"evidence": entry["evidence"],
            "queries_run": entry["queries_run"],
            "scope": entry["scope"],
            "artifacts_scanned": 0, "cached": True}


def _collector_cache_store(investigation_id: Any, subject_key: str,
                           threat_titles: list, artifacts: list,
                           evidence: list, queries_run: list,
                           scope: str) -> None:
    key = (investigation_id,
           subject_key or "",
           hashlib.sha1(json.dumps(sorted(str(t) for t in
                                           (threat_titles or [])),
                                   separators=(",", ":")).encode("utf-8")
                        ).hexdigest()[:16])
    ids = [a.id for a in (artifacts or []) if getattr(a, "id", None)]
    _COLLECTOR_CACHE[key] = {
        "evidence": evidence, "queries_run": queries_run, "scope": scope,
        "artifact_count": len(ids),
        "max_artifact_id": max(ids) if ids else 0}
    while len(_COLLECTOR_CACHE) > _COLLECTOR_CACHE_MAX:
        _COLLECTOR_CACHE.pop(next(iter(_COLLECTOR_CACHE)))


def research_collector_handle(env: dict[str, Any], db: Any) -> dict[str, Any]:
    """Intent ``collect_research``: agentic multi-query search over local artifacts."""
    payload = env.get("payload", {})
    product_name = payload.get("product_name", "")
    use_case = payload.get("use_case", "")
    threat_titles = payload.get("threat_titles", [])
    investigation_id = payload.get("investigation_id")
    top_k = int(payload.get("top_k", 8))
    subject_key = payload.get("subject_key") or ""

    if db is None:
        return reply_envelope(env, "research-collector", "research_collected",
                              {"evidence": [], "queries_run": [], "scope": "none",
                               "note": "no DB session — skipped"},
                              note="skipped (no db)")

    from .models import Artifact

    queries = _derive_queries(product_name, use_case, threat_titles)
    scope = "all investigations"
    artifacts: list[Any] = []
    if investigation_id is not None:
        try:
            artifacts = db.query(Artifact).filter(
                Artifact.investigation_id == int(investigation_id)).all()
            scope = f"investigation #{investigation_id}"
        except (TypeError, ValueError):
            artifacts = []
    if not artifacts:
        # Fall back to the whole app graph so the section is never empty
        # when the current investigation has no matching artifacts yet.
        artifacts = db.query(Artifact).all()
        scope = "all investigations (current one had no matches)"

    if subject_key and investigation_id is not None:
        hit = _collector_cache_lookup(investigation_id, subject_key,
                                      threat_titles, db)
        if hit is not None:
            return reply_envelope(
                env, "research-collector", "research_collected", hit,
                note=(f"{len(hit['evidence'])} evidence items "
                      f"({hit['scope']}, cache hit)"))

    best: dict[int, dict[str, Any]] = {}
    queries_run: list[str] = []
    for label, terms in queries:
        queries_run.append(f"{label}: {', '.join(terms)}")
        for art in artifacts:
            score, hits = _score_artifact(art, terms)
            if score <= 0:
                continue
            prev = best.get(art.id)
            if prev is None or score > prev["score_raw"]:
                best[art.id] = {
                    "artifact_id": art.id,
                    "investigation_id": art.investigation_id,
                    "title": art.title,
                    "artifact_type": art.artifact_type,
                    "url": art.url,
                    "author": art.author,
                    "tags": art.tags,
                    "relevance": round(score, 2),
                    "score_raw": score,
                    "matched_on": sorted(set((prev.get("matched_on", []) if prev else []) + hits)),
                    "query_group": label if not prev else prev["query_group"] + f",{label}",
                    "snippet": ((art.description or art.content or "")[:280]),
                }
            else:
                prev["matched_on"] = sorted(set(prev["matched_on"] + hits))
                prev["query_group"] = prev["query_group"] + f",{label}"

    ranked = sorted(best.values(), key=lambda e: -e.pop("score_raw"))[: max(1, top_k)]
    for e in ranked:
        e["reason"] = f"Matched {e['query_group']} ({'; '.join(e['matched_on'][:4])})"
    _audit_evidence(ranked, artifacts)
    if subject_key and investigation_id is not None:
        _collector_cache_store(investigation_id, subject_key, threat_titles,
                               artifacts, ranked, queries_run, scope)
    return reply_envelope(
        env, "research-collector", "research_collected",
        {"evidence": ranked, "queries_run": queries_run,
         "scope": scope, "artifacts_scanned": len(artifacts),
         "cached": False},
        note=f"{len(ranked)} evidence items ({scope}, {len(artifacts)} scanned)",
    )


# ----------------------------------------------------- threat-intel agent ---

KNOWN_ATTACKS: list[dict[str, Any]] = [
    {
        "id": "KE-01", "title": "Indirect prompt injection (Greshake et al., 2024)",
        "attack_class": "Prompt injection via retrieved content",
        "threat_ids": ["T05", "T04"],
        "match": ["prompt injection", "indirect prompt", "instruction"],
        "description": (
            "Attackers plant instructions in retrievable content (docs, comments, asset "
            "names). When the AI assistant ingests that content as context, it follows "
            "the planted instruction — exfiltrating data or poisoning output. Directly "
            "applicable to a metadata assistant that drafts from catalog text."),
        "relevance": ("Asset descriptions, column comments and linked docs are untrusted "
                      "input to the writing assistant's prompt."),
        "mitigation": "Delimit/escape catalog content in prompts; instruction hierarchy; adversarial prompt tests.",
    },
    {
        "id": "KE-02", "title": "Training-data extraction (Carlini et al., 2021/2023)",
        "attack_class": "Memorization / extraction",
        "threat_ids": ["T02", "T01"],
        "match": ["extraction", "memorization", "training data", "leakage", "PII"],
        "description": (
            "LLMs memorize training samples (PII, secrets, verbatim text) that can be "
            "extracted with crafted prompts. Prompts retained for training/abuse "
            "monitoring re-enter the corpus and may resurface to other tenants."),
        "relevance": "Pasted restricted/confidential metadata retained by a vendor endpoint can leak cross-tenant.",
        "mitigation": "Zero-retention / no-train contracts; schema-only prompts; DLP redaction pre-prompt.",
    },
    {
        "id": "KE-03", "title": "Jailbreaks & refusal bypass (many-shot / persona attacks)",
        "attack_class": "Safety-guardrail bypass",
        "threat_ids": ["T06", "T05"],
        "match": ["jailbreak", "refusal", "safety training", "bypass"],
        "description": (
            "Iterative or many-shot prompting defeats model refusals, coaxing out "
            "restricted content. A malicious insider can iteratively rephrase requests "
            "to launder data they can preview into shareable catalog text."),
        "relevance": "Insider exfiltration path (T06): 'summarise this restricted table in plain words…' loops.",
        "mitigation": "Rate-limit + anomaly detection; immutable prompt audit log; dual-control publish.",
    },
    {
        "id": "KE-04", "title": "Sleeper agents / deceptive alignment (Hubinger et al., 2024)",
        "attack_class": "Backdoor persistence through safety training",
        "threat_ids": ["T09", "T07"],
        "match": ["sleeper", "backdoor", "deceptive alignment", "trojan"],
        "description": (
            "Models trained with hidden triggers behave safely until the trigger "
            "appears, surviving safety training. Third-party or fine-tuned models in "
            "the supply chain may carry such triggers."),
        "relevance": "Vendor-supplied model behind the assistant is trusted code — compromise poisons all drafts.",
        "mitigation": "Pin model snapshots; require vendor eval evidence; monitor draft anomalies.",
    },
    {
        "id": "KE-05", "title": "WMDP dual-use capability benchmark (Li et al., 2024)",
        "attack_class": "Dangerous-capability measurement",
        "threat_ids": ["T12", "T09"],
        "match": ["WMDP", "dual-use", "benchmark", "biosecurity"],
        "description": (
            "Frontier models show concerning WMD-relevant knowledge on WMDP. Assistants "
            "operating over technical catalogs can surface or systematize dual-use "
            "know-how present in metadata."),
        "relevance": "Catalogs in life-sciences/defence domains need domain-aware output review.",
        "mitigation": "Domain block-lists in prompts; expert review queue for flagged domains.",
    },
    {
        "id": "KE-06", "title": "System-prompt & RAG-context leakage",
        "attack_class": "Context disclosure",
        "threat_ids": ["T04", "T05"],
        "match": ["prompt leak", "system prompt", "context", "schema"],
        "description": (
            "'Repeat the instructions above' style probes extract system prompts and "
            "retrieved context. Over-helpful descriptions likewise disclose schema "
            "semantics (thresholds, rules) to catalog readers lacking source access."),
        "relevance": "AI-drafted descriptions can leak confidential process logic into widely-readable catalog text.",
        "mitigation": "Forbid emitting example values/thresholds; align catalog ACLs with source ACLs.",
    },
    {
        "id": "KE-07", "title": "RAG / catalog poisoning",
        "attack_class": "Knowledge-base poisoning",
        "threat_ids": ["T03", "T09"],
        "match": ["poison", "misclassif", "mislabel", "label noise"],
        "description": (
            "Poisoned or mislabelled documents in the retrieval corpus propagate into "
            "generated output. Misclassified files are the catalog analogue: the "
            "assistant launders the wrong label into published descriptions."),
        "relevance": "Bulk imports with default/stale labels silently widen sharing via AI-drafted text.",
        "mitigation": "Classification gate before first suggestion; re-classification scans; quarantine on disagreement.",
    },
    {
        "id": "KE-08", "title": "Paraphrase / DLP-bypass exfiltration",
        "attack_class": "Egress-filter evasion",
        "threat_ids": ["T01", "T06"],
        "match": ["DLP", "exfiltration", "bypass", "paraphrase", "PII"],
        "description": (
            "Naive DLP fails when sensitive content is paraphrased or split across "
            "turns. Employees pasting samples and insiders drip-feeding context both "
            "evade regex-only egress filters."),
        "relevance": "Client-side regex DLP alone is insufficient for assistant prompts.",
        "mitigation": "NER + secret-detection + per-user usage anomaly detection; scrubbed prompt logs.",
    },
]


def threat_intel_handle(env: dict[str, Any]) -> dict[str, Any]:
    """Intent ``map_attacks``: join catalogue with collector evidence, cite sources,
    and return per-threat applicability + evidence confidence."""
    payload = env.get("payload", {})
    evidence: list[dict[str, Any]] = payload.get("evidence", [])
    threat_ids: list[str] = payload.get("threat_ids", [])
    declared_controls: list[str] = payload.get("declared_controls", []) or []
    base_applicability: dict[str, float] = payload.get("applicability", {}) or {}

    def ev_matches(entry: dict[str, Any]) -> list[dict[str, Any]]:
        out = []
        kws = [k.lower() for k in entry.get("match", [])]
        for ev in evidence:
            hay = f"{ev.get('title','')} {ev.get('tags','')} {ev.get('snippet','')}".lower()
            if any(k in hay for k in kws):
                out.append(ev)
        return out[:3]

    known_exploits = []
    for entry in KNOWN_ATTACKS:
        if threat_ids and not any(t in threat_ids for t in entry["threat_ids"]):
            continue
        refs = ev_matches(entry)
        known_exploits.append({
            "id": entry["id"],
            "title": entry["title"],
            "attack_class": entry["attack_class"],
            "threat_ids": entry["threat_ids"],
            "description": entry["description"],
            "relevance": entry["relevance"],
            "mitigation": entry["mitigation"],
            "local_refs": [
                {"artifact_id": r["artifact_id"], "title": r["title"],
                 "artifact_type": r.get("artifact_type"), "url": r.get("url")}
                for r in refs
            ],
        })

    # ---- per-threat evidence confidence: attacks mapped, corroborating artifacts,
    # ---- and whether the declared controls cover it all move this number.
    evidence_confidence: dict[str, float] = {}
    for tid in threat_ids:
        mapped = [k for k in known_exploits if tid in k["threat_ids"]]
        corroborating = sum(len(k.get("local_refs", [])) for k in mapped)
        conf = 0.2 + min(0.5, 0.18 * len(mapped)) + min(0.3, 0.1 * corroborating)
        evidence_confidence[tid] = round(min(1.0, conf), 2)

    # Applicability the control-analyst proposed, kept explicit so the trace shows
    # where each number came from (LLM proposal, then this join).
    applicability: dict[str, float] = {}
    for tid in threat_ids:
        try:
            applicability[tid] = max(0.0, min(1.0, float(base_applicability.get(tid, 0.7))))
        except (TypeError, ValueError):
            applicability[tid] = 0.7

    # Deterministic evidence re-judge: the analyst judged before any evidence
    # existed. Evidence (and focus) can only confirm relevance -- lift toward
    # 1.0, never acquit below what was proposed -- so the floor philosophy
    # stays intact while real signals differentiate the threats. The re-judge
    # uses the same model profile: a profile-excluded chat threat stays
    # excluded (domain chatter in evidence must not re-animate what the
    # charter rules out), while every other threat lifts normally.
    from . import security as _sec
    _profile = _sec.profile_model_subject(payload.get("product_name", ""),
                                          payload.get("use_case", ""),
                                          payload.get("focus") or [])
    rej = heuristic_applicability(payload.get("product_name", ""),
                                  payload.get("use_case", ""),
                                  evidence, payload.get("focus") or [],
                                  model_profile=_profile)
    for tid in threat_ids:
        if tid in rej:
            try:
                applicability[tid] = max(float(applicability.get(tid, 0.0)),
                                         rej[tid])
            except (TypeError, ValueError):
                pass

    return reply_envelope(
        env, "threat-intel", "attacks_mapped",
        {"known_exploits": known_exploits, "catalogue_size": len(KNOWN_ATTACKS),
         "applicability": applicability,
         "evidence_confidence": evidence_confidence,
         "declared_controls": declared_controls},
        note=(f"{len(known_exploits)} known attacks mapped, applicability for "
              f"{len(applicability)} threats, mean evidence confidence "
              f"{(sum(evidence_confidence.values())/len(evidence_confidence) if evidence_confidence else 0):.2f}"),
    )


# ---------------------------------------------------- report-writer agent ---

def _llm_exec_paragraph(product: str, exposure_label: str, residual: float,
                        inherent: float, exploits: list[dict],
                        evidence: list[dict], controls: list[str]) -> tuple:
    """LLM-drafted executive paragraph, plus the grounding check on it.

    Returns ``(text, grounding)``. The paragraph is free prose, so there are no
    quotes to verify -- the only externally checkable thing in it is the
    ``#id`` evidence references it was told to cite. A drafted paragraph that
    cites nothing real is treated as unbacked (``violation``) and the caller
    falls back to deterministic text rather than shipping a confident-sounding
    paragraph resting on evidence that does not exist.

    Raises on any failure, same as before; the caller already has a
    deterministic paragraph for that case.
    """
    from . import llm as _llm

    ev_txt = "\n".join(f"- #{e['artifact_id']} {e['title']} (rel {e.get('relevance')})"
                       for e in sorted(evidence, key=lambda e: -e.get("relevance", 0))[:6]) or "- none"
    ke_txt = "\n".join(f"- {k['id']} {k['title']} → {', '.join(k['threat_ids'])}"
                       for k in exploits[:6]) or "- none"
    ctl_txt = ", ".join(controls) or "none declared"
    sys = ("You are an AI security engineer writing one executive-summary paragraph. "
           "Be concrete and cite the evidence by artifact #id. Reply with the paragraph only.")
    user = (f"Product: {product}\nExposure tier: {exposure_label}\n"
            f"Inherent risk: {inherent:g}/100\nResidual risk after controls: {residual:g}/100\n"
            f"Controls in place: {ctl_txt}\n"
            f"Known attacks mapped:\n{ke_txt}\nIn-app evidence:\n{ev_txt}\n\n"
            "Write 3-4 sentences: verdict, how the controls change the risk, "
            "sharpest attack path, what the in-app evidence confirms.")
    text = _llm.chat([{"role": "system", "content": sys},
                      {"role": "user", "content": user}],
                     temperature=0.2, max_tokens=512).strip()
    # A model told it may cite "#id" will sometimes invent one, and a citation
    # that resolves to nothing is indistinguishable from real support to a
    # reader. Check every id against the evidence actually supplied.
    check = grounding.verify_citation_ids(
        text, [e.get("artifact_id") for e in evidence or []])
    check["method"] = "citation_id_check"
    return text, check


def report_writer_handle(env: dict[str, Any]) -> dict[str, Any]:
    """Intent ``write_section``: exploits section + exec bullets (+LLM paragraph)."""
    payload = env.get("payload", {})
    known_exploits: list[dict[str, Any]] = payload.get("known_exploits", [])
    evidence: list[dict[str, Any]] = payload.get("evidence", [])
    product = payload.get("product_name", "the product")
    exposure_label = payload.get("exposure_label", "")
    control_plan = payload.get("control_plan", {}) or {}
    declared_controls = control_plan.get("declared_controls", []) or []

    lines: list[str] = []
    A = lines.append
    A("## 6. Known exploits & research evidence")
    A("")
    A("_Produced by the `threat-intel` + `report-writer` sub-agents via the agent-to-agent "
      "protocol: `research-collector` searched this app's knowledge graph for related papers, "
      "and each known attack below is mapped to the threat IDs in §5._")
    A("")
    if not known_exploits:
        A("- No catalogue entries matched this assessment's threat set.")
    for ke in known_exploits:
        A(f"### {ke['id']} — {ke['title']}")
        A("")
        A(f"- **Attack class:** {ke['attack_class']}")
        A(f"- **Maps to threats:** {', '.join(ke['threat_ids'])}")
        A(f"- **How it works:** {ke['description']}")
        A(f"- **Why it matters for this workflow:** {ke['relevance']}")
        A(f"- **Mitigation pointer:** {ke['mitigation']}")
        if ke.get("local_refs"):
            A("- **Related in-app research:**")
            for r in ke["local_refs"]:
                A(f"  - {r['title']} (artifact #{r['artifact_id']})")
        else:
            A("- **Related in-app research:** none found — consider running the collector agent on this topic.")
        A("")

    bullets: list[str] = []
    for ke in known_exploits[:5]:
        n_refs = len(ke.get("local_refs", []))
        src = f"cited by {n_refs} in-app artifact(s)" if n_refs else "no in-app source yet — collection advised"
        bullets.append(f"{ke['id']} {ke['title']} → {', '.join(ke['threat_ids'])} ({src}).")
    if evidence:
        top = sorted(evidence, key=lambda e: -e.get("relevance", 0))[:5]
        ev_lines = [f"#{e['artifact_id']} {e['title']} (relevance {e.get('relevance')})" for e in top]
    else:
        ev_lines = ["No related in-app artifacts found — run the collector agent on this topic."]

    paragraph = ""
    llm_note = "deterministic fallback"
    gcheck: dict = {}
    draft_accepted = False
    try:
        residual = float(payload.get("residual_pct", payload.get("overall_pct", 0)))
        inherent = float(payload.get("inherent_pct", payload.get("overall_pct", 0)))
    except (TypeError, ValueError):
        residual = inherent = 0.0
    try:
        paragraph, gcheck = _llm_exec_paragraph(
            product, exposure_label, residual, inherent,
            known_exploits, evidence, declared_controls)
        # An invented "#id" is a hallucinated citation: it looks exactly like
        # real support to a reader but points at nothing. Rather than ship it
        # or try to edit it out of prose, drop the whole paragraph and let the
        # deterministic one below carry the claim.
        if gcheck.get("invented"):
            llm_note = (f"rejected: drafted paragraph cited non-existent "
                        f"artifact id(s) {gcheck['invented']}")
            paragraph = ""
        elif gcheck.get("violation"):
            llm_note = ("rejected: drafted paragraph cited no evidence it was "
                        "given")
            paragraph = ""
        else:
            draft_accepted = True
            llm_note = "drafted by report-writer via LLM gateway"
    except Exception as exc:
        paragraph = ""
        llm_note = f"LLM unavailable ({exc}); deterministic fallback"
    if not (paragraph or "").strip():
        # Empty LLM reply (or no gateway): grounded deterministic paragraph.
        top_ke = ", ".join(k["id"] for k in known_exploits[:3]) or "none"
        n_ref = sum(1 for k in known_exploits if k.get("local_refs"))
        top_ev = "; ".join(
            f"#{e['artifact_id']} {e['title'][:60]}"
            for e in sorted(evidence, key=lambda e: -e.get("relevance", 0))[:2]
        ) or "no in-app artifacts matched"
        ctl = (f"with {len(declared_controls)} control(s) in place "
               f"({', '.join(declared_controls[:4])})"
               if declared_controls else "with no controls declared yet")
        paragraph = (
            f"Residual risk is {residual:g}/100 for {product} under the {exposure_label} tier, "
            f"down from an inherent {inherent:g}/100 {ctl}. "
            f"The sharpest paths are accidental sensitive-data paste (T01) and prompt "
            f"injection via catalog content (T05), with {len(known_exploits)} known attacks "
            f"mapped ({top_ke}), {n_ref} of them corroborated by in-app evidence: {top_ev}. "
            f"Close the remaining gap with the §5 mitigations before enablement."
        )
        if llm_note == "deterministic fallback":
            llm_note = "deterministic grounded paragraph (LLM empty/unavailable)"

    # Audit the paragraph that actually ships, not the draft that was thrown
    # away: a reviewer asking "is this text backed?" means the text in front of
    # them. The deterministic paragraph names artifacts from the same evidence
    # list, so it passes the same check -- and if it ever does not, that is a
    # real signal rather than a formatting artefact.
    shipped = grounding.verify_citation_ids(
        paragraph or "", [e.get("artifact_id") for e in evidence or []])
    shipped["method"] = "citation_id_check"
    _audit_exec_paragraph(paragraph, shipped)

    return reply_envelope(
        env, "report-writer", "section_written",
        {"exploits_markdown": "\n".join(lines),
         "exec_evidence_lines": bullets,
         "exec_evidence_refs": ev_lines,
         "exec_paragraph": paragraph,
         "exec_paragraph_grounding": {
             "method": shipped["method"],
             "verdict": shipped["verdict"],
             "cited": shipped["cited"],
             "invented": shipped["invented"],
             "draft_accepted": draft_accepted,
             # The draft's own verdict, kept because a rejection is the most
             # interesting thing a reviewer can be told: it is the difference
             # between "the model agreed with us" and "the model invented #99
             # and we caught it".
             "draft": {"verdict": gcheck.get("verdict", "unverified"),
                       "cited": gcheck.get("cited", []),
                       "invented": gcheck.get("invented", [])},
             "note": llm_note},
         "residual_pct": residual,
         "inherent_pct": inherent},
        note=f"section with {len(known_exploits)} exploits drafted ({llm_note})",
    )


def _audit_exec_paragraph(paragraph: str, gcheck: dict) -> None:
    """Record the drafted executive paragraph and its grounding on the ledger.

    The claim is content-addressed like any other, so contamination tracing and
    ``/claims?ungrounded_only`` see it too. A citation-id check yields a
    ``n_sources`` equal to the number of artifacts actually referenced, which
    the corroboration ladder then reads normally.

    No-ops without an open run, and never raises: this is bookkeeping, and the
    caller must not fail over it.
    """
    try:
        from . import ledger as _ledger
        kept = gcheck.get("kept") or []
        if kept:
            verdict = {"kept": [{"source": f"artifact:{i}"} for i in kept],
                       "dropped": [{"source": f"artifact:{i}", "quote": "",
                                    "reason": "id_not_in_evidence"}
                                   for i in (gcheck.get("invented") or [])],
                       "n_sources": len(kept),
                       "confidence": grounding.confidence_for(len(kept)),
                       "verdict": "supported", "violation": False,
                       "claim": (paragraph or "")[:200]}
        else:
            # Nothing the paragraph leans on survived, so this is an
            # ungrounded claim and the gate should see it as one.
            verdict = {"kept": [], "dropped": [], "n_sources": 0,
                       "confidence": "none", "verdict": "unverified",
                       "violation": True, "claim": (paragraph or "")[:200]}
        _ledger.record_claim(paragraph or "", [], {}, actor="report-writer",
                             grounding=verdict)
    except Exception:  # noqa: BLE001 - auditing must not break the report
        return


# ------------------------------------------------------------ orchestrator ---

_HANDLERS = {
    "control-analyst": {"analyse_controls": control_analyst_handle},
    "research-collector": {"collect_research": research_collector_handle},
    "threat-intel": {"map_attacks": threat_intel_handle},
    "report-writer": {"write_section": report_writer_handle},
    "mitigation-advisor": {"advise_portfolio_risks": mitigation_advisor_handle},
}


# ----------------------------------------------------------- audit ledger --

def default_mandate() -> Any:
    """Policy derived from the agent cards and the handler table: who exists and
    which intents they are actually wired for.

    Deriving it rather than hand-writing it means the boundary cannot drift away
    from the code -- an envelope addressed to a recipient or intent that is not
    registered is denied on the record, instead of quietly doing nothing.
    """
    intents: list[str] = []
    for handlers in _HANDLERS.values():
        for intent in handlers:
            if intent not in intents:
                intents.append(intent)
    return ledger.Mandate(
        objective="A2A security assessment",
        allowed_actors=[c["name"] for c in AGENT_CARDS],
        allowed_intents=intents,
        planned_intents=intents,
        max_events=500,
        max_llm_calls=60,
        loop_threshold=6,
    )


def _audit_run_id(env: dict[str, Any]) -> str:
    """One ledger run per A2A task, keyed by the protocol's own task id, so the
    audit trail and the protocol trace share a correlation key."""
    return env.get("task_id") or f"a2a-{uuid.uuid4().hex[:12]}"


def _payload_claim_refs(payload: Any) -> list[str]:
    """Collect the claim hashes a request is built on.

    Evidence carries its own ``claim_hash`` from the collector, and the
    orchestrator forwards that same list to threat-intel and report-writer, so
    walking the payload recovers the real lineage without the orchestrator
    having to know the ledger exists.
    """
    refs: list[str] = []

    def walk(node: Any, depth: int = 0) -> None:
        if depth > 6:
            return
        if isinstance(node, dict):
            h = node.get("claim_hash")
            if isinstance(h, str) and len(h) == 64 and h not in refs:
                refs.append(h)
            for v in node.values():
                walk(v, depth + 1)
        elif isinstance(node, (list, tuple)):
            for v in node:
                walk(v, depth + 1)

    walk(payload)
    return refs


def _audit_hop(ctx: Any, env: dict[str, Any], result: dict[str, Any],
               latency_ms: int) -> None:
    try:
        if ctx is not None:
            ctx.hop(env.get("from", "?"), env.get("to", "?"), env.get("intent", "?"),
                    env.get("payload") or {}, result.get("payload") or {},
                    task_id=env.get("task_id"), protocol=env.get("protocol", PROTOCOL),
                    latency_ms=latency_ms,
                    input_refs=_payload_claim_refs(env.get("payload") or {}))
    except Exception as exc:  # noqa: BLE001 - auditing must not break the bus
        obs.log("a2a.hop_audit_dropped", level="error",
                error=f"{type(exc).__name__}: {exc}")


def dispatch(env: dict[str, Any], db: Any = None) -> dict[str, Any]:
    """Route one A2A envelope to the target agent's handler (the protocol bus).

    Also the audit checkpoint for agent traffic: every hop lands on the task's
    ledger chain, and the run is made current for the duration of the handler so
    the model calls inside it are recorded against the same chain.

    Adopts a trace for the duration of the hop. A local dispatch inherits the
    caller's, so a click's trace reaches the model calls its agents make; an
    envelope arriving from a peer carries its own ``trace_id``, because a
    contextvar does not cross a process boundary and adopting the sender's id is
    the only way both sides' events end up under one trace.

    Note ``trace_id``, not ``trace``: on an envelope ``trace`` is the hop log.
    Reading it as an id bound a list where a string belonged, and the next
    ledger write died on it.
    """
    if env.get("protocol") != PROTOCOL:
        raise ValueError(f"unsupported protocol: {env.get('protocol')}")
    agent_handlers = _HANDLERS.get(env.get("to", ""), {})
    handler = agent_handlers.get(env.get("intent", ""))
    if handler is None:
        raise ValueError(f"no handler for {env.get('to')}.{env.get('intent')}")

    run_id = _audit_run_id(env)
    try:
        scope = ledger.scope(run_id, default_mandate(),
                             label=f"A2A {env.get('intent')} task {run_id}")
    except Exception as exc:                       # pragma: no cover - ledger down
        # Auditing must never be the reason a security review cannot run. If the
        # ledger is unavailable, drop this hop rather than the whole assessment;
        # the chain will show a gap, which is itself the signal.
        obs.log("a2a.scope_unavailable", level="error", run_id=run_id,
                error=f"{type(exc).__name__}: {exc}")
        scope = contextlib.nullcontext(None)
    hop_trace = (env.get("trace_id") or obs.current_trace()
                 or obs.new_trace(env.get("task_id")))
    with obs.trace_scope(hop_trace), scope as ctx:
        t0 = time.time()
        result = handler(env, db) if env["to"] == "research-collector" else handler(env)
        _audit_hop(ctx, env, result, int((time.time() - t0) * 1000))
    return result


def _hop_io(trace: list[dict[str, Any]], agent: str, intent: str,
            inputs: str, outputs: str) -> None:
    """Attach an input/output summary to an agent's last trace entry."""
    for entry in reversed(trace):
        if entry.get("agent") == agent and entry.get("intent") == intent:
            entry["inputs"] = inputs
            entry["outputs"] = outputs
            return


# --------------------------------------- model assessment A2A path ---------
# A separate workflow for when the subject is a MODEL, not a conversational
# product. Same envelope bus, different agents and different arithmetic: the
# standard path scores catalog threats written around an AI writing
# assistant; this one scores the model's own dimensions (training-data
# privacy, model integrity, deployment surface, governance) with the
# weighting in security.MODEL_DIMENSIONS. No AI-standards mapping happens
# anywhere on this path -- frameworks describe product controls, and a
# weights-and-data question is answered from the model, not the catalogue.


def model_profiler_handle(env: dict[str, Any]) -> dict[str, Any]:
    """Intent ``profile_model``: deterministic subject profile.

    Pure function of product/use_case/focus -- no model call, so it cannot
    fail, hallucinate, or stall. Everything downstream reads this profile
    instead of re-guessing what kind of thing is being assessed.
    """
    from . import security as sec
    payload = env.get("payload", {})
    profile = sec.profile_model_subject(payload.get("product_name", ""),
                                        payload.get("use_case", ""),
                                        payload.get("focus") or [])
    return reply_envelope(
        env, "model-profiler", "model_profiled", {"profile": profile},
        note=(f"subject_kind={'model' if profile['is_model_query'] else 'other'}; "
              f"{profile['summary'] or 'no model signals'}"),
    )


def _model_finding(fid: str, title: str, dimension: str, likelihood: int,
                   impact: int, rationale: str,
                   mitigations: list[str]) -> dict[str, Any]:
    from .security import _severity
    likelihood = max(1, min(5, int(likelihood)))
    impact = max(1, min(5, int(impact)))
    inherent = likelihood * impact
    return {"id": fid, "title": title, "dimension": dimension,
            "likelihood": float(likelihood), "impact": float(impact),
            "inherent_score": float(inherent),
            "residual_score": float(inherent),
            "residual_severity": _severity(inherent),
            "coverage": 0.0, "controls": [], "applicable": True,
            "applicability": 1.0, "rationale": rationale,
            "mitigations": list(mitigations)}


def _model_fallback_findings(profile: dict[str, Any]) -> tuple[list[dict], list[str]]:
    """Deterministic internals findings from the profile alone.

    Every finding states only what the profile evidences; severities are fixed
    per rule and documented here, not tuned per subject. Anything subtler
    waits for the LLM branch (or a human).
    """
    findings: list[dict[str, Any]] = []
    excluded: list[str] = []
    data = " ".join(profile.get("data", []))
    if profile.get("personal_data"):
        findings.append(_model_finding(
            "M01", "Training-data memorization and extraction", "training_data_privacy",
            4, 5, "trains on personal data: memorized rows are extractable outputs",
            ["Minimize training rows to task-relevant columns",
             "Deduplicate training data",
             "Canary + extraction testing before release"]))
    elif profile.get("trains_on_data"):
        findings.append(_model_finding(
            "M01", "Training-set membership inference", "training_data_privacy",
            3, 4, "trains on data: membership is inferable from outputs",
            ["Membership-inference testing", "Output rounding / top-k limiting"]))
    if "tabular" in data:
        findings.append(_model_finding(
            "M02", "Schema and distribution inference from outputs",
            "training_data_privacy", 3, 3,
            "tabular outputs reveal column semantics and distributions",
            ["Return predictions without confidence where unused",
             "Rate-limit high-volume scoring"]))
    if profile.get("model_class") in ("foundation", "large generative",
                                      "pretrained", "pretrained encoder",
                                      "pretrained encoder-decoder"):
        findings.append(_model_finding(
            "M03", "Weights provenance and supply chain", "model_integrity",
            3, 4, "pretrained weights inherit upstream data and backdoor risk",
            ["Pin weights by hash", "Provenance record per checkpoint"]))
    if profile.get("model_class") == "fine-tuned":
        findings.append(_model_finding(
            "M03", "Poisoned fine-tuning data", "model_integrity",
            3, 4, "fine-tuning inherits the tuning set's integrity",
            ["Curate and version tuning data", "Pre/post eval diff"]))
    if profile.get("interface") == "non_conversational":
        excluded.append("prompt injection via conversational UI (no chat surface)")
    if not findings:
        findings.append(_model_finding(
            "M00", "Model internals review inconclusive from brief alone",
            "governance", 2, 3,
            "profile carries no architecture/data signals; nothing asserted",
            ["Supply architecture and data-flow documentation, then re-run"]))
    return findings, excluded


def model_internals_handle(env: dict[str, Any]) -> dict[str, Any]:
    """Intent ``review_internals``: architecture, training and inference review.

    LLM proposes per-dimension findings; the deterministic fallback below
    still returns a usable, profile-honest review when the model is down.
    """
    from . import security as sec
    payload = env.get("payload", {})
    product = payload.get("product_name", "the model")
    use_case = payload.get("use_case", "")
    focus = payload.get("focus") or []
    profile = payload.get("profile") or sec.profile_model_subject(
        product, use_case, focus)
    findings, excluded = _model_fallback_findings(profile)
    source = "deterministic profile rules (no LLM)"
    try:
        from . import llm as _llm
        sys_p = (
            "You are a machine-learning security reviewer. Review the MODEL "
            "below -- its architecture, training, weights and inference "
            "surface -- not a chatbot product. "
            f"Profile: {profile['summary'] or 'unclassified model'}. "
            "Reply with STRICT JSON only: {\"findings\": [{\"id\": \"M##\", "
            "\"title\": str, \"dimension\": one of training_data_privacy | "
            "model_integrity | deployment_surface | governance, "
            "\"likelihood\": 1-5, \"impact\": 1-5, "
            "\"rationale\": str (one sentence, grounded in the profile), "
            "\"mitigations\": [str]}], "
            "\"excluded\": [str] (threat classes with no surface here, e.g. "
            "conversational prompt injection when there is no chat UI)}."
        )
        user_p = (f"Model: {product}\nUse: {use_case}\n"
                  f"Profile: {profile['summary'] or 'unclassified'}\n"
                  f"Data: {', '.join(profile['data']) or 'unknown'}\n"
                  f"Interface: {profile['interface']}\n"
                  f"Focus: {', '.join(focus) or 'none stated'}")
        raw = _llm.chat([{"role": "system", "content": sys_p},
                         {"role": "user", "content": user_p}],
                        temperature=0.1, max_tokens=1200).strip()
        m = re.search(r"\{.*\}", raw, re.S)
        if not m:
            raise ValueError("model did not return a findings object")
        data = json.loads(m.group(0))
        llm_findings = []
        for i, f in enumerate(data.get("findings") or [], 1):
            if not isinstance(f, dict) or not f.get("title"):
                continue
            dim = str(f.get("dimension") or "governance")
            if dim not in ("training_data_privacy", "model_integrity",
                           "deployment_surface", "governance"):
                dim = "governance"
            llm_findings.append(_model_finding(
                str(f.get("id") or f"M{i:02d}"), str(f["title"])[:140], dim,
                f.get("likelihood", 3), f.get("impact", 3),
                str(f.get("rationale") or "LLM-proposed finding")[:300],
                [str(x)[:160] for x in (f.get("mitigations") or [])][:4]))
        if llm_findings:
            findings = llm_findings
            excluded = [str(x)[:160] for x in (data.get("excluded") or [])][:6]
            source = "model-internals via LLM gateway"
    except Exception as exc:
        source = f"deterministic profile rules (LLM unavailable: {exc})"
    return reply_envelope(
        env, "model-internals", "internals_reviewed",
        {"findings": findings, "excluded": excluded, "profile": profile,
         "source": source},
        note=(f"{len(findings)} internals findings, "
              f"{len(excluded)} ruled out ({source})"),
    )


def model_privacy_handle(env: dict[str, Any]) -> dict[str, Any]:
    """Intent ``assess_model_privacy``: data minimization, retention, PII.

    Privacy gets its own hop because for models the privacy question is about
    the DATA LIFECYCLE (collect -> train -> serve -> log -> delete), not about
    a UI surface. Same shape as internals: LLM first, profile rules on failure.
    """
    from . import security as sec
    payload = env.get("payload", {})
    product = payload.get("product_name", "the model")
    use_case = payload.get("use_case", "")
    focus = payload.get("focus") or []
    profile = payload.get("profile") or sec.profile_model_subject(
        product, use_case, focus)
    findings: list[dict[str, Any]] = []
    if profile.get("personal_data"):
        findings.append(_model_finding(
            "P01", "Personal data in training/serving data", "training_data_privacy",
            4, 5, "personal data present: minimization and purpose limits apply",
            ["Document lawful basis per data source",
             "Minimize retained columns", "Deletion path for served data"]))
        findings.append(_model_finding(
            "P02", "Inference-time logging of personal data", "deployment_surface",
            3, 4, "served prompts/outputs may be logged with personal data",
            ["Log shapes, not values", "Short retention with deletion"]))
    else:
        findings.append(_model_finding(
            "P01", "Training-data minimization unverified", "governance",
            2, 3, "no personal-data signals; minimization posture unstated",
            ["Record what the model trains on, even when benign"]))
    if "tabular records" in profile.get("data", []) or "data rows" in profile.get("data", []):
        findings.append(_model_finding(
            "P03", "Row-level re-identification via outputs", "training_data_privacy",
            3, 4, "tabular outputs can single out rows",
            ["k-anonymity checks on served slices", "Suppress rare-combination outputs"]))
    source = "deterministic profile rules (no LLM)"
    try:
        from . import llm as _llm
        sys_p = (
            "You are a privacy reviewer for MACHINE-LEARNING models, not apps. "
            "Judge data minimization, retention, and personal-data handling across "
            "collect -> train -> serve -> log -> delete. "
            f"Profile: {profile['summary'] or 'unclassified model'}. "
            "Reply with STRICT JSON only: {\"findings\": [{\"id\": \"P##\", "
            "\"title\": str, \"dimension\": one of training_data_privacy | "
            "deployment_surface | governance, \"likelihood\": 1-5, \"impact\": 1-5, "
            "\"rationale\": str, \"mitigations\": [str]}]}."
        )
        user_p = (f"Model: {product}\nUse: {use_case}\n"
                  f"Profile: {profile['summary'] or 'unclassified'}\n"
                  f"Data: {', '.join(profile['data']) or 'unknown'}\n"
                  f"Personal data: {profile['personal_data']}\n"
                  f"Focus: {', '.join(focus) or 'none stated'}")
        raw = _llm.chat([{"role": "system", "content": sys_p},
                         {"role": "user", "content": user_p}],
                        temperature=0.1, max_tokens=1000).strip()
        m = re.search(r"\{.*\}", raw, re.S)
        if not m:
            raise ValueError("model did not return a findings object")
        data = json.loads(m.group(0))
        llm_findings = []
        for i, f in enumerate(data.get("findings") or [], 1):
            if not isinstance(f, dict) or not f.get("title"):
                continue
            dim = str(f.get("dimension") or "governance")
            if dim not in ("training_data_privacy", "deployment_surface",
                           "governance", "model_integrity"):
                dim = "governance"
            llm_findings.append(_model_finding(
                str(f.get("id") or f"P{i:02d}"), str(f["title"])[:140], dim,
                f.get("likelihood", 3), f.get("impact", 3),
                str(f.get("rationale") or "LLM-proposed finding")[:300],
                [str(x)[:160] for x in (f.get("mitigations") or [])][:4]))
        if llm_findings:
            findings = llm_findings
            source = "model-privacy via LLM gateway"
    except Exception as exc:
        source = f"deterministic profile rules (LLM unavailable: {exc})"
    return reply_envelope(
        env, "model-privacy", "model_privacy_assessed",
        {"findings": findings, "source": source},
        note=f"{len(findings)} privacy findings ({source})",
    )


def model_reporter_handle(env: dict[str, Any], db: Any = None) -> dict[str, Any]:
    """Intent ``write_model_report``: model sections markdown + exec paragraph.

    The exec paragraph follows the same grounding discipline as the standard
    writer: every #id it cites must resolve to supplied evidence, else the
    deterministic fallback ships instead of confident fiction.
    """
    payload = env.get("payload", {})
    product = payload.get("product_name", "the model")
    exposure_label = payload.get("exposure_label", "")
    profile = payload.get("profile", {}) or {}
    dimensions = payload.get("dimensions", []) or []
    findings = payload.get("findings", []) or []
    evidence = payload.get("evidence", []) or []
    scoring = payload.get("scoring", {}) or {}
    lines: list[str] = []
    A = lines.append
    # No profile header here: render_model_markdown prints the one Subject
    # profile section (with architectures, which this payload does not carry).
    # A second copy used to ship inside these sections, so the report stated
    # the profile twice, back to back.
    A("## Internals review (weighted dimensions)")
    A("")
    _by_dim: dict[str, list] = {}
    for _f in findings:
        _by_dim.setdefault(str(_f.get("dimension") or ""), []).append(_f)
    for d in dimensions:
        _ds = sorted(_by_dim.get(str(d["id"]), []),
                     key=lambda f: -(f.get("inherent_score", 0) or 0))
        # The weight table in the renderer already states the arithmetic; this
        # list used to repeat it number for number. Now each dimension names
        # the finding that drives it, which the table cannot show.
        _driver = (f" — driven by **{_ds[0]['id']}** {_ds[0]['title']}"
                   if _ds else " — no finding mapped")
        A(f"- **{d['id']}** ({d['weight']:.0%} weight): "
          f"**{d['score']:.0f}/100**{_driver}.")
    A("")
    A("## Privacy findings")
    A("")
    for f in [x for x in findings if x["id"].startswith("P")]:
        A(f"- **{f['id']} {f['title']}** — {f['rationale']} "
          f"Mitigations: {'; '.join(f['mitigations']) or '—'}.")
    if not [x for x in findings if x["id"].startswith("P")]:
        A("No privacy findings recorded.")
    A("")
    A("## Internals findings")
    A("")
    for f in [x for x in findings if not x["id"].startswith("P")]:
        A(f"- **{f['id']} {f['title']}** (L{f['likelihood']:g}×I{f['impact']:g}) — "
          f"{f['rationale']} Mitigations: {'; '.join(f['mitigations']) or '—'}.")
    A("")
    exec_paragraph = ""
    try:
        from . import llm as _llm
        ev_txt = "\n".join(
            f"- #{e['artifact_id']} {e['title']} (rel {e.get('relevance')})"
            for e in sorted(evidence, key=lambda e: -e.get("relevance", 0))[:6]) or "- none"
        sys = ("You are an AI security engineer writing one executive-summary "
               "paragraph about a MACHINE-LEARNING model. Be concrete and cite "
               "the evidence by artifact #id. Reply with the paragraph only.")
        user = (f"Model: {product} ({profile.get('summary') or 'unclassified'})\n"
                f"Exposure tier: {exposure_label}\n"
                f"Model risk: {scoring.get('overall_pct', 0):g}/100 "
                f"({scoring.get('method', 'model-internals-v1')})\n"
                f"In-app evidence:\n{ev_txt}\n\n"
                "Write 3-4 sentences: verdict, sharpest model-native attack "
                "path, what the evidence confirms.")
        text = _llm.chat([{"role": "system", "content": sys},
                          {"role": "user", "content": user}],
                         temperature=0.2, max_tokens=512).strip()
        check = grounding.verify_citation_ids(
            text, [e.get("artifact_id") for e in evidence or []])
        check["method"] = "citation_id_check"
        if check.get("status") == "violation":
            raise ValueError("exec paragraph cites nothing real")
        exec_paragraph = text
    except Exception:
        top = sorted(findings,
                     key=lambda f: -(f.get("inherent_score", 0)))[:2]
        exec_paragraph = (
            f"Model risk is {scoring.get('overall_pct', 0):g}/100 for {product} "
            f"({profile.get('summary') or 'unclassified model'}). "
            + ("Sharpest paths: " + "; ".join(
                f"{f['id']} {f['title']}" for f in top) + ". " if top else "")
            + "Deterministic brief: no model call made.")
    return reply_envelope(
        env, "model-reporter", "model_report_written",
        {"model_sections": "\n".join(lines), "exec_paragraph": exec_paragraph},
        note=(f"model report ({len(lines)} lines) + "
              f"{len(exec_paragraph)}-char exec paragraph"),
    )


def run_model_a2a_workflow(
    product_name: str,
    use_case: str,
    focus: Optional[list[str]] = None,
    db: Any = None,
    investigation_id: Any = None,
    exposure_label: str = "",
    exposure: str = "confidential_data",
) -> dict[str, Any]:
    """Model assessment workflow: profiler → internals → collector →
    privacy → scoring (engine) → reporter. Never raises.

    Separate from run_security_a2a_workflow on purpose: different agents,
    different arithmetic (dimension weights, not catalog L×I), and NO
    standards mapping anywhere on this path. Returns the same top-level
    keys the standard workflow returns, so storage and UI need no new
    columns -- the content differs, the contract does not.
    """
    from . import security as sec
    task_id = new_task_id(prefix="mod")
    trace: list[dict[str, Any]] = [{
        "agent": "model-orchestrator", "intent": "plan_model_assessment",
        "at": _now(),
        "note": (f"task {task_id}: model-profiler → model-internals → "
                 "research-collector → model-privacy → scoring engine → "
                 "model-reporter (no standards mapping)"),
    }]
    focus = focus or []
    evidence: list[dict[str, Any]] = []
    queries_run: list[str] = []
    scope = ""
    findings: list[dict[str, Any]] = []
    excluded: list[str] = []
    profile: dict[str, Any] = {}
    scoring: dict[str, Any] = {}
    exec_paragraph = ""
    model_sections = ""
    try:
        env0 = new_envelope(
            "model-orchestrator", "model-profiler", "profile_model",
            {"product_name": product_name, "use_case": use_case,
             "focus": focus},
            task_id=task_id, trace=trace,
            note="deterministic subject profile",
        )
        res0 = dispatch(env0, db)
        trace = res0["trace"]
        profile = res0["payload"].get("profile", {})

        env1 = new_envelope(
            "model-orchestrator", "model-internals", "review_internals",
            {"product_name": product_name, "use_case": use_case,
             "focus": focus, "profile": profile},
            task_id=task_id, trace=trace,
            note="architecture/training/inference review",
        )
        res1 = dispatch(env1, db)
        trace = res1["trace"]
        findings = list(res1["payload"].get("findings", []))
        excluded = list(res1["payload"].get("excluded", []))

        env2 = new_envelope(
            "model-orchestrator", "research-collector", "collect_research",
            {"product_name": product_name, "use_case": use_case,
             "threat_titles": [f["title"] for f in findings],
             "top_k": 8, "investigation_id": investigation_id},
            task_id=task_id, trace=trace,
            note="delegate agentic in-app search",
        )
        res2 = dispatch(env2, db)
        trace = res2["trace"]
        evidence = res2["payload"].get("evidence", [])
        queries_run = res2["payload"].get("queries_run", [])
        scope = res2["payload"].get("scope", "")
        _hop_io(trace, "research-collector", "collect_research",
                f"{len(queries_run)} queries · scope {scope or 'all'}",
                f"{len(evidence)} artifacts, top relevance "
                f"{max((e.get('relevance', 0) for e in evidence), default=0):.2f}")

        env3 = new_envelope(
            "model-orchestrator", "model-privacy", "assess_model_privacy",
            {"product_name": product_name, "use_case": use_case,
             "focus": focus, "profile": profile},
            task_id=task_id, trace=trace,
            note="data lifecycle privacy review",
        )
        res3 = dispatch(env3, db)
        trace = res3["trace"]
        findings = findings + list(res3["payload"].get("findings", []))

        scoring = sec.score_model_assessment(
            {d["id"]: d["score"] for d in _model_dimension_inputs(
                profile, findings)})
        trace.append({
            "agent": "model-orchestrator", "intent": "score",
            "at": _now(),
            "note": (f"model aggregate {scoring.get('overall_pct', 0):g}/100 "
                     f"({scoring.get('method', '')})"),
        })

        env4 = new_envelope(
            "model-orchestrator", "model-reporter", "write_model_report",
            {"product_name": product_name, "exposure_label": exposure_label,
             "profile": profile, "dimensions": scoring.get("dimensions", []),
             "findings": findings, "evidence": evidence, "scoring": scoring},
            task_id=task_id, trace=trace,
            note="draft model sections + exec paragraph",
        )
        res4 = dispatch(env4, db)
        trace = res4["trace"]
        model_sections = res4["payload"].get("model_sections", "")
        exec_paragraph = res4["payload"].get("exec_paragraph", "")
        _hop_io(trace, "model-reporter", "write_model_report",
                f"{len(findings)} findings, {len(evidence)} evidence items",
                f"{len(model_sections)} chars sections, "
                f"{len(exec_paragraph)} chars paragraph")
    except Exception as exc:
        trace.append({"agent": "model-orchestrator", "intent": "workflow_error",
                      "at": _now(), "note": f"{exc}"})
    return {
        "task_id": task_id,
        "evidence": evidence,
        "queries_run": queries_run,
        "scope": scope,
        "known_exploits": [],
        "exploits_markdown": "",
        "exec_evidence_lines": [],
        "exec_evidence_refs": [],
        "exec_paragraph": exec_paragraph,
        "control_plan": {},
        "applicability": {},
        "evidence_confidence": {},
        "scoring": scoring,
        "a2a_trace": trace,
        # model-path extras (ignored by standard consumers)
        "model_profile": profile,
        "model_dimensions": scoring.get("dimensions", []),
        "model_findings": findings,
        "model_excluded": excluded,
        "model_sections": model_sections,
    }


def _model_dimension_inputs(profile: dict[str, Any],
                            findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Per-dimension 0..100 inputs for the scoring engine: mean finding score
    per dimension, baseline where a dimension drew no findings."""
    from . import security as sec
    by_dim: dict[str, list[float]] = {}
    for f in findings:
        try:
            score = float(f.get("inherent_score", 0)) / 25.0 * 100.0
        except (TypeError, ValueError):
            continue
        by_dim.setdefault(str(f.get("dimension", "governance")), []).append(score)
    out = []
    for dim_id, _weight, _desc in sec.MODEL_DIMENSIONS:
        vals = by_dim.get(dim_id, [])
        out.append({"id": dim_id,
                    "score": sum(vals) / len(vals) if vals else 20.0})
    return out


def _misuse_scenario(sid: str, title: str, dimension: str, goal: str,
                     chain: list[str], prerequisites: list[str],
                     achieves: str, feasibility: int, impact: int,
                     rationale: str, detections: list[str],
                     mitigations: list[str]) -> dict[str, Any]:
    """One engineered adversarial scenario, scored for attacker value.

    ``feasibility`` is how reachable the chain is (1 = needs a novel exploit
    and privileged access, 5 = works with plain query access); ``impact`` is
    what the attacker gets. Their product is the scenario's weight, because a
    devastating chain nobody can reach ranks below a modest one they can run
    today. Deliberately not a "likelihood" -- nothing here describes the
    model failing on its own.
    """
    from .security import _severity
    feasibility = max(1, min(5, int(feasibility)))
    impact = max(1, min(5, int(impact)))
    score = float(feasibility * impact)
    return {
        "id": sid, "title": title, "dimension": dimension,
        "stride": "abuse", "owasp": "LLM/ML misuse",
        "attacker_goal": goal, "chain": list(chain),
        "prerequisites": list(prerequisites), "achieves": achieves,
        "feasibility": float(feasibility), "impact": float(impact),
        "likelihood": float(feasibility), "inherent_score": score,
        "residual_score": score, "residual_severity": _severity(score),
        "coverage": 0.0, "controls": [], "applicable": True,
        "applicability": 1.0, "rationale": rationale,
        "detections": list(detections), "mitigations": list(mitigations),
    }


# Deterministic capability derivation: what the profile says an attacker can
# DO with this model. Families map to the abuse each one's native capability
# affords, so "Tabular foundation models" yields a scoring oracle, a
# membership oracle and a schema oracle without naming a product. Every
# capability is traceable to a profile signal; nothing is asserted about a
# model whose profile says nothing.
def _model_capability_fallback(profile: dict[str, Any]) -> tuple[list[dict], list[str]]:
    caps: list[dict[str, Any]] = []
    unexploitable: list[str] = []
    data = " ".join(profile.get("data", []))
    families = [f.lower() for f in profile.get("families", [])]
    cls = profile.get("model_class", "unknown")
    tabular = "tabular" in data
    generative = cls == "generative" or "diffusion" in profile.get("architectures", [])
    conversational = profile.get("interface") == "conversational"
    pretrained = cls in ("foundation", "pretrained", "pretrained encoder",
                         "pretrained encoder-decoder", "large generative")

    if tabular:
        caps.append({"id": "C01", "capability": "batch scoring oracle",
                     "dimension": "capability_abuse", "strength": 4,
                     "basis": "tabular scoring interface accepts arbitrary row batches",
                     "gives": "attacker-chosen inputs scored at scale"})
        caps.append({"id": "C02", "capability": "membership oracle",
                     "dimension": "data_recon", "strength": 4,
                     "basis": "predictions on candidate rows reveal training membership",
                     "gives": "confirmation that a specific record was in training"})
        caps.append({"id": "C03", "capability": "schema and distribution oracle",
                     "dimension": "data_recon", "strength": 3,
                     "basis": "output distributions expose column semantics and ranges",
                     "gives": "reconstruction of the training schema and class balance"})
        caps.append({"id": "C04", "capability": "downstream decision manipulation",
                     "dimension": "capability_abuse", "strength": 4,
                     "basis": "tabular predictions gate credit, fraud and clinical decisions",
                     "gives": "targeted inputs engineered to flip a real decision"})
        caps.append({"id": "C05", "capability": "adversarial row synthesis",
                     "dimension": "manipulation", "strength": 4,
                     "basis": "searchable input space lets an attacker hill-climb rows",
                     "gives": "rows that evade a screening classifier while keeping the label"})
        caps.append({"id": "C06", "capability": "model extraction by distillation",
                     "dimension": "capability_abuse", "strength": 3,
                     "basis": "deterministic outputs support query-based surrogate training",
                     "gives": "a functional copy that inherits the IP but not the controls"})
    if generative:
        caps.append({"id": "C07", "capability": "unbounded synthetic content",
                     "dimension": "capability_abuse", "strength": 5,
                     "basis": "generative class produces content at scale",
                     "gives": "synthetic identities, documents or media at volume"})
        caps.append({"id": "C08", "capability": "identity and narrative laundering",
                     "dimension": "evasion", "strength": 4,
                     "basis": "generated text passes authorship and plausibility checks",
                     "gives": "content that survives review while carrying the attacker's framing"})
    if conversational:
        caps.append({"id": "C09", "capability": "instruction-hijacked output",
                     "dimension": "evasion", "strength": 5,
                     "basis": "chat interface accepts adversarial instructions as input",
                     "gives": "model output steered away from its operator's intent"})
        caps.append({"id": "C10", "capability": "cross-tenant context bleed",
                     "dimension": "data_recon", "strength": 3,
                     "basis": "shared model serves many sessions",
                     "gives": "one user's data surfacing in another's session"})
    elif profile.get("interface") != "unknown":
        # No chat surface, so the conversational attack surface is absent --
        # stated from the profile rather than left for a reader to infer.
        unexploitable.append(
            "conversational prompt injection via the UI (no chat surface)")
    if pretrained:
        caps.append({"id": "C11", "capability": "inherited upstream capability",
                     "dimension": "capability_abuse", "strength": 3,
                     "basis": "pretrained class carries capabilities trained elsewhere",
                     "gives": "capability the deploying org never evaluated"})
    if profile.get("personal_data"):
        caps.append({"id": "C12", "capability": "attribute inference",
                     "dimension": "data_recon", "strength": 4,
                     "basis": "personal data present: predictions correlate with withheld traits",
                     "gives": "sensitive attributes inferred for people who withheld them"})
    else:
        unexploitable.append(
            "personal-attribute inference (no personal-data signal in profile)")
    if "tabular" in data:
        # Quasi-identifier re-identification is a structured-data phenomenon:
        # a handful of columns plus an external dataset is the whole attack, and
        # it needs the row/column structure an image or audio model lacks.
        caps.append({"id": "C13", "capability": "record deanonymization",
                     "dimension": "evasion", "strength": 4,
                     "basis": "quasi-identifiers in tabular data survive 'anonymization'",
                     "gives": "re-identifying supposedly anonymized records"})
    if "audio" in data:
        caps.append({"id": "C15", "capability": "voice synthesis and speaker ID",
                     "dimension": "capability_abuse", "strength": 4,
                     "basis": "audio-in, audio-out model reproduces a voice",
                     "gives": "cloned voice for fraud, or a named speaker from a recording"})
    if "images" in data:
        caps.append({"id": "C16", "capability": "synthetic identity imagery",
                     "dimension": "evasion", "strength": 4,
                     "basis": "image models produce photorealistic faces on demand",
                     "gives": "faces and documents that pass a human check"})
    if profile.get("trains_on_data"):
        caps.append({"id": "C14", "capability": "clean-label poisoning entry",
                     "dimension": "manipulation", "strength": 3,
                     "basis": "training data reachable wherever the pipeline ingests it",
                     "gives": "backdoored behaviour that looks like ordinary training error"})
    if not caps:
        caps.append({"id": "C00", "capability": "no capability derivable from brief",
                     "dimension": "capability_abuse", "strength": 1,
                     "basis": "profile carries no family, class, data or interface signal",
                     "gives": "nothing asserted; supply architecture and interface detail"})
    return caps, unexploitable


def model_adversary_handle(env: dict[str, Any], db: Any = None) -> dict[str, Any]:
    """Intent ``derive_capabilities``: what could someone build with this?

    Reads the profile the model-profiler already produced and names the
    capabilities an attacker would actually reach for, each tied to the
    profile signal that justifies it. LLM first, deterministic profile rules on
    failure -- a down gateway must not silently produce zero capabilities,
    because zero would read as "this model is useless to an attacker".
    """
    from . import security as sec
    payload = env.get("payload", {})
    product = payload.get("product_name", "the model")
    use_case = payload.get("use_case", "")
    focus = payload.get("focus") or []
    profile = payload.get("profile") or sec.profile_model_subject(
        product, use_case, focus)
    caps, unexploitable = _model_capability_fallback(profile)
    source = "deterministic capability rules (no LLM)"
    try:
        from . import llm as _llm
        sys_p = (
            "You are an adversary-in-residence modelling what an attacker can "
            "BUILD WITH a machine-learning model -- not how to break it. The "
            "model is the tool, not the target. "
            f"Profile: {profile['summary'] or 'unclassified model'}. "
            "Reply with STRICT JSON only: {\"capabilities\": [{\"id\": \"C##\", "
            "\"capability\": str (what the attacker does), "
            "\"dimension\": one of capability_abuse | data_recon | evasion | "
            "manipulation | abuse_persistence, \"strength\": 1-5, "
            "\"basis\": str (the model property that makes it possible), "
            "\"gives\": str (what the attacker walks away with)}]}. "
            "Only cite properties the profile states. If the profile is thin, "
            "return fewer capabilities, not invented ones."
        )
        user_p = (f"Model: {product}\nUse: {use_case}\n"
                  f"Profile: {profile['summary'] or 'unclassified'}\n"
                  f"Family: {', '.join(profile['families']) or 'unknown'}\n"
                  f"Class: {profile['model_class']}\n"
                  f"Architecture: {', '.join(profile['architectures']) or 'unknown'}\n"
                  f"Data: {', '.join(profile['data']) or 'unknown'}\n"
                  f"Interface: {profile['interface']}\n"
                  f"Focus: {', '.join(focus) or 'none stated'}")
        raw = _llm.chat([{"role": "system", "content": sys_p},
                         {"role": "user", "content": user_p}],
                        temperature=0.1, max_tokens=1200).strip()
        m = re.search(r"\{.*\}", raw, re.S)
        if not m:
            raise ValueError("model did not return a capabilities object")
        data = json.loads(m.group(0))
        valid = {d[0] for d in sec.ADVERSARIAL_DIMENSIONS}
        llm_caps = []
        for i, c in enumerate(data.get("capabilities") or [], 1):
            if not isinstance(c, dict) or not c.get("capability"):
                continue
            dim = str(c.get("dimension") or "capability_abuse")
            if dim not in valid:
                dim = "capability_abuse"
            llm_caps.append({
                "id": str(c.get("id") or f"C{i:02d}"),
                "capability": str(c["capability"])[:140], "dimension": dim,
                "strength": max(1, min(5, int(c.get("strength", 3)))),
                "basis": str(c.get("basis") or "LLM-proposed")[:240],
                "gives": str(c.get("gives") or "unstated")[:240]})
        if llm_caps:
            caps = llm_caps
            source = "model-adversary via LLM gateway"
    except Exception as exc:
        source = f"deterministic capability rules (LLM unavailable: {exc})"
    return reply_envelope(
        env, "model-adversary", "capabilities_derived",
        {"capabilities": caps, "unexploitable": unexploitable,
         "profile": profile, "source": source},
        note=(f"{len(caps)} attacker capabilities, "
              f"{len(unexploitable)} ruled out ({source})"),
    )


# Deterministic scenario engineering: each capability becomes an attack chain
# with prerequisites and an outcome. Written per capability id so the
# fallback answer is specific to the model family rather than a template.
_MISUSE_SCENARIO_RULES: dict[str, tuple[dict[str, Any], ...]] = {
    "C01": (
        {"title": "Churn injection through the scoring API",
         "goal": "shift a production model's decisions on a target population",
         "chain": ["enumerate the reachable endpoint and its rate limits",
                   "generate candidate row batches matching the expected schema",
                   "score them and keep rows that flip the target decision",
                   "submit the surviving rows in volume"],
         "prerequisites": ["an inference endpoint that accepts arbitrary rows",
                           "knowledge of the input schema and the decision to flip"],
         "achieves": "targeted decision flips on real applicants or accounts",
         "feasibility": 4, "impact": 5,
         "rationale": "a scoring API is a free oracle; batch throughput turns one query into thousands",
         "detections": ["per-entity score volume spikes", "impossible input distributions"],
         "mitigations": ["per-entity rate limits", "schema and value-range validation at the edge",
                         "drift alarms on decision distribution"]},
    ),
    "C02": (
        {"title": "Training-membership confirmation as a privacy oracle",
         "goal": "confirm whether a specific person's record was used in training",
         "chain": ["choose candidate records from a known population",
                   "score them and neighbouring perturbations",
                   "compare confidence or loss across the perturbations",
                   "keep records whose scores separate from the population"],
         "prerequisites": ["query access to the model's outputs",
                           "candidate records whose membership matters"],
         "achieves": "a membership test anyone can run at scale, on real people",
         "feasibility": 4, "impact": 4,
         "rationale": "membership is a property of the output distribution, not of any secret",
         "detections": ["high-volume repeated scoring of near-duplicate rows"],
         "mitigations": ["round or clip outputs", "k-anonymity gates on near-duplicate queries",
                         "membership-inference testing before release"]},
        {"title": "Differential privacy accounting to find under-protected records",
         "goal": "isolate the individuals whose data was least protected during training",
         "chain": ["query the model on a candidate population",
                   "measure per-record score deviation from the population mean",
                   "rank records by deviation",
                   "treat the extremes as the least-protected records"],
         "prerequisites": ["query access", "a population to rank"],
         "achieves": "an ordering of people's privacy exposure",
         "feasibility": 3, "impact": 4,
         "rationale": "where the noise budget was thin, the output says so",
         "detections": ["repeating query patterns over small populations"],
         "mitigations": ["uniform per-subject noise floors", "query-set size limits"]},
    ),
    "C03": (
        {"title": "Training schema and distribution reconstruction",
         "goal": "rebuild the training schema, ranges and class balance",
         "chain": ["submit single-feature sweeps with all other fields neutral",
                   "read the score response per feature",
                   "infer feature semantics, ranges and monotone relationships",
                   "repeat until the response surface is mapped"],
         "prerequisites": ["query access to a model trained on the target data"],
         "achieves": "a working map of a dataset the attacker never saw",
         "feasibility": 5, "impact": 3,
         "rationale": "outputs encode what the model learned; one sweep at a time is enough",
         "detections": ["systematic single-feature sweeps from one source"],
         "mitigations": ["return predictions without confidence where unused",
                         "coarsen outputs to buckets", "per-session query budgets"]},
    ),
    "C04": (
        {"title": "Adversarial row synthesis to defeat downstream screening",
         "goal": "keep a record's true label while making it pass a risk classifier",
         "chain": ["obtain the screening model's gradients or query feedback",
                   "hill-climb input features against the screening decision",
                   "verify the crafted row keeps the real-world outcome",
                   "repeat across the record population"],
         "prerequisites": ["query access to the screening model",
                           "an objective that survives the crafted inputs"],
         "achieves": "records that defeat automated screening while staying effective",
         "feasibility": 4, "impact": 5,
         "rationale": "screening models are optimisation targets, not walls",
         "detections": ["inputs with adversarial feature interaction signatures",
                        "low naturalness for high-score records"],
         "mitigations": ["input sanitization and plausibility constraints",
                         "ensemble screening with a non-differentiable check",
                         "manual review of high-value overrides"]},
    ),
    "C05": (
        {"title": "Silent contamination of a future training set",
         "goal": "plant records that shape the next training round",
         "chain": ["identify where unlabeled records enter the pipeline",
                   "craft records that are individually plausible",
                   "wait for them to be labeled by a model or a weak reviewer",
                   "watch the behaviour change in the next version"],
         "prerequisites": ["a path to influence ingestion", "a labeling step that is not human-only"],
         "achieves": "attacker-chosen behaviour inside a model nobody re-reviewed",
         "feasibility": 2, "impact": 5,
         "rationale": "poisoning needs a supply-chain position, not a query",
         "detections": ["label-distribution drift on ingested records",
                        "canary behaviour checks per model version"],
         "mitigations": ["human-only labeling for sensitive fields",
                         "ingestion provenance and dedup", "per-version behaviour diffs"]},
    ),
    "C06": (
        {"title": "Query-based model extraction",
         "goal": "rebuild a functional copy of a proprietary model",
         "chain": ["sample a query set over the input space",
                   "query the target and record label or score pairs",
                   "train a surrogate on the pairs",
                   "transfer the surrogate's capability to the attacker's product"],
         "prerequisites": ["high query volume", "a representative query distribution"],
         "achieves": "a competing model that inherits the target's capability",
         "feasibility": 4, "impact": 4,
         "rationale": "extraction needs volume, not access to weights",
         "detections": ["query distributions far from production traffic",
                        "sudden label-distribution diversity"],
         "mitigations": ["query budgets per account", "watermark outputs", "canary queries"]},
    ),
    "C07": (
        {"title": "Volume content abuse with no human in the loop",
         "goal": "produce material at a scale no review process can absorb",
         "chain": ["drive the model with templated but varied prompts",
                   "batch the generations",
                   "filter output with the same class of model",
                   "publish at volume"],
         "prerequisites": ["generation access", "any downstream channel"],
         "achieves": "spam, fraud listings or propaganda past human review",
         "feasibility": 5, "impact": 4,
         "rationale": "generation cost is the only real limit, and it keeps falling",
         "detections": ["burst generation patterns", "near-duplicate output clusters"],
         "mitigations": ["provenance marking on generated content",
                         "rate limits per account", "detonation limits downstream"]},
    ),
    "C08": (
        {"title": "Laundered identity and fabricated provenance",
         "goal": "have a model vouch for something the attacker wrote",
         "chain": ["generate a plausible technical artifact or reference",
                   "reference it as independent third-party validation",
                   "lean on downstream actors who trust the surface"],
         "prerequisites": ["generation access", "a process that trusts generated text"],
         "achieves": "attack framing that arrives pre-validated by a machine",
         "feasibility": 4, "impact": 3,
         "rationale": "the laundering works wherever nobody checks whether the source is the model",
         "detections": ["citations with no resolvable provenance"],
         "mitigations": ["require retrievable sources", "mark generated content"]},
    ),
    "C09": (
        {"title": "Operator-instruction hijack at the chat surface",
         "goal": "make a deployed assistant act against its operator's policy",
         "chain": ["frame the request as a system or developer message",
                   "carry the payload inside retrieved or quoted content",
                   "let the model answer the injected instruction",
                   "act on the output inside the operator's own trust boundary"],
         "prerequisites": ["a chat surface", "untrusted content reaching the context"],
         "achieves": "policy bypass performed by the operator's own assistant",
         "feasibility": 4, "impact": 5,
         "rationale": "the model cannot tell its operator from an attacker who quotes one",
         "detections": ["instruction-shaped inputs in user content",
                        "policy refusals followed by compliant output"],
         "mitigations": ["privilege separation for tool calls", "output-side policy checks",
                         "treat retrieved text as untrusted data, never as instructions"]},
    ),
    "C10": (
        {"title": "Cross-session data bleed on a shared model",
         "goal": "read another user's data through shared serving state",
         "chain": ["probe for state that survives a session boundary",
                   "seed the context with a canary",
                   "read the canary back in a later session"],
         "prerequisites": ["multi-tenant serving", "a stateful context path"],
         "achieves": "one tenant's data served to another",
         "feasibility": 2, "impact": 5,
         "rationale": "shared weights plus sloppy session state is the whole bug class",
         "detections": ["canary leakage tests per release"],
         "mitigations": ["hard session isolation", "no cross-session caches on shared weights",
                         "adversarial canary suite in CI"]},
    ),
    "C11": (
        {"title": "Undeclared upstream capability",
         "goal": "use behaviour the deploying organisation never evaluated",
         "chain": ["probe the deployed model for upstream-known capabilities",
                   "compare against the local evaluation record",
                   "exploit the difference"],
         "prerequisites": ["query access", "a gap between upstream evals and local ones"],
         "achieves": "capability discovered in production",
         "feasibility": 3, "impact": 3,
         "rationale": "inherited weights bring inherited behaviour",
         "detections": ["capability probes from unusual clients"],
         "mitigations": ["evaluate the deployed artefact, not the upstream card",
                         "pin weights by hash", "re-eval on every version bump"]},
    ),
    "C12": (
        {"title": "Infer withheld attributes from model outputs",
         "goal": "learn a sensitive trait about someone who never disclosed it",
         "chain": ["assemble features known to correlate with the target trait",
                   "score the subject",
                   "read the trait from the score shape"],
         "prerequisites": ["personal data in training or serving", "query access"],
         "achieves": "a protected attribute for a person who withheld it",
         "feasibility": 4, "impact": 5,
         "rationale": "predictions leak the training distribution, not just the label",
         "detections": ["attribute-inference evaluation before release"],
         "mitigations": ["suppress attribute-correlated outputs", "train on minimized features",
                         "document residual inference risk"]},
    ),
    "C13": (
        {"title": "Re-identification of 'anonymized' records",
         "goal": "attach names to records believed anonymous",
         "chain": ["predict each quasi-identifier from the released model",
                   "match predictions against external data",
                   "join on the surviving quasi-identifiers"],
         "prerequisites": ["a release that kept quasi-identifiers", "an external dataset to join"],
         "achieves": "named individuals from data published as anonymous",
         "feasibility": 4, "impact": 5,
         "rationale": "anonymization that keeps the model's strongest features is not anonymization",
         "detections": ["k-anonymity and uniqueness checks before release"],
         "mitigations": ["l-diversity before release", "suppress rare-combination outputs",
                         "drop quasi-identifiers that predict identity"]},
    ),
    "C14": (
        {"title": "Clean-label backdoor via the training pipeline",
         "goal": "install triggerable behaviour in a model trained on attacker records",
         "chain": ["craft records that look clean but carry a trigger pattern",
                   "get them labeled by an automated step",
                   "train the next version on the poisoned set",
                   "activate the trigger on demand"],
         "prerequisites": ["ingestion influence", "automated labeling"],
         "achieves": "a backdoor that passes every review gate",
         "feasibility": 2, "impact": 5,
         "rationale": "the trigger is invisible until used",
         "detections": ["trigger-hunting per version", "label-flip analysis on ingested data"],
         "mitigations": ["human verification for sensitive labeling",
                         "trigger-hunting suite in CI", "signed datasets"]},
    ),
    "C15": (
        {"title": "Voice clone for account takeover",
         "goal": "authenticate as a customer using their voice",
         "chain": ["obtain a short sample of the target's voice",
                   "synthesize matching speech for the expected phrase",
                   "place the call into a channel that trusts voice as proof",
                   "let the clone satisfy the check"],
         "prerequisites": ["a voice sample in any public recording",
                           "a voice-based authentication step"],
         "achieves": "account takeover without ever touching the victim's device",
         "feasibility": 3, "impact": 5,
         "rationale": "voice is treated as strong evidence, and synthesis no longer needs a lot of audio",
         "detections": ["synthesis artifacts in the audio channel",
                        "liveness checks absent on accepted calls"],
         "mitigations": ["liveness challenges in the call path",
                         "callback to a number on file", "out-of-band confirmation"]},
        {"title": "Speaker identification against an audio corpus",
         "goal": "name the speaker in recorded material",
         "chain": ["segment the recording into speakers",
                   "embed each segment",
                   "match embeddings against a reference set",
                   "attach names to the recording"],
         "prerequisites": ["a recording with speech", "a reference voice sample"],
         "achieves": "identification of people in audio the operator assumed was anonymous",
         "feasibility": 3, "impact": 4,
         "rationale": "speaker ID is a solved task the moment the model is reachable",
         "detections": ["embedding queries over long audio"],
         "mitigations": ["strip speaker embeddings from public audio",
                         "log and review embedding-API access"]},
    ),
    "C16": (
        {"title": "Fabricated identity documents and faces",
         "goal": "produce a convincing identity artefact",
         "chain": ["prompt an image model for a document or face",
                   "iterate until it passes visual inspection",
                   "submit it to a process that checks appearance only"],
         "prerequisites": ["image generation access", "a process without strong document verification"],
         "achieves": "a synthetic identity that defeats a human reviewer",
         "feasibility": 4, "impact": 5,
         "rationale": "appearance checks were never a security boundary",
         "detections": ["document re-upload and forgery detection",
                        "metadata inconsistency checks"],
         "mitigations": ["cryptographically verifiable credentials",
                         "database verification of the claimed identity",
                         "liveness capture rather than uploaded images"]},
    ),
    "C00": (
        {"title": "Misuse surface undetermined from the brief",
         "goal": "n/a",
         "chain": ["supply the model's family, interface and data types",
                   "re-run the misuse assessment"],
         "prerequisites": ["a fuller brief"],
         "achieves": "nothing asserted",
         "feasibility": 1, "impact": 1,
         "rationale": "profile carried no capability signal; a confident scenario would be fiction",
         "detections": ["n/a"],
         "mitigations": ["document architecture, interface and training data sources"]},
    ),
}


def misuse_scout_handle(env: dict[str, Any], db: Any = None) -> dict[str, Any]:
    """Intent ``engineer_scenarios``: capabilities turned into attack chains.

    Each scenario is only as strong as its capability: the profile decides
    which chains exist, and this agent supplies the chain, the prerequisites
    and the outcome. Never invents a capability the adversary did not derive.
    """
    from . import security as sec
    payload = env.get("payload", {})
    product = payload.get("product_name", "the model")
    use_case = payload.get("use_case", "")
    focus = payload.get("focus") or []
    profile = payload.get("profile") or sec.profile_model_subject(
        product, use_case, focus)
    caps = payload.get("capabilities") or []
    scenarios: list[dict[str, Any]] = []
    n = 0
    for cap in caps:
        rules = _MISUSE_SCENARIO_RULES.get(str(cap.get("id", "")), ())
        for rule in rules:
            n += 1
            scenarios.append(_misuse_scenario(
                f"A{n:02d}",
                f"{rule['title']} (from {cap.get('capability', 'capability')})",
                str(cap.get("dimension") or "capability_abuse"),
                rule["goal"], rule["chain"], rule["prerequisites"],
                rule["achieves"], rule["feasibility"], rule["impact"],
                f"{rule['rationale']}; capability basis: {cap.get('basis', 'unstated')}",
                rule["detections"], rule["mitigations"]))
    source = "deterministic scenario catalogue (no LLM)"
    try:
        from . import llm as _llm
        cap_txt = "\n".join(
            f"- {c.get('id')}: {c.get('capability')} (dim {c.get('dimension')}, "
            f"strength {c.get('strength')}) — {c.get('basis')}"
            for c in caps) or "- none derived"
        sys_p = (
            "You are a red-team planner. Turn the ATTACKER CAPABILITIES below "
            "into concrete adversarial scenarios against a machine-learning "
            "model. The model is the tool, not the target: every scenario must "
            "read as 'someone builds X with this model', never 'the model is "
            "broken'. Never invent a capability that is not listed. "
            "Reply with STRICT JSON only: {\"scenarios\": [{\"title\": str, "
            "\"dimension\": one of capability_abuse | data_recon | evasion | "
            "manipulation | abuse_persistence, \"attacker_goal\": str, "
            "\"chain\": [str] (ordered steps), \"prerequisites\": [str], "
            "\"achieves\": str, \"feasibility\": 1-5 (how reachable), "
            "\"impact\": 1-5, \"rationale\": str, \"detections\": [str], "
            "\"mitigations\": [str]}]}."
        )
        user_p = (f"Model: {product}\nUse: {use_case}\n"
                  f"Profile: {profile.get('summary') or 'unclassified'}\n"
                  f"Interface: {profile['interface']}\n"
                  f"Data: {', '.join(profile.get('data') or []) or 'unknown'}\n"
                  f"Focus: {', '.join(focus) or 'none stated'}\n"
                  f"Attacker capabilities:\n{cap_txt}")
        raw = _llm.chat([{"role": "system", "content": sys_p},
                         {"role": "user", "content": user_p}],
                        temperature=0.15, max_tokens=1600).strip()
        m = re.search(r"\{.*\}", raw, re.S)
        if not m:
            raise ValueError("model did not return a scenarios object")
        data = json.loads(m.group(0))
        valid = {d[0] for d in sec.ADVERSARIAL_DIMENSIONS}
        llm_sc = []
        for i, s in enumerate(data.get("scenarios") or [], 1):
            if not isinstance(s, dict) or not s.get("title"):
                continue
            dim = str(s.get("dimension") or "capability_abuse")
            if dim not in valid:
                dim = "capability_abuse"
            llm_sc.append(_misuse_scenario(
                f"A{i:02d}", str(s["title"])[:160], dim,
                str(s.get("attacker_goal") or "unstated")[:200],
                [str(x)[:200] for x in (s.get("chain") or [])][:6],
                [str(x)[:200] for x in (s.get("prerequisites") or [])][:5],
                str(s.get("achieves") or "unstated")[:240],
                s.get("feasibility", 3), s.get("impact", 3),
                str(s.get("rationale") or "LLM-proposed scenario")[:300],
                [str(x)[:160] for x in (s.get("detections") or [])][:4],
                [str(x)[:160] for x in (s.get("mitigations") or [])][:4]))
        if llm_sc:
            scenarios = llm_sc
            source = "misuse-scout via LLM gateway"
    except Exception as exc:
        source = f"deterministic scenario catalogue (LLM unavailable: {exc})"
    scenarios.sort(key=lambda s: -s["inherent_score"])
    return reply_envelope(
        env, "misuse-scout", "scenarios_engineered",
        {"scenarios": scenarios, "source": source},
        note=(f"{len(scenarios)} adversarial scenarios "
              f"(top {scenarios[0]['inherent_score']:g}/25)" if scenarios
              else "0 scenarios") + f" ({source})",
    )


def misuse_reporter_handle(env: dict[str, Any], db: Any = None) -> dict[str, Any]:
    """Intent ``write_misuse_report``: ranked scenarios + abuse chain.

    Same grounding discipline as the other reporters: the executive paragraph
    must cite only artifact ids that exist, or the deterministic fallback
    ships instead of confident fiction.
    """
    payload = env.get("payload", {})
    product = payload.get("product_name", "the model")
    exposure_label = payload.get("exposure_label", "")
    profile = payload.get("profile", {}) or {}
    capabilities = payload.get("capabilities", []) or []
    scenarios = payload.get("scenarios", []) or []
    evidence = payload.get("evidence", []) or []
    scoring = payload.get("scoring", {}) or {}
    lines: list[str] = []
    A = lines.append
    A(f"## What this model is, as a tool — {product}")
    A("")
    A(f"_{profile.get('summary') or 'Unclassified model: misuse treated conservatively.'}_")
    A("")
    A("This assessment asks the second question. The first one — *is this "
      "model sound?* — is a separate assessment with its own score; the "
      "number below is not that number. A model can be perfectly well built "
      "and still be the most valuable tool in someone else's operation.")
    A("")
    A("### Attacker capabilities")
    A("")
    for c in capabilities:
        A(f"- **{c.get('id')} {c.get('capability')}** (strength "
          f"{c.get('strength')}/5) — {c.get('gives', 'unstated')}. "
          f"_Basis:_ {c.get('basis', 'unstated')}.")
    if not capabilities:
        A("- none derivable from the brief.")
    A("")
    A("## Misuse potential (weighted dimensions)")
    A("")
    _by_dim: dict[str, list] = {}
    for _s in scenarios:
        _by_dim.setdefault(str(_s.get("dimension") or ""), []).append(_s)
    for d in scoring.get("dimensions", []):
        _ds = sorted(_by_dim.get(str(d["id"]), []),
                     key=lambda s: -(s.get("inherent_score", 0) or 0))
        _driver = (f" — sharpest chain **{_ds[0]['id']}** {_ds[0]['title']}"
                   if _ds else " — no scenario mapped")
        A(f"- **{d['id']}** ({d['weight']:.0%} weight): **{d['score']:.0f}/100**{_driver}.")
    A("")
    A("## Engineered adversarial scenarios")
    A("")
    for s in scenarios:
        A(f"### {s['id']} — {s['title']}")
        A("")
        A(f"_Goal:_ {s['attacker_goal']} · _Achieves:_ {s['achieves']} "
          f"· _Reachability_ {s['feasibility']:g}/5, _impact_ {s['impact']:g}/5 "
          f"(severity {s['residual_severity']}).")
        A("")
        A("Chain:")
        for i, step in enumerate(s["chain"], 1):
            A(f"{i}. {step}")
        if s["prerequisites"]:
            A("")
            A(f"_Prerequisites:_ {'; '.join(s['prerequisites'])}.")
        if s["detections"]:
            A("")
            A(f"_Would show up as:_ {'; '.join(s['detections'])}.")
        if s["mitigations"]:
            A("")
            A(f"_What actually helps:_ {'; '.join(s['mitigations'])}.")
        A("")
    if not scenarios:
        A("No adversarial scenarios derived from the brief.")
        A("")
    exec_paragraph = ""
    try:
        from . import llm as _llm
        ev_txt = "\n".join(
            f"- #{e['artifact_id']} {e['title']} (rel {e.get('relevance')})"
            for e in sorted(evidence, key=lambda e: -e.get("relevance", 0))[:6]) or "- none"
        sys = ("You are a red-team lead writing one executive paragraph on what "
               "an attacker could BUILD WITH a machine-learning model. The model "
               "is the tool, not the target. Be concrete, cite evidence by "
               "artifact #id, and say what would have to be true for the worst "
               "scenario to work. Reply with the paragraph only.")
        user = (f"Model: {product} ({profile.get('summary') or 'unclassified'})\n"
                f"Exposure tier: {exposure_label}\n"
                f"Misuse potential: {scoring.get('overall_pct', 0):g}/100 "
                f"({scoring.get('method', 'model-misuse-v1')})\n"
                f"Top scenarios: "
                + ("; ".join(f"{s['id']} {s['title']} ({s['inherent_score']:g}/25)"
                             for s in scenarios[:3]) or "none") + "\n"
                f"In-app evidence:\n{ev_txt}\n\n"
                "Write 3-4 sentences: what the model is useful to an attacker, "
                "the sharpest chain, and the one prerequisite that would break it.")
        text = _llm.chat([{"role": "system", "content": sys},
                          {"role": "user", "content": user}],
                         temperature=0.2, max_tokens=512).strip()
        check = grounding.verify_citation_ids(
            text, [e.get("artifact_id") for e in evidence or []])
        check["method"] = "citation_id_check"
        if check.get("status") == "violation":
            raise ValueError("exec paragraph cites nothing real")
        exec_paragraph = text
    except Exception:
        top = scenarios[:2]
        exec_paragraph = (
            f"Misuse potential is {scoring.get('overall_pct', 0):g}/100 for "
            f"{product} ({profile.get('summary') or 'unclassified model'}), "
            "weighted toward capability value rather than model defects. "
            + ("Sharpest chains: " + "; ".join(
                f"{s['id']} {s['title']}" for s in top) + ". " if top else "")
            + "Deterministic brief: no model call made.")
    return reply_envelope(
        env, "misuse-reporter", "misuse_report_written",
        {"misuse_sections": "\n".join(lines), "exec_paragraph": exec_paragraph},
        note=(f"misuse report ({len(scenarios)} scenarios, {len(lines)} lines) "
              f"+ {len(exec_paragraph)}-char exec paragraph"),
    )


# ------------------------------------------------ hypothesis synthesis ----
# Flow 3. Reads the stored rows of flows 1 and 2 and drafts CLAIMS rather than
# findings. The distinction is the whole point: a finding is true by
# construction, a hypothesis is held to a confidence and names what would
# refute it. Every claim below carries premise -> mechanism -> consequence plus
# a falsifier, and the verifier is expected to produce counter-evidence -- a set
# where nothing argues against anything is a broken verifier, not a clean
# system.
def _hypothesis(fid: str, claim: str, premise: str, mechanism: str,
                consequence: str, falsifier: str,
                supporting: list[str] | None = None,
                counter: list[str] | None = None,
                impact: int = 3, testability: int = 3) -> dict[str, Any]:
    from .security import _severity
    impact = max(1, min(5, int(impact)))
    testability = max(1, min(5, int(testability)))
    # A hypothesis has no likelihood: nothing has been tested. Severity here
    # means "how much is at stake if the claim holds", not likelihood x impact,
    # so the familiar residual columns stay empty rather than implying a
    # measured risk that does not exist.
    return {
        "id": fid, "hypothesis_id": fid, "claim": claim,
        "premise": premise, "mechanism": mechanism,
        "consequence": consequence, "falsifier": falsifier,
        "falsifiers": [falsifier] if falsifier else [],
        "status": "untested", "source_flows": [],
        "supporting": list(supporting or []), "counter_evidence": list(counter or []),
        "impact": float(impact), "testability": float(testability),
        "inherent_score": float(impact), "residual_score": float(impact),
        "residual_severity": _severity(impact),
        "likelihood": None, "coverage": 0.0, "controls": [],
        "applicable": True, "applicability": 1.0,
        "rationale": f"stakes if true: {impact}/5; refutable by: {falsifier}",
        "mitigations": [f"Observe: {falsifier}"],
    }


def _hypothesis_fallback(target_rows: list[dict[str, Any]],
                         adv_rows: list[dict[str, Any]],
                         profile: dict[str, Any],
                         ) -> list[dict[str, Any]]:
    """Deterministic cross-flow claims: only where flows 1 and 2 overlap.

    The interesting hypotheses are the ones both flows reached independently --
    an internals finding about training data AND a misuse scenario about
    extraction is a stronger claim than either alone, because two different
    questions converged on it. Single-flow claims are still emitted, marked as
    such, because a claim only one path reached is a claim worth testing.

    Every rule below is a conjunction of things the two stored rows actually
    say. Nothing is asserted from the product name alone.
    """
    out: list[dict[str, Any]] = []
    t_by_dim: dict[str, list[dict]] = {}
    for r in target_rows:
        t_by_dim.setdefault(str(r.get("dimension") or ""), []).append(r)
    a_by_dim: dict[str, list[dict]] = {}
    for r in adv_rows:
        a_by_dim.setdefault(str(r.get("dimension") or ""), []).append(r)

    def _has(store: dict, dim: str, *words: str) -> list[dict]:
        rows = store.get(dim) or []
        if not words:
            return rows
        return [r for r in rows
                if any(w in str(r.get("title", "")).lower()
                       or w in str(r.get("rationale", "")).lower() for w in words)]

    t_priv = t_by_dim.get("training_data_privacy") or []
    a_recon = a_by_dim.get("data_recon") or []
    if t_priv and a_recon:
        out.append(_hypothesis(
            "H01",
            "held-out training rows are recoverable through the serving surface",
            "the profile says it trains on personal data, and the misuse flow "
            "derived an inference-side extraction capability from the same "
            "profile",
            "memorised rows are reachable by querying the model and reading "
            "the residual memorisation back out",
            "confidential training records leave via the inference API, which "
            "is the one surface access control already treats as trusted",
            "sample 20 training rows the model was fit on and request them back "
            "verbatim; if it declines or paraphrases on every row, the claim "
            "does not hold",
            supporting=[r["id"] for r in t_priv] + [r["id"] for r in a_recon],
            counter=[r["id"] for r in _has(t_by_dim, "training_data_privacy", "minimis", "minimiz")],
            impact=5, testability=5))
    t_integ = t_by_dim.get("model_integrity") or []
    a_manip = a_by_dim.get("manipulation") or []
    if t_integ and a_manip:
        out.append(_hypothesis(
            "H02",
            "the model can be steered by whoever controls its training or "
            "fine-tuning input",
            "both flows independently flagged the supply path: internals on "
            "provenance, misuse on poisoning and backdooring",
            "an actor with ingestion or fine-tuning access can plant behaviour "
            "that persists across restarts and is indistinguishable from the "
            "model's own",
            "a silent behavioural change ships inside a model artefact that "
            "every downstream control trusts",
            "run the model against a held-out behavioural test set; if its "
            "refusals and outputs are stable, the backdoor is not present",
            supporting=[r["id"] for r in t_integ] + [r["id"] for r in a_manip],
            counter=[],
            impact=5, testability=3))
    t_deploy = t_by_dim.get("deployment_surface") or []
    a_evas = a_by_dim.get("evasion") or []
    if t_deploy and a_evas:
        out.append(_hypothesis(
            "H03",
            "the serving surface is also an evasion surface -- content and "
            "decisions can be laundered through it",
            "internals flagged inference exposure and logging gaps; misuse "
            "derived laundering and identity-spoofing capabilities from the "
            "same interface facts",
            "an output that no control inspects is an output no control can "
            "constrain, and a model generates plausible text faster than any "
            "reviewer can read it",
            "policy checks that gate the tool are bypassed by going through the "
            "model's own output",
            "send known-bad content through the model and check whether it "
            "survives to the consumer; if the consumer blocks it, the claim "
            "fails",
            supporting=[r["id"] for r in t_deploy] + [r["id"] for r in a_evas],
            counter=[],
            impact=4, testability=4))
    a_cap = a_by_dim.get("capability_abuse") or []
    if a_cap:
        out.append(_hypothesis(
            "H04",
            "the model's raw capability is the asset, and it is exposed to "
            "whoever can reach an endpoint",
            "the misuse flow derived capabilities that need no model defect at "
            "all -- only a reachable endpoint",
            "capability abuse needs no backdoor and no poisoned weights, which "
            "means no finding in flow 1 will ever detect it",
            "the risk lives in access control to the endpoint, not in the "
            "model's integrity -- and it is invisible to a model review",
            "remove the endpoint and re-run the misuse scenarios; if they no "
            "longer apply, exposure was the whole mechanism",
            supporting=[r["id"] for r in a_by_dim["capability_abuse"]],
            counter=[],
            impact=4, testability=5))
    if not out and profile.get("is_model_query"):
        # Never return an empty set for a model: an empty hypothesis list reads
        # as "nothing to test" when it actually means "the two flows produced
        # nothing to cross-reference". Say that instead.
        out.append(_hypothesis(
            "H01",
            "the two prior assessments produced no overlapping signal to test",
            f"profile: {profile.get('summary') or 'unclassified model'}",
            "with neither internals findings nor misuse scenarios recorded, "
            "there is no evidence base for a claim",
            "this hypothesis is untested by construction and exists to mark the "
            "gap, not to assert anything",
            "run the internals and misuse assessments and re-run this flow",
            supporting=[], counter=[], impact=1, testability=1))
    return out


def hypothesis_analyst_handle(env: dict[str, Any], db: Any = None) -> dict[str, Any]:
    """Intent ``draft_hypotheses``: claims from the two prior flows.

    Reads the stored internals findings and misuse scenarios handed to it and
    drafts falsifiable claims. LLM first, deterministic cross-flow conjunction
    rules on failure -- a down gateway must not yield an empty hypothesis set,
    which would read as "nothing worth testing".
    """
    from . import security as sec
    payload = env.get("payload", {})
    product = payload.get("product_name", "the model")
    use_case = payload.get("use_case", "")
    focus = payload.get("focus") or []
    profile = payload.get("profile") or sec.profile_model_subject(
        product, use_case, focus)
    target_rows = [r for r in (payload.get("target_rows") or []) if isinstance(r, dict)]
    adv_rows = [r for r in (payload.get("adversarial_rows") or []) if isinstance(r, dict)]
    hyps = _hypothesis_fallback(target_rows, adv_rows, profile)
    source = "deterministic cross-flow rules (no LLM)"
    try:
        from . import llm as _llm
        sys_p = (
            "You are a research lead turning two completed AI security "
            "assessments into FALSIFIABLE HYPOTHESES. Flow 1 asked whether the "
            "model is sound (findings about the model). Flow 2 asked what an "
            "attacker could build with it (scenarios about misuse). "
            "A hypothesis is a CLAIM someone could test and be wrong about -- "
            "not a restatement of a finding. Every claim needs a premise, a "
            "mechanism, a consequence if true, and a falsifier that would "
            "REFUTE it. Prefer claims both assessments support; mark "
            "single-assessment claims. Never assert a control that is not "
            "named. Check every claim against the flow-1 findings: a claim "
            "must not assert what a finding denies (the verifier will flag "
            "it and mark the report). Reply with STRICT JSON only: {\"hypotheses\": [{\"id\": "
            "\"H##\", \"claim\": str (one falsifiable sentence), \"premise\": str, "
            "\"mechanism\": str, \"consequence\": str, \"falsifier\": str (a "
            "specific observation that would refute it), \"impact\": 1-5 (stakes "
            "if true), \"testability\": 1-5}]}."
        )
        user_p = (f"Model: {product}\nUse: {use_case}\n"
                  f"Profile: {profile.get('summary') or 'unclassified'}\n"
                  f"Flow 1 (internals) findings: "
                  f"{json.dumps([{k: r.get(k) for k in ('id','title','dimension','inherent_score')} for r in target_rows])[:2500]}\n"
                  f"Flow 2 (misuse) scenarios: "
                  f"{json.dumps([{k: r.get(k) for k in ('id','title','dimension','inherent_score')} for r in adv_rows])[:2500]}")
        raw = _llm.chat([{"role": "system", "content": sys_p},
                         {"role": "user", "content": user_p}],
                        temperature=0.1, max_tokens=1500).strip()
        m = re.search(r"\{.*\}", raw, re.S)
        if not m:
            raise ValueError("model did not return a hypotheses object")
        data = json.loads(m.group(0))
        llm_h = []
        for i, h in enumerate(data.get("hypotheses") or [], 1):
            if not isinstance(h, dict) or not h.get("claim"):
                continue
            if not h.get("falsifier"):
                continue          # a claim with no refutation is an assertion
            llm_h.append(_hypothesis(
                str(h.get("id") or f"H{i:02d}"), str(h["claim"])[:200],
                str(h.get("premise") or "unstated")[:240],
                str(h.get("mechanism") or "unstated")[:240],
                str(h.get("consequence") or "unstated")[:240],
                str(h["falsifier"])[:240],
                impact=h.get("impact", 3), testability=h.get("testability", 3)))
        if llm_h:
            # Re-attach traceability the prose lost. The claims stay the
            # LLM's, but each one now names the rows of flows 1 and 2 it can be
            # read off, so the verifier can still tell a corroborated claim
            # from one only a single flow reached.
            for h in llm_h:
                h["supporting"] = (_match_hyp_sources(h, target_rows)
                                   + _match_hyp_sources(h, adv_rows))
            hyps = llm_h
            source = "hypothesis-analyst via LLM gateway"
    except Exception as exc:
        source = f"deterministic cross-flow rules (LLM unavailable: {exc})"
    hyps.sort(key=lambda h: (-h["impact"], -h["testability"]))
    return reply_envelope(
        env, "hypothesis-analyst", "hypotheses_drafted",
        {"hypotheses": hyps, "source": source},
        note=(f"{len(hyps)} claims drafted, {sum(1 for h in hyps if h['falsifier'])} "
              f"with falsifiers" if hyps else "0 claims") + f" ({source})",
    )


def hypothesis_verifier_handle(env: dict[str, Any], db: Any = None) -> dict[str, Any]:
    """Intent ``verify_hypotheses``: argue with each claim.

    Assigns support, surfaces the evidence that argues AGAINST each claim, and
    flags the ones whose refutation test is too vague to settle anything. A
    claim scoring high with no counter-evidence is downgraded on purpose --
    "nothing argues against this" is more often a gap in collection than a
    well-supported claim.
    """
    from . import security as sec
    payload = env.get("payload", {})
    hyps = [h for h in (payload.get("hypotheses") or []) if isinstance(h, dict)]
    evidence = [e for e in (payload.get("evidence") or []) if isinstance(e, dict)]
    target_rows = [r for r in (payload.get("target_rows") or [])
                   if isinstance(r, dict)]
    verified = []
    for h in hyps:
        support = list(h.get("supporting") or [])
        counter = list(h.get("counter_evidence") or [])
        # Flow-1 cross-check: a claim that denies what an internals finding
        # states (or asserts what it rules out) is arguing with its own
        # evidence base, not corroborated by it. Named and penalised like
        # counter-evidence, through the same dimension.
        contradicted = _hypothesis_contradictions(h, target_rows)
        testability = float(h.get("testability", 3))
        impact = float(h.get("impact", 3))
        # Evidence support: cited source rows, plus any in-app artifact the
        # claim's keywords match. Not a count -- capped, because ten artifacts
        # repeating one source is not ten independent confirmations.
        support_score = min(100.0, 25.0 + 20.0 * min(3, len(support)))
        blob = " ".join((str(h.get("claim", "")), str(h.get("mechanism", "")))).lower()
        matched = [e for e in evidence
                   if any(tok in blob for tok in
                          _hyp_keywords(str(e.get("title", ""))))]
        if matched:
            top = max(float(e.get("relevance", 0) or 0) for e in matched)
            support_score = min(100.0, support_score + 25.0 * top)
        # Cross-flow corroboration: a claim both flows reached is worth more
        # than one only a single path produced.
        tgt = any(r in support for r in (h.get("_target_ids") or []))
        adv = any(r in support for r in (h.get("_adversarial_ids") or []))
        corroborated = tgt and adv
        cross = 100.0 if corroborated else (55.0 if (tgt or adv) else 30.0)
        # Penalty for an unfalsifiable claim: "review the deployment" settles
        # nothing, and a claim nobody can refute cannot be promoted.
        if not str(h.get("falsifier", "")).strip():
            testability = 1.0
        dims = {
            "evidence_support": max(0.0, min(100.0, support_score
                                            - 15.0 * len(counter)
                                            - 15.0 * len(contradicted))),
            "cross_flow_corroboration": cross,
            "testability": testability / 5.0 * 100.0,
            "impact_if_true": impact / 5.0 * 100.0,
        }
        v = dict(h)
        if not v.get("hypothesis_id"):
            v["hypothesis_id"] = v.get("id")
        fals = [f for f in (v.get("falsifiers") or []) if str(f).strip()]
        if v.get("falsifier") and str(v["falsifier"]).strip() not in fals:
            fals = [str(v["falsifier"]).strip()] + fals
        v["falsifiers"] = fals
        flows = []
        if any(r in support for r in (h.get("_target_ids") or [])):
            flows.append("model")
        if any(r in support for r in (h.get("_adversarial_ids") or [])):
            flows.append("model_adversarial")
        v["source_flows"] = flows
        # The verifier judges corroboration, never refutation: refuted is
        # set explicitly by a human or by later evidence, not inferred here.
        if counter or contradicted:
            v["status"] = "contested"
        elif dims["evidence_support"] >= 60.0:
            v["status"] = "supported"
        else:
            v["status"] = "untested"
        v.update({
            "support_score": round(dims["evidence_support"], 1),
            "cross_flow": corroborated,
            "verification_dimensions": {k: round(x, 1) for k, x in dims.items()},
            "counter_evidence": counter,
            "contradicted_by": contradicted,
            "supporting_artifacts": [e.get("artifact_id") for e in matched[:5]],
            # Confidence is the verifier's own read, not the drafter's.
            "confidence": round(
                0.40 * dims["evidence_support"]
                + 0.25 * dims["cross_flow_corroboration"]
                + 0.20 * dims["testability"]
                + 0.15 * dims["impact_if_true"], 1),
        })
        verified.append(v)
    verified.sort(key=lambda v: -v.get("confidence", 0))
    return reply_envelope(
        env, "hypothesis-verifier", "hypotheses_verified",
        {"verified": verified,
         "dimension_inputs": _hypothesis_dimension_inputs(verified)},
        note=(f"{len(verified)} claims verified, "
              f"{sum(1 for v in verified if v.get('cross_flow'))} corroborated "
              f"by both flows, {sum(1 for v in verified if not v.get('counter_evidence'))} "
              f"uncountered, {sum(1 for v in verified if v.get('contradicted_by'))} "
              f"in tension with flow-1 findings"),
    )


_NEGATION_TOKENS = {"no", "not", "never", "without", "absent", "lack",
                    "lacks", "lacking", "fail", "fails", "failed", "cannot",
                    "none", "neither", "unverified", "deny", "denies",
                    "refutes"}

_CLAIM_STOP = {"the", "and", "with", "from", "that", "this", "into", "your",
               "what", "which", "will", "would", "could", "should", "there",
               "their", "they", "them", "then", "than", "also", "only",
               "such", "have", "has", "are", "was", "were", "been", "being",
               "does", "about", "across", "under", "over", "between",
               "through", "while", "model", "models", "claim", "claims"}


def _stem(tok: str) -> str:
    for suf in ("ing", "ed", "es", "s"):
        if len(tok) - len(suf) >= 4 and tok.endswith(suf):
            return tok[:-len(suf)]
    return tok


def _content_tokens(text: str) -> set[str]:
    return {_stem(t) for t in re.findall(r"[a-z]{4,}", text.lower())
            if t not in _CLAIM_STOP}


def _negated(text: str) -> bool:
    toks = set(re.findall(r"[a-z]+", text.lower()))
    return bool(toks & _NEGATION_TOKENS)


def _hypothesis_contradictions(h: dict[str, Any],
                               target_rows: list[dict[str, Any]]) -> list[str]:
    """Flow-1 finding ids the claim argues with.

    A claim shares distinctive tokens with a finding but exactly one side is
    negated: the claim's premise says the profile trains on personal data
    while P01 states there are no personal-data signals. Such a claim is not
    corroborated by that finding -- it contradicts it -- so the id is
    returned for the verifier to penalise and the report to name.

    Conservative by construction: needs at least two shared content tokens
    AND negation on exactly one side, compared field by field -- a "no" in
    the mechanism must not launder an affirmative premise that denies a
    finding, and quoting a finding's own denial must not flag either.
    """
    fields = [str(h.get(k, "")) for k in ("claim", "premise", "mechanism")]
    if not any(_content_tokens(f) for f in fields):
        return []
    out = []
    for r in target_rows or []:
        if not isinstance(r, dict) or not r.get("id"):
            continue
        ftext = " ".join((str(r.get("title", "")),
                          str(r.get("rationale", ""))))
        ftoks = _content_tokens(ftext)
        fneg = _negated(ftext)
        for field in fields:
            btoks = _content_tokens(field)
            if len(btoks & ftoks) >= 2 and _negated(field) != fneg:
                out.append(str(r["id"]))
                break
    return out


def _hyp_keywords(title: str) -> list[str]:
    """Distinctive tokens of an artifact title, for evidence matching.

    Short and generic tokens are dropped: matching a claim on the word
    "model" would attach every artifact in the investigation and make the
    evidence column decorative.
    """
    stop = {"the", "and", "for", "with", "from", "that", "this", "model", "data",
            "using", "into", "your", "what", "how", "why", "are", "was", "can"}
    toks = [t for t in re.findall(r"[a-z]{5,}", title.lower()) if t not in stop]
    return toks[:8]


def _match_hyp_sources(h: dict[str, Any],
                       rows: list[dict[str, Any]]) -> list[str]:
    """Source-row ids a drafted claim can be traced to.

    The LLM is handed ids and titles but writes prose, so a claim it drafted
    arrives with an empty ``supporting`` list. Without this the verifier reads
    it as uncorroborated and the confidence aggregate collapses the moment the
    gateway comes back up -- the better-connected answer gets the worse score,
    and the report's "corroborated by both flows" column empties itself in
    production while every test run on the deterministic branch passes.

    Matching is deliberately conservative: a distinctive token must appear in
    BOTH the claim and the row, and at most four ids are taken per flow, so one
    vague claim cannot stake a claim on the entire evidence base.
    """
    blob = " ".join((str(h.get("claim", "")), str(h.get("premise", "")),
                     str(h.get("mechanism", "")),
                     str(h.get("consequence", "")))).lower()
    out: list[str] = []
    for r in rows:
        rid = r.get("id")
        if not rid:
            continue
        src = " ".join((str(r.get("title", "")), str(r.get("rationale", "")),
                        str(r.get("dimension", "")).replace("_", " "))).lower()
        toks = _hyp_keywords(src)
        if any(t in blob for t in toks) and str(rid) not in out:
            out.append(str(rid))
    return out[:4]


def _hypothesis_dimension_inputs(verified: list[dict[str, Any]],
                                 ) -> dict[str, float]:
    """Mean verifier dimension across claims, shaped for the confidence scorer.

    Mean, not max: the aggregate describes the claim SET, and a set is only as
    good as the claims that make it up. Taking the strongest claim would let
    one well-evidenced claim vouch for ten vague ones.
    """
    if not verified:
        return {}
    keys = ("evidence_support", "cross_flow_corroboration", "testability",
            "impact_if_true")
    out: dict[str, float] = {}
    for k in keys:
        vals = [float((v.get("verification_dimensions") or {}).get(k, 0.0))
                for v in verified]
        out[k] = round(sum(vals) / len(vals), 1)
    return out


def hypothesis_reporter_handle(env: dict[str, Any], db: Any = None) -> dict[str, Any]:
    """Intent ``write_hypothesis_report``: the claims as prose + diagrams.

    Each claim gets its own section with the evidence, the counter-evidence and
    the falsifier stated next to it, because a claim printed without its
    refutation is an assertion wearing a hypothesis's clothes.
    """
    from . import security as sec
    payload = env.get("payload", {})
    product = payload.get("product_name", "the model")
    verified = [h for h in (payload.get("verified") or []) if isinstance(h, dict)]
    scoring = payload.get("scoring") or {}
    lines: list[str] = ["## Hypotheses and what would settle them", ""]
    lines.append(
        f"Confidence aggregate **{scoring.get('confidence_pct', 0):g}/100** "
        f"— {_HYPOTHESIS_CAVEAT}")
    lines.append("")
    for h in verified:
        conf = h.get("confidence", 0)
        lines.append(f"### {h['id']} — {h['claim']}")
        lines.append("")
        lines.append(f"_Confidence {conf:g}/100 · stakes if true "
                     f"{h.get('impact', 0):g}/5 · refutable "
                     f"{'yes' if str(h.get('falsifier', '')).strip() else 'NO'}_")
        lines.append("")
        if h.get("premise"):
            lines.append(f"- **Premise:** {h['premise']}")
        if h.get("mechanism"):
            lines.append(f"- **Mechanism:** {h['mechanism']}")
        if h.get("consequence"):
            lines.append(f"- **If true:** {h['consequence']}")
        if h.get("falsifier"):
            lines.append(f"- **Refuted by:** {h['falsifier']}")
        if h.get("supporting"):
            lines.append(f"- **Traces to:** {', '.join(h['supporting'])}")
        if h.get("counter_evidence"):
            lines.append(f"- **Counter-evidence:** "
                         f"{', '.join(h['counter_evidence'])}")
        if h.get("contradicted_by"):
            lines.append(f"- **In tension with flow 1:** "
                         f"{', '.join(h['contradicted_by'])} — the claim and "
                         f"the finding disagree; settle it before acting on "
                         f"either.")
        if h.get("supporting_artifacts"):
            arts = ", ".join(f"#{a}" for a in h["supporting_artifacts"])
            lines.append(f"- **In-app evidence:** {arts}")
        if h.get("cross_flow"):
            lines.append("- **Corroborated:** reached independently by the "
                         "internals and misuse assessments")
        lines.append("")
        lines.append("```mermaid")
        lines.append(sec.mermaid_hypothesis_chain(h).rstrip())
        lines.append("```")
        lines.append("")
    exec_paragraph = ""
    if verified:
        # Short sentences, rounded numbers. This used to recompute the mean
        # inline (:g keeps six significant digits, hence "83.9333/100" in
        # prose) and to cram every claim into one run-on sentence. The claims
        # themselves live in the sections below; the paragraph is a pointer.
        mean = scoring.get("confidence_pct", 0)
        strongest = max(verified, key=lambda h: h.get("confidence", 0))
        stakes = max(verified, key=lambda h: h.get("impact", 0))
        exec_paragraph = (
            f"{len(verified)} testable claims at {mean:g}/100 mean confidence. "
            f"Best-evidenced: {strongest['id']} "
            f"({strongest.get('confidence', 0):g}/100). "
            f"Highest stakes: {stakes['id']} ({stakes.get('impact', 0):g}/5). "
            "Every claim below names its refutation; test the high-stakes "
            "ones first.")
    return reply_envelope(
        env, "hypothesis-reporter", "hypothesis_report_written",
        {"hypothesis_sections": "\n".join(lines),
         "exec_paragraph": exec_paragraph},
        note=(f"hypothesis report ({len(verified)} claims, {len(lines)} lines) "
              f"+ {len(exec_paragraph)}-char exec paragraph"),
    )


_HYPOTHESIS_CAVEAT = (
    "this is a CONFIDENCE aggregate, not a risk score. Higher means the claims "
    "below are better evidenced, not that the system is more dangerous."
)


# --------------------------------------- model-engineering assessment ---
# W1 (adversarial research) + W2 (adoption risk) for a model subject.
# Same envelope discipline as the other model flows: LLM first, deterministic
# fallbacks that never invent evidence, never raises.


def _model_w1_terms(meta: dict[str, Any]) -> list[str]:
    terms = [meta.get("model_name") or "", meta.get("model_family") or ""]
    terms += ["memorization", "membership inference", "training data extraction",
              "model inversion", "adversarial examples", "poisoning backdoor",
              "prompt injection", "model stealing distillation"]
    terms += list(meta.get("focus_terms") or [])[:6]
    return [t for t in terms if t]


def _model_w2_terms(meta: dict[str, Any]) -> list[str]:
    terms = [meta.get("model_name") or "", meta.get("model_family") or ""]
    terms += ["model card", "weights release limitations", "training data",
              "privacy memorization", "bias limitations", "known incidents CVEs",
              "deployment on-prem API", "eval harness monitoring"]
    terms += list(meta.get("focus_terms") or [])[:6]
    return [t for t in terms if t]


_W1_FALLBACK_MATCH: list[tuple[str, tuple[str, ...]]] = [
    ("membership_inference", ("membership inference", "member inference")),
    ("extraction", ("training data extraction", "data extraction",
                    "memorization", "memorized", "extract training")),
    ("inversion", ("model inversion", "invert", "attribute inference")),
    ("evasion", ("adversarial example", "evasion", "perturbation")),
    ("poisoning", ("poison", "backdoor", "trojan")),
    ("injection", ("prompt injection", "injection", "jailbreak")),
    ("theft", ("distill", "model stealing", "steal weights", "side channel",
                "side-channel")),
    ("cascade", ("downstream", "cascade", "deployed")),
]

_W1_FALLBACK_MITIGATIONS: dict[str, list[str]] = {
    "membership_inference": ["differential-privacy training or output perturbation",
                             "limit per-entity query volume"],
    "extraction": ["deduplicate training data", "canary sets to detect leakage"],
    "inversion": ["return labels not confidences where possible",
                  "rate-limit query access"],
    "evasion": ["input validation at the edge", "adversarial eval gates"],
    "poisoning": ["training-data provenance checks", "eval gates per release"],
    "injection": ["delimit untrusted conditioning content",
                  "instruction hierarchy"],
    "theft": ["weight access control", "query rate limits", "watermarking"],
    "cascade": ["human-in-the-loop on high-stakes decisions",
                "monitor downstream decision distribution"],
}


def _w1_fallback_findings(meta: dict[str, Any],
                          evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Evidence-keyed W1 findings without an LLM: a class is reported only
    when collected evidence actually names it. Nothing matched means no
    findings -- which scores as no-evidence, never as secure."""
    name = (meta.get("model_name") or "").lower()
    weights = meta.get("weights_source") or "unknown"
    prereq = (["open weights"] if weights == "open_weights"
              else ["query access"] if weights == "api_only"
              else ["model access (weights or API)"])
    out: list[dict[str, Any]] = []
    for cls, keys in _W1_FALLBACK_MATCH:
        hits = []
        for e in evidence or []:
            text = f"{e.get('title') or ''} {e.get('snippet') or ''}".lower()
            if any(k in text for k in keys):
                scope = ("model_specific" if name and name in text
                         else "family")
                hits.append((e.get("artifact_id"), scope))
        if not hits:
            continue
        aids = [h[0] for h in hits if h[0] is not None]
        scope = "model_specific" if any(h[1] == "model_specific"
                                        for h in hits) else "family"
        out.append({
            "attack_id": f"MA-{len(out) + 1:02d}",
            "title": f"{cls.replace('_', ' ')} ({scope})",
            "attack_class": cls,
            "applies_to": scope,
            "confidence": 0.7 if scope == "model_specific" else 0.45,
            "prerequisites": prereq,
            "evidence_artifact_ids": aids,
            "mitigations": _W1_FALLBACK_MITIGATIONS.get(cls, []),
            "residual_notes": ("family-level literature only; no "
                                "model-specific evidence collected"
                                if scope == "family" else ""),
        })
    return out


def model_adv_intel_handle(env: dict[str, Any],
                           db: Any = None) -> dict[str, Any]:
    """Intent ``map_model_attacks``: W1 attack findings from evidence.

    Analyst guidance (encoded, not suggested): prefer primary literature and
    model cards; separate capability (attacks in the literature) from
    exploitability in this deployment (weights/API, rate limits); cite family
    evidence explicitly; never claim "this checkpoint memorizes row X" without
    support; never claim "no risk" -- only "no evidence found as of" a date.
    LLM first, evidence-keyed fallback on failure.
    """
    from . import model_eval as _me
    payload = env.get("payload", {})
    meta = payload.get("model_meta") or {}
    evidence = payload.get("evidence") or []
    name = meta.get("model_name") or "the model"
    family = meta.get("model_family") or "unknown"
    findings = _w1_fallback_findings(meta, evidence)
    source = "evidence-keyed rules (no LLM)"
    try:
        from . import llm as _llm
        classes = ", ".join(sorted(_me.ATTACK_CLASSES))
        ev_lines = "\n".join(
            f"- [{e.get('artifact_id')}] {e.get('title') or ''}: "
            f"{(e.get('snippet') or '')[:200]}" for e in evidence[:20])
        sys_p = (
            "You map published attacks onto a machine-learning model. "
            "Reply with STRICT JSON only: {\"findings\": [{\"attack_class\": one of "
            f"{classes}, \"title\": str, \"applies_to\": "
            "model_specific|family|modality, \"confidence\": 0..1, "
            "\"prerequisites\": [str], \"evidence_artifact_ids\": [int], "
            "\"mitigations\": [str], \"residual_notes\": str}]}. "
            "Rules: use model_specific ONLY for evidence naming this model; "
            "otherwise family or modality. Prefer primary literature and model "
            "cards over blogs. Separate capability (attacks published) from "
            "exploitability in this deployment "
            f"(weights: {meta.get('weights_source') or 'unknown'}). "
            "Never claim this checkpoint does something unsourced; never claim "
            "\"no risk\" -- at most \"no evidence found\". Fewer findings, not "
            "invented ones.")
        user_p = (f"Model: {name}\nFamily: {family}\nEvidence:\n{ev_lines or '(none)'}")
        raw = _llm.chat([{"role": "system", "content": sys_p},
                         {"role": "user", "content": user_p}],
                        temperature=0.1, max_tokens=2000).strip()
        m = re.search(r"\{.*\}", raw, re.S)
        if not m:
            raise ValueError("model did not return a findings object")
        data = json.loads(m.group(0))
        valid_ids = {e.get("artifact_id") for e in evidence}
        llm_findings = []
        for i, f in enumerate(data.get("findings") or [], 1):
            if not isinstance(f, dict):
                continue
            cls = str(f.get("attack_class") or "other")
            if cls not in _me.ATTACK_CLASSES:
                cls = "other"
            scope = str(f.get("applies_to") or "family")
            if scope not in ("model_specific", "family", "modality"):
                scope = "family"
            try:
                conf = max(0.0, min(1.0, float(f.get("confidence", 0.5))))
            except (TypeError, ValueError):
                conf = 0.5
            llm_findings.append({
                "attack_id": str(f.get("attack_id") or f"MA-{i:02d}"),
                "title": str(f.get("title") or cls)[:160],
                "attack_class": cls, "applies_to": scope, "confidence": conf,
                "prerequisites": [str(p)[:120] for p in
                                  (f.get("prerequisites") or [])][:6],
                "evidence_artifact_ids": [
                    a for a in (f.get("evidence_artifact_ids") or [])
                    if a in valid_ids][:12],
                "mitigations": [str(x)[:200] for x in
                                (f.get("mitigations") or [])][:6],
                "residual_notes": str(f.get("residual_notes") or "")[:300]})
        if llm_findings:
            findings = llm_findings
            source = "model-adv-intel via LLM gateway"
    except Exception as exc:
        source = f"evidence-keyed rules (LLM unavailable: {exc})"
    return reply_envelope(
        env, "model-adv-intel", "model_attacks_mapped",
        {"findings": findings, "source": source},
        note=f"{len(findings)} W1 attack findings ({source})",
    )


def model_adoption_analyst_handle(env: dict[str, Any],
                                 db: Any = None) -> dict[str, Any]:
    """Intent ``rate_adoption``: W2 dimension ratings from evidence.

    Missing evidence rates ``unknown`` with an explicit documentation gap --
    the same honesty rule as product assessments. LLM first, all-unknown
    fallback on failure.
    """
    from . import model_eval as _me
    payload = env.get("payload", {})
    meta = payload.get("model_meta") or {}
    evidence = payload.get("evidence") or []
    name = meta.get("model_name") or "the model"
    dims = [{"dimension": d_id,
             "rating": "unknown",
             "rationale": "no collected evidence addresses this dimension",
             "evidence_artifact_ids": [],
             "adoption_implications": ["verify before production adoption"]}
            for d_id, _, _ in _me.ADOPTION_DIMENSIONS]
    source = "all-unknown fallback (no LLM)"
    try:
        from . import llm as _llm
        dim_list = ", ".join(d[0] for d in _me.ADOPTION_DIMENSIONS)
        ev_lines = "\n".join(
            f"- [{e.get('artifact_id')}] {e.get('title') or ''}: "
            f"{(e.get('snippet') or '')[:200]}" for e in evidence[:20])
        sys_p = (
            "You rate engineering adoption risk for a machine-learning model. "
            "Reply with STRICT JSON only: {\"dimensions\": [{\"dimension\": one of "
            f"{dim_list}, \"rating\": low|medium|high|critical|unknown, "
            "\"rationale\": str, \"evidence_artifact_ids\": [int], "
            "\"adoption_implications\": [str]}]}. "
            "Rate unknown with a documentation-gap rationale whenever evidence "
            "is absent -- never assume safe. Name downstream decision types "
            "(credit, medical, safety-critical generation) when the use case "
            "implies them. Fewer rated dimensions, not invented ones.")
        user_p = (f"Model: {name}\nFamily: {meta.get('model_family')}\n"
                  f"Weights: {meta.get('weights_source')}\n"
                  f"Training data: {meta.get('training_data_posture')}\n"
                  f"Deployment: {meta.get('deployment_pattern')}\n"
                  f"Use case: {payload.get('use_case') or ''}\n"
                  f"Evidence:\n{ev_lines or '(none)'}")
        raw = _llm.chat([{"role": "system", "content": sys_p},
                         {"role": "user", "content": user_p}],
                        temperature=0.1, max_tokens=2400).strip()
        m = re.search(r"\{.*\}", raw, re.S)
        if not m:
            raise ValueError("model did not return a dimensions object")
        data = json.loads(m.group(0))
        valid_ids = {e.get("artifact_id") for e in evidence}
        valid_dims = {d[0] for d in _me.ADOPTION_DIMENSIONS}
        by_id = {d["dimension"]: d for d in dims}
        for d in data.get("dimensions") or []:
            if not isinstance(d, dict) or d.get("dimension") not in valid_dims:
                continue
            rating = str(d.get("rating") or "unknown").lower()
            if rating not in ("low", "medium", "high", "critical", "unknown"):
                rating = "unknown"
            by_id[d["dimension"]] = {
                "dimension": d["dimension"], "rating": rating,
                "rationale": str(d.get("rationale") or "")[:400],
                "evidence_artifact_ids": [
                    a for a in (d.get("evidence_artifact_ids") or [])
                    if a in valid_ids][:12],
                "adoption_implications": [
                    str(x)[:200] for x in
                    (d.get("adoption_implications") or [])][:6]}
        dims = [by_id[d[0]] for d in _me.ADOPTION_DIMENSIONS]
        source = "model-adoption-analyst via LLM gateway"
    except Exception as exc:
        source = f"all-unknown fallback (LLM unavailable: {exc})"
    return reply_envelope(
        env, "model-adoption-analyst", "adoption_rated",
        {"dimensions": dims, "source": source},
        note=(f"{sum(1 for d in dims if d['rating'] != 'unknown')}/"
              f"{len(dims)} dimensions rated ({source})"),
    )


def _model_eval_recommendations(meta: dict[str, Any],
                                findings: list[dict[str, Any]],
                                dimensions: list[dict[str, Any]]) -> list[str]:
    """Deterministic engineering backlog from the rated risks."""
    from . import model_eval as _me
    recs: list[str] = []
    rated = {d["dimension"]: d for d in dimensions or [] if isinstance(d, dict)}
    for d_id, _, _ in _me.ADOPTION_DIMENSIONS:
        d = rated.get(d_id, {})
        if d.get("rating") in ("high", "critical"):
            recs.append(f"30-day: contain {d_id.replace('_', ' ')} -- "
                        f"{(d.get('adoption_implications') or ['mitigate before production'])[0]}")
    for f in findings or []:
        if isinstance(f, dict) and (f.get("mitigations") or []):
            recs.append(f"60-day: {f.get('mitigations')[0]} "
                        f"({f.get('attack_id')}: {f.get('title') or ''})"[:160])
    unknowns = [d_id for d_id, _, _ in _me.ADOPTION_DIMENSIONS
                if rated.get(d_id, {}).get("rating", "unknown") == "unknown"]
    for d_id in unknowns[:4]:
        recs.append(f"90-day: close the evidence gap on "
                    f"{d_id.replace('_', ' ')} before broad enablement")
    return recs[:12]


def model_eval_reporter_handle(env: dict[str, Any],
                               db: Any = None) -> dict[str, Any]:
    """Intent ``write_model_eval_report``: dual-section report + exec summary.

    Deterministic template from findings and dimensions; the LLM is only
    asked for the executive paragraph, with the template paragraph as the
    fallback -- the report never depends on phrasing luck.
    """
    from . import model_eval as _me
    payload = env.get("payload", {})
    meta = payload.get("model_meta") or {}
    name = meta.get("model_name") or "the model"
    findings = payload.get("findings") or []
    dimensions = payload.get("dimensions") or []
    w1 = payload.get("w1_scoring") or {}
    w2 = payload.get("w2_scoring") or {}
    mitigation = payload.get("mitigation") or {"plan": [], "deferred": [],
                                               "uncovered_risks": [],
                                               "roadmap": {}}
    w3 = payload.get("w3_scoring") or {}
    L: list[str] = []
    A = L.append
    A(f"# Model engineering assessment — {name}")
    A("")
    A(f"_Family:_ {meta.get('model_family')} · _Modality:_ {meta.get('modality')} · "
      f"_Weights:_ {meta.get('weights_source')} · _Training data:_ "
      f"{meta.get('training_data_posture')} · _Deployment:_ "
      f"{meta.get('deployment_pattern')}_")
    A("")
    A("## W1 — Adversarial research evaluation")
    A("")
    if findings:
        A("| Attack | Class | Applies to | Confidence | Prerequisites |")
        A("|---|---|---|---|---|")
        for f in findings:
            A(f"| {f.get('attack_id')} {f.get('title') or ''} "
              f"| {f.get('attack_class')} | {f.get('applies_to')} "
              f"| {float(f.get('confidence', 0)):.0%} "
              f"| {'; '.join(f.get('prerequisites') or ['unstated'])} |")
        A("")
        for f in findings:
            A(f"### {f.get('attack_id')} — {f.get('title') or ''}")
            A("")
            if f.get("mitigations"):
                A("**Mitigations.** " + "; ".join(f["mitigations"]) + ".")
                A("")
            if f.get("residual_notes"):
                A(f"**Residual notes.** {f['residual_notes']}")
                A("")
    else:
        A("No adversarial evidence found in the collected corpus as of this "
          "run. That is a statement about the evidence, not about the model: "
          "absence of literature is not evidence of safety.")
        A("")
    A("## W2 — Adoption risk evaluation")
    A("")
    if dimensions:
        A("| Dimension | Rating | Rationale |")
        A("|---|---|---|")
        for d in dimensions:
            A(f"| {d.get('dimension')} | {d.get('rating')} "
              f"| {(d.get('rationale') or '')[:160]} |")
        A("")
    unknowns = [d.get("dimension") for d in dimensions
                if d.get("rating") == "unknown"]
    if unknowns:
        A("**Unknown dimensions.** " + ", ".join(unknowns) + ": no evidence "
          "was collected, so these raise uncertainty rather than lowering "
          "risk. See the evidence gaps.")
        A("")
    recs = _model_eval_recommendations(meta, findings, dimensions)
    if recs:
        A("## Engineering backlog")
        A("")
        for r in recs:
            A(f"- {r}")
        A("")
    plan = mitigation.get("plan") or []
    from . import model_eval as _me
    w3_requested = "mitigation_controls" in (
        meta.get("workflows") or list(_me.WORKFLOWS))
    if w3_requested and not plan:
        A("## W3 — Mitigation plan")
        A("")
        A("No mitigations proposed: no drivers and no mitigation literature "
          "to plan against. This is insufficient evidence, not a clean bill "
          "of health.")
        A("")
    if plan or mitigation.get("deferred"):
        A("## W3 — Mitigation plan")
        A("")
        A(f"Method {w3.get('method') or 'mitigation_residual_v1'}, catalog "
          f"{w3.get('mitigation_version') or '1.0.0'}. Residuals below are "
          f"indicative planning aids: efficacy hints are priors, not "
          f"measurements, and the Mapper recommends and tracks this plan -- "
          f"it does not implement these controls.")
        A("")
        if plan:
            A("| # | Control | Burden | Residual effect | Limitations |")
            A("|---|---|---|---|---|")
            for p in plan:
                resid = (w3.get("per_class") or {})
                A(f"| {p.get('priority')} | **{p.get('control_id')}** "
                  f"{(p.get('rationale') or '')[:90]} | {p.get('burden')} | "
                  f"indicative | {(p.get('residual_limitations') or '')[:90]} |")
            A("")
            for p in plan:
                if p.get("implementation_notes"):
                    A(f"- **{p.get('control_id')} notes.** "
                      f"{p['implementation_notes']}")
            if any(p.get("implementation_notes") for p in plan):
                A("")
        for d in mitigation.get("deferred") or []:
            A(f"- **{d.get('control_id')} deferred.** {d.get('reason')}.")
        if mitigation.get("deferred"):
            A("")
        if mitigation.get("uncovered_risks"):
            A("**Still uncovered.** "
              + "; ".join(mitigation["uncovered_risks"]) + ".")
            A("")
        roadmap = mitigation.get("roadmap") or {}
        if any(roadmap.get(k) for k in ("30d", "60d", "90d")):
            A("**Roadmap.**")
            A("")
            for k in ("30d", "60d", "90d"):
                for item in roadmap.get(k) or []:
                    A(f"- **{k}:** {item}")
            A("")
    experiments = payload.get("experiments") or []
    if experiments:
        A("## Experiments — plan only")
        A("")
        A("Ranked probes for what is still open. Nothing here executes "
          "anything: execution is out of band.")
        A("")
        for e in experiments:
            A(f"- **{e.get('id')} {e.get('title')}** "
              f"[{e.get('method_type')}, effort {e.get('effort')}] — "
              f"{(e.get('rationale') or '')[:140]}")
        A("")
    report = "\n".join(L)
    exec_paragraph = (
        f"{name} ({meta.get('model_family')}) shows "
        f"{len(findings)} documented adversarial attack class(es) and "
        f"{sum(1 for d in dimensions if d.get('rating') in ('high', 'critical'))} "
        f"high-or-critical adoption dimension(s); "
        f"{len(unknowns)} dimension(s) could not be rated from collected evidence.")
    try:
        from . import llm as _llm
        raw = _llm.chat([
            {"role": "system",
             "content": ("You write one executive paragraph for a model "
                         "security assessment. Ground every claim in the data "
                         "given. Never claim 'no risk'. Reply with the "
                         "paragraph only.")},
            {"role": "user",
             "content": (f"Model: {name}\nW1 findings: {len(findings)}\n"
                         f"W2 high/critical: {sum(1 for d in dimensions if d.get('rating') in ('high', 'critical'))}\n"
                         f"Unknown dimensions: {unknowns}\n"
                         f"Template: {exec_paragraph}")}],
            temperature=0.2, max_tokens=300).strip()
        if raw:
            exec_paragraph = raw
    except Exception:
        pass
    return reply_envelope(
        env, "model-eval-reporter", "model_eval_report_written",
        {"report_markdown": report, "exec_paragraph": exec_paragraph,
         "recommendations": recs},
        note=f"W1 {len(findings)} findings, W2 "
             f"{sum(1 for d in dimensions if d.get('rating') != 'unknown')}/"
             f"{len(dimensions)} rated",
    )


def run_model_engineering_a2a_workflow(
    model_meta: dict[str, Any],
    use_case: str = "",
    focus_terms: list[str] | None = None,
    db: Any = None,
    investigation_id: Any = None,
    exposure: str = "confidential_data",
    exposure_label: str = "",
    stop_after: str | None = None,
) -> dict[str, Any]:
    """Model-engineering workflow: W1 research+intel, W2 research+analyst,
    W3 mitigation, deterministic scoring, reporter. Never raises.

    Workflows run independently per the requested subset; a skipped workflow
    leaves its section explicitly empty rather than silently absent. W3 alone
    still runs the W1/W2 collectors for signals: mitigations with zero risk
    context are not proposed. ``stop_after="analyst"`` ends after the
    mitigation analyst so the approval gate can park on the plan.
    """
    from . import model_eval as _me
    from . import security as sec
    task_id = new_task_id(prefix="mev")
    trace: list[dict[str, Any]] = [{
        "agent": "model-eval-orchestrator", "intent": "plan_model_assessment",
        "at": _now(),
        "note": (f"task {task_id}: model metadata → W1 research-collector → "
                 "model-adv-intel → W2 research-collector → "
                 "model-adoption-analyst → scoring engine → "
                 "model-eval-reporter"),
    }]
    workflows = model_meta.get("workflows") or list(_me.WORKFLOWS)
    if "mitigation_controls" in workflows and not (
            "adversarial_research" in workflows
            or "adoption_risk" in workflows):
        # W3 without risk context is not proposed: run the collectors for
        # signals so the plan has drivers, and say so on the trace.
        workflows = list(workflows) + ["adversarial_research",
                                       "adoption_risk"]
        trace.append({"agent": "model-eval-orchestrator",
                      "intent": "context_signals",
                      "at": _now(),
                      "note": "W3 requested alone: W1/W2 collectors run for "
                              "signals so mitigations have risk context"})
    name = model_meta.get("model_name") or "the model"
    skey = collector_subject_key("model_engineering", name,
                                 model_meta.get("model_family"))
    cache_hits = 0
    evidence_w1: list[dict[str, Any]] = []
    evidence_w2: list[dict[str, Any]] = []
    evidence_w3: list[dict[str, Any]] = []
    queries_run: list[str] = []
    findings: list[dict[str, Any]] = []
    dimensions: list[dict[str, Any]] = []
    w1: dict[str, Any] = {"method": "adversarial_coverage_v1",
                          "overall_pct": None}
    w2: dict[str, Any] = {"method": "adoption_risk_v1", "overall_pct": None}
    w3: dict[str, Any] = {"method": "mitigation_residual_v1"}
    mitigation: dict[str, Any] = {"plan": [], "deferred": [],
                                  "uncovered_risks": [],
                                  "roadmap": {"30d": [], "60d": [], "90d": []}}
    report_markdown = ""
    exec_paragraph = ""
    recommendations: list[str] = []
    try:
        weight = (sec.EXPOSURE_META.get(exposure, {}) or {}).get("weight", 1.0)
        if "adversarial_research" in workflows:
            env = new_envelope(
                "model-eval-orchestrator", "research-collector",
                "collect_research",
                {"product_name": name, "use_case": use_case,
                 "subject_key": skey,
                 "threat_titles": _model_w1_terms(model_meta), "top_k": 10,
                 "investigation_id": investigation_id},
                task_id=task_id, trace=trace,
                note="W1 adversarial literature from the app graph",
            )
            res = dispatch(env, db)
            trace = res["trace"]
            cache_hits += 1 if res["payload"].get("cached") else 0
            evidence_w1 = res["payload"].get("evidence", [])
            queries_run += res["payload"].get("queries_run", [])
            env = new_envelope(
                "model-eval-orchestrator", "model-adv-intel", "map_model_attacks",
                {"model_meta": model_meta, "evidence": evidence_w1},
                task_id=task_id, trace=trace,
                note="map published attacks onto this model",
            )
            res = dispatch(env, db)
            trace = res["trace"]
            findings = res["payload"].get("findings", [])
            _hop_io(trace, "model-adv-intel", "map_model_attacks",
                    f"{len(evidence_w1)} evidence items",
                    f"{len(findings)} attack findings")
            w1 = _me.score_adversarial(findings, weight)
        if "adoption_risk" in workflows:
            env = new_envelope(
                "model-eval-orchestrator", "research-collector",
                "collect_research",
                {"product_name": name, "use_case": use_case,
                 "subject_key": skey,
                 "threat_titles": _model_w2_terms(model_meta), "top_k": 10,
                 "investigation_id": investigation_id},
                task_id=task_id, trace=trace,
                note="W2 model cards and primary sources from the app graph",
            )
            res = dispatch(env, db)
            trace = res["trace"]
            cache_hits += 1 if res["payload"].get("cached") else 0
            evidence_w2 = res["payload"].get("evidence", [])
            queries_run += res["payload"].get("queries_run", [])
            env = new_envelope(
                "model-eval-orchestrator", "model-adoption-analyst",
                "rate_adoption",
                {"model_meta": model_meta, "use_case": use_case,
                 "evidence": evidence_w2},
                task_id=task_id, trace=trace,
                note="rate adoption dimensions from primary sources",
            )
            res = dispatch(env, db)
            trace = res["trace"]
            dimensions = res["payload"].get("dimensions", [])
            _hop_io(trace, "model-adoption-analyst", "rate_adoption",
                    f"{len(evidence_w2)} evidence items",
                    f"{sum(1 for d in dimensions if d.get('rating') != 'unknown')}/"
                    f"{len(dimensions)} rated")
            w2 = _me.score_adoption(dimensions, weight)
        if "mitigation_controls" in workflows:
            env = new_envelope(
                "model-eval-orchestrator", "research-collector",
                "collect_research",
                {"product_name": name, "use_case": use_case,
                 "subject_key": skey,
                 "threat_titles": _model_w3_terms(model_meta), "top_k": 10,
                 "investigation_id": investigation_id},
                task_id=task_id, trace=trace,
                note="W3 mitigation literature for this family",
            )
            res = dispatch(env, db)
            trace = res["trace"]
            cache_hits += 1 if res["payload"].get("cached") else 0
            evidence_w3 = res["payload"].get("evidence", [])
            queries_run += res["payload"].get("queries_run", [])
            env = new_envelope(
                "model-eval-orchestrator", "model-mitigation-analyst",
                "propose_model_mitigations",
                {"model_meta": model_meta, "use_case": use_case,
                 "findings": findings, "dimensions": dimensions,
                 "evidence": evidence_w3},
                task_id=task_id, trace=trace,
                note="ranked MM* plan tied to W1/W2 drivers",
            )
            res = dispatch(env, db)
            trace = res["trace"]
            mitigation = res["payload"]
            w3 = _me.score_mitigation_residual(
                findings, dimensions, mitigation.get("plan", []), weight)
            _hop_io(trace, "model-mitigation-analyst",
                    "propose_model_mitigations",
                    f"{len(evidence_w3)} evidence items",
                    f"{len(mitigation.get('plan', []))} proposed, "
                    f"{len(mitigation.get('deferred', []))} deferred")
            if stop_after == "analyst":
                return {
                    "task_id": task_id,
                    "evidence": evidence_w1 + evidence_w2 + evidence_w3,
                    "queries_run": queries_run,
                    "scoring": {"w1": w1, "w2": w2, "w3": w3,
                                "assessment_path": "model_engineering"},
                    "collector_cache_hits": cache_hits,
                    "a2a_trace": trace,
                    "model_meta": model_meta,
                    "model_attacks": findings,
                    "adoption_dimensions": dimensions,
                    "mitigation": mitigation,
                    "w3_scoring": w3,
                    "experiments": [],
                }
        experiments: list[dict[str, Any]] = []
        if "experiment_plan" in workflows:
            env = new_envelope(
                "model-eval-orchestrator", "experiment-planner",
                "plan_experiments",
                {"model_meta": model_meta,
                 "findings": findings, "dimensions": dimensions,
                 "hypotheses": [],
                 "mitigation_plan": (mitigation.get("plan") or [])},
                task_id=task_id, trace=trace,
                note="ranked probes for what is still open",
            )
            res = dispatch(env, db)
            trace = res["trace"]
            experiments = res["payload"].get("experiments", [])
            _hop_io(trace, "experiment-planner", "plan_experiments",
                    "W1/W2/MM open questions",
                    f"{len(experiments)} experiments planned")
        env = new_envelope(
            "model-eval-orchestrator", "model-eval-reporter",
            "write_model_eval_report",
            {"model_meta": model_meta, "findings": findings,
             "dimensions": dimensions, "w1_scoring": w1, "w2_scoring": w2,
             "mitigation": mitigation, "w3_scoring": w3,
             "experiments": experiments},
            task_id=task_id, trace=trace,
            note="dual-section report + exec paragraph",
        )
        res = dispatch(env, db)
        trace = res["trace"]
        report_markdown = res["payload"].get("report_markdown", "")
        exec_paragraph = res["payload"].get("exec_paragraph", "")
        recommendations = res["payload"].get("recommendations", [])
        trace.append({"agent": "model-eval-orchestrator", "intent": "score",
                      "at": _now(),
                      "note": (f"W1 {w1.get('overall_pct')} "
                               f"({w1.get('method')}) · W2 {w2.get('overall_pct')} "
                               f"({w2.get('method')}) · W3 "
                               f"{len((mitigation.get('plan') or []))} proposed "
                               f"({w3.get('method')})")})
    except Exception as exc:
        trace.append({"agent": "model-eval-orchestrator", "intent": "workflow_error",
                      "at": _now(), "note": f"{exc}"})
    return {
        "task_id": task_id,
        "evidence": evidence_w1 + evidence_w2 + evidence_w3,
        "queries_run": queries_run,
        "scope": f"model {name}",
        "known_exploits": [],
        "exploits_markdown": "",
        "exec_evidence_lines": [],
        "exec_evidence_refs": [],
        "exec_paragraph": exec_paragraph,
        "control_plan": {},
        "applicability": {},
        "evidence_confidence": {},
        "scoring": {"overall_pct": w2.get("overall_pct"),
                     "w1": w1, "w2": w2, "w3": w3,
                     "assessment_path": "model_engineering"},
        "collector_cache_hits": cache_hits,
        "a2a_trace": trace,
        "model_meta": model_meta,
        "model_attacks": findings,
        "adoption_dimensions": dimensions,
        "mitigation": mitigation,
        "w3_scoring": w3,
        "experiments": experiments,
        "report_markdown": report_markdown,
        "recommendations": recommendations,
    }


def _model_w3_terms(meta: dict[str, Any]) -> list[str]:
    terms = [meta.get("model_name") or "", meta.get("model_family") or ""]
    terms += ["differential privacy machine learning",
              "machine unlearning", "model watermarking",
              "membership inference defense", "robustness benchmark"]
    terms += list(meta.get("focus_terms") or [])[:6]
    return [t for t in terms if t]


def model_mitigation_analyst_handle(env: dict[str, Any],
                                    db: Any = None) -> dict[str, Any]:
    """Intent ``propose_model_mitigations``: W3 ranked control plan.

    The deterministic rank (prefilter + driver pressure − burden) is the
    plan's spine: the LLM only writes rationale and trims to what the
    evidence supports. Analyst guidance: propose proportionate controls
    matched to burden and evidence strength; prefer deployable controls for
    this weights_source/deployment; separate training/serving/governance
    time; state DP/watermarking/unlearning limitations; never imply the
    Mapper implements the control -- it recommends and tracks the plan.
    """
    from . import model_eval as _me
    payload = env.get("payload", {})
    meta = payload.get("model_meta") or {}
    findings = payload.get("findings") or []
    dimensions = payload.get("dimensions") or []
    evidence = payload.get("evidence") or []
    name = meta.get("model_name") or "the model"
    base_plan = _me.plan_or_empty(meta, findings, dimensions, evidence)
    _, deferred = _me.prefilter_mitigations(meta)
    valid_ids = {e.get("artifact_id") for e in evidence}
    plan = [dict(item) for item in base_plan]
    source = "deterministic rank (no LLM)"
    try:
        from . import llm as _llm
        plan_lines = "\n".join(
            f"- {p['control_id']}: addresses "
            f"{p['addresses']['attacks'] + p['addresses']['dimensions']}; "
            f"burden {p['burden']}" for p in plan[:10])
        ev_lines = "\n".join(
            f"- [{e.get('artifact_id')}] {e.get('title') or ''}: "
            f"{(e.get('snippet') or '')[:160]}" for e in evidence[:12])
        sys_p = (
            "You finalize a model-hardening plan. Reply with STRICT JSON only: "
            "{\"items\": [{\"control_id\": str, \"rationale\": str, "
            "\"efficacy_confidence\": 0..1, \"implementation_notes\": str, "
            "\"evidence_artifact_ids\": [int]}], "
            "\"uncovered_risks\": [str], "
            "\"roadmap\": {\"30d\": [str], \"60d\": [str], \"90d\": [str]}}. "
            "Rules: keep only controls from the proposed list, in an order that "
            "matches burden to exposure and evidence strength; rationale per "
            "control in one sentence naming the W1/W2 driver; efficacy is a "
            "prior, never a guarantee -- state one limitation per control via "
            "implementation_notes where it matters; separate training-time, "
            "serving-time and governance-time measures across 30/60/90d; never "
            "claim a control eliminates a risk.")
        user_p = (f"Model: {name} ({meta.get('model_family')}, "
                  f"{meta.get('weights_source')}, "
                  f"{meta.get('deployment_pattern')})\n"
                  f"Proposed plan:\n{plan_lines or '(none applicable)'}\n"
                  f"Evidence:\n{ev_lines or '(none)'}")
        raw = _llm.chat([{"role": "system", "content": sys_p},
                         {"role": "user", "content": user_p}],
                        temperature=0.1, max_tokens=2200).strip()
        m = re.search(r"\{.*\}", raw, re.S)
        if not m:
            raise ValueError("model did not return a plan object")
        data = json.loads(m.group(0))
        by_id = {p["control_id"]: p for p in plan}
        refined = []
        for it in data.get("items") or []:
            if not isinstance(it, dict) or it.get("control_id") not in by_id:
                continue
            base = dict(by_id[it["control_id"]])
            if it.get("rationale"):
                base["rationale"] = str(it["rationale"])[:300]
            try:
                base["efficacy_confidence"] = max(
                    0.0, min(1.0, float(it.get("efficacy_confidence",
                                               base["efficacy_confidence"]))))
            except (TypeError, ValueError):
                pass
            if it.get("implementation_notes"):
                base["implementation_notes"] = str(
                    it["implementation_notes"])[:300]
            base["evidence_artifact_ids"] = [
                a for a in (it.get("evidence_artifact_ids") or [])
                if a in valid_ids][:8]
            refined.append(base)
        if refined:
            plan = refined
            source = "model-mitigation-analyst via LLM gateway"
        uncovered = [str(x)[:200] for x in
                     (data.get("uncovered_risks") or [])][:8]
        roadmap = {k: [str(x)[:200] for x in (data.get("roadmap") or {}).get(k, [])][:6]
                   for k in ("30d", "60d", "90d")}
    except Exception as exc:
        source = f"deterministic rank (LLM unavailable: {exc})"
        uncovered = []
        roadmap = {"30d": [], "60d": [], "90d": []}
    rated_dims = [d for d in dimensions
                  if d.get("rating") not in (None, "", "unknown")]
    if not findings and not rated_dims and not evidence:
        # Zero risk context: an explicit empty plan, not a silent success.
        # The reporter and dossier both render this as "insufficient
        # evidence", never as a clean bill of health.
        plan = []
    if not uncovered:
        covered_classes = {c for p in plan
                           for c in p.get("addresses", {}).get("attacks", [])}
        uncovered = [f.get("attack_class") for f in findings
                     if f.get("attack_class") not in covered_classes]
        uncovered = sorted({c for c in uncovered if c})
    if not any((roadmap or {}).get(k) for k in ("30d", "60d", "90d")):
        # Deterministic backlog by burden when the model wrote none:
        # cheap controls first, structural work last.
        roadmap = {"30d": [], "60d": [], "90d": []}
        for p in plan:
            bucket = {"low": "30d", "medium": "60d"}.get(
                p.get("burden"), "90d")
            roadmap[bucket].append(
                f"{p.get('control_id')}: "
                f"{(p.get('rationale') or p.get('residual_limitations') or '')[:100]}")
    residual = _me.score_mitigation_residual(findings, dimensions, plan)
    return reply_envelope(
        env, "model-mitigation-analyst", "model_mitigations_proposed",
        {"plan": plan, "deferred": deferred, "uncovered_risks": uncovered,
         "roadmap": roadmap, "residual": residual, "source": source},
        note=f"{len(plan)} proposed, {len(deferred)} deferred ({source})",
    )


def experiment_planner_handle(env: dict[str, Any],
                              db: Any = None) -> dict[str, Any]:
    """Intent ``plan_experiments``: ranked probes for open questions.

    Deterministic mapping first (unknowns, confident attacks, open
    falsifiers, top MM validations); the LLM only sharpens titles and
    rationale. A plan with nothing to target is an explicit empty list.
    Plan only: nothing here executes anything.
    """
    from . import model_eval as _me
    payload = env.get("payload", {})
    meta = payload.get("model_meta") or {}
    base = _me.plan_experiments(
        meta, payload.get("findings") or [], payload.get("dimensions") or [],
        payload.get("hypotheses") or [], payload.get("mitigation_plan") or [])
    experiments = base["experiments"]
    source = "deterministic mapping (no LLM)"
    try:
        from . import llm as _llm
        lines = "\n".join(
            f"- {e['id']} [{e['method_type']}] {e['title']}: {e['rationale']}"
            for e in experiments[:12])
        sys_p = (
            "You sharpen an experiment plan. Reply with STRICT JSON only: "
            "{\"items\": [{\"id\": str, \"title\": str, \"rationale\": str}]}. "
            "Rules: keep every id, drop none, add none; one-sentence titles "
            "naming what is measured; rationale names the open question it "
            "settles; never promise an outcome, only information gain.")
        user_p = (f"Model: {meta.get('model_name') or 'the model'}\n"
                  f"Deployment: {meta.get('deployment_pattern')}, "
                  f"weights: {meta.get('weights_source')}\n"
                  f"Plan:\n{lines or '(empty)'}")
        raw = _llm.chat([{"role": "system", "content": sys_p},
                         {"role": "user", "content": user_p}],
                        temperature=0.1, max_tokens=1600).strip()
        m = re.search(r"\{.*\}", raw, re.S)
        if not m:
            raise ValueError("model did not return an items object")
        data = json.loads(m.group(0))
        by_id = {e["id"]: e for e in experiments}
        refined = []
        for it in data.get("items") or []:
            if not isinstance(it, dict) or it.get("id") not in by_id:
                continue
            base_item = dict(by_id[it["id"]])
            if it.get("title"):
                base_item["title"] = str(it["title"])[:160]
            if it.get("rationale"):
                base_item["rationale"] = str(it["rationale"])[:300]
            refined.append(base_item)
        if refined:
            experiments = refined
            source = "experiment-planner via LLM gateway"
    except Exception as exc:
        source = f"deterministic mapping (LLM unavailable: {exc})"
    return reply_envelope(
        env, "experiment-planner", "experiments_planned",
        {"experiments": experiments, "roadmap": base["roadmap"],
         "method": base["method"], "method_version": base["method_version"],
         "method_fingerprint": base["method_fingerprint"],
         "note": base["note"], "source": source},
        note=f"{len(experiments)} experiments planned ({source})",
    )


_MODEL_HANDLERS = {
    "experiment-planner": {"plan_experiments": experiment_planner_handle},
    "model-adv-intel": {"map_model_attacks": model_adv_intel_handle},
    "model-adoption-analyst": {"rate_adoption": model_adoption_analyst_handle},
    "model-mitigation-analyst": {"propose_model_mitigations":
                                 model_mitigation_analyst_handle},
    "model-eval-reporter": {"write_model_eval_report": model_eval_reporter_handle},
    "model-profiler": {"profile_model": model_profiler_handle},
    "model-internals": {"review_internals": model_internals_handle},
    "model-privacy": {"assess_model_privacy": model_privacy_handle},
    "model-reporter": {"write_model_report": model_reporter_handle},
    "model-adversary": {"derive_capabilities": model_adversary_handle},
    "misuse-scout": {"engineer_scenarios": misuse_scout_handle},
    "misuse-reporter": {"write_misuse_report": misuse_reporter_handle},
    "hypothesis-analyst": {"draft_hypotheses": hypothesis_analyst_handle},
    "hypothesis-verifier": {"verify_hypotheses": hypothesis_verifier_handle},
    "hypothesis-reporter": {"write_hypothesis_report": hypothesis_reporter_handle},
}


def _adversarial_dimension_inputs(scenarios: list[dict[str, Any]],
                                  ) -> list[dict[str, Any]]:
    """Per-dimension 0..100 inputs for the misuse scorer: mean scenario
    feasibility×impact per dimension, baseline where a dimension drew none.

    Deliberately NOT the internals aggregation. There, the worst finding
    dominates because a single catastrophic defect outweighs a broad set of
    small ones. Here every scenario is a choice an attacker makes, so breadth
    of reachable options is the risk: a model with five mediocre chains is more
    dangerous than one with a single unreachable one.
    """
    from . import security as sec
    by_dim: dict[str, list[float]] = {}
    for s in scenarios:
        try:
            score = float(s.get("inherent_score", 0)) / 25.0 * 100.0
        except (TypeError, ValueError):
            continue
        by_dim.setdefault(str(s.get("dimension", "capability_abuse")), []).append(score)
    out = []
    for dim_id, _weight, _desc in sec.ADVERSARIAL_DIMENSIONS:
        vals = by_dim.get(dim_id, [])
        out.append({"id": dim_id,
                    "score": sum(vals) / len(vals) if vals else 20.0})
    return out


def run_model_adversarial_a2a_workflow(
    product_name: str,
    use_case: str,
    focus: Optional[list[str]] = None,
    db: Any = None,
    investigation_id: Any = None,
    exposure_label: str = "",
    exposure: str = "confidential_data",
) -> dict[str, Any]:
    """Adversarial-misuse workflow: profiler → adversary → scout → collector →
    scoring (engine) → misuse-reporter. Never raises.

    The second model flow, and deliberately a separate assessment from
    run_model_a2a_workflow rather than a second section of it. The two answer
    different questions -- "is this model sound?" versus "what can someone
    build with it?" -- and a sound model is still a weapon. Averaging them
    would hide both. Shares the profiler (one subject, one profile) and the
    collector, but not a single agent, not a single weight, and not a single
    stored number. No standards mapping, same policy as the target path.
    """
    from . import security as sec
    task_id = new_task_id(prefix="adv")
    trace: list[dict[str, Any]] = [{
        "agent": "adversary-orchestrator", "intent": "plan_misuse_assessment",
        "at": _now(),
        "note": (f"task {task_id}: model-profiler → model-adversary → "
                 "misuse-scout → research-collector → scoring engine → "
                 "misuse-reporter (no standards mapping)"),
    }]
    focus = focus or []
    evidence: list[dict[str, Any]] = []
    queries_run: list[str] = []
    scope = ""
    capabilities: list[dict[str, Any]] = []
    unexploitable: list[str] = []
    scenarios: list[dict[str, Any]] = []
    profile: dict[str, Any] = {}
    scoring: dict[str, Any] = {}
    exec_paragraph = ""
    misuse_sections = ""
    try:
        env0 = new_envelope(
            "adversary-orchestrator", "model-profiler", "profile_model",
            {"product_name": product_name, "use_case": use_case, "focus": focus},
            task_id=task_id, trace=trace,
            note="reuse the same subject profile; capability derivation reads it",
        )
        res0 = dispatch(env0, db)
        trace = res0["trace"]
        profile = res0["payload"].get("profile", {})

        env1 = new_envelope(
            "adversary-orchestrator", "model-adversary", "derive_capabilities",
            {"product_name": product_name, "use_case": use_case,
             "focus": focus, "profile": profile},
            task_id=task_id, trace=trace,
            note="what could an attacker build with this model",
        )
        res1 = dispatch(env1, db)
        trace = res1["trace"]
        capabilities = list(res1["payload"].get("capabilities", []))
        unexploitable = list(res1["payload"].get("unexploitable", []))

        env2 = new_envelope(
            "adversary-orchestrator", "misuse-scout", "engineer_scenarios",
            {"product_name": product_name, "use_case": use_case,
             "focus": focus, "profile": profile, "capabilities": capabilities},
            task_id=task_id, trace=trace,
            note="turn capabilities into attack chains",
        )
        res2 = dispatch(env2, db)
        trace = res2["trace"]
        scenarios = list(res2["payload"].get("scenarios", []))
        _hop_io(trace, "misuse-scout", "engineer_scenarios",
                f"{len(capabilities)} capabilities in",
                f"{len(scenarios)} scenarios, top "
                f"{max((s.get('inherent_score', 0) for s in scenarios), default=0):g}/25")

        env3 = new_envelope(
            "adversary-orchestrator", "research-collector", "collect_research",
            {"product_name": product_name, "use_case": use_case,
             "threat_titles": [s["title"].split(" (from ")[0] for s in scenarios],
             "top_k": 8, "investigation_id": investigation_id},
            task_id=task_id, trace=trace,
            note="delegate agentic in-app search on the scenario set",
        )
        res3 = dispatch(env3, db)
        trace = res3["trace"]
        evidence = res3["payload"].get("evidence", [])
        queries_run = res3["payload"].get("queries_run", [])
        scope = res3["payload"].get("scope", "")
        _hop_io(trace, "research-collector", "collect_research",
                f"{len(queries_run)} queries · scope {scope or 'all'}",
                f"{len(evidence)} artifacts, top relevance "
                f"{max((e.get('relevance', 0) for e in evidence), default=0):.2f}")

        scoring = sec.score_model_adversarial(
            {d["id"]: d["score"] for d in _adversarial_dimension_inputs(scenarios)})
        trace.append({
            "agent": "adversary-orchestrator", "intent": "score",
            "at": _now(),
            "note": (f"misuse aggregate {scoring.get('overall_pct', 0):g}/100 "
                     f"({scoring.get('method', '')})"),
        })

        env4 = new_envelope(
            "adversary-orchestrator", "misuse-reporter", "write_misuse_report",
            {"product_name": product_name, "exposure_label": exposure_label,
             "profile": profile, "capabilities": capabilities,
             "scenarios": scenarios, "evidence": evidence, "scoring": scoring},
            task_id=task_id, trace=trace,
            note="draft misuse sections + exec paragraph",
        )
        res4 = dispatch(env4, db)
        trace = res4["trace"]
        misuse_sections = res4["payload"].get("misuse_sections", "")
        exec_paragraph = res4["payload"].get("exec_paragraph", "")
        _hop_io(trace, "misuse-reporter", "write_misuse_report",
                f"{len(scenarios)} scenarios, {len(evidence)} evidence items",
                f"{len(misuse_sections)} chars sections, "
                f"{len(exec_paragraph)} chars paragraph")
    except Exception as exc:
        trace.append({"agent": "adversary-orchestrator", "intent": "workflow_error",
                      "at": _now(), "note": f"{exc}"})
    return {
        "task_id": task_id,
        "evidence": evidence,
        "queries_run": queries_run,
        "scope": scope,
        "known_exploits": [],
        "exploits_markdown": "",
        "exec_evidence_lines": [],
        "exec_evidence_refs": [],
        "exec_paragraph": exec_paragraph,
        "control_plan": {},
        "applicability": {},
        "evidence_confidence": {},
        "scoring": scoring,
        "a2a_trace": trace,
        # misuse-path extras (ignored by standard consumers)
        "model_profile": profile,
        "adversarial_dimensions": scoring.get("dimensions", []),
        "adversarial_capabilities": capabilities,
        "adversarial_scenarios": scenarios,
        "adversarial_unexploitable": unexploitable,
        "misuse_sections": misuse_sections,
    }
_HANDLERS.update(_MODEL_HANDLERS)


def run_hypothesis_a2a_workflow(
    product_name: str,
    use_case: str,
    focus: Optional[list[str]] = None,
    db: Any = None,
    investigation_id: Any = None,
    target_rows: Optional[list[dict[str, Any]]] = None,
    adversarial_rows: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    """Hypothesis-synthesis workflow: analyst → collector → verifier →
    scoring (engine) → reporter. Never raises.

    The third flow, and the only one that READS the other two: it is handed
    their stored rows and turns them into falsifiable claims. That ordering is
    why it is a separate run rather than a section of either -- a claim drawn
    across both flows cannot be made until both have finished, and the queue
    claims jobs in id order, so launching it third guarantees the rows exist.

    Shares the collector with the other two (one graph, one search) and shares
    no agent and no weight with either. Its aggregate is a confidence, not a
    risk, and the scorer says so in its method string.
    """
    from . import security as sec
    task_id = new_task_id(prefix="hyp")
    trace: list[dict[str, Any]] = [{
        "agent": "hypothesis-orchestrator", "intent": "plan_hypothesis_synthesis",
        "at": _now(),
        "note": (f"task {task_id}: hypothesis-analyst → research-collector → "
                 "hypothesis-verifier → scoring engine → hypothesis-reporter "
                 f"(reads {len(target_rows or [])} internals finding(s) and "
                 f"{len(adversarial_rows or [])} misuse scenario(s))"),
    }]
    focus = focus or []
    evidence: list[dict[str, Any]] = []
    queries_run: list[str] = []
    scope = ""
    hypotheses: list[dict[str, Any]] = []
    verified: list[dict[str, Any]] = []
    scoring: dict[str, Any] = {}
    profile: dict[str, Any] = {}
    exec_paragraph = ""
    hypothesis_sections = ""
    try:
        env0 = new_envelope(
            "hypothesis-orchestrator", "model-profiler", "profile_model",
            {"product_name": product_name, "use_case": use_case, "focus": focus},
            task_id=task_id, trace=trace,
            note="the shared subject profile both prior flows used",
        )
        res0 = dispatch(env0, db)
        trace = res0["trace"]
        profile = res0["payload"].get("profile", {})

        env1 = new_envelope(
            "hypothesis-orchestrator", "hypothesis-analyst", "draft_hypotheses",
            {"product_name": product_name, "use_case": use_case,
             "focus": focus, "profile": profile,
             "target_rows": target_rows or [],
             "adversarial_rows": adversarial_rows or []},
            task_id=task_id, trace=trace,
            note="claims from what the two prior assessments found",
        )
        res1 = dispatch(env1, db)
        trace = res1["trace"]
        hypotheses = list(res1["payload"].get("hypotheses", []))
        # Carry the source ids per claim so the verifier can tell a claim both
        # flows reached from one only a single flow produced. Computed here,
        # not in the handler, because it is a join across two inputs.
        tgt_ids = {str(r.get("id")) for r in (target_rows or [])}
        adv_ids = {str(r.get("id")) for r in (adversarial_rows or [])}
        for h in hypotheses:
            sup = {str(s) for s in (h.get("supporting") or [])}
            h["supported_by_target"] = bool(sup & tgt_ids)
            h["supported_by_adversarial"] = bool(sup & adv_ids)
            h["_target_ids"] = sorted(sup & tgt_ids)
            h["_adversarial_ids"] = sorted(sup & adv_ids)
        _hop_io(trace, "hypothesis-analyst", "draft_hypotheses",
                f"{len(target_rows or [])} findings + "
                f"{len(adversarial_rows or [])} scenarios in",
                f"{len(hypotheses)} claims, "
                f"{sum(1 for h in hypotheses if h.get('falsifier'))} with falsifiers")

        env2 = new_envelope(
            "hypothesis-orchestrator", "research-collector", "collect_research",
            {"product_name": product_name, "use_case": use_case,
             "threat_titles": [h.get("claim", "") for h in hypotheses],
             "top_k": 8, "investigation_id": investigation_id},
            task_id=task_id, trace=trace,
            note="evidence for the claims, not for the product",
        )
        res2 = dispatch(env2, db)
        trace = res2["trace"]
        evidence = res2["payload"].get("evidence", [])
        queries_run = res2["payload"].get("queries_run", [])
        scope = res2["payload"].get("scope", "")
        _hop_io(trace, "research-collector", "collect_research",
                f"{len(queries_run)} queries · scope {scope or 'all'}",
                f"{len(evidence)} artifacts")

        env3 = new_envelope(
            "hypothesis-orchestrator", "hypothesis-verifier", "verify_hypotheses",
            {"product_name": product_name, "use_case": use_case,
             "hypotheses": hypotheses, "evidence": evidence,
             "target_rows": target_rows},
            task_id=task_id, trace=trace,
            note="argue with each claim; counter-evidence is the point",
        )
        res3 = dispatch(env3, db)
        trace = res3["trace"]
        verified = list(res3["payload"].get("verified", []))
        _hop_io(trace, "hypothesis-verifier", "verify_hypotheses",
                f"{len(hypotheses)} claims + {len(evidence)} artifacts in",
                f"{len(verified)} verified, mean confidence "
                f"{(sum(float(v.get('confidence', 0)) for v in verified) / len(verified)) if verified else 0:.0f}/100")

        env4_inputs = res3["payload"].get("dimension_inputs", {})
        # The confidence aggregate is arithmetic, so it runs in the engine and
        # is traced as a hop -- not dispatched to an "agent" that does not
        # exist. Same rule the other two flows follow.
        scoring = sec.score_hypotheses(env4_inputs)
        trace.append({
            "agent": "hypothesis-orchestrator", "intent": "score",
            "at": _now(),
            "note": (f"confidence aggregate {scoring.get('confidence_pct', 0):g}/100 "
                     f"({scoring.get('method', '')}) — a confidence, not a risk"),
        })

        env5 = new_envelope(
            "hypothesis-orchestrator", "hypothesis-reporter",
            "write_hypothesis_report",
            {"product_name": product_name, "use_case": use_case,
             "verified": verified, "scoring": scoring, "profile": profile},
            task_id=task_id, trace=trace,
            note="claims with confidence, evidence and falsifiers",
        )
        res5 = dispatch(env5, db)
        trace = res5["trace"]
        hypothesis_sections = res5["payload"].get("hypothesis_sections", "")
        exec_paragraph = res5["payload"].get("exec_paragraph", "")
        _hop_io(trace, "hypothesis-reporter", "write_hypothesis_report",
                f"{len(verified)} verified claims in",
                f"{len(hypothesis_sections)} chars + diagrams")
    except Exception as exc:                       # pragma: no cover - defensive
        trace.append({"agent": "hypothesis-orchestrator", "intent": "error",
                      "at": _now(), "note": f"{type(exc).__name__}: {exc}"})
        # A synthesis flow with no claims is a legitimate result: it means the
        # two prior assessments produced nothing to cross-reference. Score the
        # documented neutral baseline rather than failing the run, so the
        # report can say so in as many words.
        hypotheses = hypotheses or []
        verified = verified or []
        scoring = scoring or sec.score_hypotheses({})
        hypothesis_sections = hypothesis_sections or (
            "## Hypotheses and what would settle them\n\n"
            "_No claims were drafted: this flow had no evidence base to work "
            "from._")
    return {
        "task_id": task_id,
        "a2a_trace": trace,
        "evidence": evidence,
        "queries_run": queries_run,
        "scope": scope,
        "hypotheses": hypotheses,
        "hypothesis_verified": verified,
        "hypothesis_sections": hypothesis_sections,
        "exec_paragraph": exec_paragraph,
        "scoring": scoring,
        "model_profile": profile,
    }


def run_security_a2a_workflow(
    product_name: str,
    use_case: str,
    threat_titles: list[str],
    threat_ids: list[str],
    db: Any = None,
    investigation_id: Any = None,
    exposure_label: str = "",
    overall_pct: float = 0,
    top_k: int = 8,
    exposure: str = "confidential_data",
    declared_controls: Optional[list[str]] = None,
    score_fn: Any = None,
    focus: Optional[list[str]] = None,
    control_plan_override: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Orchestrator: control-analyst → collector → intel → writer. Never raises.

    ``score_fn`` is a deterministic callable injected by the engine: it receives
    the control-analyst plan, the intel applicability/confidence maps, and
    returns the scoring dict. It runs between threat-intel and report-writer so
    the writer quotes the real inherent/residual numbers, while all arithmetic
    stays in the engine (agents only propose and cite).
    """
    task_id = new_task_id()
    trace: list[dict[str, Any]] = [{
        "agent": "security-orchestrator", "intent": "plan_assessment",
        "at": _now(),
        "note": (f"task {task_id}: control-analyst → collector → intel → writer"),
    }]
    evidence: list[dict[str, Any]] = []
    queries_run: list[str] = []
    scope = ""
    known_exploits: list[dict[str, Any]] = []
    exploits_markdown = ""
    exec_lines: list[str] = []
    exec_refs: list[str] = []
    exec_paragraph = ""
    control_plan: dict[str, Any] = {}
    applicability: dict[str, float] = {}
    evidence_confidence: dict[str, float] = {}
    scoring: dict[str, Any] = {}
    try:
        if control_plan_override:
            # Operator approved the plan at a gate: reuse it, do not re-run the agent.
            control_plan = dict(control_plan_override)
            trace.append({
                "agent": "control-analyst", "intent": "control_plan_approved",
                "at": _now(),
                "note": (f"plan approved at gate: {len(control_plan.get('declared_controls', []))} "
                         f"control(s), confidence {control_plan.get('confidence', 0):.2f}"),
            })
        else:
            env0 = new_envelope(
                "security-orchestrator", "control-analyst", "analyse_controls",
                {"product_name": product_name, "use_case": use_case,
                 "exposure": exposure, "declared_controls": declared_controls or [],
                 "focus": focus or []},
                task_id=task_id, trace=trace,
                note="read declared controls, propose applicability + extra controls",
            )
            res0 = dispatch(env0, db)
            trace = res0["trace"]
            control_plan = res0["payload"]
        applicability = dict(control_plan.get("applicability", {}))
        base_applicability = dict(applicability)

        env1 = new_envelope(
            "security-orchestrator", "research-collector", "collect_research",
            {"product_name": product_name, "use_case": use_case,
             "threat_titles": threat_titles, "top_k": top_k,
             "investigation_id": investigation_id},
            task_id=task_id, trace=trace,
            note="delegate agentic in-app search",
        )
        res1 = dispatch(env1, db)
        trace = res1["trace"]
        evidence = res1["payload"].get("evidence", [])
        queries_run = res1["payload"].get("queries_run", [])
        scope = res1["payload"].get("scope", "")
        _hop_io(trace, "research-collector", "collect_research",
                f"{len(queries_run)} queries · scope {scope or 'all'}",
                f"{len(evidence)} artifacts, top relevance "
                f"{max((e.get('relevance', 0) for e in evidence), default=0):.2f}")

        env2 = new_envelope(
            "security-orchestrator", "threat-intel", "map_attacks",
            {"evidence": evidence, "threat_ids": threat_ids,
             "declared_controls": control_plan.get("declared_controls", []),
             "applicability": base_applicability,
             "product_name": product_name, "use_case": use_case,
             "focus": focus or []},
            task_id=task_id, trace=trace,
            note="map known attacks, join local evidence, judge applicability",
        )
        res2 = dispatch(env2, db)
        trace = res2["trace"]
        known_exploits = res2["payload"].get("known_exploits", [])
        applicability = res2["payload"].get("applicability", applicability)
        evidence_confidence = res2["payload"].get("evidence_confidence", {})
        _hop_io(trace, "threat-intel", "map_attacks",
                f"{len(evidence)} evidence items, {len(threat_ids)} threat ids",
                f"{len(known_exploits)} attacks mapped, confidence for "
                f"{len(evidence_confidence)} threats")

        if score_fn is not None:
            try:
                scoring = score_fn({
                    "control_plan": control_plan,
                    "applicability": applicability,
                    "evidence_confidence": evidence_confidence,
                }) or {}
            except Exception as exc:
                trace.append({"agent": "security-orchestrator", "intent": "score_error",
                              "at": _now(), "note": f"{exc}"})
            trace.append({
                "agent": "security-orchestrator", "intent": "score",
                "at": _now(),
                "note": (f"inherent {scoring.get('inherent_pct', 0):g}/100 → "
                         f"residual {scoring.get('residual_pct', 0):g}/100 "
                         f"({scoring.get('delta', 0):+g}) with "
                         f"{len(scoring.get('active_controls', []))} control(s)"),
            })

        env3 = new_envelope(
            "security-orchestrator", "report-writer", "write_section",
            {"known_exploits": known_exploits, "evidence": evidence,
             "product_name": product_name, "exposure_label": exposure_label,
             "overall_pct": scoring.get("inherent_pct", overall_pct),
             "inherent_pct": scoring.get("inherent_pct", overall_pct),
             "residual_pct": scoring.get("residual_pct", overall_pct),
             "control_plan": control_plan,
             "evidence_confidence": evidence_confidence},
            task_id=task_id, trace=trace,
            note="draft exploits section + exec bullets",
        )
        res3 = dispatch(env3, db)
        trace = res3["trace"]
        exploits_markdown = res3["payload"].get("exploits_markdown", "")
        exec_lines = res3["payload"].get("exec_evidence_lines", [])
        exec_refs = res3["payload"].get("exec_evidence_refs", [])
        exec_paragraph = res3["payload"].get("exec_paragraph", "")
        _hop_io(trace, "report-writer", "write_section",
                f"{len(known_exploits)} attacks, residual "
                f"{scoring.get('residual_pct', overall_pct):g}/100",
                f"{len(exec_lines)} exec bullets, {len(exec_paragraph)} chars paragraph")
    except Exception as exc:
        trace.append({"agent": "security-orchestrator", "intent": "workflow_error",
                      "at": _now(), "note": f"{exc}"})
    return {
        "task_id": task_id,
        "evidence": evidence,
        "queries_run": queries_run,
        "scope": scope,
        "known_exploits": known_exploits,
        "exploits_markdown": exploits_markdown,
        "exec_evidence_lines": exec_lines,
        "exec_evidence_refs": exec_refs,
        "exec_paragraph": exec_paragraph,
        "control_plan": control_plan,
        "applicability": applicability,
        "evidence_confidence": evidence_confidence,
        "scoring": scoring,
        "a2a_trace": trace,
    }
