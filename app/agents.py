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


def research_collector_handle(env: dict[str, Any], db: Any) -> dict[str, Any]:
    """Intent ``collect_research``: agentic multi-query search over local artifacts."""
    payload = env.get("payload", {})
    product_name = payload.get("product_name", "")
    use_case = payload.get("use_case", "")
    threat_titles = payload.get("threat_titles", [])
    investigation_id = payload.get("investigation_id")
    top_k = int(payload.get("top_k", 8))

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
    return reply_envelope(
        env, "research-collector", "research_collected",
        {"evidence": ranked, "queries_run": queries_run,
         "scope": scope, "artifacts_scanned": len(artifacts)},
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
# weightage in security.MODEL_DIMENSIONS. No AI-standards mapping happens
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
    A(f"## Subject profile — {product}")
    A("")
    A(f"_{profile.get('summary') or 'Unclassified model: assess conservatively.'}_")
    A("")
    if profile.get("families"):
        A(f"Family: {', '.join(profile['families'])}. ")
    if profile.get("data"):
        A(f"Processes {', '.join(profile['data'])}.")
    A("")
    A("## Internals review (weighted dimensions)")
    A("")
    for d in dimensions:
        A(f"- **{d['id']}** ({d['weight']:.0%} weight): "
          f"**{d['score']:.0f}/100**.")
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


_MODEL_HANDLERS = {
    "model-profiler": {"profile_model": model_profiler_handle},
    "model-internals": {"review_internals": model_internals_handle},
    "model-privacy": {"assess_model_privacy": model_privacy_handle},
    "model-reporter": {"write_model_report": model_reporter_handle},
}
_HANDLERS.update(_MODEL_HANDLERS)


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
