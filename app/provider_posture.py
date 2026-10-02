"""Provider AGI data posture: PDP dimensions, findings, contribution map.

The question this answers is not "is the model safe" but "how safe is our
data from the labs building it": what providers collect, whether customer
content trains models, how long it is kept, who reviews it, and whether the
organisation is a datapoint directly or only through the public web.

Three honesty rules shape everything here:

1. **Stated policy, independent reporting, unknown.** A finding is only as
   strong as its evidence. Deterministic assessment yields ``partial`` at
   best; ``supported`` needs a named tier-specific term a human verified.
   Internal training mixes are non-public -- they read ``unknown``, never a
   guess.
2. **No scores for posture.** PDP findings carry standings, not residuals. A
   "LOW residual" must never read as "safe from lab training", so the
   register rows built from these findings carry no severity at all.
3. **No access is invented.** Nothing here claims knowledge of a provider's
   internal systems. Collection posture is judged from public terms and
   reputable reporting, and the gaps say so.

Fingerprinted and versioned like the other catalogs: every register row that
cites a PDP dimension carries the version and fingerprint that produced it.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

PDP_ID = "akm-provider-data-posture"
PDP_VERSION = "1.0.0"

#: Semver rule, same as the other catalogs: a patch moves no finding, a minor
#: adds or removes a dimension, a major changes what a dimension means.
PDP_CHANGELOG: dict[str, dict[str, Any]] = {
    "major": "change what a dimension means or its layer",
    "minor": "add/remove/rename a dimension",
    "patch": "wording only -- no standing may move",
    "version": PDP_VERSION,
}

#: Finding standings. ``unknown`` is the default and the most common honest
#: answer; ``contradicted`` means accepted sources disagree with each other.
STANDINGS = ("supported", "partial", "unknown", "contradicted")


def _fingerprint(payload: Any) -> str:
    canon = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                       default=str)
    return hashlib.sha1(canon.encode("utf-8")).hexdigest()[:12]


#: PDP01-PDP10. ``layer`` routes the register row: data-handling dimensions
#: are privacy rows, chain-and-contract ones are supply-chain rows. ``tiers``
#: names the product tiers the question depends on, because "does the vendor
#: train" is meaningless without "on which tier".
PDP_DIMENSIONS: list[dict[str, Any]] = [
    {"id": "PDP01", "name": "Training use of customer content",
     "question": "Does submitted content train models, by tier?",
     "layer": "privacy",
     "tiers": ["consumer", "api", "enterprise"],
     "controls": ["C04", "C11"], "process": ["PR02"],
     "evidence_terms": ["train", "training", "improve", "opt-out", "opt out",
                        "data usage", "zero retention", "no-train"]},
    {"id": "PDP02", "name": "Retention and deletion",
     "question": "How long is content kept, and can it be deleted?",
     "layer": "privacy",
     "tiers": ["consumer", "api", "enterprise"],
     "controls": ["C04", "C08"], "process": ["PR02", "PR04"],
     "evidence_terms": ["retention", "retain", "delete", "deletion",
                        "30 days", "data controls"]},
    {"id": "PDP03", "name": "Human review and abuse pipelines",
     "question": "When do staff or contractors see submitted content?",
     "layer": "privacy",
     "tiers": ["consumer", "api", "enterprise"],
     "controls": ["C06", "C12"], "process": ["PR01", "PR05"],
     "evidence_terms": ["human review", "review", "abuse", "moderation",
                        "contractor", "trust and safety"]},
    {"id": "PDP04", "name": "Subprocessors and residency",
     "question": "Who else processes the data, and where does it live?",
     "layer": "supply_chain",
     "tiers": ["api", "enterprise"],
     "controls": ["C11", "C04"], "process": ["PR02"],
     "evidence_terms": ["subprocessor", "sub-processor", "residency",
                        "region", "transfer", "data processing addendum",
                        "DPA"]},
    {"id": "PDP05", "name": "Enterprise, ZDR and contractual controls",
     "question": "What can an organisation actually contract for?",
     "layer": "supply_chain",
     "tiers": ["enterprise"],
     "controls": ["C04", "C11"], "process": ["PR02"],
     "evidence_terms": ["enterprise", "zero retention", "zero data retention",
                        "ZDR", "business associate", "contract", "workspace",
                        "admin controls"]},
    {"id": "PDP06", "name": "Evaluation and red-team data",
     "question": "Do prompts enter eval sets or red-team corpora?",
     "layer": "privacy",
     "tiers": ["consumer", "api", "enterprise"],
     "controls": ["C06", "C12"], "process": ["PR05"],
     "evidence_terms": ["eval", "evaluation", "red team", "red-team",
                        "feedback", "thumbs"]},
    {"id": "PDP07", "name": "Indirect ingestion",
     "question": "What reaches training through the public web and third parties?",
     "layer": "supply_chain",
     "tiers": [],
     "controls": ["C15"], "process": ["PR02"],
     "evidence_terms": ["crawl", "scrap", " Common Crawl", "public",
                        "third-party", "licensed data"]},
    {"id": "PDP08", "name": "Account and organisation metadata",
     "question": "What telemetry, connectors and workspace content is collected?",
     "layer": "privacy",
     "tiers": ["consumer", "api", "enterprise"],
     "controls": ["C01", "C10"], "process": ["PR01"],
     "evidence_terms": ["telemetry", "metadata", "connector", "integration",
                        "workspace", "account data"]},
    {"id": "PDP09", "name": "Downstream AGI-relevant use",
     "question": "Do stated terms allow research or model-improvement use?",
     "layer": "supply_chain",
     "tiers": ["consumer", "api"],
     "controls": ["C04"], "process": ["PR02"],
     "evidence_terms": ["research", "improve", "develop", "AGI", "frontier",
                        "model improvement"]},
    {"id": "PDP10", "name": "User-as-datapoint clarity",
     "question": "Is it plain when you are in the train/retain loop?",
     "layer": "privacy",
     "tiers": ["consumer", "api", "enterprise"],
     "controls": ["C01", "C03"], "process": ["PR01"],
     "evidence_terms": ["opt-out", "opt out", "choice", "control", "setting",
                        "privacy center"]},
]

DIMENSION_BY_ID = {d["id"]: d for d in PDP_DIMENSIONS}


def pdp_fingerprint() -> str:
    """The catalog fingerprint register rows cite."""
    return _fingerprint({"id": PDP_ID, "version": PDP_VERSION,
                         "dimensions": PDP_DIMENSIONS})


#: Canonical provider names with the aliases people actually type. Detection
#: matches on these; anything else is an explicit extra topic, never a guess.
PROVIDERS: list[dict[str, Any]] = [
    {"name": "OpenAI", "aliases": ["openai", "chatgpt", "gpt-4", "gpt-5",
                                   "o1", "o3"],
     "offerings": ["consumer chat", "API", "enterprise"]},
    {"name": "Anthropic", "aliases": ["anthropic", "claude"],
     "offerings": ["consumer chat", "API", "enterprise"]},
    {"name": "Google", "aliases": ["google", "gemini", "bard", "deepmind",
                                   "vertex"],
     "offerings": ["consumer chat", "API", "workspace", "cloud"]},
    {"name": "Meta", "aliases": ["meta", "llama", "facebook"],
     "offerings": ["consumer chat", "API", "open weights"]},
    {"name": "xAI", "aliases": ["xai", "x.ai", "grok"],
     "offerings": ["consumer chat", "API"]},
    {"name": "Mistral", "aliases": ["mistral", "mixtral", "le chat"],
     "offerings": ["consumer chat", "API", "open weights"]},
    {"name": "Cohere", "aliases": ["cohere", "command"],
     "offerings": ["API", "enterprise"]},
    {"name": "DeepSeek", "aliases": ["deepseek"],
     "offerings": ["consumer chat", "API", "open weights"]},
]

PROVIDER_BY_NAME = {p["name"].lower(): p for p in PROVIDERS}

#: Words that make a provider mention a *data* question rather than a
#: capability question. A command naming a lab without any of these is not a
#: posture investigation -- it might be asking about benchmarks.
DATA_SIGNALS = ("train", "training", "retain", "retention", "collect",
                "collection", "privacy", "private", "datapoint",
                "data point", "my data", "our data", "customer data",
                "opt-out", "opt out", "human review", "subprocessor",
                "exposure", "leak", "residency", "deletion", "delete")

#: Directions that rule a posture plan out: capability chatter without a data
#: question never becomes a provider investigation on its own.
CAPABILITY_ONLY = ("benchmark", "leaderboard", "timeline", "agi timeline",
                   "who is winning", "race", "which model is best")


def detect_providers(command: str) -> list[dict[str, Any]]:
    """Providers named in the command, in canonical form.

    No guessing: a provider appears here only when the command names it (or a
    known alias). "Plus other providers" without names produces nothing extra.
    """
    import re
    text = command or ""
    out = []
    for p in PROVIDERS:
        for alias in [p["name"]] + p["aliases"]:
            if re.search(r"\b" + re.escape(alias) + r"\b", text,
                         re.IGNORECASE):
                out.append(p)
                break
    return out


def is_posture_command(command: str) -> bool:
    """Whether the command asks a provider *data* question.

    Needs both halves: a named provider and a data-collection question. A
    capability question about a lab ("who leads on benchmarks") is not one,
    and a data question with no named provider has no subject to assess.
    """
    text = (command or "").lower()
    if any(sig in text for sig in CAPABILITY_ONLY) and \
            not any(sig in text for sig in DATA_SIGNALS):
        return False
    return bool(detect_providers(command)) and \
        sum(1 for sig in DATA_SIGNALS if sig in text) >= 1


#: Focus and anti-focus every provider topic carries. Anti-focus keeps
#: collection on policy, trust and practice sources instead of drifting into
#: capability leaderboards.
PROVIDER_FOCUS = ["training data use", "retention and deletion",
                  "API data handling", "enterprise and zero-retention tiers",
                  "subprocessors and residency", "human review pipelines"]
PROVIDER_ANTI_FOCUS = ["capability benchmarks", "model quality leaderboards",
                       "AGI timelines", "weight-leak drama"]

#: Seeded keywords so collection targets primary sources first: official
#: terms, trust material, then independent reporting.
PROVIDER_KEYWORDS = (
    "privacy policy, API data usage, training opt-out, enterprise terms, "
    "zero data retention, DPA, subprocessor list, trust center, SOC 2, "
    "security whitepaper, data retention deletion, human review disclosure, "
    "training data practices, incident report, regulatory action")


def provider_plan(command: str, exposure: str = "confidential_data",
                  max_topics: int = 6) -> dict[str, Any] | None:
    """Deterministic manager plan for a provider posture command.

    Returns None when the command is not a posture question, so the normal
    parse paths stay untouched. One topic per named provider, subject set to
    the canonical provider name -- never the verb phrase.
    """
    if not is_posture_command(command):
        return None
    providers = detect_providers(command)[:max_topics]
    if not providers:
        return None
    topics = []
    for p in providers:
        offerings = ", ".join(p["offerings"])
        topics.append({
            "title": f"{p['name']} data posture: training, retention, collection",
            "subject": p["name"],
            "task": "provider_data_posture",
            "description": (
                f"Data exposure posture of {p['name']} ({offerings}) as an "
                f"organisation would meet it: consumer, API and enterprise "
                f"tiers. Primary sources first -- privacy policy, API data "
                f"usage and training opt-out terms, enterprise and "
                f"zero-retention terms, DPA and subprocessor list, trust "
                f"center and security whitepaper (claims, not proof of "
                f"tenancy), policy changelog; secondary -- reputable "
                f"analyses of training-data practices, known incidents, "
                f"regulatory actions (labelled as secondary)."),
            "keywords": f"{p['name']}, provider_data_posture, {PROVIDER_KEYWORDS}",
            "focus": list(PROVIDER_FOCUS),
            "anti_focus": list(PROVIDER_ANTI_FOCUS),
            "exposure": None,
        })
    names = ", ".join(p["name"] for p in providers)
    return {
        "domain": "provider_data_privacy_agi",
        "exposure": exposure,
        "topics": topics,
        "summary": {
            "title": "Cross-provider data and AGI-collection posture",
            "description": (
                f"Synthesize direct/indirect datapoint risks and org "
                f"mitigations across: {names}. Compare PDP01-PDP10 per "
                f"provider, map what is shared (public web is common to all "
                f"labs), and state the enterprise-tier delta.")},
        "parsed_by": "provider_template",
    }


#: Default situation for a provider posture assessment: org confidential data
#: possibly containing PII, reached over the API by employees and service
#: accounts, processed by an external party. Stated, not measured -- the
#: operator corrects it per org.
PROVIDER_SITUATION = {
    "data": {"classification": "confidential", "pii_likelihood": True},
    "channel": "api",
    "actors": ["employees", "service_accounts"],
    "controls": {},
    "blast_radius": {},
    "external": True,
    "obligations": [],
}

#: Marker seeded into provider investigation keywords so downstream stages
#: (planner families, PDP assessment, register rows) recognise the template
#: without guessing from prose.
PROVIDER_MARKER = "provider_data_posture"


def is_provider_investigation(title: str = "", keywords: str = "",
                              description: str = "") -> bool:
    """Whether an investigation belongs to the provider posture template."""
    blob = f"{title or ''}\n{keywords or ''}\n{description or ''}".lower()
    return PROVIDER_MARKER in blob


# --------------------------------------------------------------------------
# PDP assessment: findings from accepted evidence, unknowns otherwise
# --------------------------------------------------------------------------

def blank_findings() -> list[dict[str, Any]]:
    """One unknown finding per dimension. The starting point, not a result."""
    return [{"id": d["id"], "dimension": d["name"],
             "claim_class": "data_handling", "standing": "unknown",
             "summary": "No accepted evidence assessed yet.",
             "evidence_ids": [], "tier_notes": {}}
            for d in PDP_DIMENSIONS]


def assess_pdp(accepted_artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    """Derive PDP standings from accepted artifacts only.

    A dimension with at least one accepted artifact whose title or tags carry
    its evidence terms reads ``partial``; everything else stays ``unknown``.
    ``supported`` and ``contradicted`` are never derived -- they need a human
    who read the tier-specific term and said which tier it binds. Pending or
    rejected artifacts are not evidence under any setting.

    The safety firewall: a safety-typed source (system card, RSP, eval
    literature) informs a PDP dimension only when the same document also
    states data-handling terms. A card that discusses training in the abstract
    must not move training-use-of-customer-content off unknown.
    """
    textual = []
    for a in accepted_artifacts or []:
        if not isinstance(a, dict) or a.get("review") != "accepted":
            continue
        blob = _artifact_blob(a)
        if is_safety_typed(a) and not _has_data_terms(blob):
            continue
        textual.append({"id": a.get("id"), "blob": blob,
                        "title": a.get("title") or ""})
    findings = []
    for d in PDP_DIMENSIONS:
        hits = [t for t in textual
                if any(term.strip().lower() in t["blob"]
                       for term in d["evidence_terms"] if term.strip())]
        if hits:
            findings.append({
                "id": d["id"], "dimension": d["name"],
                "claim_class": "data_handling",
                "standing": "partial",
                "summary": f"{len(hits)} accepted source(s) touch this "
                           f"dimension; tier-specific terms not verified.",
                "evidence_ids": [t["id"] for t in hits if t["id"]],
                "tier_notes": {}})
        else:
            findings.append({
                "id": d["id"], "dimension": d["name"],
                "claim_class": "data_handling",
                "standing": "unknown",
                "summary": "No accepted evidence assessed yet.",
                "evidence_ids": [], "tier_notes": {}})
    return {"method": "provider_posture_v1", "version": PDP_VERSION,
            "catalog": PDP_ID, "fingerprint": pdp_fingerprint(),
            "findings": findings,
            "note": ("Partial means a source exists, not that the practice is "
                     "confirmed. Supported needs a human who read the "
                     "tier-specific term.")}


def set_pdp_finding(findings: list[dict[str, Any]], dim_id: str, *,
                    standing: str, summary: str = "",
                    evidence_ids: list[int] | None = None,
                    actor: str = "") -> dict[str, Any]:
    """Human override of one dimension. The only path to supported/contradicted.

    Raises ValueError on an unknown dimension or standing: a finding that
    names nothing is not a finding.
    """
    if standing not in STANDINGS:
        raise ValueError(f"unknown standing: {standing}")
    for f in findings or []:
        if f.get("id") == dim_id:
            f["standing"] = standing
            if summary:
                f["summary"] = summary
            if evidence_ids is not None:
                f["evidence_ids"] = list(evidence_ids)
            if actor:
                f["reviewed_by"] = actor
            return f
    raise ValueError(f"unknown PDP dimension: {dim_id}")


def assess_posture(accepted_artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    """The full posture envelope: PDP findings plus safety context.

    Both halves derive from the same accepted sources, each under its own
    catalog and fingerprint, and the safety half can never move a PDP
    standing -- the firewall sits inside ``assess_pdp``, so every caller
    inherits it. Stored on the assessment as ``pdp_json``.
    """
    pdp = assess_pdp(accepted_artifacts)
    safety = assess_safety(accepted_artifacts)
    rlhf = assess_rlhf(accepted_artifacts)
    return {
        "method": "provider_posture_v1", "version": PDP_VERSION,
        "catalog": PDP_ID, "fingerprint": pdp_fingerprint(),
        "findings": pdp["findings"],
        "safety": safety["findings"],
        "safety_catalog": SAFETY_ID, "safety_version": SAFETY_VERSION,
        "safety_fingerprint": safety["fingerprint"],
        "rlhf": rlhf["findings"],
        "rlhf_catalog": RLHF_ID, "rlhf_version": RLHF_VERSION,
        "rlhf_fingerprint": rlhf["fingerprint"],
        "note": ("Partial means a source exists, not that the practice is "
                 "confirmed. Safety findings contextualize governance and "
                 "eval practice; posture findings alone answer data use."),
    }


def pdp_table(findings: list[dict[str, Any]]) -> str:
    """Compare-table rows: dimension, standing, evidence count. For synthesis."""
    lines = ["| Dimension | Standing | Evidence |",
             "|---|---|---|"]
    by_id = {f.get("id"): f for f in findings or []}
    for d in PDP_DIMENSIONS:
        f = by_id.get(d["id"]) or {}
        n = len(f.get("evidence_ids") or [])
        lines.append(f"| {d['id']} {d['name']} | "
                     f"{f.get('standing', 'unknown')} | "
                     f"{n} source(s) |")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Direct vs indirect contribution map
# --------------------------------------------------------------------------

#: Paths by which org data can reach a lab. ``direct`` paths run through the
#: org's own tooling (more controllable); ``indirect`` paths run through the
#: public world (less controllable, common to all labs).
CONTRIBUTION_PATHS: list[dict[str, Any]] = [
    {"edge": "training_opt_in", "id": "direct-paste", "direct": True, "name": "Employee paste into consumer chat",
     "controllability": "high", "pathways": ["LP01"],
     "guidance": "Block consumer tools for confidential data; enterprise/API-only policy."},
    {"edge": "abuse_log", "id": "direct-api-logs", "direct": True, "name": "API logs under standard terms",
     "controllability": "high", "pathways": ["LP03", "LP04"],
     "guidance": "Tier selection, retention settings, deletion runbooks."},
    {"id": "direct-connectors", "direct": True, "name": "Connectors (drive, mail, tickets)",
     "controllability": "medium", "pathways": ["LP01", "LP06"],
     "guidance": "Least-privilege connectors, DLP, allowlisted apps."},
    {"edge": "feedback_submitted", "id": "direct-feedback", "direct": True, "name": "Feedback, thumbs, bug reports with content",
     "controllability": "high", "pathways": ["LP03"],
     "guidance": "Disable content feedback on sensitive projects."},
    {"edge": "training_opt_in", "id": "direct-finetune", "direct": True, "name": "Fine-tuning jobs with org data",
     "controllability": "high", "pathways": ["LP04"],
     "guidance": "Contractual limits; know the fine-tune data retention term."},
    {"edge": "crawl", "id": "indirect-web", "direct": False, "name": "Public website and docs in web corpora",
     "controllability": "low", "pathways": ["LP07"],
     "guidance": "Public-data policy; assume public is trainable."},
    {"edge": "crawl", "id": "indirect-oss", "direct": False, "name": "Open-source code, papers, social posts",
     "controllability": "low", "pathways": ["LP07"],
     "guidance": "Assume published material trains someone's model."},
    {"id": "indirect-thirdparty", "direct": False, "name": "Third-party apps sending data to the same lab",
     "controllability": "medium", "pathways": ["LP05"],
     "guidance": "Ask vendors about their AI use; questionnaire, not trust."},
    {"id": "indirect-supplychain", "direct": False, "name": "Vendors in your supply chain using the provider",
     "controllability": "medium", "pathways": ["LP05"],
     "guidance": "Downstream AI use belongs in vendor questionnaires."},
    {"edge": "crawl", "id": "indirect-benchmarks", "direct": False, "name": "Shared benchmarks with published data",
     "controllability": "low", "pathways": [],
     "guidance": "Published benchmark data is training data in practice."},
    {"edge": "feedback_submitted", "id": "direct-safety-feedback", "direct": True, "name": "Org eval, red-team or bounty submissions",
     "controllability": "high", "pathways": ["PDP06"], "safety": True,
     "guidance": "Treat external eval and red-team participation as a data-sharing decision: scope what leaves."},
    {"edge": "crawl", "id": "indirect-safety-feedback", "direct": False, "name": "Public adversarial examples and bounty writeups",
     "controllability": "low", "pathways": [], "safety": True,
     "guidance": "Public red-team outputs train someone's model; assume published findings are ingested."},
]

PATH_BY_ID = {p["id"]: p for p in CONTRIBUTION_PATHS}


def contribution_map(register_rows: list[dict[str, Any]],
                     situations: list[dict[str, Any]] | None = None
                     ) -> dict[str, Any]:
    """Direct vs indirect contribution edges from register rows.

    A path is *active* when a register row evidences it (a leakage pathway
    derived from a stated situation, or a PDP row touching the same ground);
    otherwise it is listed as *possible but unevidenced*. The map never
    invents an active path: no situation, no active direct edge.
    """
    tags: set[str] = set()
    for s in situations or []:
        tags |= set((s or {}).get("tags") or [])
    refs = set()
    bands: dict[str, str] = {}
    for r in register_rows or []:
        if r.get("source_ref"):
            refs.add(str(r["source_ref"]))
            bands[str(r["source_ref"])] = str(
                r.get("confidence_band") or "unknown")
    active, possible = [], []
    for p in CONTRIBUTION_PATHS:
        if p.get("safety"):
            # Safety-feedback paths activate only on an evidenced eval-data
            # finding: a public red-team writeup alone does not put the org
            # in the loop.
            hit = bands.get("PDP06") in ("partial", "supported")
        else:
            hit = bool(set(p["pathways"]) & refs)
        entry = {"id": p["id"], "name": p["name"],
                 "direct": p["direct"],
                 "controllability": p["controllability"],
                 "guidance": p["guidance"],
                 "edge": p.get("edge"),
                 "status": "active" if hit else "possible"}
        (active if hit else possible).append(entry)
    return {
        "direct": [e for e in active if e["direct"]] +
                  [e for e in possible if e["direct"]],
        "indirect": [e for e in active if not e["direct"]] +
                    [e for e in possible if not e["direct"]],
        "active_count": len(active),
        "note": ("Active means a stated situation or finding evidences the "
                 "path. Possible means the shape exists whether or not this "
                 "org was seen using it."),
    }


def contribution_mermaid(cmap: dict[str, Any], provider: str = "lab") -> str:
    """Indirect/direct diagram for the synthesis artifact. Text, not a claim."""
    L = ["graph LR", f'    ORG["organisation"]']
    for e in (cmap.get("direct") or []) + (cmap.get("indirect") or []):
        node = e["id"].replace("-", "_")
        style = "" if e["status"] == "active" else ":::possible"
        if e["direct"]:
            L.append(f'    ORG -->|{e["id"]}| {node}["{e["name"]}"]')
        else:
            L.append(f'    PUB["public world / supply chain"] -->|{e["id"]}| {node}["{e["name"]}"]')
        L.append(f'    {node} --> LAB["{provider}"]')
    L.append('    classDef possible stroke-dasharray:5 5;')
    return "\n".join(L)


def datapoint_summary(provider: str, findings: list[dict[str, Any]],
                      cmap: dict[str, Any]) -> str:
    """The explicit answer: org data, individual presence, unknowns.

    Three sentences with three different burdens of proof. The unknowns are
    named because "we do not know the training mix" is the load-bearing fact
    of this whole template.
    """
    by_id = {f.get("id"): f for f in findings or []}
    train = (by_id.get("PDP01") or {}).get("standing", "unknown")
    org = (f"Org data: training use reads **{train}** under current public "
           f"terms for {provider} -- tier terms decide, and consumer defaults "
           f"are the riskiest tier. Retention, review and subprocessors are "
           f"contract questions, not model questions.")
    indiv = ("Individual presence: anything public (site, code, posts, "
             "papers) is practically trainable by some lab; consumer-account "
             "content follows the consumer tier terms.")
    unknowns = [d["id"] for d in PDP_DIMENSIONS
                if (by_id.get(d["id"]) or {}).get("standing") == "unknown"]
    unk = (f"Unknowns: {', '.join(unknowns) if unknowns else 'none open'} -- "
           f"internal training mixes, eval-set membership and contractor "
           f"visibility are non-public and stay labelled unknown.")
    return f"{org}\n\n{indiv}\n\n{unk}"


# --------------------------------------------------------------------------
# Claim guard: no definite training assertions without tier evidence
# --------------------------------------------------------------------------

#: Sentence shapes that assert a provider definitely trains on customer data.
#: Kept only when the sentence also carries tier-specific evidence terms;
#: otherwise stripped, because "definitely trains on your API data" without a
#: tier term is exactly the narrative this template must not write.
DEFINITE_TRAIN_PATTERNS = (
    "trains on your", "train on your", "uses your data to train",
    "definitely train", "certainly train", "all api data is used",
    "everything you send is used for training",
    "your api data trains",
    "rlhf is safe from memorization", "safe from memorization",
    "no memorization risk", "your api data is in the reward model",
    "is in the reward model",
)
TIER_EVIDENCE_TERMS = (
    "consumer", "enterprise", "api tier", "opt-out", "opt out",
    "zero retention", "business tier", "workspace", "DPA",
)


def guard_provider_claims(text: str) -> dict[str, Any]:
    """Strip definite training assertions that lack tier evidence.

    Returns the kept text plus what was removed, so the removal itself is
    auditable. Short fragments and headings pass through untouched; only
    sentences making the specific forbidden claim are examined.
    """
    import re
    kept, removed = [], []
    for sent in re.split(r"(?<=[.!?])\s+", text or ""):
        low = sent.lower()
        if len(sent.strip()) < 24:
            kept.append(sent)
            continue
        if any(p in low for p in DEFINITE_TRAIN_PATTERNS) and \
                not any(t in low for t in TIER_EVIDENCE_TERMS):
            removed.append(sent.strip())
            continue
        kept.append(sent)
    return {"text": " ".join(kept).strip(),
            "removed": removed,
            "removed_count": len(removed)}


# --------------------------------------------------------------------------
# AI safety research context (adjacent catalog, not posture evidence)
# --------------------------------------------------------------------------

#: Safety research informs capability, misuse, governance and evaluation
#: practice. It is supporting context, never a substitute for privacy policy
#: or data-processing evidence -- which is why it lives in its own catalog
#: with its own fingerprint, and why SAF findings can never move a PDP
#: standing (see the firewall in ``assess_pdp``).
SAFETY_ID = "akm-provider-safety-context"
SAFETY_VERSION = "1.0.0"

#: Claim classes every safety-sourced claim carries. ``data_handling`` is the
#: only class that may touch a PDP dimension, and only when the same document
#: states data use -- the class tag is what makes the firewall checkable.
CLAIM_CLASSES = ("safety_governance", "safety_eval_data", "capability",
                 "deployment_policy", "data_handling")

SAF_DIMENSIONS: list[dict[str, Any]] = [
    {"id": "SAF01", "name": "Published safety framework / RSP",
     "question": "Is there a versioned, dated safety framework?",
     "claim_class": "safety_governance",
     "evidence_terms": ["responsible scaling", "rsp", "safety framework",
                        "frontier safety", "preparedness", "safety policy"]},
    {"id": "SAF02", "name": "Safety eval / red-team disclosure",
     "question": "What eval and red-team practice is published vs opaque?",
     "claim_class": "safety_eval_data",
     "evidence_terms": ["system card", "model card", "red team", "red-team",
                        "safety evaluation", " evals", "eval ", "catastrophic"]},
    {"id": "SAF03", "name": "Safety-eval data handling",
     "question": "Does the safety process imply retention or human review?",
     "claim_class": "safety_eval_data",
     "evidence_terms": ["human review", "evaluation data", "review",
                        "logging", "retention", "eval data"]},
    {"id": "SAF04", "name": "Deployment policy vs public API",
     "question": "Is access staged, and do usage policies differ by tier?",
     "claim_class": "deployment_policy",
     "evidence_terms": ["deployment", "staged", "usage policy", "api access",
                        "structured access", "tiers"]},
    {"id": "SAF05", "name": "Incident and risk reporting posture",
     "question": "Are safety updates published as process, not PR?",
     "claim_class": "safety_governance",
     "evidence_terms": ["incident", "reporting", "transparency",
                        "safety update", "blog"]},
    {"id": "SAF06", "name": "Safety claims vs customer-data claims",
     "question": "Does any one source speak to both safety and data terms?",
     "claim_class": "data_handling",
     "evidence_terms": ["data usage", "customer data", "privacy", "training",
                        "retention"],
     "requires_data_terms": True},
]

SAF_BY_ID = {d["id"]: d for d in SAF_DIMENSIONS}


def safety_fingerprint() -> str:
    """The safety catalog fingerprint cited on stored findings."""
    return _fingerprint({"id": SAFETY_ID, "version": SAFETY_VERSION,
                         "dimensions": SAF_DIMENSIONS})


#: Tags and title terms that mark an artifact as safety-typed. A safety-typed
#: source informs SAF dimensions; it reaches a PDP dimension only with data
#: terms present (the firewall).
SAFETY_TAGS = ("ai_safety", "rsp", "model_card", "eval", "red_team", "rlhf",
               "data_practice", "deployment_policy")
SAFETY_TITLE_TERMS = ("system card", "model card", "responsible scaling",
                      "frontier safety", "red team", "red-team", "safety eval",
                      "constitutional ai", "rlhf", "preference data",
                      "preparedness")

#: Data-handling markers a safety-typed source must also carry before it may
#: inform a PDP dimension. Same document, both halves stated -- otherwise the
#: safety literature would quietly upgrade posture it says nothing about.
DATA_HANDLING_MARKERS = ("data usage", "customer data", "retention",
                         "opt-out", "opt out", "privacy", "training data",
                         "delete", "deletion", "human review")


def _artifact_blob(a: dict[str, Any]) -> str:
    return f"{a.get('title') or ''} {a.get('tags') or ''} " \
           f"{a.get('artifact_type') or ''}".lower()


def is_safety_typed(a: dict[str, Any]) -> bool:
    """Whether a source reads as AI safety literature rather than terms."""
    blob = _artifact_blob(a)
    tags = f" {(a.get('tags') or '').lower()} "
    if any(f" {t} " in tags for t in SAFETY_TAGS):
        return True
    return any(t in blob for t in SAFETY_TITLE_TERMS)


def _has_data_terms(blob: str) -> bool:
    return any(m in blob for m in DATA_HANDLING_MARKERS)


#: Title terms that mark a source as policy/terms evidence (privacy policy,
#: data-processing terms, DPA, subprocessor lists). Together with safety
#: typing, this is what the intel feed watches for re-review triggers.
POLICY_TITLE_TERMS = ("privacy policy", "data usage", "terms of service",
                      "dpa", "data processing", "subprocessor",
                      "zero retention", "opt-out", "opt out")


def is_posture_evidence(a: dict[str, Any]) -> bool:
    """Whether a source can move posture or safety findings.

    Safety literature and policy/terms sources both qualify; a CVE advisory
    or a capability essay does not. The intel feed uses this to surface new
    terms and safety publications as re-review triggers.
    """
    if (a.get("artifact_type") or "") == "cve_advisory":
        return False
    if is_safety_typed(a):
        return True
    return any(t in _artifact_blob(a) for t in POLICY_TITLE_TERMS)


def blank_safety() -> list[dict[str, Any]]:
    """One unknown SAF finding per dimension. The starting point."""
    return [{"id": d["id"], "dimension": d["name"],
             "claim_class": d["claim_class"], "standing": "unknown",
             "summary": "No accepted safety source assessed yet.",
             "evidence_ids": []}
            for d in SAF_DIMENSIONS]


def assess_safety(accepted_artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    """Derive SAF standings from accepted safety sources only.

    Same discipline as PDP: a dimension with a matching accepted source reads
    ``partial``; everything else stays ``unknown``. ``supported`` is never
    derived -- it needs a human who read the version, date or scope and said
    what it binds.
    """
    textual = []
    for a in accepted_artifacts or []:
        if not isinstance(a, dict) or a.get("review") != "accepted":
            continue
        textual.append({"id": a.get("id"), "blob": _artifact_blob(a),
                        "title": a.get("title") or ""})
    findings = []
    for d in SAF_DIMENSIONS:
        hits = [t for t in textual
                if any(term.strip().lower() in t["blob"]
                       for term in d["evidence_terms"] if term.strip())]
        if d.get("requires_data_terms"):
            hits = [t for t in hits if _has_data_terms(t["blob"])]
        if hits:
            findings.append({
                "id": d["id"], "dimension": d["name"],
                "claim_class": d["claim_class"], "standing": "partial",
                "summary": f"{len(hits)} accepted source(s) touch this "
                           f"dimension; version, date and scope unverified.",
                "evidence_ids": [t["id"] for t in hits if t["id"]]})
        else:
            findings.append({
                "id": d["id"], "dimension": d["name"],
                "claim_class": d["claim_class"], "standing": "unknown",
                "summary": "No accepted safety source assessed yet.",
                "evidence_ids": []})
    return {"method": "provider_safety_context_v1",
            "version": SAFETY_VERSION, "catalog": SAFETY_ID,
            "fingerprint": safety_fingerprint(), "findings": findings,
            "note": ("Partial means a source exists, not that the practice "
                     "is confirmed. Safety literature evidences governance "
                     "and eval practice, never secret corpus membership.")}


def set_safety_finding(findings: list[dict[str, Any]], dim_id: str, *,
                       standing: str, summary: str = "",
                       evidence_ids: list[int] | None = None,
                       actor: str = "") -> dict[str, Any]:
    """Human override of one SAF dimension. The only path to supported."""
    if standing not in STANDINGS:
        raise ValueError(f"unknown standing: {standing}")
    for f in findings or []:
        if f.get("id") == dim_id:
            f["standing"] = standing
            if summary:
                f["summary"] = summary
            if evidence_ids is not None:
                f["evidence_ids"] = list(evidence_ids)
            if actor:
                f["reviewed_by"] = actor
            return f
    raise ValueError(f"unknown SAF dimension: {dim_id}")


# --------------------------------------------------------------------------
# RLHF / preference-feedback retention (adjacent catalog)
# --------------------------------------------------------------------------

#: Preference, feedback and post-training data: the real channels by which
#: user and org interactions still become alignment data, distinct from
#: classic RLHF reward-model pipelines. Never collapsed into one "RLHF" row
#: in the UI -- the umbrella label is "preference, feedback & post-training
#: data" with the subclasses below.
RLHF_ID = "akm-rlhf-feedback-retention"
RLHF_VERSION = "1.0.0"

#: Data classes A-F from the investigation brief. Each dimension names its
#: class so the register, the tier table and the datapoint answers agree.
RLHF_CLASSES = {
    "A": "explicit preference / feedback",
    "B": "sampled human review",
    "C": "post-training / improve-the-model corpora",
    "D": "safety / abuse monitoring logs",
    "E": "contractor / labeler preference sets",
    "F": "enterprise eval / fine-tune shares",
}

RLHF_DIMENSIONS: list[dict[str, Any]] = [
    {"id": "RLHF01", "name": "Preference and feedback into training",
     "question": "Do thumbs, rankings or feedback send transcripts to training? Override opt-out?",
     "class": "A", "layer": "privacy",
     "tiers": ["consumer", "api", "enterprise"],
     "controls": ["C12", "C06"], "process": ["PR05", "PR01"],
     "evidence_terms": ["feedback", "thumbs", "thumbs-up", "thumbs up",
                        "rating", "ranking", "preference", "rate this",
                        "/feedback", "human feedback"]},
    {"id": "RLHF02", "name": "Feedback retention duration",
     "question": "How long is feedback kept; what de-identification is claimed?",
     "class": "A", "layer": "privacy",
     "tiers": ["consumer", "api", "enterprise"],
     "controls": ["C04", "C08"], "process": ["PR02", "PR04"],
     "evidence_terms": ["retention", "retain", "years", "months",
                        "de-identif", "anonym", "delete"]},
    {"id": "RLHF03", "name": "Human-review sampling",
     "question": "Who reviews sampled content; is it de-linked; how long kept?",
     "class": "B", "layer": "privacy",
     "tiers": ["consumer", "api", "enterprise"],
     "controls": ["C06", "C12"], "process": ["PR01", "PR05"],
     "evidence_terms": ["human review", "reviewer", "contractor",
                        "sampling", "sampled", "de-linked", "delinked"]},
    {"id": "RLHF04", "name": "Post-training opt-in and opt-out defaults",
     "question": "Consumer default on or off; commercial default?",
     "class": "C", "layer": "privacy",
     "tiers": ["consumer", "api", "enterprise"],
     "controls": ["C04", "C01"], "process": ["PR02"],
     "evidence_terms": ["opt-out", "opt out", "default", "improve the model",
                        "model improvement", "setting", "training"]},
    {"id": "RLHF05", "name": "Safety-log retention vs training",
     "question": "Abuse and safety window; flagged extension; separate from training claims?",
     "class": "D", "layer": "privacy",
     "tiers": ["api", "enterprise"],
     "controls": ["C08", "C04"], "process": ["PR04"],
     "evidence_terms": ["abuse", "monitoring", "safety", "flagged",
                        "30 days", "monitoring logs"]},
    {"id": "RLHF06", "name": "ZDR vs frontier safety retention",
     "question": "Can zero-retention coexist with mandatory safety retention on covered models?",
     "class": "D", "layer": "privacy",
     "tiers": ["api", "enterprise"],
     "controls": ["C04"], "process": ["PR02"],
     "evidence_terms": ["zero retention", "ZDR", "covered model",
                        "mandatory retention", "safety retention"]},
    {"id": "RLHF07", "name": "Deletion efficacy",
     "question": "Does deleting a chat exclude future training; do review copies remain?",
     "class": "A", "layer": "privacy",
     "tiers": ["consumer", "api"],
     "controls": ["C04", "C08"], "process": ["PR04"],
     "evidence_terms": ["delete", "deletion", "erase", "remove", "copy",
                        "remain"]},
    {"id": "RLHF08", "name": "Enterprise explicit share paths",
     "question": "Eval, fine-tune and feedback opt-in shares: what, where, revocable?",
     "class": "F", "layer": "privacy",
     "tiers": ["enterprise"],
     "controls": ["C04", "C11"], "process": ["PR02"],
     "evidence_terms": ["eval", "share", "fine-tune", "fine tune",
                        "opt-in", "opt in", "playground"]},
]

RLHF_BY_ID = {d["id"]: d for d in RLHF_DIMENSIONS}


def rlhf_fingerprint() -> str:
    """The RLHF catalog fingerprint cited on stored findings."""
    return _fingerprint({"id": RLHF_ID, "version": RLHF_VERSION,
                         "dimensions": RLHF_DIMENSIONS})


def blank_rlhf() -> list[dict[str, Any]]:
    """One unknown RLHF finding per dimension. The starting point."""
    return [{"id": d["id"], "dimension": d["name"],
             "class": d["class"],
             "class_name": RLHF_CLASSES[d["class"]],
             "claim_class": "data_handling", "standing": "unknown",
             "summary": "No accepted feedback-retention source assessed yet.",
             "evidence_ids": [], "tiers": list(d["tiers"])}
            for d in RLHF_DIMENSIONS]


def assess_rlhf(accepted_artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    """Derive RLHF standings from accepted sources only.

    Same discipline as PDP and SAF: a dimension with a matching accepted
    source reads ``partial``; everything else stays ``unknown``. ``supported``
    needs a human who read the duration, tier and override terms. Safety logs
    (RLHF05/06) stand on their own evidence -- "API not used for training"
    never satisfies them, and the test pins exactly that.
    """
    textual = []
    for a in accepted_artifacts or []:
        if not isinstance(a, dict) or a.get("review") != "accepted":
            continue
        textual.append({"id": a.get("id"), "blob": _artifact_blob(a),
                        "title": a.get("title") or "",
                        "url": a.get("url") or "",
                        "published": a.get("date_published") or ""})
    findings = []
    for d in RLHF_DIMENSIONS:
        hits = [t for t in textual
                if any(term.strip().lower() in t["blob"]
                       for term in d["evidence_terms"] if term.strip())]
        if hits:
            first = hits[0]
            findings.append({
                "id": d["id"], "dimension": d["name"],
                "class": d["class"],
                "class_name": RLHF_CLASSES[d["class"]],
                "claim_class": "data_handling", "standing": "partial",
                "summary": f"{len(hits)} accepted source(s) touch this "
                           f"dimension; durations, tiers and opt-out "
                           f"override unverified.",
                "evidence_ids": [t["id"] for t in hits if t["id"]],
                "tiers": list(d["tiers"]),
                "as_of": first["published"] or None,
                "source_urls": [t["url"] for t in hits if t["url"]][:4]})
        else:
            findings.append({
                "id": d["id"], "dimension": d["name"],
                "class": d["class"],
                "class_name": RLHF_CLASSES[d["class"]],
                "claim_class": "data_handling", "standing": "unknown",
                "summary": "No accepted feedback-retention source assessed yet.",
                "evidence_ids": [], "tiers": list(d["tiers"]),
                "as_of": None, "source_urls": []})
    return {"method": "rlhf_feedback_retention_v1",
            "version": RLHF_VERSION, "catalog": RLHF_ID,
            "fingerprint": rlhf_fingerprint(), "findings": findings,
            "note": ("Partial means a source exists, not that the duration "
                     "or override is confirmed. Never applied across tiers: "
                     "a consumer row says nothing about the API tier.")}


def set_rlhf_finding(findings: list[dict[str, Any]], dim_id: str, *,
                     standing: str, summary: str = "",
                     evidence_ids: list[int] | None = None,
                     actor: str = "") -> dict[str, Any]:
    """Human override of one RLHF dimension. The only path to supported."""
    if standing not in STANDINGS:
        raise ValueError(f"unknown standing: {standing}")
    for f in findings or []:
        if f.get("id") == dim_id:
            f["standing"] = standing
            if summary:
                f["summary"] = summary
            if evidence_ids is not None:
                f["evidence_ids"] = list(evidence_ids)
            if actor:
                f["reviewed_by"] = actor
            return f
    raise ValueError(f"unknown RLHF dimension: {dim_id}")


def rlhf_tier_table(provider: str,
                    findings: list[dict[str, Any]]) -> str:
    """Per-tier compare rows: dimension, class, applicable tiers, standing.

    For the provider report and the cross-lab synthesis. Tier cells name
    which tiers the question applies to; the standing never varies by tier
    unless a human recorded tier notes -- one row per dimension, no invented
    tier splits.
    """
    by_id = {f.get("id"): f for f in findings or []}
    lines = ["| Dimension | Class | Tiers | Standing | Evidence |",
             "|---|---|---|---|---|"]
    for d in RLHF_DIMENSIONS:
        f = by_id.get(d["id"]) or {}
        n = len(f.get("evidence_ids") or [])
        lines.append(f"| {d['id']} {d['name']} | {d['class']} | "
                     f"{', '.join(d['tiers'])} | "
                     f"{f.get('standing', 'unknown')} | "
                     f"{n} source(s) |")
    return "\n".join(lines)


def datapoint_answers(provider: str, rlhf: list[dict[str, Any]],
                      pdp: list[dict[str, Any]] | None = None
                      ) -> dict[str, str]:
    """Capability vs safety datapoint answers, kept separate by construction.

    Three answers with three different burdens of proof. A silent tier is an
    unknown, never a no.
    """
    by_rlhf = {f.get("id"): f for f in rlhf or []}
    g = lambda i: (by_rlhf.get(i) or {}).get("standing", "unknown")
    cap_bits = []
    if g("RLHF01") != "unknown" or g("RLHF04") != "unknown":
        cap_bits.append(
            f"consumer feedback and training defaults read "
            f"{g('RLHF01')}/{g('RLHF04')} -- check the tier terms")
    else:
        cap_bits.append("consumer feedback and training defaults unassessed")
    cap = ("Direct capability datapoint: " +
           ("yes, if " if g("RLHF04") == "partial" else "possible where ") +
           "; ".join(cap_bits) + ".")
    safety_bits = []
    if g("RLHF05") != "unknown" or g("RLHF06") != "unknown":
        safety_bits.append(
            f"safety-log retention reads {g('RLHF05')}/{g('RLHF06')}")
    else:
        safety_bits.append("safety-log retention unassessed")
    safety = ("Safety-monitoring datapoint: possible under monitoring and "
              "flagged retention even when capability training is off; " +
              "; ".join(safety_bits) + ".")
    api = ("Org API datapoint for capability training: usually no by "
           "default; yes only on an opt-in share or non-ZDR log use beyond "
           "abuse handling -- which needs its own evidence, not an "
           "inference from consumer rows.")
    return {"capability": cap, "safety": safety, "org_api": api,
            "provider": provider}

