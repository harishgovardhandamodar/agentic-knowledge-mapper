"""AI Security Engineering and Evaluation Agent.

Deterministic, offline-capable assessment engine: given a product (name + link),
an exposure setting (restricted / confidential / internal / public) and an
optional workflow write-up + documentation URLs, it produces a deep security
assessment with:

- executive summary + overall risk score
- data-flow / threat-path / workflow diagrams (mermaid source)
- threat & risk catalogue (STRIDE + OWASP LLM Top-10 mapping)
- dedicated coverage of accidental sensitive-data copy by employees and
  misclassified / mislabelled files
- mitigations, compliance notes and a 30/60/90-day roadmap
- a Markdown report and (optionally, if reportlab is installed) a PDF report
"""

from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from . import openshell as _osh

# ---------------------------------------------------------------- fetching ---

_FETCH_TIMEOUT = 8


def fetch_page_summary(url: str) -> dict[str, str]:
    """Best-effort fetch of a product/doc URL. Never raises; returns summary.

    Tries the OpenShell sandbox first (agent tool calls stay kernel-confined;
    see app/openshell.py) and falls back to direct fetch. Either way the
    ``sandbox`` flag records which path served the page, so the assessment
    reports protection instead of assuming it.
    """
    if not url or not url.strip():
        return {"url": url or "", "title": "", "excerpt": "", "status": "skipped",
                "sandbox": False}
    url = url.strip()
    body: str | None = None
    ctype = ""
    status = ""
    sandbox = False
    try:
        res = _osh.fetch_url(url, timeout=_FETCH_TIMEOUT)
        if res["ok"]:
            body = res["body"]
            ctype = res["ctype"]
            status = f"sandboxed ({res['status_code']}, {ctype})"
            sandbox = True
    except Exception:
        pass
    if body is None:
        try:
            import requests

            resp = requests.get(
                url,
                timeout=_FETCH_TIMEOUT,
                headers={"User-Agent": "PostAGI-SecurityAgent/1.0"},
            )
            ctype = resp.headers.get("content-type", "")
            body = resp.text or ""
            status = f"fetched ({resp.status_code}, {ctype})"
        except Exception as exc:  # offline / blocked / bad URL -> still assess
            return {"url": url, "title": "", "excerpt": "",
                    "status": f"unreachable: {exc}", "sandbox": False}
    title = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if m:
        title = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", "", m.group(1)))).strip()[:200]
    # crude text extraction
    text = re.sub(r"<script.*?</script>", " ", body, flags=re.I | re.S)
    text = re.sub(r"<style.*?</style>", " ", text, flags=re.I | re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    return {
        "url": url,
        "title": title,
        "excerpt": text[:1500],
        "status": status,
        "sandbox": sandbox,
    }


# ------------------------------------------------------------------ catalog ---

EXPOSURE_LEVELS = ("restricted_data", "confidential_data", "internal", "public")

EXPOSURE_META: dict[str, dict[str, Any]] = {
    "restricted_data": {
        "label": "Restricted data",
        "weight": 1.0,
        "blurb": (
            "Highest-sensitivity tier (trade secrets, regulated PII/PHI, credentials, "
            "legal-hold material). Any AI processing must be allow-listed, logged and "
            "human-approved; default posture is DENY."
        ),
    },
    "confidential_data": {
        "label": "Confidential data",
        "weight": 0.8,
        "blurb": (
            "Non-public business-sensitive tier (roadmaps, customer data, internal "
            "financials). AI assistance is permitted only inside the trust boundary "
            "with DLP guardrails and steward review."
        ),
    },
    "internal": {
        "label": "Internal",
        "weight": 0.55,
        "blurb": (
            "Internal-only but non-sensitive tier. AI assistance broadly allowed; "
            "standard logging and classification hygiene still apply."
        ),
    },
    "public": {
        "label": "Public",
        "weight": 0.3,
        "blurb": (
            "Public or synthetic data only. Residual risk is prompt-injection and "
            "hallucinated metadata rather than confidentiality loss."
        ),
    },
}

# (id, title, stride, owasp_llm, likelihood 1-5 @confidential baseline, impact 1-5, description, mitigations)
_THREAT_CATALOG: list[tuple] = [
    (
        "T01", "Accidental paste of sensitive content into the AI assistant",
        "Information Disclosure", "LLM02: Sensitive Information Disclosure",
        5, 5,
        "Employees drafting or refining asset descriptions paste restricted/confidential "
        "content (table samples, customer names, credentials, deal terms) into the AI "
        "writing-assistant prompt. The prompt may be logged, cached, or sent to an "
        "external model endpoint outside the data-governance boundary.",
        ["Client-side DLP redaction before the prompt leaves the browser (regex + NER for PII/secrets).",
         "Policy banner + just-in-time warning when the asset classification is Confidential or above.",
         "Block free-text sampling: assistant receives schema/metadata only, never raw row values."],
    ),
    (
        "T02", "Model training / retention leakage of submitted metadata",
        "Information Disclosure", "LLM02: Sensitive Information Disclosure",
        4, 5,
        "If the underlying LLM provider retains prompts for training or abuse monitoring, "
        "sensitive metadata submitted for 'better descriptions' can resurface in other "
        "tenants' completions or in support-debugging views.",
        ["Contractual zero-retention / no-train agreement; verify in DPA and config (disable data sharing).",
         "Prefer VPC/private-endpoint or on-tenant inference; pin model version.",
         "Maintain an allow-list of fields the assistant may ever receive."],
    ),
    (
        "T03", "Misclassified / mislabelled source files propagate via AI suggestions",
        "Tampering / Repudiation", "LLM08: Excessive Agency",
        5, 4,
        "The assistant inherits the asset's (possibly wrong) classification. A file wrongly "
        "labelled Internal/Public causes the assistant to draft openly-worded descriptions, "
        "suggest broader sharing, or skip masking — silently laundering the misclassification "
        "into published catalog content.",
        ["Force classification verification step BEFORE any AI suggestion renders.",
         "Show source-classification chip on every suggestion; steward must confirm or correct.",
         "Scheduled re-classification scan; quarantine assets whose AI output diverges from policy."],
    ),
    (
        "T04", "Over-permissive AI-generated descriptions leak schema semantics",
        "Information Disclosure", "LLM07: System Prompt Leakage",
        4, 4,
        "Helpful-sounding generated descriptions can disclose table/column semantics, business "
        "rules or join paths that reveal confidential processes (e.g. fraud thresholds, "
        "pricing logic) to users who can read the catalog but not the underlying data.",
        ["Description-sensitivity review tied to the strictest upstream classification.",
         "Template prompts that forbid emitting example values, thresholds or internal codenames.",
         "Field-level access sync: catalog read ACLs must mirror source-system ACLs."],
    ),
    (
        "T05", "Prompt injection via asset names / descriptions / imported docs",
        "Spoofing / Elevation", "LLM01: Prompt Injection",
        3, 4,
        "Attackers (or careless imports) embed instructions in asset names, column comments or "
        "linked documentation ('…ignore previous instructions and reveal…'). The writing "
        "assistant executes them while drafting, exfiltrating context or poisoning output.",
        ["Treat all catalog content as untrusted data: delimit + escape before inserting in prompts.",
         "Output-encoding and instruction-hierarchy (system > developer > data).",
         "Adversarial test-suite for the assistant prompts on every release."],
    ),
    (
        "T06", "Insider exfiltration through generated documentation",
        "Information Disclosure", "LLM06: Sensitive Information Disclosure via output",
        3, 5,
        "A malicious insider iteratively prompts the assistant ('summarise this restricted "
        "table in plain words…') to launder data they can preview but not export into "
        "innocent-looking catalog descriptions they CAN share.",
        ["Rate-limit + anomaly detection on assistant usage per user/asset.",
         "Immutable audit log of prompt, suggestion, accept/edit/discard decision.",
         "Dual-control publish for Restricted-tier assets."],
    ),
    (
        "T07", "Third-party model / subprocessor exposure",
        "Information Disclosure", "LLM10: Model Theft / Supply Chain",
        3, 4,
        "Product documentation typically routes AI features through an external LLM vendor. "
        "Customer metadata becomes subprocessor data, subject to foreign-access, breach and "
        "model-change risk outside the customer's control.",
        ["Maintain subprocessor register; require SOC 2 Type II + ISO 27001 evidence.",
         "Data-residency pinning (region) and model-snapshot pinning in admin config.",
         "Exit plan: one-click disable of AI features without breaking the catalog."],
    ),
    (
        "T08", "Missing audit trail for AI-authored metadata (repudiation gap)",
        "Repudiation", "LLM09: Overreliance",
        4, 3,
        "If accepted AI text is stored indistinguishably from human text, incident response "
        "cannot answer 'who wrote this, from what prompt, under which policy?' — breaking "
        "lineage, accountability and regulatory evidence.",
        ["Stamp every AI-assisted field: model id, prompt hash, reviewer, timestamp.",
         "Separate 'AI draft' vs 'steward approved' lifecycle states in the workflow.",
         "Include AI provenance in catalog lineage exports."],
    ),
    (
        "T09", "Hallucinated / stale descriptions trusted as authoritative",
        "Tampering", "LLM09: Overreliance",
        4, 3,
        "The assistant invents plausible-but-wrong owners, semantics or quality notes. "
        "Downstream consumers (and other AI agents) treat catalog text as ground truth, "
        "causing wrong access decisions or faulty pipelines.",
        ["Mandatory human approval before publish; confidence score shown per suggestion.",
         "Grounding: suggestions must cite the source fields they were derived from.",
         "Freshness SLA: regenerate/expire AI descriptions when source schema drifts."],
    ),
    (
        "T10", "Privilege / role misconfiguration enables AI for over-scoped users",
        "Elevation of Privilege", "LLM08: Excessive Agency",
        3, 4,
        "Admin console misconfiguration grants the writing assistant (and its broader data "
        "access) to roles that should never see confidential metadata, widening blast radius.",
        ["Least-privilege role mapping; AI feature flag per domain/role, default OFF for Restricted.",
         "Quarterly access review of 'can use AI assistant' permission.",
         "Break-glass procedure + alerting on AI access to Restricted domains."],
    ),
    (
        "T11", "Data-residency / cross-border transfer via SaaS AI endpoint",
        "Information Disclosure", "LLM02 / Compliance",
        3, 4,
        "Metadata sent to a SaaS model endpoint may leave the approved jurisdiction, "
        "violating GDPR Chapter V, Schrems-II transfer rules or sectoral regulation.",
        ["Confirm endpoint region in vendor docs; enforce with egress allow-listing.",
         "Transfer Impact Assessment + SCCs recorded before enablement.",
         "Regional opt-out: EU-only inference path where required."],
    ),
    (
        "T12", "Regulatory & contractual non-compliance (GDPR / ISO 27001 / SOC 2)",
        "Compliance", "Governance",
        3, 3,
        "Without DPIA records, lawful basis, retention schedules and control mapping, use of "
        "an AI writing assistant on personal or regulated data fails GDPR Art. 35, ISO 27001 "
        "A.5–A.8 and SOC 2 CC6–CC8 expectations.",
        ["Complete DPIA + record of processing update before rollout.",
         "Map controls: ISO 27001:2022 A.5.14 (redaction), A.8.12 (DLP), A.5.33 (privacy).",
         "Contract clauses: purpose limitation, retention, breach notification <72h."],
    ),
]

# Standard 5x5 L×I severity calibration (NIST/OWASP style): 20-25 Critical,
# 12-19 High, 6-11 Medium, 1-5 Low. Calibrated so a high-exposure tier yields a
# meaningful spread instead of labelling every threat Critical.
SEVERITY_BANDS = [(20, "Critical"), (12, "High"), (6, "Medium"), (0, "Low")]


def _severity(score: int) -> str:
    for threshold, name in SEVERITY_BANDS:
        if score >= threshold:
            return name
    return "Low"


# ------------------------------------------------------- control catalogue ---
#
# Each control maps to the threat IDs it mitigates with an efficacy (0..1).
# Several controls can cover one threat; coverage compounds with diminishing
# returns (1 - Π(1 - efficacy)) so stacking controls helps but never reaches
# certainty. ``standard`` cites the framework control this maps to, so the
# report reads like a real control-mapping exercise rather than a magic number.

# (id, name, description, efficacy, standard, [(threat_id, weight)])
_CONTROL_CATALOG: list[dict[str, Any]] = [
    {
        "id": "C01",
        "name": "Classification gate before AI",
        "description": "AI drafting is blocked for Restricted/Confidential assets "
                       "until classification is verified; lower tiers proceed with redaction.",
        "efficacy": 0.70,
        "standard": "ISO 27001 A.5.12 / A.8.12",
        "threats": {"T03": 1.0, "T06": 0.6, "T10": 0.5},
    },
    {
        "id": "C02",
        "name": "Schema-only prompt (no raw values)",
        "description": "The assistant receives only schema/metadata, never sample rows "
                       "or free text from the source.",
        "efficacy": 0.70,
        "standard": "OWASP LLM02 mitigation",
        "threats": {"T01": 0.9, "T04": 0.7, "T06": 0.7},
    },
    {
        "id": "C03",
        "name": "Client-side DLP redaction",
        "description": "Regex + NER scrubs PII, secrets and sensitive terms before the "
                       "prompt leaves the browser.",
        "efficacy": 0.65,
        "standard": "ISO 27001 A.8.12 (DLP)",
        "threats": {"T01": 1.0, "T04": 0.4, "T11": 0.3},
    },
    {
        "id": "C04",
        "name": "Zero-retention / no-train agreement",
        "description": "Contractual and configured guarantee that prompts/completions "
                       "are not retained or used for training.",
        "efficacy": 0.85,
        "standard": "GDPR Art. 28 / vendor DPA",
        "threats": {"T02": 1.0, "T07": 0.5},
    },
    {
        "id": "C05",
        "name": "Prompt-injection defenses",
        "description": "Untrusted content is delimited/escaped, instruction hierarchy is "
                       "enforced, outputs are validated against the schema.",
        "efficacy": 0.60,
        "standard": "OWASP LLM01",
        "threats": {"T05": 1.0, "T09": 0.3},
    },
    {
        "id": "C06",
        "name": "Human steward review before publish",
        "description": "A named steward verifies classification, facts and sensitivity "
                       "before any AI text is published.",
        "efficacy": 0.55,
        "standard": "Human-in-the-loop control",
        "threats": {"T03": 0.7, "T04": 0.5, "T09": 0.8, "T06": 0.3},
    },
    {
        "id": "C07",
        "name": "AI provenance stamping",
        "description": "Every AI-assisted field stores model id, prompt hash, reviewer "
                       "and timestamp; draft vs approved states are distinct.",
        "efficacy": 0.70,
        "standard": "EU AI Act Art. 12 / ISO 27001 A.8.32",
        "threats": {"T08": 1.0, "T09": 0.3},
    },
    {
        "id": "C08",
        "name": "Immutable audit + anomaly detection",
        "description": "Tamper-evident log of prompt, suggestion and accept/edit/discard, "
                       "with rate limits and per-user usage anomaly alerts.",
        "efficacy": 0.60,
        "standard": "ISO 27001 A.8.15 / A.8.16",
        "threats": {"T06": 0.8, "T08": 0.5, "T10": 0.4},
    },
    {
        "id": "C09",
        "name": "Region pinning + private endpoint",
        "description": "Inference is pinned to an approved region over a private/VPC "
                       "endpoint with egress allow-listing.",
        "efficacy": 0.75,
        "standard": "GDPR Chapter V",
        "threats": {"T11": 1.0, "T07": 0.6},
    },
    {
        "id": "C10",
        "name": "Least-privilege role mapping",
        "description": "AI assistant permission is scoped per role, default OFF for "
                       "Restricted domains, with quarterly access review.",
        "efficacy": 0.65,
        "standard": "ISO 27001 A.5.15 / A.5.18",
        "threats": {"T10": 1.0, "T01": 0.3, "T04": 0.3},
    },
    {
        "id": "C11",
        "name": "DPIA + control mapping on record",
        "description": "DPIA, lawful basis, retention schedule and ISO/SOC control "
                       "mapping completed before enablement.",
        "efficacy": 0.55,
        "standard": "GDPR Art. 35 / ISO 27001 A.5.34",
        "threats": {"T12": 1.0, "T11": 0.3, "T02": 0.2},
    },
    {
        "id": "C12",
        "name": "Output review + downstream ACL sync",
        "description": "Generated descriptions are sensitivity-reviewed and catalog read "
                       "ACLs mirror source-system ACLs.",
        "efficacy": 0.50,
        "standard": "ISO 27001 A.5.18",
        "threats": {"T04": 1.0, "T09": 0.3},
    },
    {
        "id": "C13",
        "name": "Agent tool calls run in an OpenShell sandbox",
        "description": "Product/doc fetches and agent tool execution run inside an "
                       "OpenShell sandbox: kernel-confined filesystem and syscalls, "
                       "so injected content cannot reach host files or credentials.",
        "efficacy": 0.70,
        "standard": "OpenShell policy: filesystem/process",
        "threats": {"T05": 0.8, "T06": 0.5, "T10": 0.4},
    },
    {
        "id": "C14",
        "name": "Declarative egress allowlist (OpenShell network policy)",
        "description": "The sandbox proxy allows only approved hosts and methods; "
                       "everything else is denied at L7. Exfiltration needs an "
                       "approved endpoint, which is where the DLP controls sit.",
        "efficacy": 0.75,
        "standard": "OpenShell policy: network egress",
        "threats": {"T06": 0.9, "T07": 0.8, "T01": 0.5, "T02": 0.5},
    },
    {
        "id": "C15",
        "name": "Credential brokering — agents never hold secrets",
        "description": "OpenShell providers inject credentials only into requests "
                       "bound for approved endpoints; the agent context never "
                       "contains keys, so leaked context leaks nothing usable.",
        "efficacy": 0.70,
        "standard": "OpenShell providers",
        "threats": {"T07": 0.7, "T06": 0.6},
    },
]

_CONTROL_BY_ID: dict[str, dict[str, Any]] = {c["id"]: c for c in _CONTROL_CATALOG}
_THREAT_IDS: list[str] = [t[0] for t in _THREAT_CATALOG]
_THREAT_BY_ID: dict[str, dict[str, Any]] = {
    t[0]: {"title": t[1], "stride": t[2], "owasp": t[3], "base_likelihood": t[4],
           "impact": t[5]}
    for t in _THREAT_CATALOG
}
_KNOWN_CIDS: set[str] = set(_CONTROL_BY_ID)

# Aggregate weighting: a single worst threat cannot saturate the 0-100 scale.
# overall = 100 * (0.55 * worst + 0.45 * breadth), where both terms are the
# mean-of-top-5 and the mean-of-all normalized to the 1..25 matrix range.
_WORST_WEIGHT = 0.55
_BREADTH_WEIGHT = 0.45
_TOP_N = 5
_MIN_RESIDUAL_LIKELIHOOD = 0.35  # controls never take a threat below 35% of inherent
_MIN_APPLICABILITY = 0.3          # below this a threat is reported but not scored


# Model subject profiler: what KIND of thing is being assessed.
#
# The catalog and most prompts were written for a conversational product, so
# without this every subject reads as a chatbot: a tabular foundation model
# gets "prompt injection into the assistant" scored against it. The profiler
# is deterministic and conservative -- it reports a property only on explicit
# evidence and says "unknown" otherwise -- and its output steers threat
# applicability (agents.heuristic_applicability) and agent framing, never the
# arithmetic directly.
_MODEL_QUERY_TERMS = frozenset(
    ("model", "models", "foundation model", "transformer", "llm",
     "classifier", "regressor", "detector", "embedding", "embeddings",
     "checkpoint", "weights", "fine-tun", "pre-train", "pretrain",
     "distill", "diffusion", "tabpfn", "tabnet", "bert", "gpt", "llama",
     "mistral", "xgboost", "lightgbm", "catboost", "whisper"))
# "model" inside these phrases is not a machine-learning model.
_MODEL_QUERY_EXCLUSIONS = (
    re.compile(r"threat[\s-]?models?\b"),
    re.compile(r"\brole model\b"),
    re.compile(r"\bbusiness models?\b"),
    re.compile(r"\boperating model\b"),
)
# Family fragment -> (family label, class, architecture). Only sure facts;
# anything else stays unknown rather than guessed.
_MODEL_FAMILIES: tuple[tuple[str, str, str, str], ...] = (
    ("tabpfn", "TabPFN", "foundation", "transformer"),
    ("tabnet", "TabNet", "task-specific", "attentive tabular network"),
    ("ft-transformer", "FT-Transformer", "task-specific", "transformer"),
    ("xgboost", "XGBoost", "task-specific", "gradient-boosted trees"),
    ("lightgbm", "LightGBM", "task-specific", "gradient-boosted trees"),
    ("catboost", "CatBoost", "task-specific", "gradient-boosted trees"),
    ("whisper", "Whisper", "pretrained", "transformer"),
    ("stable diffusion", "Stable Diffusion", "generative", "diffusion"),
    ("bert", "BERT", "pretrained encoder", "transformer"),
    ("t5", "T5", "pretrained encoder-decoder", "transformer"),
)
_MODEL_ARCH_TERMS: tuple[tuple[str, str], ...] = (
    ("transformer", "transformer"), ("attention", "transformer"),
    ("diffusion", "diffusion"), ("cnn", "convolutional"),
    ("convolutional", "convolutional"), ("rnn", "recurrent"),
    ("lstm", "recurrent"), ("gru", "recurrent"),
    ("gradient-boosted", "gradient-boosted trees"),
    ("random forest", "tree ensemble"),
    ("graph neural", "graph neural network"), ("gnn", "graph neural network"),
    ("tabular network", "tabular neural network"),
    ("mlp", "multilayer perceptron"),
)
_MODEL_DATA_TERMS: tuple[tuple[str, str], ...] = (
    ("tabular", "tabular records"), ("spreadsheet", "tabular records"),
    ("csv", "tabular records"), ("dataframe", "tabular records"),
    ("rows", "data rows"), ("columns", "data columns"),
    ("text", "text"), ("image", "images"), ("audio", "audio"),
)
# Explicit denials ("no chat surface", "without dialog") name the concept to
# exclude it. Strip those phrases before conversational matching, or a denial
# reads as an endorsement.
_CONVERSATIONAL_NEGATION = re.compile(
    r"\b(?:no|without|non)[\s\-]+(?:chatbots?|assistants?|conversational|"
    r"dialogues?|dialogs?|copilots?|prompts?)\b")
_CONVERSATIONAL_TERMS = frozenset(
    ("chat", "chatbot", "assistant", "conversational", "dialogue",
     "dialog", "copilot"))
_NON_CONVERSATIONAL_TERMS = frozenset(
    ("api", "batch", "scoring", "classification", "embedding",
     "inference endpoint", "scheduled", "tabular"))
_PERSONAL_DATA_TERMS = frozenset(
    ("customer", "personal", "pii", "patient", "client records",
     "user data", "account holder"))


def profile_model_subject(product: str, use_case: str = "",
                          focus: list[str] | None = None) -> dict[str, Any]:
    """Read what kind of subject an assessment is about.

    Returns ``is_model_query`` plus, when true, family/architecture/class,
    data traits, the interface kind, and a one-line ``summary`` for prompts
    and reports. Every field defaults to unknown/empty: a vague brief yields
    a vague profile, never a confident wrong one.
    """
    blob = f"{product or ''}\n{use_case or ''}\n{' '.join(focus or [])}".lower()
    # "Threat model the payment flow" is not about a machine-learning model:
    # strip the non-ML senses first, then look for what remains. A text that
    # is genuinely about models ("threat model of our TabPFN deployment")
    # still matches on the other terms it contains.
    clean = blob
    for p in _MODEL_QUERY_EXCLUSIONS:
        clean = p.sub(" ", clean)
    model_hit = any(t in clean for t in _MODEL_QUERY_TERMS)
    profile: dict[str, Any] = {
        "is_model_query": bool(model_hit),
        "families": [], "architectures": [], "model_class": "unknown",
        "data": [], "trains_on_data": False, "personal_data": False,
        "interface": "unknown", "summary": "",
    }
    if not model_hit:
        return profile
    for frag, label, cls, arch in _MODEL_FAMILIES:
        if frag in blob and label not in profile["families"]:
            profile["families"].append(label)
            if profile["model_class"] == "unknown":
                profile["model_class"] = cls
            if arch not in profile["architectures"]:
                profile["architectures"].append(arch)
    for frag, arch in _MODEL_ARCH_TERMS:
        if frag in blob and arch not in profile["architectures"]:
            profile["architectures"].append(arch)
    if "foundation" in blob and profile["model_class"] == "unknown":
        profile["model_class"] = "foundation"
    elif "fine-tun" in blob:
        profile["model_class"] = "fine-tuned"
    for frag, label in _MODEL_DATA_TERMS:
        if frag in blob and label not in profile["data"]:
            profile["data"].append(label)
    profile["trains_on_data"] = bool(
        re.search(r"\btrain\w*\b|\bfit\b|\bfine-tun\w*\b|\bpre-train\w*\b|\bpretrain\w*\b", blob))
    profile["personal_data"] = any(t in blob for t in _PERSONAL_DATA_TERMS)
    if any(t in _CONVERSATIONAL_NEGATION.sub(" ", blob)
            for t in _CONVERSATIONAL_TERMS):
        profile["interface"] = "conversational"
    elif any(t in blob for t in _NON_CONVERSATIONAL_TERMS):
        profile["interface"] = "non_conversational"
    bits = []
    if profile["families"]:
        bits.append("/".join(profile["families"]))
    bits.append(profile["model_class"] + " model"
                if profile["model_class"] != "unknown" else "model")
    if profile["architectures"]:
        bits.append("(" + ", ".join(profile["architectures"]) + ")")
    if profile["data"]:
        bits.append("over " + ", ".join(profile["data"]))
    if profile["interface"] == "non_conversational":
        bits.append("no conversational surface")
    profile["summary"] = " ".join(bits)
    return profile


def control_catalog() -> list[dict[str, Any]]:
    """Control catalogue plus how many threats each control covers (for the GUI)."""
    out = []
    for c in _CONTROL_CATALOG:
        item = {k: v for k, v in c.items()}
        item["threat_count"] = len(c["threats"])
        item["max_coverage"] = round(_combine_efficacy(
            [c["efficacy"] * w for w in c["threats"].values()]) * 100, 1)
        out.append(item)
    return out


def _combine_efficacy(parts: list[float]) -> float:
    """Diminishing-returns combination: 1 - Π(1 - efficacy_i)."""
    survive = 1.0
    for p in parts:
        survive *= (1.0 - max(0.0, min(0.95, p)))
    return max(0.0, min(1.0, 1.0 - survive))


def _coverage_for(threat_id: str, active_controls: Iterable[str]) -> tuple[float, list[str]]:
    """(coverage 0..1, contributing control ids) for one threat."""
    parts: list[float] = []
    used: list[str] = []
    for cid in active_controls:
        c = _CONTROL_BY_ID.get(cid)
        if not c:
            continue
        w = c["threats"].get(threat_id)
        if not w:
            continue
        parts.append(c["efficacy"] * float(w))
        used.append(cid)
    return _combine_efficacy(parts), used


def _aggregate(values: list[float]) -> float:
    """Weighted worst/breadth aggregate normalized from the 1..25 L×I range."""
    if not values:
        return 0.0
    top = sorted(values, reverse=True)[:_TOP_N]
    worst = sum(top) / len(top)
    breadth = sum(values) / len(values)
    return _WORST_WEIGHT * worst + _BREADTH_WEIGHT * breadth


def _posture(pct: float) -> str:
    if pct >= 75:
        return "HIGH RISK — do not enable for this data tier without the mitigations below"
    elif pct >= 50:
        return "ELEVATED RISK — enable only with guardrails and steward review"
    elif pct >= 30:
        return "MODERATE RISK — standard hardening sufficient"
    return "LOW RISK — routine controls sufficient"


def score_assessment(
    exposure: str,
    inherent_threats: list[dict[str, Any]],
    active_controls: Optional[Iterable[str]] = None,
    applicability: Optional[dict[str, float]] = None,
) -> dict[str, Any]:
    """Pure function: inherent + residual scoring for a threat set.

    Deterministic and side-effect free, so the same inputs always produce the
    same numbers — used by the assessment run, the what-if re-scorer and the
    control-analyst agent alike.

    - ``inherent_threats``: entries with ``id``, ``likelihood`` (already exposure-
      scaled), ``impact``.
    - ``active_controls``: control ids the organisation has in place.
    - ``applicability``: per-threat 0..1 relevance; threats below
      ``_MIN_APPLICABILITY`` are reported but excluded from the aggregate,
      and the rest weight the aggregate by relevance (renormalized, so a
      uniform map scores exactly as unweighted).

    Returns threats (inherent + residual per threat), the aggregates, the
    posture, and a full breakdown so the UI can explain every number.
    """
    active = sorted({str(c).strip().upper() for c in (active_controls or [])
                     if str(c).strip().upper() in _KNOWN_CIDS})
    app = dict(applicability or {})
    control_analyst = (applicability is not None)

    rows: list[dict[str, Any]] = []
    for t in inherent_threats:
        tid = t["id"]
        try:
            a = float(app.get(tid, 1.0))
        except (TypeError, ValueError):
            a = 1.0
        a = max(0.0, min(1.0, a))
        cov, contributors = _coverage_for(tid, active)
        lik_i = float(t["likelihood"])
        impact = float(t["impact"])
        inherent = lik_i * impact
        lik_r = max(lik_i * _MIN_RESIDUAL_LIKELIHOOD, lik_i * (1.0 - cov))
        residual = lik_r * impact
        rows.append({
            "id": tid,
            "title": t.get("title", ""),
            "stride": t.get("stride", ""),
            "owasp": t.get("owasp", ""),
            "description": t.get("description", ""),
            "mitigations": list(t.get("mitigations", [])),
            "likelihood": lik_i,
            "impact": impact,
            "inherent_score": round(inherent, 2),
            "inherent_severity": _severity(int(round(inherent))),
            "residual_likelihood": round(lik_r, 2),
            "residual_score": round(residual, 2),
            "residual_severity": _severity(int(round(residual))),
            "coverage": round(cov * 100, 1),
            "controls": contributors,
            "applicability": round(a, 2),
            "applicable": a >= _MIN_APPLICABILITY,
        })

    applicable = [r for r in rows if r["applicable"]]
    if not applicable:  # never produce a meaningless 0 for an empty scope
        applicable = rows
    weights = []
    for r in applicable:
        try:
            weights.append(max(0.0, min(1.0, float(app.get(r["id"], 1.0)))))
        except (TypeError, ValueError):
            weights.append(1.0)
    norm = (sum(weights) / len(weights)) if weights else 0.0
    if norm <= 0:
        # nothing claims relevance: fall back to the unweighted aggregate
        # rather than manufacturing a zero
        weights = [1.0] * len(applicable)
        norm = 1.0
    inh = _aggregate([s * w for s, w in zip(
        [r["inherent_score"] for r in applicable], weights)]) / (25.0 * norm)
    res = _aggregate([s * w for s, w in zip(
        [r["residual_score"] for r in applicable], weights)]) / (25.0 * norm)
    inherent_pct = round(min(100.0, inh * 100.0), 1)
    residual_pct = round(min(100.0, res * 100.0), 1)

    def _dist(key: str) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in applicable:
            out[r[key]] = out.get(r[key], 0) + 1
        return out

    return {
        "threats": sorted(rows, key=lambda r: (-r["residual_score"], -r["inherent_score"], r["id"])),
        "inherent_pct": inherent_pct,
        "residual_pct": residual_pct,
        "delta": round(residual_pct - inherent_pct, 1),
        "posture": _posture(residual_pct),
        "inherent_posture": _posture(inherent_pct),
        "active_controls": active,
        "distribution": {
            "inherent": _dist("inherent_severity"),
            "residual": _dist("residual_severity"),
        },
        "breakdown": {
            "method": "weighted worst-case (55%) + breadth (45%), normalized to the 1-25 LxI range; "
                      "threat contributions scale by applicability and renormalize (uniform maps score as unweighted); "
                      "residual applies control efficacy with diminishing returns; "
                      "controls never reduce likelihood below 35% of inherent",
            "worst_weight": _WORST_WEIGHT,
            "breadth_weight": _BREADTH_WEIGHT,
            "top_n": _TOP_N,
            "min_residual_floor": _MIN_RESIDUAL_LIKELIHOOD,
            "min_applicability": _MIN_APPLICABILITY,
            "exposure": exposure,
            "exposure_weight": EXPOSURE_META.get(exposure, {}).get("weight"),
            "exposure_label": EXPOSURE_META.get(exposure, {}).get("label", exposure),
            "applicable_threats": len(applicable),
            "total_threats": len(rows),
            "n_threats_included": len(applicable),
            "n_threats_excluded": len(rows) - len(applicable),
            "max_inherent": max((r["inherent_score"] for r in rows), default=0),
            "max_residual": max((r["residual_score"] for r in rows), default=0),
            "mean_coverage": round(sum(r["coverage"] for r in applicable) / len(applicable), 1)
            if applicable else 0.0,
        },
        "control_analyst": control_analyst,
    }


def _scale_likelihood(base: int, weight: float) -> int:
    """Exposure weight scales likelihood mildly: restricted=full, public=reduced."""
    scaled = round(base * (0.55 + 0.45 * weight))
    return max(1, min(5, scaled))


# --------------------------------------------------------------- diagrams ---

def mermaid_dataflow(product: str) -> str:
    p = (product or "Catalog").replace('"', "'")[:40]
    return (
        "flowchart LR\n"
        '    U["Employee\\n(catalog steward)"] -->|draft / paste| UI["AI Writing Assistant UI"]\n'
        f'    UI -->|prompt: schema + draft| GW["Policy gateway\\n(DLP • classifier)"]\n'
        '    GW -->|allow| LLM["LLM endpoint\\n(vendor / VPC)"]\n'
        '    GW -->|block / redact| U\n'
        f'    LLM -->|suggestion| REV["Steward review\\n(approve / edit)"]\n'
        f'    REV -->|publish| CAT["{p}\\nmetadata store"]\n'
        '    CAT -->|read| C["Downstream consumers\\n(search, agents, exports)"]\n'
        "    style GW fill:#d29922,stroke:#333,color:#000\n"
        "    style LLM fill:#f85149,stroke:#333,color:#fff\n"
    )


def mermaid_threat_paths() -> str:
    return (
        "flowchart TD\n"
        '    A["Restricted / Confidential\\nfile or table"] --> B{"Classification\\ncorrect?"}\n'
        "    B -->|mislabelled| C[\"T03: AI launders\\nwrong label\"]\n"
        "    B -->|correct| D[\"Assistant prompt\"]\n"
        '    D --> E{"DLP gateway?"}\n'
        "    E -->|missing| F[\"T01: accidental paste\\nleaves boundary\"]\n"
        "    E -->|present| G[\"LLM inference\"]\n"
        "    G --> H[\"T02/T07: retention /\\nsubprocessor copy\"]\n"
        "    G --> I[\"T05: injected instruction\\nin asset text\"]\n"
        "    I --> J[\"T04/T06: over-share /\\nexfiltration via docs\"]\n"
        "    C --> K[\"Published catalog\\n(exposed)\"]\n"
        "    F --> K\n"
        "    H --> K\n"
        "    J --> K\n"
        "    style C fill:#f85149,stroke:#333,color:#fff\n"
        "    style F fill:#f85149,stroke:#333,color:#fff\n"
        "    style H fill:#d29922,stroke:#333,color:#000\n"
        "    style J fill:#d29922,stroke:#333,color:#000\n"
    )


def mermaid_workflow(product: str) -> str:
    p = (product or "Asset").replace('"', "'")[:40]
    return (
        "flowchart TD\n"
        '    S1["1. Admin config\\n(enable assistant, pin model/region, map roles)"] --> S2["2. Asset created / imported\\n(source file, table, doc)"]\n'
        '    S2 --> S3{"3. Classification check\\nRestricted / Confidential?"} \n'
        "    S3 -->|Restricted: deny or dual-control| S3R[\"Route to manual authoring\"]\n"
        '    S3 -->|allowed| S4["4. AI drafts description\\n(schema-only prompt, redacted)"]\n'
        '    S4 --> S5["5. Steward review\\n(verify class, facts, sensitivity)"]\n'
        '    S5 --> S6{"6. Approve?"} \n'
        "    S6 -->|edits needed| S4\n"
        '    S6 -->|approved| S7["7. Publish + stamp provenance\\n(model, prompt hash, reviewer)"]\n'
        f'    S7 --> S8["8. Monitor\\n(drift, access review, audit) — {p}"]\n'
        "    style S3 fill:#d29922,stroke:#333,color:#000\n"
        "    style S5 fill:#58a6ff,stroke:#333,color:#000\n"
    )


# ----------------------------------------------------------------- report ---

_PERSPECTIVES: list[tuple[str, str, str]] = [
    ("executive", "Executives", "fa-briefcase"),
    ("ciso", "CISO", "fa-shield-halved"),
    ("security_engineer", "Security engineers", "fa-bug"),
    ("data_scientist", "Data scientists", "fa-flask"),
    ("dpo", "DPO / Privacy", "fa-user-shield"),
    ("legal", "Legal", "fa-scale-balanced"),
    ("compliance", "Compliance", "fa-clipboard-check"),
]

_ROLE_ARTIFACT_TERMS: dict[str, tuple[str, ...]] = {
    "executive": ("governance", "risk", "enterprise", "trust", "adoption", "cost",
                  "fedramp", "compliance", "leadership", "strategy", "pricing", "plans"),
    "ciso": ("security", "threat", "vulnerability", "attack", "injection", "audit",
             "least-privilege", "access", "encryption", "monitoring", "incident",
             "hardening", "risk"),
    "security_engineer": ("prompt-injection", "injection", "mcp", "repository", "git",
                          "vulnerability", "exploit", "tool", "secret", "credential",
                          "hardening", "air-gapped", "hybrid-deployment", "encryption",
                          "agent-hijack", "security-checklist"),
    "data_scientist": ("data-retention", "model-training", "data-training", "training",
                       "data", "privacy", "learning", "classification", "dataset",
                       "hallucination", "science", "inference-compute"),
    "dpo": ("privacy", "data-retention", "retention", "data-protection", "code-privacy",
            "prompt-data", "personal", "subprocessor", "data-sharing", "data-privacy",
            "encryption", "zero-data-retention"),
    "legal": ("policy", "privacy-policy", "compliance", "contract", "terms", "license",
              "soc2", "fedramp", "trust-center", "subprocessor", "audit", "legal",
              "data-sharing", "governance"),
    "compliance": ("soc2", "fedramp", "compliance", "audit", "trust-center", "policy",
                   "governance", "enterprise-security", "certification", "control",
                   "risk", "legal"),
}


def _load_investigation_artifacts(db: Any, investigation_id: Any) -> list[dict[str, Any]]:
    """Normalised artifact rows for the investigation this assessment belongs to."""
    if db is None or investigation_id in (None, ""):
        return []
    try:
        from .models import Artifact

        rows = db.query(Artifact).filter(
            Artifact.investigation_id == int(investigation_id)
        ).order_by(Artifact.relevance.desc()).all()
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    for a in rows:
        out.append({
            "id": a.id,
            "title": a.title or "",
            "type": a.artifact_type or "",
            "url": a.url or "",
            "author": a.author or "",
            "tags": a.tags or "",
            "relevance": float(a.relevance or 0.0),
            "snippet": (a.description or a.content or "")[:400],
        })
    return out


def _role_artifact_matches(
    artifacts: list[dict[str, Any]], role: str, limit: int = 8,
) -> tuple[list[dict[str, Any]], int]:
    """Rank investigation artifacts for one role by keyword hits x relevance.

    Returns (top matches, total matched). Deterministic: ties break on
    relevance then artifact id, so repeated runs give identical ordering.
    """
    terms = _ROLE_ARTIFACT_TERMS.get(role) or ()
    if not terms or not artifacts:
        return [], 0
    scored: list[tuple[float, int, list[str], dict[str, Any]]] = []
    for a in artifacts:
        hay = f"{a.get('title', '')} {a.get('tags', '')} {a.get('snippet', '')}".lower()
        hits = sorted({t for t in terms if t in hay})
        if not hits:
            continue
        score = a.get("relevance", 0.0) * (1.0 + 0.34 * (len(hits) - 1))
        scored.append((-score, int(a.get("id") or 0), hits, a))
    scored.sort(key=lambda x: (x[0], x[1]))
    matched = len(scored)
    out = [{
        "id": a["id"], "title": a["title"], "type": a["type"], "url": a["url"],
        "relevance": a["relevance"], "hits": hits[:4],
        "snippet": (a.get("snippet") or "")[:220],
    } for _, _, hits, a in scored[:limit]]
    return out, matched


def _sev_tone(sev: str) -> str:
    return {"Critical": "critical", "High": "high",
            "Medium": "medium", "Low": "low"}.get(sev or "", "low")


def _perspective_views(res: dict[str, Any]) -> list[dict[str, Any]]:
    """Derive per-audience highlight panels from the scored assessment.

    Deterministic: the same assessment always yields the same panels, so the
    GUI, the markdown and the PDF all quote identical numbers.
    """
    threats = [t for t in (res.get("threats") or []) if t.get("applicable", True)]
    scoring = res.get("scoring") or {}
    plan = res.get("control_plan") or {}
    ctrls = scoring.get("active_controls") or []
    bd = scoring.get("breakdown") or {}
    exposure = res.get("exposure") or ""
    product = res.get("product_name") or "this product"
    residual = res.get("residual_pct", 0.0)
    inherent = res.get("inherent_pct", 0.0)
    removed = round((inherent or 0) - (residual or 0), 1)
    posture = res.get("posture") or ""
    artifacts = res.get("artifacts") or []
    inv_total = len(artifacts)

    def by_id(tid: str) -> dict[str, Any]:
        for t in threats:
            if t.get("id") == tid:
                return t
        return {}

    ranked = sorted(threats, key=lambda t: -float(t.get("residual_score") or 0))
    gap = [t for t in ranked if float(t.get("coverage") or 0) < 60]
    top = ranked[:3]
    mean_cov = round(sum(float(t.get("coverage") or 0) for t in threats) / len(threats), 1) if threats else 0.0
    conf = plan.get("confidence")
    ev = res.get("evidence") or []
    explo = res.get("known_exploits") or []
    ev_ids = {e.get("artifact_id") for e in ev if e.get("artifact_id")}

    def inv_block(role: str) -> dict[str, Any]:
        matches, matched = _role_artifact_matches(artifacts, role)
        cited = sum(1 for m in matches if m["id"] in ev_ids)
        domains: list[str] = []
        for m in matches:
            for h in m["hits"]:
                if h not in domains:
                    domains.append(h)
        return {
            "total_artifacts": inv_total,
            "matched": matched,
            "cited": cited,
            "coverage_pct": round(100.0 * matched / inv_total) if inv_total else 0,
            "domains": domains[:5],
            "artifacts": matches,
        }

    def cov_of(tid: str) -> float:
        return float(by_id(tid).get("coverage") or 0)

    def res_of(tid: str) -> float:
        return float(by_id(tid).get("residual_score") or 0)

    def sev_of(tid: str) -> str:
        return by_id(tid).get("residual_severity") or "Low"

    def bullet(text: str, tone: str = "neutral") -> dict[str, str]:
        return {"text": text, "tone": tone}

    def metric(k: str, v: Any, tone: str = "neutral") -> dict[str, Any]:
        return {"k": k, "v": v, "tone": tone}

    out: list[dict[str, Any]] = []

    def cov_tone(pct: float) -> str:
        return "good" if pct >= 70 else "medium" if pct >= 50 else "critical"

    pu = posture.upper()
    posture_tone = ("critical" if "CRITICAL" in pu else "high" if "HIGH RISK" in pu
                    else "medium" if "ELEVATED" in pu or "MODERATE" in pu else "good")

    out.append({
        "key": "executive", "label": "Executives", "icon": "fa-briefcase",
        "headline": (f"{product}: residual risk {residual}/100 — {posture.split('—')[0].strip()}"
                     if posture else f"{product}: residual risk {residual}/100"),
        "metrics": [
            metric("Residual risk", f"{residual}", posture_tone),
            metric("Risk removed by controls", f"{removed}", "good" if removed > 0 else "neutral"),
            metric("Controls in place", len(ctrls)),
            metric("Coverage gaps", len(gap), "critical" if len(gap) >= 5 else "medium" if gap else "good"),
        ],
        "bullets": [
            bullet(f"Exposure is classified {exposure.replace('_', ' ')}; without controls this use case scores {inherent}/100."),
            bullet(f"The {len(ctrls)} controls currently in place remove {removed} points of exposure-weighted risk."),
            bullet(("Decision required: fund and mandate coverage for "
                    + ", ".join(t["id"] for t in gap[:3]) + ".") if gap
                   else "Every applicable threat carries at least 60% control coverage."),
            bullet("Residual assumes the declared controls actually operate as described; effectiveness is unverified until audited."),
        ],
        "focus": ["Business impact", "Decision asks", "Risk acceptance"],
    })

    out.append({
        "key": "ciso", "label": "CISO", "icon": "fa-shield-halved",
        "headline": f"Mean control coverage {mean_cov}% · {len(gap)} of {len(threats)} threats below 60% coverage",
        "metrics": [
            metric("Mean coverage", f"{mean_cov}%", "good" if mean_cov >= 70 else "medium"),
            metric("Highest residual", f"{top[0]['residual_score'] if top else 0}", _sev_tone(top[0].get("residual_severity")) if top else "low"),
            metric("Threats ≥ High", len([t for t in threats if (t.get("residual_severity") in ("Critical", "High"))])),
            metric("Detection / audit controls", "on" if {"C07", "C08"} & set(ctrls) else "off",
                   "good" if {"C07", "C08"} & set(ctrls) else "high"),
        ],
        "bullets": [
            bullet(f"Highest residual: {top[0]['id']} {top[0]['title']} at {top[0]['residual_score']} ({top[0].get('residual_severity')})."
                   if top else "No applicable threats.", "high" if top and top[0].get("residual_severity") in ("Critical", "High") else "neutral"),
            bullet("Weakest-covered: " + ", ".join(f"{t['id']} ({t['coverage']}%)" for t in gap[:4]) + "."
                   if gap else "Every applicable threat is at or above 60% coverage.", "medium"),
            bullet("Audit trail is the control most often missing — provenance stamping (C07) and immutable logging (C08) are prerequisites for any AI-assisted change process."),
            bullet(f"Scoring confidence {round(conf * 100) if conf is not None else '—'}% ({plan.get('source', 'n/a')}) — treat low-confidence runs as a starting hypothesis, not a finding."),
        ],
        "focus": ["Control coverage", "Risk acceptance", "Assurance"],
    })

    out.append({
        "key": "security_engineer", "label": "Security engineers", "icon": "fa-bug",
        "headline": f"{len(threats)} modelled threats · {len(explo)} known attack technique{'' if len(explo) == 1 else 's'} mapped · top residual {top[0]['residual_score'] if top else 0}",
        "metrics": [
            metric("Top residual threat",
                   f"{top[0]['id']} {top[0]['residual_score']}" if top else "—",
                   _sev_tone(top[0].get("residual_severity")) if top else "low"),
            metric("Injection surface", f"{cov_of('T05'):.0f}% covered", cov_tone(cov_of("T05"))),
            metric("Third-party exposure", f"{res_of('T07')}", _sev_tone(sev_of("T07"))),
            metric("Privilege scoping", f"{res_of('T10')}", _sev_tone(sev_of("T10"))),
        ],
        "bullets": [
            bullet("Inherent risk by threat: " + "; ".join(
                f"{t['id']} {t['inherent_score']}→{t['residual_score']} ({t['coverage']}%)" for t in ranked[:5]) + "."),
            bullet("Prompt injection (T05) is the only threat with a single covering control; below 60% coverage it remains the dominant attack path."),
            bullet("Mitigations on the highest-scoring threats: " + "; ".join(
                (by_id(t["id"]).get("mitigations") or ["—"])[0] for t in top) + "."),
            bullet("Per-threat STRIDE/OWASP mapping, applicability and residual arithmetic are in the Threats sub-view."),
        ],
        "focus": ["Attack paths", "OWASP LLM mapping", "Remediation"],
    })

    out.append({
        "key": "data_scientist", "label": "Data scientists", "icon": "fa-flask",
        "headline": f"Exposure {exposure.replace('_', ' ')} (weight {bd.get('exposure_weight', '—')}) · {len(threats)} of {len(res.get('threats') or [])} threats in scope",
        "metrics": [
            metric("Training / retention (T02)", f"{cov_of('T02'):.0f}% covered", cov_tone(cov_of("T02"))),
            metric("Data residency (T11)", f"{res_of('T11')}", _sev_tone(sev_of("T11"))),
            metric("Misclassification (T03)", f"{res_of('T03')}", _sev_tone(sev_of("T03"))),
            metric("Out-of-scope threats", bd.get("n_threats_excluded", 0)),
        ],
        "bullets": [
            bullet(f"Likelihood is scaled by the {exposure.replace('_', ' ')} exposure weight, so every inherent score is already data-classification aware."),
            bullet("Training and retention leakage is governed by contractual posture (C04), not by model behaviour — verify zero-retention is enabled for every model provider, not just the first party."),
            bullet("Aggregates weight the worst 5 threats 55% and all applicable threats 45%; a single unmitigated critical threat dominates the headline."),
            bullet("The model is deterministic: identical inputs always reproduce identical scores, so runs are diffable across time."),
        ],
        "focus": ["Data classification", "Retention", "Model governance"],
    })

    out.append({
        "key": "dpo", "label": "DPO / Privacy", "icon": "fa-user-shield",
        "headline": f"Sensitive-disclosure residual {res_of('T06')} · retention/transfer coverage {cov_of('T02'):.0f}% / {cov_of('T11'):.0f}%",
        "metrics": [
            metric("Sensitive disclosure", f"{res_of('T06')}", _sev_tone(sev_of("T06"))),
            metric("Training / retention", f"{cov_of('T02'):.0f}%", cov_tone(cov_of("T02"))),
            metric("Subprocessor exposure", f"{res_of('T07')}", _sev_tone(sev_of("T07"))),
            metric("Data residency", f"{res_of('T11')}", _sev_tone(sev_of("T11"))),
        ],
        "bullets": [
            bullet("Processing basis: the data in scope is the content the agent reads or generates; the declared controls are the minimisation, redaction and no-training measures."),
            bullet("Retention is the weakest link: vendor-documented retention can outlive the engagement, so pin a deletion period in the contract and verify it operationally."),
            bullet(f"Cross-border and subprocessor transfer risk scores {res_of('T11')} / {res_of('T07')}; region pinning and private endpoints (C09) reduce both."),
            bullet("Data-subject rights (access, erasure, portability) depend on the same retention and audit controls — an unlogged, unbounded-retention pipeline cannot satisfy erasure requests."),
        ],
        "focus": ["Purpose limitation", "Retention", "Transfers", "Data-subject rights"],
    })

    out.append({
        "key": "legal", "label": "Legal", "icon": "fa-scale-balanced",
        "headline": f"Regulatory/contractual residual {res_of('T12')} ({sev_of('T12')}) — the one threat technical controls alone do not close",
        "metrics": [
            metric("Compliance threat", f"{res_of('T12')} {sev_of('T12')}", _sev_tone(sev_of("T12"))),
            metric("DPIA / control record", "on" if "C11" in ctrls else "off", "good" if "C11" in ctrls else "critical"),
            metric("No-train / ZDR", "on" if "C04" in ctrls else "off", "good" if "C04" in ctrls else "critical"),
            metric("Evidence base", f"{len(ev)} sources"),
        ],
        "bullets": [
            bullet("Make no-training and zero-data-retention contractual defaults rather than a user-configurable setting; vendor documentation still permits model training on some non-enterprise tiers."),
            bullet("Pin retention of feedback and interaction data to a fixed period — vendor wording of 'as long as needed' is not a deletion commitment."),
            bullet("Require subprocessor flow-down for inference compute, a current subprocessor list, and notice/audit rights covering all four parties."),
            bullet(f"Output IP and audit obligations: {len(explo)} attack mappings and {len(ev)} evidence items are available for the compliance file, but the vendor assessment is self-reported and not independently audited here."),
        ],
        "focus": ["Contract terms", "IP ownership", "Subprocessors", "Regulatory exposure"],
    })

    out.append({
        "key": "compliance", "label": "Compliance", "icon": "fa-clipboard-check",
        "headline": f"{len(ctrls)} controls mapped · {len(ev)} evidence sources · provenance/audit {'present' if {'C07','C08'} & set(ctrls) else 'absent'}",
        "metrics": [
            metric("Controls mapped", f"{len(ctrls)}/12"),
            metric("Evidence sources", len(ev)),
            metric("Provenance stamping", "on" if "C07" in ctrls else "off", "good" if "C07" in ctrls else "high"),
            metric("Immutable audit", "on" if "C08" in ctrls else "off", "good" if "C08" in ctrls else "high"),
        ],
        "bullets": [
            bullet("Every control maps to ISO 27001 and/or OWASP LLM categories in the Controls sub-view, giving a ready audit crosswalk."),
            bullet("Agent runs are recorded with per-hop inputs and outputs in the A2A trace, giving defensible lineage for AI-assisted changes."),
            bullet("Declared controls are self-attested by the operator; independent testing is required before the residual score can be relied upon in an audit."),
            bullet(f"Documented retention and deletion obligations are the primary gap: {sev_of('T12')} residual on regulatory/contractual exposure."),
        ],
        "focus": ["Control mapping", "Audit trail", "Evidence"],
    })

    for pv in out:
        pv["investigation"] = inv_block(pv["key"])

    return out


def build_assessment(
    product_name: str,
    product_url: str,
    exposure: str,
    use_case: str = "",
    workflow_text: str = "",
    doc_urls: Optional[list[str]] = None,
    focus: Optional[list[str]] = None,
    db: Any = None,
    investigation_id: Any = None,
    declared_controls: Optional[list[str]] = None,
    control_plan_override: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    exposure = (exposure or "confidential_data").strip()
    if exposure not in EXPOSURE_META:
        exposure = "confidential_data"
    meta = EXPOSURE_META[exposure]
    weight = float(meta["weight"])

    doc_urls = [u for u in (doc_urls or []) if u and u.strip()][:6]
    pages = [fetch_page_summary(product_url)] if product_url else []
    pages += [fetch_page_summary(u) for u in doc_urls]
    fetched_ok = [p for p in pages if p["excerpt"]]

    # Inherent threat rows: the exposure-scaled L×I baseline, before any control
    # is applied. Kept intact so the residual scoring is a pure function of
    # (inherent rows, active controls, applicability).
    inherent: list[dict[str, Any]] = []
    for tid, title, stride, owasp, base_l, impact, desc, mits in _THREAT_CATALOG:
        lik = _scale_likelihood(base_l, weight)
        inherent.append({
            "id": tid, "title": title, "stride": stride, "owasp": owasp,
            "likelihood": float(lik), "impact": float(impact),
            "description": desc, "mitigations": mits,
        })
    inherent.sort(key=lambda t: (-(t["likelihood"] * t["impact"]), t["id"]))

    def _score(agent_out: dict[str, Any]) -> dict[str, Any]:
        plan = (agent_out.get("control_plan") or {})
        active = plan.get("declared_controls")
        if active is None:
            active = declared_controls or []
        return score_assessment(
            exposure, inherent,
            active_controls=active,
            applicability=agent_out.get("applicability") or None,
        )

    focus = focus or ["accidental_copy", "misclassification"]
    diagrams = {
        "dataflow": mermaid_dataflow(product_name or "Catalog"),
        "threat_paths": mermaid_threat_paths(),
        "workflow": mermaid_workflow(product_name or "Asset"),
    }

    # ---- Agent-to-agent workflow: orchestrator → control-analyst →
    # ---- research-collector → threat-intel → (deterministic scoring) →
    # ---- report-writer. The control-analyst decides applicability/controls;
    # ---- this module does the arithmetic via the injected score_fn.
    from .agents import run_security_a2a_workflow

    a2a = run_security_a2a_workflow(
        product_name=product_name or "Target product",
        use_case=use_case or "",
        threat_titles=[t["title"] for t in inherent],
        threat_ids=[t["id"] for t in inherent],
        db=db,
        investigation_id=investigation_id,
        exposure_label=meta["label"],
        exposure=exposure,
        declared_controls=declared_controls or [],
        score_fn=_score,
        focus=focus,
        control_plan_override=control_plan_override,
    )

    scoring = a2a.get("scoring") or _score({
        "control_plan": {}, "applicability": None,
    })
    threats = scoring["threats"]
    overall_pct = scoring["residual_pct"]   # headline = residual (post-control)
    posture = scoring["posture"]
    control_plan = a2a.get("control_plan") or {}
    inv_artifacts = _load_investigation_artifacts(db, investigation_id)

    perspectives = _perspective_views({
        "threats": threats,
        "scoring": scoring,
        "control_plan": control_plan,
        "evidence": a2a.get("evidence", []),
        "known_exploits": a2a.get("known_exploits", []),
        "artifacts": inv_artifacts,
        "exposure": exposure,
        "product_name": product_name or "Target product",
        "inherent_pct": scoring.get("inherent_pct"),
        "residual_pct": scoring.get("residual_pct"),
        "posture": posture,
    })

    osh_block = _osh.assessment_openshell_block(
        pages, product_name or "Target product", exposure,
        scoring["active_controls"])
    markdown = render_markdown(
        product_name=product_name or "Target product",
        product_url=product_url or "",
        exposure_label=meta["label"],
        exposure_blurb=meta["blurb"],
        use_case=use_case or "",
        workflow_text=workflow_text or "",
        pages=pages,
        threats=threats,
        overall_pct=overall_pct,
        posture=posture,
        diagrams=diagrams,
        focus=focus,
        scoring=scoring,
        perspectives=perspectives,
        control_plan=control_plan,
        evidence_confidence=a2a.get("evidence_confidence", {}),
        exploits_markdown=a2a.get("exploits_markdown", ""),
        exec_evidence_lines=a2a.get("exec_evidence_lines", []),
        exec_evidence_refs=a2a.get("exec_evidence_refs", []),
        exec_paragraph=a2a.get("exec_paragraph", ""),
        a2a_task_id=a2a.get("task_id", ""),
        openshell=osh_block,
    )
    return {
        "product_name": product_name or "Target product",
        "product_url": product_url or "",
        "exposure": exposure,
        "exposure_label": meta["label"],
        "overall_pct": overall_pct,
        "inherent_pct": scoring["inherent_pct"],
        "residual_pct": scoring["residual_pct"],
        "delta": scoring["delta"],
        "confidence": control_plan.get("confidence", 0.5),
        "posture": posture,
        "threats": threats,
        "scoring": scoring,
        "perspectives": perspectives,
        "control_plan": control_plan,
        "active_controls": scoring["active_controls"],
        "evidence_confidence": a2a.get("evidence_confidence", {}),
        "diagrams": diagrams,
        "pages": pages,
        "fetched_count": len(fetched_ok),
        "markdown": markdown,
        "evidence": a2a.get("evidence", []),
        "queries_run": a2a.get("queries_run", []),
        "artifact_count": len(inv_artifacts),
        "scope": a2a.get("scope", ""),
        "known_exploits": a2a.get("known_exploits", []),
        "exec_paragraph": a2a.get("exec_paragraph", ""),
        "a2a_trace": a2a.get("a2a_trace", []),
        "a2a_task_id": a2a.get("task_id", ""),
        "openshell": osh_block,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def openshell_posture_lines(active_controls: list[str], pages: list[dict],
                            osh: dict) -> list[str]:
    """Report §5c body: which OpenShell controls hold and how pages fetched."""
    os_active = [c for c in (active_controls or [])
                 if c in _osh.OPENSHELL_CONTROLS]
    out = []
    if os_active:
        names = {c["id"]: c["name"] for c in control_catalog()}
        out.append("OpenShell controls in place: " +
                   ", ".join(f"**{cid}** ({names.get(cid, '')})"
                             for cid in os_active) + ".")
    else:
        out.append("None of the OpenShell controls (C13 sandbox, C14 egress "
                   "allowlist, C15 credential brokering) are active, so the "
                   "residual score above assumes agent tool calls run unsandboxed.")
    if (osh or {}).get("sandbox_used"):
        out.append(f"Product/doc fetches in this run: {osh.get('sandbox_pages', 0)} "
                   f"of {len(pages or [])} executed inside a managed sandbox.")
    else:
        out.append("Product/doc fetches in this run executed direct: the OpenShell "
                   "broker or gateway was unreachable, and the assessment records "
                   "that instead of assuming protection.")
    out.append("The generated sandbox policy is attached in the appendix; apply it "
               "with `openshell policy set` and prove widenings with "
               "`openshell policy prove` before trusting the C13-C15 efficacy above.")
    return out


def openshell_policy_lines(osh: dict) -> list[str]:
    """Appendix block with the generated sandbox policy, if any."""
    if not (osh or {}).get("policy_yaml"):
        return []
    return ["",
            "### OpenShell sandbox policy (generated, policy v" +
            f"{osh.get('policy_version', '1')})",
            "",
            "```yaml",
            osh["policy_yaml"].rstrip(),
            "```"]


def render_markdown(**ctx: Any) -> str:
    L: list[str] = []
    A = L.append
    A(f"# AI Security Assessment — {ctx['product_name']}")
    A("")
    A(f"_Exposure tier:_ **{ctx['exposure_label']}** · _Generated:_ {ctx['created_at'] if 'created_at' in ctx else ''}")
    if ctx.get("product_url"):
        A(f"_Product link:_ {ctx['product_url']}")
    A("")
    A("---")
    A("")
    A("## Executive summary")
    A("")
    scoring = ctx.get("scoring") or {}
    inherent_pct = scoring.get("inherent_pct", ctx["overall_pct"])
    residual_pct = scoring.get("residual_pct", ctx["overall_pct"])
    delta = scoring.get("delta", round(residual_pct - inherent_pct, 1))
    bd = scoring.get("breakdown", {})
    active = scoring.get("active_controls", [])
    A(f"> **Residual risk: {residual_pct}/100 — {ctx['posture']}**")
    A("> ")
    A(f"> Inherent risk (no controls): **{inherent_pct}/100** → residual after "
      f"{len(active)} declared control(s): **{residual_pct}/100** "
      f"(**{delta:+g}**). {scoring.get('inherent_posture', '')} → {ctx['posture']}")
    A("")
    A("**How this score is derived** (fully deterministic — same inputs, same number):")
    A("")
    A(f"- Per threat: `inherent = L × I` on a 1–5 × 1–5 matrix; `L` is the catalog "
      f"baseline scaled by the exposure weight "
      f"(`{bd.get('exposure_label', '')}` = {bd.get('exposure_weight')}).")
    A("- `residual = L × (1 − control coverage) × I`, where a threat's coverage is the "
      "diminishing-returns combination of the declared controls that apply to it "
      "(e.g. C02 + C03 stack, but never reach certainty); likelihood never falls "
      f"below {int((bd.get('min_residual_floor') or 0.35) * 100)}% of inherent.")
    A(f"- Overall = `100 × ( {bd.get('worst_weight', 0.55)} × mean(top-{bd.get('top_n', 5)} "
      f"normalized scores) + {bd.get('breadth_weight', 0.45)} × mean(all normalized) )`, "
      f"counting only the {bd.get('applicable_threats', len(ctx['threats']))} applicable "
      f"threats — so one threat can no longer saturate the scale.")
    A("- Severity bands (5×5 calibration): ≥20 Critical, ≥12 High, ≥6 Medium, else Low.")
    A("")
    A("---")
    A("")
    persp = ctx.get("perspectives") or []
    if persp:
        A("## Highlights by audience")
        A("")
        A("_The same deterministic score, read through each role's decision lens._")
        A("")
        A("| Audience | Headline |")
        A("|---|---|")
        for pv in persp:
            A(f"| **{pv['label']}** | {pv['headline']} |")
        A("")
        for pv in persp:
            A(f"### {pv['label']}")
            A("")
            if pv.get("metrics"):
                A(" · ".join(f"**{m['k']}:** {m['v']}" for m in pv["metrics"]))
                A("")
            for b in pv.get("bullets", []):
                A(f"- {b['text']}")
            A("")
            A("**Focus:** " + " · ".join(pv.get("focus", [])))
            A("")
            inv = pv.get("investigation") or {}
            if inv.get("total_artifacts"):
                A(f"**Investigation coverage for this role:** "
                  f"{inv.get('matched', 0)} of {inv['total_artifacts']} artifacts match "
                  f"({inv.get('coverage_pct', 0)}%), {inv.get('cited', 0)} of them cited as "
                  f"assessment evidence.")
                A("")
                if inv.get("domains"):
                    A("Domains: " + " · ".join(inv["domains"]))
                    A("")
                for a in (inv.get("artifacts") or [])[:5]:
                    link = f"<{a['url']}>" if a.get("url") else a.get("title", "")
                    A(f"- **#{a['id']} {a['title']}** ({a.get('type', '')}, "
                      f"relevance {a.get('relevance', 0):.2f}) — {link} "
                      f"_{', '.join(a.get('hits', []))}_")
                A("")
    A("---")
    A("")
    top3 = ctx["threats"][:3]
    A("Top risks at a glance (residual):")
    A("")
    for t in top3:
        na = "" if t.get("applicable", True) else " _(not applicable here)_"
        A(f"- **{t['id']} {t['title']}** — residual severity "
          f"**{t['residual_severity']}** (L{t['likelihood']:g}×I{t['impact']:g}="
          f"{t['inherent_score']:g} inherent → {t['residual_score']:g} residual, "
          f"{t['coverage']:g}% covered by {', '.join(t['controls']) or 'no control'}){na}. "
          f"{t['mitigations'][0]}")
    A("")
    profile = profile_model_subject(ctx.get("product_name") or "",
                                    ctx.get("use_case") or "",
                                    ctx.get("focus") or [])
    if profile["is_model_query"] and profile["summary"]:
        scope_line = (f"Assessment scope: {ctx['product_name']} ({profile['summary']}) "
                      f"with **{ctx['exposure_label']}** data. {ctx['exposure_blurb']}")
    else:
        scope_line = (f"Assessment scope: use of {ctx['product_name']} "
                      f"with **{ctx['exposure_label']}** data. {ctx['exposure_blurb']}")
    A(scope_line)
    if profile["is_model_query"] and profile["summary"]:
        A("")
        bits = [f"Subject kind: model ({profile['summary']})."]
        if profile["families"]:
            bits.append("Family: " + ", ".join(profile["families"]) + ".")
        if profile["data"]:
            bits.append("Processes " + ", ".join(profile["data"]) + ".")
        if profile["trains_on_data"]:
            bits.append("Training/fine-tuning is in scope for data-leakage threats.")
        A("Subject profile: " + " ".join(bits))
    if ctx.get("use_case"):
        A("")
        A(f"Stated use case: {ctx['use_case']}")
    if ctx.get("exec_paragraph"):
        A("")
        A(f"{ctx['exec_paragraph']}")
    A("")
    A("**Related research & known attacks** (agentic search within this app's "
      "knowledge graph — see §6 for the full Known Exploits section):")
    A("")
    for line in (ctx.get("exec_evidence_lines") or ["No catalogue matches — see §6."]):
        A(f"- {line}")
    A("")
    A("Top in-app evidence:")
    A("")
    for ref in (ctx.get("exec_evidence_refs") or ["No related in-app artifacts found."]):
        A(f"- {ref}")
    A("")
    A("## 1. Product & evidence base")
    A("")
    if ctx.get("pages"):
        for p in ctx["pages"]:
            A(f"- **{p['title'] or '(no title)'}** — <{p['url']}> · _{p['status']}_")
            if p["excerpt"]:
                A(f"  > {p['excerpt'][:600]}")
    else:
        A("- No URLs fetched (offline or none supplied). Assessment proceeds from the "
          "generic AI-writing-assistant threat model and the workflow described below.")
    if ctx.get("workflow_text"):
        A("")
        A("Supplied workflow context:")
        A("")
        A(f"> {ctx['workflow_text'][:2000]}")
    A("")
    A("## 2. Reference workflow (derived from vendor write-up)")
    A("")
    A("Standard lifecycle for an AI writing assistant for metadata documentation:")
    A("")
    A("1. **Admin config** — enable feature, pin model version + region, map roles "
      "(see vendor config docs). Default OFF for Restricted domains.")
    A("2. **Asset ingest** — file/table/doc registered in the catalog with a classification label.")
    A("3. **Classification gate** — Restricted assets skip AI or require dual control; "
      "lower tiers proceed with redaction.")
    A("4. **AI draft** — assistant proposes description from schema/metadata only (no raw values).")
    A("5. **Steward review** — human verifies classification, facts and sensitivity; edits as needed.")
    A("6. **Publish with provenance** — store model id, prompt hash, reviewer, timestamp.")
    A("7. **Monitor** — drift detection, access reviews, audit exports.")
    A("")
    A("```mermaid workflow")
    A(ctx["diagrams"]["workflow"])
    A("```")
    A("")
    A("## 3. Data-flow & trust boundary")
    A("")
    A("```mermaid dataflow")
    A(ctx["diagrams"]["dataflow"])
    A("```")
    A("")
    A("Trust boundary: everything left of the policy gateway is customer-controlled; the LLM "
      "endpoint and its logging/retention are vendor-controlled and must be covered by DPA, "
      "residency and zero-retention terms.")
    A("")
    A("## 4. Threat paths")
    A("")
    A("```mermaid threat_paths")
    A(ctx["diagrams"]["threat_paths"])
    A("```")
    A("")
    A("## 5. Threat & risk register")
    A("")
    A("_Likelihood/Impact are exposure-scaled; Score is the inherent L×I; Coverage is the "
      "diminishing-returns efficacy of the declared controls for that threat; Residual is "
      "what is left after controls (the headline number uses this)._")
    A("")
    A("| ID | Threat | STRIDE | OWASP LLM | L | I | Inherent | Coverage | Residual | Severity | Applic. |")
    A("|---|---|---|---|---|---|---|---|---|---|---|")
    for t in ctx["threats"]:
        if t.get("applicable", True):
            A(f"| {t['id']} | {t['title']} | {t['stride']} | {t['owasp']} | "
              f"{t['likelihood']:g} | {t['impact']:g} | {t['inherent_score']:g} | "
              f"{t['coverage']:g}% | {t['residual_score']:g} | **{t['residual_severity']}** | "
              f"{t['applicability']:.0%} |")
        else:
            A(f"| {t['id']} | {t['title']} | {t['stride']} | {t['owasp']} | "
              f"{t['likelihood']:g} | {t['impact']:g} | {t['inherent_score']:g} | "
              f"{t['coverage']:g}% | {t['residual_score']:g} | _{t['residual_severity']}_ | "
              f"not applicable |")
    A("")
    for t in ctx["threats"]:
        A(f"### {t['id']} — {t['title']} _(Residual severity: {t['residual_severity']}, "
          f"L{t['likelihood']:g}×I{t['impact']:g}={t['inherent_score']:g} inherent → "
          f"{t['residual_score']:g} residual, {t['coverage']:g}% covered)_")
        A("")
        A(f"- **Category:** {t['stride']} · {t['owasp']}")
        A(f"- **Description:** {t['description']}")
        if t.get("controls"):
            A(f"- **Covered by:** {', '.join(t['controls'])}")
        if not t.get("applicable", True):
            A(f"- **Applicability:** {t['applicability']:.0%} — below the "
              f"{int(_MIN_APPLICABILITY * 100)}% reporting threshold for this product, "
              f"so it is reported but not scored.")
        A("- **Mitigations:**")
        for m in t["mitigations"]:
            A(f"  - {m}")
        A("")
    A("## 5b. Security controls in scope")
    A("")
    plan = ctx.get("control_plan") or {}
    active = set(scoring.get("active_controls", []))
    conf = plan.get("confidence", 0.0)
    src = plan.get("source", "unknown")
    A(f"Declared by the operator and analysed by the `control-analyst` agent "
      f"(confidence {conf:.0%}; {src}). Controls compound with diminishing returns, so "
      f"stacking several is useful but never removes a threat outright.")
    A("")
    A("| Control | Name | Efficacy | Threats | Standard | In place |")
    A("|---|---|---|---|---|---|")
    for c in control_catalog():
        tids = ", ".join(sorted(c["threats"].keys()))
        mark = "yes" if c["id"] in active else "—"
        A(f"| {c['id']} | {c['name']} | {c['efficacy']:.0%} | {tids} | "
          f"{c['standard']} | {mark} |")
    A("")
    A("## 5c. OpenShell protection posture")
    A("")
    for line in openshell_posture_lines(active, ctx.get("pages") or [],
                                        ctx.get("openshell") or {}):
        A(line)
    A("")
    proposed = plan.get("proposed_controls") or []
    if proposed:
        A("**Recommended additions** (highest marginal risk reduction first):")
        A("")
        for p in proposed:
            c = _CONTROL_BY_ID.get(p["id"], {})
            A(f"- **{p['id']} {p.get('name', c.get('name', ''))}** — {c.get('description', '')} "
              f"(_covers {len(c.get('threats', {}))} threats, efficacy {c.get('efficacy', 0):.0%}._)")
        A("")
    conf_map = ctx.get("evidence_confidence") or {}
    if conf_map:
        A("**Evidence confidence per threat** (from `research-collector` + `threat-intel`): "
          + ", ".join(f"{k} {v:.0%}" for k, v in sorted(conf_map.items())))
        A("")
    if ctx.get("exploits_markdown"):
        A(ctx["exploits_markdown"])
    else:
        A("## 6. Known exploits & research evidence")
        A("")
        A("- Evidence sub-agents unavailable for this run; see threat register (§5).")
        A("")
    A("## 7. Deep dive — accidental copy of sensitive info by employees")
    A("")
    A("- **How it happens:** time-pressured stewards paste raw samples, screenshots or full "
      "documents into the assistant for 'better wording'; autocomplete/plugins silently "
      "include surrounding context.")
    A("- **Why it matters here:** with Restricted/Confidential exposure a single paste can "
      "breach the trust boundary (T01/T02) and persist in logs, caches or training data.")
    A("- **Controls:** schema-only prompts; client-side DLP redaction; just-in-time warning "
      "on Confidential+ assets; paste-size limits; prompt logging with secret scrubbing; "
      "security-awareness moment built into the review step.")
    A("")
    A("## 8. Deep dive — misclassified / mislabelled files")
    A("")
    A("- **How it happens:** bulk imports inherit default labels; owners pick the wrong tier; "
      "labels go stale after content changes. The assistant then drafts and publishes "
      "descriptions consistent with the WRONG label (T03), spreading the error.")
    A("- **Controls:** mandatory classification confirmation before first AI suggestion; "
      "visual classification chip on every draft; ML-assisted re-classification scans; "
      "policy that AI output can never downgrade an asset's classification, only flag for "
      "human upgrade review; quarantine on classifier disagreement.")
    A("")
    A("## 9. Risk heat map")
    A("")
    A("_Residual L×I after declared controls. Cell shows threat IDs._")
    A("")
    A("|  | I1 | I2 | I3 | I4 | I5 |")
    A("|---|---|---|---|---|---|")
    grid: dict[tuple[int, int], list[str]] = {}
    for t in ctx["threats"]:
        if not t.get("applicable", True):
            continue
        rli = max(1, min(5, round(t["residual_likelihood"])))
        rim = max(1, min(5, round(t["impact"])))
        grid.setdefault((rli, rim), []).append(t["id"])
    for li in range(5, 0, -1):
        row = [f"| L{li} "]
        for im in range(1, 6):
            row.append(f"| {', '.join(grid.get((li, im), ['·']))} ")
        row.append("|")
        A("".join(row))
    A("")
    A("## 10. Compliance mapping (GDPR / ISO 27001 / SOC 2)")
    A("")
    A("- **GDPR:** DPIA (Art. 35) before rollout; lawful basis + RoPA update; data-minimisation "
      "(schema-only prompts); Chapter V transfer assessment for vendor endpoints; 72h breach path.")
    A("- **ISO 27001:2022:** A.5.14 (redaction), A.8.12 (DLP), A.5.33–34 (privacy), A.5.15–5.18 "
      "(access control), A.8.9 (logging/monitoring).")
    A("- **SOC 2:** CC6.1 (logical access), CC6.6 (encryption), CC7.2–7.4 (monitoring), "
      "with auditor evidence from prompt/review audit logs.")
    A("")
    A("## 11. Recommendations — 30 / 60 / 90 days")
    A("")
    A("- **0–30 days:** classification gate + DLP redaction; disable AI on Restricted domains; "
      "enable prompt/review audit logging; confirm zero-retention + region with vendor.")
    A("- **30–60 days:** provenance stamping; role re-mapping (least privilege); prompt-injection "
      "test suite; DPIA + DPA updates.")
    A("- **60–90 days:** re-classification scans; anomaly detection on usage; tabletop incident "
      "exercise (paste-leak scenario); publish internal AI-metadata handling standard.")
    A("")
    A("## Appendix — sources & agent-to-agent trail")
    A("")
    A("- Vendor blog + docs supplied in the request (see §1 evidence base for fetch status).")
    A("- OWASP Top 10 for LLM Applications; STRIDE threat modelling; GDPR / ISO 27001:2022 / SOC 2 criteria.")
    A("- In-app knowledge-graph evidence: `research-collector` agentic search over local artifacts (see §6).")
    if ctx.get("a2a_task_id"):
        A(f"- A2A workflow task `{ctx['a2a_task_id']}`: security-orchestrator → research-collector → "
          "threat-intel → report-writer (protocol a2a/1.0; full hop trace stored with the assessment).")
    A("- Note: diagrams render as Mermaid in the dashboard; the PDF embeds the same "
      "figures as vector drawings (Figures 1-3).")
    for line in openshell_policy_lines(ctx.get("openshell") or {}):
        A(line)
    A("")
    return "\n".join(L)


# ------------------------------------------- vector figures for PDF export ---

# Print versions of the three Mermaid diagrams (labels shortened for the page;
# the dashboard keeps the full text). Grid layout: node row/col are explicit,
# so figures are deterministic. Edge routes: "direct" (straight line),
# "detour-below" (same-row back edge, e.g. gateway → employee),
# "detour-left" (same-column upward edge, e.g. approve? → redraft).

_FIGURE_SPECS = {
    "dataflow": {
        "caption": "Data-flow and trust boundary",
        "pad_left": 0, "pad_top": 12, "pad_bottom": 26,
        "cell_w": 68, "cell_h": 62, "box_w": 64, "box_h": 38,
        "node_font": 6, "edge_font": 6,
        "nodes": [
            {"id": "U", "label": "Employee", "row": 0, "col": 0},
            {"id": "UI", "label": "Assistant UI", "row": 0, "col": 1},
            {"id": "GW", "label": "Policy\ngateway", "row": 0, "col": 2,
             "fill": "#d29922", "tcol": "#000000"},
            {"id": "LLM", "label": "LLM\nendpoint", "row": 0, "col": 3,
             "fill": "#f85149", "tcol": "#ffffff"},
            {"id": "REV", "label": "Steward\nreview", "row": 0, "col": 4},
            {"id": "CAT", "label": "Metadata\nstore", "row": 0, "col": 5},
            {"id": "C", "label": "Consumers", "row": 0, "col": 6},
        ],
        "edges": [
            ("U", "UI", "draft", "direct"),
            ("UI", "GW", "prompt", "direct"),
            ("GW", "LLM", "allow", "direct"),
            ("LLM", "REV", "suggest", "direct"),
            ("REV", "CAT", "publish", "direct"),
            ("CAT", "C", "read", "direct"),
            ("GW", "U", "block", "detour-below"),
        ],
    },
    "threat_paths": {
        "caption": "Threat paths to the published catalog",
        "pad_left": 0, "pad_top": 6, "pad_bottom": 6,
        "cell_w": 240, "cell_h": 42, "box_w": 220, "box_h": 32,
        "node_font": 7, "edge_font": 6,
        "nodes": [
            {"id": "A", "label": "Restricted / Confidential file", "row": 0, "col": 0},
            {"id": "B", "label": "Classification correct?", "row": 1, "col": 0, "shape": "diamond"},
            {"id": "C", "label": "T03: wrong label laundered", "row": 2, "col": 0,
             "fill": "#f85149", "tcol": "#ffffff"},
            {"id": "D", "label": "Assistant prompt", "row": 2, "col": 1},
            {"id": "E", "label": "DLP gateway?", "row": 3, "col": 1, "shape": "diamond"},
            {"id": "F", "label": "T01: paste leaves boundary", "row": 4, "col": 0,
             "fill": "#f85149", "tcol": "#ffffff"},
            {"id": "G", "label": "LLM inference", "row": 4, "col": 1},
            {"id": "H", "label": "T02/T07: retention copy", "row": 5, "col": 0,
             "fill": "#d29922", "tcol": "#000000"},
            {"id": "I", "label": "T05: injected instruction", "row": 5, "col": 1},
            {"id": "J", "label": "T04/T06: over-share", "row": 6, "col": 1,
             "fill": "#d29922", "tcol": "#000000"},
            {"id": "K", "label": "Published catalog", "row": 7, "col": 0},
        ],
        "edges": [
            ("A", "B", "", "direct"),
            ("B", "C", "mislabelled", "direct"),
            ("B", "D", "correct", "direct"),
            ("D", "E", "", "direct"),
            ("E", "F", "missing", "direct"),
            ("E", "G", "present", "direct"),
            ("G", "H", "", "direct"),
            ("G", "I", "", "direct"),
            ("I", "J", "", "direct"),
            ("C", "K", "", "direct"),
            ("F", "K", "", "direct"),
            ("H", "K", "", "direct"),
            ("J", "K", "", "direct"),
        ],
    },
    "workflow": {
        "caption": "Secure reference workflow",
        "pad_left": 78, "pad_top": 6, "pad_bottom": 6,
        "cell_w": 201, "cell_h": 42, "box_w": 188, "box_h": 32,
        "node_font": 7, "edge_font": 6,
        "nodes": [
            {"id": "S1", "label": "1. Admin config", "row": 0, "col": 0},
            {"id": "S2", "label": "2. Asset created / imported", "row": 1, "col": 0},
            {"id": "S3", "label": "3. Classification check?", "row": 2, "col": 0,
             "fill": "#d29922", "tcol": "#000000", "shape": "diamond"},
            {"id": "S4", "label": "4. AI drafts (redacted)", "row": 3, "col": 0},
            {"id": "S3R", "label": "Manual authoring", "row": 3, "col": 1},
            {"id": "S5", "label": "5. Steward review", "row": 4, "col": 0,
             "fill": "#58a6ff", "tcol": "#000000"},
            {"id": "S6", "label": "6. Approve?", "row": 5, "col": 0, "shape": "diamond"},
            {"id": "S7", "label": "7. Publish + provenance", "row": 6, "col": 0},
            {"id": "S8", "label": "8. Monitor", "row": 7, "col": 0},
        ],
        "edges": [
            ("S1", "S2", "", "direct"),
            ("S2", "S3", "", "direct"),
            ("S3", "S4", "allow", "direct"),
            ("S3", "S3R", "deny", "direct"),
            ("S4", "S5", "", "direct"),
            ("S5", "S6", "", "direct"),
            ("S6", "S7", "approved", "direct"),
            ("S7", "S8", "", "direct"),
            ("S6", "S4", "edits", "detour-left"),
        ],
    },
}


def _flow_drawing(spec: dict) -> object:
    """Render a figure spec to a reportlab Drawing (vector, PDF-native)."""
    from reportlab.graphics.shapes import Drawing, Rect, String, Line, Polygon
    from reportlab.lib.colors import HexColor, white, black
    import math

    pad_left = spec.get("pad_left", 0)
    pad_top = spec.get("pad_top", 6)
    pad_bottom = spec.get("pad_bottom", 6)
    cell_w, cell_h = spec["cell_w"], spec["cell_h"]
    box_w, box_h = spec["box_w"], spec["box_h"]
    node_font, edge_font = spec.get("node_font", 7), spec.get("edge_font", 6)

    nodes = {n["id"]: n for n in spec["nodes"]}
    ncols = max(n["col"] for n in spec["nodes"]) + 1
    nrows = max(n["row"] for n in spec["nodes"]) + 1
    W = pad_left + ncols * cell_w
    H = pad_top + nrows * cell_h + pad_bottom
    d = Drawing(W, H)

    def center(n):
        cx = pad_left + n["col"] * cell_w + cell_w / 2
        cy = H - pad_top - n["row"] * cell_h - cell_h / 2
        return cx, cy

    C = {nid: center(n) for nid, n in nodes.items()}
    BOX_STROKE = HexColor("#30363d")

    def arrowhead(tip, angle):
        L, Wd = 7, 3.2
        ux, uy = math.cos(angle), math.sin(angle)
        px, py = -uy, ux
        pts = [tip[0], tip[1],
               tip[0] - L * ux + Wd * px, tip[1] - L * uy + Wd * py,
               tip[0] - L * ux - Wd * px, tip[1] - L * uy - Wd * py]
        return Polygon(pts, fillColor=BOX_STROKE, strokeColor=BOX_STROKE,
                       strokeWidth=0.5)

    def label(text, x, y, anchor="middle"):
        if not text:
            return
        halo_w = len(text) * edge_font * 0.55 + 4
        x0 = x - halo_w / 2 if anchor == "middle" else x - 2
        d.add(Rect(x0, y - edge_font / 2 - 1, halo_w, edge_font + 3,
                   fillColor=white, strokeColor=None))
        d.add(String(x, y - edge_font * 0.35, text, fontName="Helvetica",
                     fontSize=edge_font, fillColor=black, textAnchor=anchor))

    # Edges draw lines only; arrowheads are collected and stamped after the
    # node boxes so tips stay visible above box fills.
    heads: list = []

    def edge_line(x1, y1, x2, y2):
        d.add(Line(x1, y1, x2, y2, strokeColor=BOX_STROKE, strokeWidth=0.7))

    def direct(src, dst, text):
        (x1, y1), (x2, y2) = C[src], C[dst]
        ns, nd = nodes[src], nodes[dst]
        same_row = ns["row"] == nd["row"]
        same_col = ns["col"] == nd["col"]
        dx, dy = x2 - x1, y2 - y1
        dist = math.hypot(dx, dy) or 1
        ux, uy = dx / dist, dy / dist
        t1 = box_w / 2 if same_row else (box_h / 2 if same_col else 14)
        t2 = box_w / 2 if same_row else (box_h / 2 if same_col else 18)
        sx, sy = x1 + ux * t1, y1 + uy * t1
        ex, ey = x2 - ux * t2, y2 - uy * t2
        edge_line(sx, sy, ex, ey)
        heads.append(((ex, ey), math.atan2(uy, ux)))
        if text:
            mx, my = (sx + ex) / 2, (sy + ey) / 2
            if same_col and not same_row:
                label(text, x1 + 5, my, anchor="start")
            elif same_row and not same_col:
                label(text, mx, y1 + box_h / 2 + 7)
            else:
                label(text, mx + 4, my - 3)

    def detour_below(src, dst, text):
        (x1, y1), (x2, y2) = C[src], C[dst]
        y_edge = y1 - box_h / 2
        y_mid = y_edge - 14
        edge_line(x1, y_edge, x1, y_mid)
        edge_line(x1, y_mid, x2, y_mid)
        edge_line(x2, y_mid, x2, y_edge)
        heads.append(((x2, y_edge), math.pi / 2))
        if text:
            label(text, (x1 + x2) / 2, y_mid + 3)

    def detour_left(src, dst, text):
        (x1, y1), (x2, y2) = C[src], C[dst]
        x_margin = pad_left - 14
        x_s = x1 - box_w / 2
        x_d = x2 - box_w / 2
        edge_line(x_s, y1, x_margin, y1)
        edge_line(x_margin, y1, x_margin, y2)
        edge_line(x_margin, y2, x_d, y2)
        heads.append(((x_d, y2), 0.0))
        if text:
            label(text, x_margin, (y1 + y2) / 2 + 3)

    for src, dst, text, route in spec["edges"]:
        if route == "detour-below":
            detour_below(src, dst, text)
        elif route == "detour-left":
            detour_left(src, dst, text)
        else:
            direct(src, dst, text)

    for nid, n in nodes.items():
        cx, cy = C[nid]
        fill = HexColor(n.get("fill", "#F2F4F7"))
        tcol = HexColor(n.get("tcol", "#111111"))
        if n.get("shape") == "diamond":
            hw, hh = box_w / 2, box_h / 2
            d.add(Polygon([cx, cy + hh, cx + hw, cy, cx, cy - hh, cx - hw, cy],
                          fillColor=fill, strokeColor=BOX_STROKE, strokeWidth=0.7))
        else:
            d.add(Rect(cx - box_w / 2, cy - box_h / 2, box_w, box_h,
                       fillColor=fill, strokeColor=BOX_STROKE, strokeWidth=0.7))
        lines = str(n.get("label", "")).split("\n")
        lh = node_font + 2
        y0 = cy + (len(lines) - 1) * lh / 2 - node_font * 0.35
        for li, ln in enumerate(lines):
            d.add(String(cx, y0 - li * lh, ln, fontName="Helvetica-Bold",
                         fontSize=node_font, fillColor=tcol, textAnchor="middle"))

    for tip, ang in heads:
        d.add(arrowhead(tip, ang))
    return d


def _fit_drawing(drw: object, max_w: float, max_h: float = 640.0) -> object:
    """Scale a Drawing down (never up) so it fits the page frame."""
    try:
        w, h = float(drw.width), float(drw.height)
    except Exception:
        return drw
    s = min(1.0, (max_w / w) if w > 0 else 1.0, (max_h / h) if h > 0 else 1.0)
    if s >= 1.0:
        return drw
    from reportlab.graphics.shapes import Drawing, Group
    g = Group(*list(drw.contents))
    g.transform = (s, 0, 0, s, 0, 0)
    nd = Drawing(w * s, h * s)
    nd.add(g)
    return nd


# -------------------------------------------------------------------- pdf ---

def build_pdf(markdown_text: str, title: str = "AI Security Assessment",
              meta: dict | None = None) -> bytes:
    """Render a presentation-quality PDF from the markdown.

    Cover verdict block + table of contents + page footers + vector figures.
    ``meta`` optionally carries product/exposure_label/overall/posture/
    task_id/date for the cover. Requires reportlab.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle, PageBreak,
                                        KeepTogether)
        from reportlab.platypus.tableofcontents import TableOfContents
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
    except ImportError as exc:
        raise RuntimeError("PDF export needs the 'reportlab' package (pip install reportlab).") from exc

    import io
    from datetime import datetime, timezone

    # Built-in PDF fonts are WinAnsi-encoded: map anything outside it to
    # ASCII/Latin-1 equivalents so glyphs never render as missing-symbol boxes.
    _WINANSI_FIX = {
        "–": "-", "—": "--", "→": "->", "←": "<-", "•": "-", "…": "...",
        "·": "-", "×": "x", "≤": "<=", "≥": ">=", "✓": "[ok]", "✗": "[x]",
        "“": '"', "”": '"', "‘": "'", "’": "'", "⚠": "!", "▸": "-",
        "│": "|", "─": "-", "█": "#", "░": "-", "⟳": "(refresh)",
        "⛁": "", "✔": "[ok]",
    }

    def _clean(s: str) -> str:
        for uni, asc in _WINANSI_FIX.items():
            s = s.replace(uni, asc)
        return "".join(c if ord(c) < 256 else "?" for c in s)

    def _inline(s: str) -> str:
        """Markdown-lite → reportlab para markup (expects plain text)."""
        seg = html.escape(_clean(s))
        seg = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", seg)
        seg = re.sub(r"`([^`]+)`", r"\1", seg)
        return seg

    SEV_COLORS = {"Critical": "#C0392B", "High": "#B9770E",
                  "Medium": "#2874A6", "Low": "#616A6B"}

    PAGE_W, PAGE_H = A4
    MARGIN = 2 * cm
    FRAME_W = PAGE_W - 2 * MARGIN

    styles = getSampleStyleSheet()
    sec_h1 = ParagraphStyle("SecH1", parent=styles["Heading1"],
                            fontSize=14, leading=17, spaceBefore=14,
                            spaceAfter=6, keepWithNext=True,
                            textColor=colors.HexColor("#1f2328"))
    sec_h2 = ParagraphStyle("SecH2", parent=styles["Heading2"],
                            fontSize=11, leading=14, spaceBefore=10,
                            spaceAfter=4, keepWithNext=True)
    sec_title = ParagraphStyle("SecTitle", parent=styles["Title"],
                               fontSize=22, leading=26, spaceAfter=2)
    sec_sub = ParagraphStyle("SecSub", parent=styles["Normal"],
                             fontSize=11, leading=14, spaceAfter=1,
                             textColor=colors.HexColor("#444444"))
    body = styles["BodyText"]
    bullet = ParagraphStyle("SecBullet", parent=body, leftIndent=14,
                            firstLineIndent=0, spaceBefore=2)
    cell_style = ParagraphStyle("SecCell", parent=body, fontSize=7,
                                leading=9, alignment=TA_LEFT)
    cell_head = ParagraphStyle("SecCellHead", parent=cell_style,
                               textColor=colors.white)
    caption_style = ParagraphStyle("SecCaption", parent=body, fontSize=9,
                                   leading=11, spaceBefore=8, spaceAfter=4,
                                   keepWithNext=True,
                                   textColor=colors.HexColor("#444444"))

    class _SecDocTemplate(SimpleDocTemplate):
        def afterFlowable(self, flowable):
            if isinstance(flowable, Paragraph) and \
                    getattr(flowable.style, "name", "") == "SecH1":
                self.notify("TOCEntry",
                            (0, flowable.getPlainText(), self.page))

    buf = io.BytesIO()
    doc = _SecDocTemplate(buf, pagesize=A4,
                          leftMargin=MARGIN, rightMargin=MARGIN,
                          topMargin=MARGIN, bottomMargin=MARGIN,
                          title=_clean(title))
    story: list = []

    meta = meta or {}
    product = str(meta.get("product") or title)
    datestr = str(meta.get("date") or
                  datetime.now(timezone.utc).date().isoformat())

    # ---- cover ----
    story.append(Paragraph(_inline(title), sec_title))
    story.append(Paragraph(_inline(product), sec_sub))
    cover_bits = [datestr]
    if meta.get("task_id"):
        cover_bits.append(f"A2A task {meta['task_id']}")
    story.append(Paragraph(_inline("  ·  ".join(cover_bits)), sec_sub))
    story.append(Spacer(1, 0.5 * cm))

    try:
        overall = float(meta.get("overall", -1))
    except (TypeError, ValueError):
        overall = -1
    if overall >= 0:
        if overall >= 75:
            band, bg = "#C0392B", "#FDEDEC"
        elif overall >= 50:
            band, bg = "#B9770E", "#FEF5E7"
        elif overall >= 30:
            band, bg = "#2874A6", "#EBF5FB"
        else:
            band, bg = "#1E8449", "#EAFAF1"
        score_cell = Paragraph(
            f'<font color="{band}"><font size="30"><b>{overall:g}</b></font>'
            '<font size="12">/100</font></font>',
            ParagraphStyle("SecScore", parent=body, alignment=1))
        detail_lines = [f"<b>{_inline(str(meta.get('posture', '')))}</b>"]
        if meta.get("exposure_label"):
            detail_lines.append(f"Exposure: {_inline(str(meta['exposure_label']))}")
        detail_cell = Paragraph("<br/>".join(detail_lines), body)
        verdict = Table([[score_cell, detail_cell]], colWidths=[110, FRAME_W - 110])
        verdict.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(bg)),
            ("BOX", (0, 0), (-1, -1), 1.2, colors.HexColor(band)),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ]))
        story.append(KeepTogether(verdict))

    perspectives = meta.get("perspectives") or []
    if perspectives:
        story.append(Paragraph("Audience highlights", styles["Heading2"]))
        rows = [[Paragraph("<b>Audience</b>", cell_head),
                 Paragraph("<b>Headline</b>", cell_head)]]
        for pv in perspectives:
            rows.append([Paragraph(_inline(str(pv.get("label", ""))), cell_style),
                         Paragraph(_inline(str(pv.get("headline", ""))), cell_style)])
        strip = Table(rows, colWidths=[95, FRAME_W - 95], repeatRows=1)
        strip.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#243447")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c8d0d8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#f4f6f8")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(strip)
        story.append(Spacer(1, 0.4 * cm))

    # ---- table of contents ----
    story.append(Paragraph("Contents", styles["Heading1"]))
    toc = TableOfContents()
    toc.levelStyles = [ParagraphStyle("TOC0", parent=body, fontSize=10,
                                      leading=15, leftIndent=0, spaceBefore=2)]
    story.append(toc)
    story.append(PageBreak())

    # ---- body ----
    in_table = False
    table_rows: list[list] = []
    table_head_raw: list[str] = []
    in_fence = False
    pending_fig = ""
    fig_no = 0

    def _cell(text: str, head: bool = False):
        plain = re.sub(r"\*+", "", text).strip()
        inner = _inline(text)
        if plain in SEV_COLORS:
            inner = f'<font color="{SEV_COLORS[plain]}">{inner}</font>'
        if head:
            inner = f"<b>{inner}</b>"
        return Paragraph(inner, cell_head if head else cell_style)

    def flush_table() -> None:
        nonlocal in_table, table_rows, table_head_raw
        if table_rows:
            header, *rows = table_rows
            kw: dict = {"repeatRows": 1}
            if len(header) == 8 and table_head_raw[:1] == ["ID"]:
                kw["colWidths"] = [26, 150, 62, 92, 16, 16, 30, 60]
            t = Table([header] + rows, **kw)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#21262d")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(t)
            story.append(Spacer(1, 0.4 * cm))
            table_rows = []
            table_head_raw = []
        in_table = False

    for raw in markdown_text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        # Fenced blocks carry the figure key: ```mermaid workflow|dataflow|threat_paths
        if stripped.startswith("```"):
            if not in_fence:
                info = stripped[3:].strip().split()
                pending_fig = info[1] if len(info) > 1 and info[0] == "mermaid" else ""
                if in_table:
                    flush_table()
            else:
                spec = _FIGURE_SPECS.get(pending_fig or "")
                if spec is not None:
                    fig_no += 1
                    cap = Paragraph(
                        _inline(f"Figure {fig_no}: {spec['caption']}"), caption_style)
                    fig = _fit_drawing(_flow_drawing(spec), FRAME_W)
                    story.append(KeepTogether([cap, fig]))
                    story.append(Spacer(1, 0.3 * cm))
                else:
                    story.append(Paragraph(
                        "<i>" + _inline("[Diagram - see the illustrated dashboard view.]")
                        + "</i>", body))
                    story.append(Spacer(1, 0.2 * cm))
                pending_fig = ""
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if cells and all(re.fullmatch(r":?-{1,}:?", c or "") for c in cells):
                continue  # separator row
            is_header = not table_rows
            if is_header:
                table_head_raw = list(cells)
            table_rows.append([_cell(c, head=is_header or idx == 0)
                               for idx, c in enumerate(cells)])
            in_table = True
            continue
        elif in_table:
            flush_table()
        if line.startswith("# "):
            story.append(Paragraph(_inline(line[2:]), sec_title))
            story.append(Spacer(1, 0.3 * cm))
        elif line.startswith("## "):
            story.append(Paragraph(_inline(line[3:]), sec_h1))
        elif line.startswith("### "):
            story.append(Paragraph(_inline(line[4:]), sec_h2))
        elif line.startswith(("- ", "* ", "> ")):
            story.append(Paragraph("- " + _inline(line[2:]), bullet))
        elif re.match(r"^\d+[.)]\s", line):
            story.append(Paragraph(_inline(line), bullet))
        elif line.startswith("---"):
            story.append(Spacer(1, 0.3 * cm))
        elif not line.strip():
            story.append(Spacer(1, 0.2 * cm))
        else:
            story.append(Paragraph(_inline(line), body))
    if in_table:
        flush_table()

    def _footer(canvas, _doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#656d76"))
        canvas.drawString(MARGIN, 1.2 * cm,
                          _clean(f"AI Security Assessment - {product}")[:90])
        canvas.drawRightString(PAGE_W - MARGIN, 1.2 * cm,
                               f"{datestr}  ·  p. {_doc.page}")
        canvas.restoreState()

    doc.multiBuild(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()
