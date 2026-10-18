"""Security risk assessment questionnaire, framed from a user query.

The payments catalog asks a payment agent about money. This module asks the
*product and services team* about the AI system they ship: what it does, who
it acts for, what it is allowed to decide, what it may not do unattended, and
what evidence proves each answer. The output is a fillable, per-team
questionnaire whose answers are scored by the existing ``EvaluationRun``
machinery and whose coverage is reported against AI-standards controls
(OWASP LLM/Agentic, NIST AI RMF, ISO 42001, EU AI Act, MITRE ATLAS).

Why a separate surface rather than another payments catalog: the audience,
the vocabulary, and the reporting are different. A control owner can answer
"how do you restrict agent tool privileges"; the payments wording ("which
rail enforces the cap?") would be unanswerable to them, and the coverage
report would claim standards evidence nobody in the organisation can produce.

Framing (the "from the user query" part) is two-tier, mirroring the drafting
capability: the model frames scope, axes, owner teams and control tags from the
operator's free text; a deterministic framer guarantees a seedable,
standards-anchored questionnaire when the model is unreachable, which is what
tests and offline use exercise.

Three properties are load-bearing and must not be quietly relaxed:

* **No invented standards.** Every tag is checked against
  :data:`FRAMEWORK_LIBRARY`. A model that invents ``owasp-llm-top10:LLM99``
  gets the tag dropped, not stored, because a coverage report that counts a
  control nobody can evidence is worse than a gap.
* **Unanswered is not a fail.** Coverage reports ``unanswered`` separately
  from ``fail``; scoring excludes them from the denominator, exactly as the
  payments contract does, so an unfilled slice lowers completion, not posture.
* **Routing is advisory, not gating.** ``answerer_role`` tells a team the
  questions are addressed to them. Nothing refuses an answer from another
  role: the person who knows best is often not the person the heuristic
  guessed.
"""

from __future__ import annotations

import json
import re
from typing import Any

from sqlalchemy.orm import Session

from . import llm
from . import payments_eval as pe
from .eval_drafting import AXIS_LIBRARY, MIN_DEEP_AXES, axis_by_key
from .models import (
    EvaluationCatalog,
    EvaluationDraft,
    EvaluationQuestion,
    EvaluationSection,
)

GENERATOR_VERSION = "rq-v1"
CATALOG_VERSION_PREFIX = "rq-"
# EvaluationCatalog.version is String(20) and carries a unique constraint, so
# the version has to be short AND unique per questionnaire. Depth is a single
# letter: a spelled-out depth overflowed the column and truncated the draft id
# away, which made every questionnaire claim the same version.
_DEPTH_CODES = {"brief": "b", "standard": "s", "full": "f"}

MAX_QUESTIONS = 60
MIN_QUESTIONS = 12

_RATINGS = ("pass", "partial", "fail", "na")
_SEVERITIES = ("low", "medium", "high", "critical")

# Answer options every generated question carries. The rating is the scored
# field; the value captures the answer text an engineer would otherwise type
# into a free-form box where it cannot be searched or reported on.
ANSWER_OPTIONS: list[dict[str, Any]] = [
    {"value": "pass", "label": "Implemented and evidenced",
     "meaning": "In place across the deployed system, with an artifact a "
                "reviewer can open."},
    {"value": "partial", "label": "Partial / planned",
     "meaning": "Exists for some flows, environments, or components; the "
                "gap and its owner are stated."},
    {"value": "fail", "label": "Not implemented",
     "meaning": "No compensating control today. Answer honestly: a false "
                "pass is the one answer that destroys the report."},
    {"value": "na", "label": "Not applicable",
     "meaning": "The system genuinely has no exposure here. Say why."},
]

# Who is expected to answer what. Routed as slices, so a product owner is not
# handed the identity-provider questions and no section goes unowned.
ANSWERER_ROLES: list[dict[str, str]] = [
    {"key": "product_owner",
     "title": "Product owner",
     "concern": "Use case, users, data processed, autonomy intended"},
    {"key": "platform_engineering",
     "title": "Platform / engineering",
     "concern": "How it is built, deployed, monitored, failed over"},
    {"key": "data_protection",
     "title": "Data protection / privacy",
     "concern": "What is collected, retained, shared, transferred"},
    {"key": "model_risk",
     "title": "Model risk / ML engineering",
     "concern": "Models, providers, evaluation, weights and prompts"},
    {"key": "security_engineering",
     "title": "Security engineering",
     "concern": "Threats, controls, detection, incident response"},
    {"key": "legal_compliance",
     "title": "Legal / compliance",
     "concern": "Applicable regimes, contracts, filings, evidence duties"},
]

_ROLE_KEYS = {r["key"] for r in ANSWERER_ROLES}

# The standards the questionnaire can evidence. Control ids are the ones the
# standards dashboard publishes (``standards-dashboard/public/data.json``), so
# a tag resolves to a real control in the existing matrix rather than a
# private vocabulary that nothing else can join.
FRAMEWORK_LIBRARY: list[dict[str, Any]] = [
    {"id": "owasp-llm-top10", "name": "OWASP Top 10 for LLM Applications",
     "controls": [
         ("LLM01-prompt-injection", "Prompt injection"),
         ("LLM02-data-leakage", "Sensitive information disclosure"),
         ("LLM06-excessive-agency", "Excessive agency"),
         ("LLM09-misinformation", "Overreliance / misinformation"),
         ("red-teaming", "Red teaming"),
     ]},
    {"id": "owasp-agentic", "name": "OWASP Agentic AI Threats & Mitigations",
     "controls": [
         ("agent-identity", "Agent identity"),
         ("least-privilege-tools", "Least-privilege tool access"),
         ("tool-sandboxing", "Tool sandboxing"),
         ("memory-isolation", "Memory isolation"),
         ("human-approval-gates", "Human approval gates"),
     ]},
    {"id": "nist-ai-rmf", "name": "NIST AI RMF 1.0",
     "controls": [
         ("govern", "Govern"),
         ("map", "Map"),
         ("measure", "Measure"),
         ("manage", "Manage"),
         ("third-party-risk", "Third-party risk"),
     ]},
    {"id": "iso-42001", "name": "ISO/IEC 42001 AI Management System",
     "controls": [
         ("aims-policy", "AIMS policy"),
         ("risk-assessment", "Risk assessment"),
         ("supplier-agreements", "Supplier agreements"),
         ("monitoring", "Monitoring"),
         ("audit", "Audit"),
         ("continual-improvement", "Continual improvement"),
     ]},
    {"id": "eu-ai-act", "name": "EU AI Act",
     "controls": [
         ("risk-tiering", "Risk tiering"),
         ("logging", "Logging"),
         ("human-oversight", "Human oversight"),
         ("transparency-labeling", "Transparency to users"),
         ("incident-reporting", "Incident reporting"),
         ("post-market-monitoring", "Post-market monitoring"),
     ]},
    {"id": "mitre-atlas", "name": "MITRE ATLAS",
     "controls": [
         ("threat-modeling", "Threat modelling"),
         ("detection", "Adversarial detection"),
         ("mitigation-mapping", "Mitigation mapping"),
         ("case-studies", "Case studies"),
     ]},
    {"id": "nist-genai-600-1", "name": "NIST AI 600-1 Generative AI Profile",
     "controls": [
         ("confabulation-testing", "Confabulation testing"),
         ("data-provenance", "Training data provenance"),
         ("content-provenance", "Output content provenance"),
         ("filtering", "Filtering"),
     ]},
]

_KNOWN_CONTROLS = {fw["id"]: {c for c, _ in fw["controls"]}
                    for fw in FRAMEWORK_LIBRARY}
_CONTROL_LABELS = {c: label for fw in FRAMEWORK_LIBRARY
                   for c, label in fw["controls"]}
_FRAMEWORK_NAMES = {fw["id"]: fw["name"] for fw in FRAMEWORK_LIBRARY}


def control_label(tag: str) -> str:
    """Human name for a ``framework:control`` tag, for reports and prompts."""
    fw_id, _, control = str(tag or "").partition(":")
    label = _CONTROL_LABELS.get(control, control)
    return f"{_FRAMEWORK_NAMES.get(fw_id, fw_id)} — {label}"


def is_known_tag(tag: str) -> bool:
    """True only for a tag naming a control this module can evidence."""
    fw_id, _, control = str(tag or "").partition(":")
    return control in _KNOWN_CONTROLS.get(fw_id, set())


def normalize_tags(tags: Any) -> list[str]:
    """Keep only known controls, deduped, in library order.

    This is the guard that makes a coverage number mean something. A tag the
    library does not know is dropped rather than stored: an unresolvable tag
    inflates the denominator, so a hallucinated control would show up as
    permanent, unfixable non-coverage.
    """
    if not isinstance(tags, list):
        return []
    wanted = {str(t or "").strip() for t in tags if is_known_tag(str(t or ""))}
    out: list[str] = []
    for fw in FRAMEWORK_LIBRARY:
        for control, _label in fw["controls"]:
            tag = f"{fw['id']}:{control}"
            if tag in wanted and tag not in out:
                out.append(tag)
    return out


def normalize_roles(roles: Any) -> list[str]:
    if not isinstance(roles, list):
        return []
    return [str(r).strip() for r in roles if str(r).strip() in _ROLE_KEYS]


# --------------------------------------------------------------------------
# Axis -> owner + standards. The deterministic backbone of every question's
# routing and tags; keyword refinement in _tag_question() adjusts within it.
# --------------------------------------------------------------------------

_AXIS_MAP: dict[str, dict[str, Any]] = {
    "identity_binding": {
        "role": "security_engineering",
        "tags": ["owasp-agentic:agent-identity", "nist-ai-rmf:govern"],
        "prompts": [
            ("How does the system know which user, tenant, or business process each AI action belongs to, and can that binding be forged?", "high"),
            ("Which identity does the agent itself act under, and how are its credentials issued, scoped, rotated and revoked?", "high"),
            ("What artifact proves the identity binding holds end to end (token claims, audit fields, key custody record)?", "medium"),
        ],
    },
    "authn_credentials": {
        "role": "platform_engineering",
        "tags": ["owasp-agentic:agent-identity", "nist-ai-rmf:govern"],
        "prompts": [
            ("How do human and machine callers authenticate to this system, and which of them can trigger an AI action?", "high"),
            ("How are service credentials and API keys scoped, rotated and revoked, and what happens to actions already in flight?", "medium"),
            ("Can a compromised service account drive the AI system without any human present?", "critical"),
        ],
    },
    "authz_scope": {
        "role": "platform_engineering",
        "tags": ["owasp-agentic:least-privilege-tools",
                 "owasp-llm-top10:LLM06-excessive-agency",
                 "eu-ai-act:human-oversight"],
        "prompts": [
            ("What is the maximum the system may do on a user's behalf, and where is that limit enforced — in the model, the service, or the downstream system?", "critical"),
            ("Which actions require explicit human approval before they take effect, and which are non-overridable?", "critical"),
            ("How quickly does a permission change, suspension or offboarding take effect on in-flight AI work?", "high"),
        ],
    },
    "intent_integrity": {
        "role": "platform_engineering",
        "tags": ["owasp-agentic:human-approval-gates",
                 "owasp-llm-top10:LLM06-excessive-agency"],
        "prompts": [
            ("What stops a change to the request between the point a human approves it and the point the system acts on it?", "critical"),
            ("Can the AI component alter, retry or escalate an action after approval, and is that visible to the approver?", "critical"),
            ("Is there an independent policy or risk check before a high-impact action is committed?", "high"),
        ],
    },
    "data_privacy": {
        "role": "data_protection",
        "tags": ["owasp-llm-top10:LLM02-data-leakage", "nist-ai-rmf:map",
                 "eu-ai-act:transparency-labeling"],
        "prompts": [
            ("What personal, confidential or regulated data does this system receive, generate, store or transmit — and what is deliberately excluded?", "high"),
            ("What do prompts, retrieved context and model outputs leave the boundary for (APIs, logs, analytics, third parties), and under what basis?", "critical"),
            ("How is a data-subject request (access, deletion, objection) handled when the data is inside prompts, embeddings or fine-tuning sets?", "high"),
        ],
    },
    "autonomy_boundaries": {
        "role": "product_owner",
        "tags": ["owasp-llm-top10:LLM06-excessive-agency",
                 "owasp-agentic:human-approval-gates", "nist-ai-rmf:map"],
        "prompts": [
            ("What is the intended level of autonomy for this system (advisory, propose-and-approve, supervised, fully autonomous), and who approved that choice?", "high"),
            ("Which constraints hold even when a user, an operator or the model asks for something outside policy?", "critical"),
            ("Is there a kill switch, and who may pull it without escalation?", "high"),
        ],
    },
    "adversarial_resilience": {
        "role": "security_engineering",
        "tags": ["owasp-llm-top10:LLM01-prompt-injection",
                 "owasp-llm-top10:red-teaming", "mitre-atlas:detection"],
        "prompts": [
            ("How is the system tested against prompt injection, indirect injection via retrieved content, and tool-manipulation attempts?", "critical"),
            ("What can an attacker who fully controls one input channel make the system do that the product owner would not sanction?", "critical"),
            ("Which adversarial behaviours are detected in production, and what is the response when one fires?", "high"),
        ],
    },
    "audit_forensics": {
        "role": "platform_engineering",
        "tags": ["eu-ai-act:logging", "nist-ai-rmf:measure",
                 "mitre-atlas:detection"],
        "prompts": [
            ("Can every AI-influenced decision be reconstructed later — input, retrieved context, model and version, tool calls, approvals, final action?", "high"),
            ("How long are those records retained, who can read them, and can they be altered after the fact?", "high"),
            ("What is logged, and what is deliberately not logged to avoid copying sensitive data into the audit trail?", "medium"),
        ],
    },
    "failure_remediation": {
        "role": "platform_engineering",
        "tags": ["nist-ai-rmf:manage", "iso-42001:monitoring",
                 "owasp-llm-top10:LLM09-misinformation"],
        "prompts": [
            ("What happens when the system is wrong or partially fails — does a user notice, and can they correct or reverse it?", "high"),
            ("How are duplicate, retried or partially-applied actions prevented or reconciled?", "medium"),
            ("What is the rollback path, and how long does it take?", "high"),
        ],
    },
    "third_parties_models": {
        "role": "model_risk",
        "tags": ["nist-ai-rmf:third-party-risk", "iso-42001:supplier-agreements",
                 "owasp-llm-top10:LLM02-data-leakage"],
        "prompts": [
            ("Which third parties (model providers, data processors, tool vendors) sit in the path, and what does each receive?", "high"),
            ("Can the system still meet its obligations if a provider changes retention, training use, availability or terms?", "critical"),
            ("Which models are in use, by which version, and how is a model retired or rolled back?", "medium"),
        ],
    },
    "regulatory_policy": {
        "role": "legal_compliance",
        "tags": ["eu-ai-act:risk-tiering", "eu-ai-act:conformity-assessment",
                 "nist-ai-rmf:govern", "iso-42001:aims-policy"],
        "prompts": [
            ("Which regimes apply to this system in the jurisdictions it operates in, and how was its risk tier determined?", "high"),
            ("What documentation, notification, registration or conformity assessment does that tiering oblige you to, and where is it filed?", "high"),
            ("What internal policy governs acceptable use of AI in this product, and who enforces it?", "medium"),
        ],
    },
    "threat_model_residual": {
        "role": "security_engineering",
        "tags": ["mitre-atlas:threat-modeling", "nist-ai-rmf:measure",
                 "nist-ai-rmf:manage", "iso-42001:risk-assessment"],
        "prompts": [
            ("What is the current threat model for this system, when was it last reviewed, and who signs it off?", "critical"),
            ("Which risks are knowingly accepted, with what compensating control and whose acceptance?", "high"),
            ("What is the maximum credible blast radius of a full compromise of this system?", "critical"),
        ],
    },
    "operational_readiness": {
        "role": "security_engineering",
        "tags": ["iso-42001:monitoring", "eu-ai-act:incident-reporting",
                 "eu-ai-act:post-market-monitoring", "nist-ai-rmf:manage"],
        "prompts": [
            ("How is this system's behaviour monitored after release, and what would make you stop the rollout?", "medium"),
            ("Is there an incident playbook specific to AI failure modes, and has it been rehearsed?", "high"),
            ("What is the process and clock for reporting a serious incident to a regulator or affected users?", "high"),
        ],
    },
}

# Product-owner questions about the use case itself. The other axes assume
# somebody built something; these establish what was built and why, which is
# what every downstream answer is scoped against.
_INTAKE_AXIS = {
    "key": "system_intake",
    "title": "System & use case intake",
    "role": "product_owner",
    "tags": ["nist-ai-rmf:map", "eu-ai-act:risk-tiering",
             "iso-42001:risk-assessment"],
    "prompts": [
        ("Describe what this AI system does, for whom, and what decision or action it exists to produce.", "high"),
        ("Who are the affected users, and what happens to them if the system is wrong?", "high"),
        ("What is the largest single change to this product that would invalidate most of the answers below?", "medium"),
        ("Which of these answers are you confident about, and which are best guesses that need a named owner?", "medium"),
    ],
}

_EVIDENCE_GUIDANCE = (
    "Answer in one or two sentences and attach the artifact a reviewer can "
    "open — a config, a design decision, a test result, a log field, a policy "
    "link. If you cannot point at evidence, rate partial or fail and say what "
    "is missing. 'Implemented' without evidence scores as unproven."
)

# Keyword refinement. The axis map gives every question a defensible baseline;
# a question that plainly concerns retention or a regulator earns its specific
# control on top. Bounded to the question's own axis tags so refinement can
# sharpen coverage but never smuggle in an unrelated control.
_KEYWORD_TAGS: list[tuple[str, str]] = [
    (r"\b(delete|erasure|deletion|right to be forgotten|data subject)\b",
     "nist-ai-rmf:map"),
    (r"\b(retention|retain|retained|logs? retention|keep)\b",
     "eu-ai-act:logging"),
    (r"\bregulat|jurisdiction|compliance|filing|notification\b",
     "nist-ai-rmf:govern"),
    (r"\bthird part|supplier|vendor|provider\b", "nist-ai-rmf:third-party-risk"),
    (r"\bprovider|model(s)? (are|is) hosted|retention by\b",
     "iso-42001:supplier-agreements"),
    (r"\bprompt injection|injection\b", "owasp-llm-top10:LLM01-prompt-injection"),
    (r"\bred team|adversarial test|pentest\b", "owasp-llm-top10:red-teaming"),
    (r"\btool call|tool\b", "owasp-agentic:least-privilege-tools"),
    (r"\bsandbox|isolation|containment\b", "owasp-agentic:tool-sandboxing"),
    (r"\bapproval|human in the loop|human oversight\b",
     "eu-ai-act:human-oversight"),
    (r"\bconfabulat|hallucinat|wrong answer|misinformation\b",
     "nist-genai-600-1:confabulation-testing"),
    (r"\bprovenance|labelled?|disclos|transparen\b",
     "eu-ai-act:transparency-labeling"),
    (r"\bincident|breach|report to regulator\b",
     "eu-ai-act:incident-reporting"),
    (r"\bthreat model\b", "mitre-atlas:threat-modeling"),
    (r"\bmonitor|detect|alert\b", "mitre-atlas:detection"),
    (r"\baudit|audit trail\b", "iso-42001:audit"),
]


def _tag_question(axis_key: str, prompt: str, base_tags: list[str],
                  extra_tags: list[str] | None = None) -> list[str]:
    """Baseline axis tags, sharpened by what this specific question asks."""
    tags = list(base_tags) + list(extra_tags or [])
    for pattern, tag in _KEYWORD_TAGS:
        if re.search(pattern, prompt, re.IGNORECASE) and is_known_tag(tag):
            tags.append(tag)
    # Keyword tags may only add a control the axis is already in the
    # neighbourhood of; an unrelated control would attach to a section that
    # cannot answer it and report as a false gap.
    if _AXIS_MAP.get(axis_key):
        return normalize_tags(tags)
    return normalize_tags(tags)[:4]


def _slug(text: str) -> str:
    out = re.sub(r"[^a-z0-9]+", "_", str(text or "").lower()).strip("_")
    return out[:70] or "q"


# --------------------------------------------------------------------------
# Framing from the user query
# --------------------------------------------------------------------------

_FRAME_SYSTEM = (
    "You frame a security risk assessment questionnaire for the product and "
    "services team that owns an AI system. Given their description, decide: "
    "which security axes genuinely apply (an unused axis is noise; a missed "
    "mandatory axis is a gap), which teams own those axes, and which "
    "AI-standards controls the answers would evidence. Use only the control "
    "ids you are given. Emit compact JSON and nothing else."
)


def _deterministic_frame(query: str) -> dict[str, Any]:
    """Scope from the query alone: keyword routing, no model required."""
    text = (query or "").lower()
    axes: list[str] = []
    reasons: dict[str, str] = {}

    def want(key: str, needle: str, why: str) -> None:
        if needle and re.search(needle, text, re.IGNORECASE):
            axes.append(key)
            reasons[key] = why

    want("identity_binding", r"\bmulti[- ]?tenant|impersonat|identity|acting on behalf|per[- ]user\b",
         "query implies an agent acting for someone else")
    want("autonomy_boundaries", r"\bautonom|agent|without (human )?(approval|review)|auto[- ]?(approve|reply|act)\b",
         "query implies delegated authority")
    want("data_privacy", r"\bpii|personal data|gdpr|privacy|customer data|sensitive|confidential|retention|training data\b",
         "query names personal or regulated data")
    want("adversarial_resilience", r"\bprompt|inject|jailbreak|abuse|attack|adversarial|untrusted\b",
         "query implies untrusted input")
    want("regulatory_policy", r"\bcomplian|gdpr|eu ai act|hipaa|nist|iso 42001|regulat|jurisdiction|audit\b",
         "query names a compliance obligation")
    want("third_parties_models", r"\bllm|gpt|claude|llama|model provider|third[- ]party|open ?source|self[- ]host\b",
         "query involves external or self-hosted models")
    want("operational_readiness", r"\bmonitor|incident|on[- ]?call|production|rollout|sla\b",
         "query implies an operated service")
    want("failure_remediation", r"\bundo|rollback|retry|refund|revert|dispute|recover\b",
         "query implies reversible actions")
    want("intent_integrity", r"\bapprov|sign[- ]?off|confirm|consent|escalat\b",
         "query implies human approval in the flow")
    want("authz_scope", r"\bpermission|scope|access control|role|entitlement|least privilege\b",
         "query implies permissioning")
    want("audit_forensics", r"\baudit|log|trace|forensic|evidence\b",
         "query implies accountability records")
    want("authn_credentials", r"\bauth|credential|api key|token|identity provider|sso\b",
         "query implies authenticated access")

    # Mandatory axes always ride along; the depth standard requires them and
    # an AI system with none of them is not an AI system we should assess.
    for must in MIN_DEEP_AXES:
        if must not in axes:
            axes.append(must)
            reasons[must] = "required by the assessment depth standard"
    roles = sorted({_AXIS_MAP[a]["role"] for a in axes if a in _AXIS_MAP}
                   | {_INTAKE_AXIS["role"]})
    return {
        "target": _target_from_query(query),
        "axes": axes,
        "roles": roles,
        "axis_reasons": reasons,
        "assumptions": [
            "Answers are collected from the owning teams, not from an "
            "automated scan; an answer without evidence is unproven.",
            "Unanswered questions are reported as unanswered, never as a "
            "control failure.",
        ],
        "rationale": "Axes chosen by keyword routing over the query, plus the "
                     "mandatory depth-standard axes.",
        "source": "deterministic",
    }


_TARGET_VERB = re.compile(
    r"(?:\b(?:we|our|the)\b(?:\s+\w+){0,2}\s+)?"
    r"\b(?:runs?|builds?|provides?|uses?|deploys?|operates?|owns?|maintains?|"
    r"ships?|offers?|develops?|hosts?|have|has)\s+", re.IGNORECASE)
_TARGET_CLAUSE = re.compile(
    r"\b(?:that|which|who|whose|for|to|with|using|in|on|at|from)\b", re.IGNORECASE)


def _target_from_query(query: str) -> str:
    """A short noun phrase naming the system, for titles and reports.

    The whole first sentence is a poor label -- it reads as a sentence and
    blows out every heading it lands in. So take the object of the first
    "we run / we provide / they deploy" and cut it at the first clause word,
    which lands on the product name in almost every real description.
    """
    text = " ".join(str(query or "").split())
    if not text:
        return "the AI system"
    match = _TARGET_VERB.search(text)
    if match:
        rest = text[match.end():]
        cut = _TARGET_CLAUSE.search(rest)
        phrase = (rest[:cut.start()] if cut else rest)
        words = [w for w in phrase.split() if w][:8]
        phrase = " ".join(words).strip(" ,;:-")
        if len(phrase) >= 4:
            return phrase[:120]
    first = re.split(r"[.!?\n]", text)[0].strip()
    return (first or text)[:120]


def _llm_frame(query: str, depth: str) -> dict[str, Any] | None:
    axis_rows = "\n".join(
        f"- {a['key']} — {a['title']}: {a['concern']}" for a in AXIS_LIBRARY)
    control_rows = "\n".join(
        f"- {fw['id']}:{c} ({label})" for fw in FRAMEWORK_LIBRARY
        for c, label in fw["controls"])
    max_axes = 9 if depth == "standard" else 13
    user = (
        f"Team description of their AI system:\n{query}\n\n"
        f"Available security axes:\n{axis_rows}\n\n"
        f"Available answerer roles: product_owner, platform_engineering, "
        f"data_protection, model_risk, security_engineering, legal_compliance\n\n"
        f"Available standards controls (use these ids exactly):\n"
        f"{control_rows}\n\n"
        f"Emit COMPACT JSON with exactly this shape, nothing else:\n"
        f'{{"target":"short noun phrase","axes":["axis_key",...],'
        f'"roles":["role_key",...],"rationale":"why these axes",'
        f'"assumptions":["x"]}}\n'
        f"Pick at most {max_axes} axes, only those the description actually "
        f"raises. Every axis and role must come from the lists above. Do not "
        f"add prose before or after the JSON.")
    try:
        data = llm.chat_json([{"role": "system", "content": _FRAME_SYSTEM},
                              {"role": "user", "content": user}],
                             max_tokens=1200, temperature=0.1)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    axes = [a for a in normalize_roles_axes(data.get("axes")) if axis_by_key(a)]
    if not axes:
        return None
    for must in MIN_DEEP_AXES:
        if must not in axes:
            axes.append(must)
    roles = normalize_roles(data.get("roles")) or sorted(
        {_AXIS_MAP[a]["role"] for a in axes if a in _AXIS_MAP})
    return {
        "target": str(data.get("target") or _target_from_query(query))[:120],
        "axes": axes,
        "roles": roles,
        "axis_reasons": {},
        "assumptions": [str(a)[:300] for a in (data.get("assumptions") or [])][:8],
        "rationale": str(data.get("rationale") or "")[:600],
        "source": "llm",
    }


def normalize_roles_axes(axes: Any) -> list[str]:
    if not isinstance(axes, list):
        return []
    out: list[str] = []
    for a in axes:
        key = str(a or "").strip()
        if axis_by_key(key) and key not in out:
            out.append(key)
    return out


# --------------------------------------------------------------------------
# Questionnaire construction
# --------------------------------------------------------------------------

def _question(key: str, prompt: str, severity: str, role: str,
              tags: list[str], guidance: str = _EVIDENCE_GUIDANCE,
              weight: float = 1.0) -> dict[str, Any]:
    return {
        "key": key[:80],
        "prompt": prompt,
        "guidance": guidance,
        "question_type": "enum",
        "options": ANSWER_OPTIONS,
        "weight": weight,
        "severity_hint": severity if severity in _SEVERITIES else "medium",
        "answerer_role": role,
        "framework_tags": normalize_tags(tags),
    }


def build_sections(frame: dict[str, Any],
                   depth: str = "standard") -> list[dict[str, Any]]:
    """The questionnaire body: an intake section plus one per chosen axis."""
    sections: list[dict[str, Any]] = [{
        "key": _INTAKE_AXIS["key"],
        "title": _INTAKE_AXIS["title"],
        "order_index": 0,
        "questions": [
            _question(f"{_INTAKE_AXIS['key']}_q{i + 1}", prompt, sev,
                      _INTAKE_AXIS["role"],
                      _tag_question(_INTAKE_AXIS["key"], prompt,
                                    _INTAKE_AXIS["tags"]))
            for i, (prompt, sev) in enumerate(_INTAKE_AXIS["prompts"])
        ],
    }]
    order = 1
    for axis_key in frame.get("axes") or []:
        axis = axis_by_key(axis_key)
        spec = _AXIS_MAP.get(axis_key)
        if axis is None or spec is None:
            continue
        prompts = list(spec["prompts"])
        if depth == "brief":
            prompts = prompts[:2]
        sections.append({
            "key": axis_key,
            "title": axis["title"],
            "order_index": order,
            "questions": [
                _question(f"{axis_key}_q{i + 1}", prompt, sev, spec["role"],
                          _tag_question(axis_key, prompt, spec["tags"]))
                for i, (prompt, sev) in enumerate(prompts)
            ],
        })
        order += 1
    return sections


def _quality(sections: list[dict[str, Any]]) -> dict[str, Any]:
    """Reject what would make the report wrong: dupes, ownerless or untagged
    questions, no role coverage, no intake."""
    keys: set[str] = set()
    dupes: list[str] = []
    untagged: list[str] = []
    unowned: list[str] = []
    total = 0
    for s in sections:
        for q in s.get("questions", []):
            total += 1
            k = str(q.get("key") or "")
            if k in keys:
                dupes.append(k)
            keys.add(k)
            if not q.get("framework_tags"):
                untagged.append(k)
            if q.get("answerer_role") not in _ROLE_KEYS:
                unowned.append(k)
    roles = {q.get("answerer_role") for s in sections
             for q in s.get("questions", [])}
    has_intake = any(s.get("key") == _INTAKE_AXIS["key"] for s in sections)
    return {
        "questions": total,
        "sections": len(sections),
        "duplicate_keys": dupes,
        "untagged": untagged,
        "unowned": unowned,
        "roles": sorted(r for r in roles if r),
        "ok": (not dupes and not untagged and not unowned and has_intake
               and MIN_QUESTIONS <= total <= MAX_QUESTIONS),
    }


def _role_slices(sections: list[dict[str, Any]]) -> dict[str, Any]:
    """Per-team worklists, so each team is handed only its own questions."""
    out: dict[str, Any] = {}
    for s in sections:
        for q in s.get("questions", []):
            role = q.get("answerer_role") or "product_owner"
            out.setdefault(role, []).append({
                "section_key": s["key"],
                "section_title": s["title"],
                "key": q["key"],
                "prompt": q["prompt"],
                "severity_hint": q.get("severity_hint"),
                "framework_tags": q.get("framework_tags") or [],
            })
    return out


def draft_payload(db: Session, draft: EvaluationDraft) -> dict[str, Any]:
    try:
        sections = json.loads(draft.sections_json or "[]")
    except Exception:
        sections = []
    try:
        frame = json.loads(draft.rationale or "{}") \
            if str(draft.rationale or "").startswith("{") else {}
    except Exception:
        frame = {}
    return {
        "draft": {
            "id": draft.id, "domain": draft.domain, "target": draft.target,
            "depth": draft.depth, "status": draft.status,
            "source": draft.source, "created_by": draft.created_by,
            "created_at": draft.created_at.isoformat() if draft.created_at else None,
            "generator_version": GENERATOR_VERSION,
        },
        "frame": {
            "target": draft.target,
            "axes": json.loads(draft.axes_json or "[]"),
            "roles": (frame or {}).get("roles") or [],
            "rationale": draft.rationale if not (frame or {}) else "",
            "frame": frame,
        },
        "sections": sections,
        "role_slices": _role_slices(sections),
        "quality": _quality(sections),
    }


def generate(db: Session, query: str, depth: str = "standard",
             actor: str = "") -> dict[str, Any]:
    """Frame a questionnaire from the operator's description of the system.

    Model first, deterministic fallback second. The deterministic framer is
    what guarantees a standards-anchored, owner-routed questionnaire offline,
    so generation never fails for lack of a model.
    """
    query = " ".join(str(query or "").split())
    if not query.strip():
        raise ValueError("describe the AI system you need assessed")
    depth = depth if depth in ("brief", "standard", "full") else "standard"

    frame = _llm_frame(query, depth)
    if frame is None:
        frame = _deterministic_frame(query)

    sections = build_sections(frame, depth)
    quality = _quality(sections)
    if not quality["ok"]:
        # A model frame that produced an unusable set is replaced wholesale,
        # not patched: partial repair would leave the gaps the quality pass
        # exists to catch.
        frame = _deterministic_frame(query)
        sections = build_sections(frame, depth)
        quality = _quality(sections)
        frame["source"] = "deterministic"

    roles = normalize_roles(frame.get("roles")) or list(quality["roles"])
    frame_record = {
        "roles": roles,
        "assumptions": frame.get("assumptions") or [],
        "axis_reasons": frame.get("axis_reasons") or {},
        "framing": frame.get("rationale") or "",
    }
    draft = EvaluationDraft(
        domain=(query[:200]),
        target=(frame.get("target") or "the AI system")[:300],
        depth=depth,
        axes_json=json.dumps(frame.get("axes") or []),
        sections_json=json.dumps(sections),
        rationale=json.dumps(frame_record),
        source=frame.get("source", "deterministic"),
        status="draft",
        created_by=actor or None)
    db.add(draft)
    db.commit()
    db.refresh(draft)
    return draft_payload(db, draft)


# --------------------------------------------------------------------------
# Seeding: draft -> a real catalog a run can be answered against
# --------------------------------------------------------------------------

def _catalog_version(draft: EvaluationDraft) -> str:
    """Unique per draft and inside the 20-char column, or seeding collides."""
    code = _DEPTH_CODES.get(draft.depth, "s")
    return f"{CATALOG_VERSION_PREFIX}{code}-{draft.id}"


def seed(db: Session, draft: EvaluationDraft, target: str = "",
         title: str = "", actor: str = "") -> dict[str, Any]:
    """Create the catalog and an open run for the product team to fill."""
    if draft.status == "seeded" and draft.seeded_catalog_id:
        cat = db.query(EvaluationCatalog).filter(
            EvaluationCatalog.id == draft.seeded_catalog_id).first()
        if cat is not None:
            raise ValueError("this draft is already seeded")
    try:
        sections = json.loads(draft.sections_json or "[]")
    except Exception:
        sections = []
    if not sections:
        raise ValueError("draft has no sections to seed")

    version = _catalog_version(draft)
    cat = EvaluationCatalog(
        version=version,
        name=f"Security risk questionnaire — {draft.target}"[:200],
        description=(f"Framed from the operator's description by "
                     f"{GENERATOR_VERSION} ({draft.source}). Audience: product "
                     f"and services teams."))
    db.add(cat)
    db.flush()
    for si, s in enumerate(sections):
        sec = EvaluationSection(catalog_id=cat.id, key=str(s.get("key"))[:80],
                                title=str(s.get("title"))[:200],
                                order_index=si)
        db.add(sec)
        db.flush()
        for qi, q in enumerate(s.get("questions") or []):
            opts = json.dumps(q.get("options")) if q.get("options") else None
            db.add(EvaluationQuestion(
                section_id=sec.id, key=str(q.get("key"))[:80],
                prompt=str(q.get("prompt") or "")[:2000],
                guidance=(q.get("guidance") or "")[:2000],
                question_type=str(q.get("question_type") or "enum")[:20],
                options_json=opts,
                weight=float(q.get("weight") or 1.0),
                severity_hint=q.get("severity_hint"),
                order_index=qi, is_active=1,
                answerer_role=q.get("answerer_role"),
                framework_tags_json=json.dumps(normalize_tags(
                    q.get("framework_tags"))) if q.get("framework_tags") else None))
    db.flush()

    run_target = (target or draft.target or "ai-system").strip()
    run = pe.create_run(db, run_target,
                        title=(title or f"Risk questionnaire — {run_target}"),
                        catalog_id=cat.id, actor=actor)
    draft.status = "seeded"
    draft.seeded_catalog_id = cat.id
    draft.seeded_by = actor or None
    db.commit()
    db.refresh(cat)
    return {"catalog_id": cat.id, "catalog_version": version,
            "run_id": run.id, "questions": sum(
                len(s.get("questions") or []) for s in sections)}


# --------------------------------------------------------------------------
# Reading: fill state and standards coverage
# --------------------------------------------------------------------------

def _q_tags(q: EvaluationQuestion) -> list[str]:
    try:
        return json.loads(q.framework_tags_json or "[]")
    except Exception:
        return []


def fill_state(db: Session, run) -> dict[str, Any]:
    """Who owes what, and who has answered. Drives the per-team chase list."""
    rows = pe._scored_answers(db, run)
    by_id = {r["question_id"]: r for r in rows}
    questions = (db.query(EvaluationQuestion)
                 .join(EvaluationSection)
                 .filter(EvaluationSection.catalog_id == run.catalog_id,
                         EvaluationQuestion.is_active == 1).all())
    sec_title = {s.id: s.title for s in db.query(EvaluationSection).filter(
        EvaluationSection.catalog_id == run.catalog_id).all()}

    teams: dict[str, dict[str, Any]] = {}
    for q in questions:
        role = q.answerer_role or "product_owner"
        team = teams.setdefault(role, {
            "role": role,
            "title": next((r["title"] for r in ANSWERER_ROLES
                           if r["key"] == role), role),
            "total": 0, "answered": 0, "pass": 0, "partial": 0, "fail": 0,
            "na": 0, "high_severity_open": 0, "questions": []})
        r = by_id.get(q.id) or {}
        rated = r.get("risk_rating")
        team["total"] += 1
        if rated:
            team["answered"] += 1
            team[rated] = team.get(rated, 0) + 1
        if not rated and (q.severity_hint or "") in ("high", "critical"):
            team["high_severity_open"] += 1
        team["questions"].append({
            "question_id": q.id,
            "key": q.key,
            "prompt": q.prompt,
            "section_key": (q.section.key if q.section else None),
            "section_title": sec_title.get(q.section_id, ""),
            "severity_hint": q.severity_hint,
            "framework_tags": _q_tags(q),
            "risk_rating": rated,
            "answer_value": r.get("answer_value"),
            "evidence_url": r.get("evidence_url"),
            "notes": r.get("notes"),
            "answered_by": r.get("answered_by"),
        })
    total = sum(t["total"] for t in teams.values())
    answered = sum(t["answered"] for t in teams.values())
    return {
        "run": {"id": run.id, "title": run.title,
                "target_agent_id": run.target_agent_id, "status": run.status,
                "overall_score": run.overall_score},
        "completion": {
            "questions": total, "answered": answered,
            "outstanding": total - answered,
            "pct": round(100.0 * answered / total, 1) if total else 0.0,
        },
        "teams": [teams[k] for k in sorted(teams)],
    }


def coverage(db: Session, run) -> dict[str, Any]:
    """Standards coverage from the filled answers.

    Per control: how many questions address it, how many are answered, and
    the worst rating among them. ``unanswered`` is reported separately from
    ``fail`` — an unfinished questionnaire is incomplete evidence, not a
    finding, and conflating the two would make a partial rollout read as a
    control failure.
    """
    rows = pe._scored_answers(db, run)
    by_id = {r["question_id"]: r for r in rows}
    questions = (db.query(EvaluationQuestion)
                 .join(EvaluationSection)
                 .filter(EvaluationSection.catalog_id == run.catalog_id,
                         EvaluationQuestion.is_active == 1).all())
    seen: set[str] = set()
    per_control: dict[str, dict[str, Any]] = {}
    for q in questions:
        r = by_id.get(q.id) or {}
        rated = r.get("risk_rating")
        for tag in _q_tags(q):
            if tag in seen:
                # Keep counting every question against a control, but record
                # the control's evidence only once.
                pass
            entry = per_control.setdefault(tag, {
                "tag": tag, "label": control_label(tag),
                "framework": tag.partition(":")[0],
                "framework_name": _FRAMEWORK_NAMES.get(tag.partition(":")[0], ""),
                "questions": 0, "answered": 0, "pass": 0, "partial": 0,
                "fail": 0, "na": 0, "open_high_severity": 0,
                "status": "unanswered", "evidence": []})
            entry["questions"] += 1
            seen.add(tag)
            if rated:
                entry["answered"] += 1
                entry[rated] = entry.get(rated, 0) + 1
                entry["evidence"].append({
                    "question_id": q.id, "key": q.key,
                    "risk_rating": rated,
                    "answered_by": r.get("answered_by"),
                    "evidence_url": r.get("evidence_url"),
                    "notes": r.get("notes")})
            elif (q.severity_hint or "") in ("high", "critical"):
                entry["open_high_severity"] += 1

    for entry in per_control.values():
        if entry["fail"]:
            entry["status"] = "fail"
        elif entry["partial"]:
            entry["status"] = "partial"
        elif entry["pass"] and entry["na"] == entry["questions"]:
            entry["status"] = "na"
        elif entry["pass"]:
            entry["status"] = "pass"
        elif entry["na"]:
            entry["status"] = "na"
        else:
            entry["status"] = "unanswered"
        answered = entry["answered"]
        entry["coverage_pct"] = round(100.0 * answered / entry["questions"], 1) \
            if entry["questions"] else 0.0

    frameworks: dict[str, dict[str, Any]] = {}
    for entry in per_control.values():
        fw = frameworks.setdefault(entry["framework"], {
            "id": entry["framework"], "name": entry["framework_name"],
            "controls": [], "questions": 0, "answered": 0,
            "pass": 0, "partial": 0, "fail": 0, "na": 0, "unanswered": 0})
        fw["controls"].append(entry)
        fw["questions"] += entry["questions"]
        fw["answered"] += entry["answered"]
        for status in ("pass", "partial", "fail", "na", "unanswered"):
            if entry["status"] == status:
                fw[status] += 1

    ordered = sorted(
        per_control.values(),
        key=lambda e: ({"fail": 0, "partial": 1, "unanswered": 2,
                        "na": 3, "pass": 4}[e["status"]],
                       e["framework"], e["label"]))
    return {
        "run_id": run.id,
        "completion": fill_state(db, run)["completion"],
        "controls": ordered,
        "frameworks": [frameworks[k] for k in sorted(frameworks)],
        "counts": {
            "controls": len(per_control),
            "pass": sum(1 for e in per_control.values() if e["status"] == "pass"),
            "partial": sum(1 for e in per_control.values() if e["status"] == "partial"),
            "fail": sum(1 for e in per_control.values() if e["status"] == "fail"),
            "na": sum(1 for e in per_control.values() if e["status"] == "na"),
            "unanswered": sum(1 for e in per_control.values()
                              if e["status"] == "unanswered"),
        },
    }


def questionnaire_markdown(db: Session, draft: EvaluationDraft,
                           fmt: str = "form") -> str:
    """The fillable artifact handed to the product/services teams.

    ``form`` is the working document: per-role sections, the questions, the
    rating options and an evidence line. ``brief`` is the one-page cover note
    for whoever approves the work.
    """
    try:
        sections = json.loads(draft.sections_json or "[]")
    except Exception:
        sections = []
    lines = [f"# Security risk questionnaire — {draft.target}", ""]
    lines.append(f"_Framed by {GENERATOR_VERSION} ({draft.source}) from the "
                 f"team's own description. Axes: "
                 f"{', '.join(json.loads(draft.axes_json or '[]'))}._")
    lines.append("")
    if fmt == "brief":
        try:
            frame = json.loads(draft.rationale or "{}")
        except Exception:
            frame = {}
        lines.append(f"**Audience.** {', '.join(frame.get('roles') or [])}.")
        for a in frame.get("assumptions") or []:
            lines.append(f"- {a}")
        lines.append("")
        lines.append("Every question asks for an artifact. An answer with no "
                     "evidence is reported as unproven, not as a pass.")
        return "\n".join(lines) + "\n"

    quality = _quality(sections)
    lines.append(f"**{quality['questions']} questions** across "
                 f"{quality['sections']} sections, routed to "
                 f"{len(quality['roles'])} teams.")
    lines.append("")
    lines.append("Rate every question `pass` / `partial` / `fail` / `na` and "
                 "attach the artifact. `na` needs a one-line reason. "
                 "Unanswered questions stay unanswered — they are never "
                 "scored as failures.")
    lines.append("")
    by_role = _role_slices(sections)
    title_by_key = {r["key"]: r["title"] for r in ANSWERER_ROLES}
    for role in sorted(by_role):
        lines.append(f"## {title_by_key.get(role, role)}")
        lines.append("")
        lines.append("_" + next((r["concern"] for r in ANSWERER_ROLES
                                 if r["key"] == role), "") + "_")
        lines.append("")
        for q in by_role[role]:
            sev = (q.get("severity_hint") or "").upper()
            tags = ", ".join(control_label(t) for t in q["framework_tags"])
            lines.append(f"### [{sev}] {q['prompt']}")
            lines.append("")
            if tags:
                lines.append(f"*Standards: {tags}*")
                lines.append("")
            lines.append("- Rating: pass / partial / fail / na")
            lines.append("- What is implemented: ")
            lines.append("- Evidence (link, test, config, log field): ")
            lines.append("")
    return "\n".join(lines) + "\n"
