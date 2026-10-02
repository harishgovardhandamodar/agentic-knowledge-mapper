"""Leakage pathways, process patterns and situational playbooks.

The product threat pack (T01-T12) asks what can go wrong *to* an AI system. The
model catalog (W1) asks what an attacker can extract *from* a model. Neither
answers the question a security team actually asks when signing off an
initiative: **where does data leave the trust boundary, and what stops it?**

This module holds that answer as versioned data, not logic:

- ``LEAKAGE_PATHWAYS`` — ``data_class -> pathway -> sink`` triples with a
  likelihood, an exposure sensitivity and the controls that cover them. A
  pathway is not a finding: it is a *shape* whose presence depends on the
  situation profile, and whose severity depends on what the controls cover.
- ``PROCESS_PATTERNS`` — DPIA, vendor review, red-team cadence, logging
  minimums, human review. Governance advice, kept separate from technical
  controls so "we need a DPIA" is never presented as a technical control.
- ``PLAYBOOKS`` — situation-keyed checklists (confidential data + external LLM,
  open-weights tabular model on customer features, agent with tool access).
  Data, not branching code, so a security lead can read and amend them.

Fingerprinted and versioned like the threat pack and the model catalogs: every
register row that cites a pathway carries the version and fingerprint that
produced it, so a later edit cannot rewrite what a stored row saw.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

LEAKAGE_ID = "akm-leakage-pathways"
LEAKAGE_VERSION = "1.0.0"
PLAYBOOK_ID = "akm-situation-playbooks"
PLAYBOOK_VERSION = "1.0.0"

#: Semver rule for this catalog, same policy as the threat pack: a patch moves
#: no number, a minor adds or removes a pathway, a major changes what a
#: pathway means.
LEAKAGE_CHANGELOG: dict[str, dict[str, Any]] = {
    "major": "change what a pathway means, or its sink",
    "minor": "add/remove/rename a pathway",
    "patch": "wording or control reference only — no number may move",
    "version": LEAKAGE_VERSION,
}


def _fingerprint(payload: Any) -> str:
    canon = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      default=str)
    return hashlib.sha1(canon.encode("utf-8")).hexdigest()[:12]


# --------------------------------------------------------------------------
# leakage pathways
# --------------------------------------------------------------------------

#: ``likelihood`` is how easily the pathway is traversed *given the situation*;
#: ``exposure_sensitivity`` is how much the sink amplifies the consequence.
#: Neither is a score -- they multiply into a pathway severity, and both are
#: shown next to it so a reader can disagree with the arithmetic.
#:
#: ``requires`` mirrors the MM catalog's vocabulary so the advisor can enforce
#: one deployment constraint check across both catalogs.
LEAKAGE_PATHWAYS: list[dict[str, Any]] = [
    {
        "id": "LP01",
        "name": "Prompt paste of sensitive input",
        "sink": "vendor_inference_endpoint",
        "t_alignment": "T01",
        "likelihood": 0.9,
        "exposure_sensitivity": 0.8,
        "description": "A user pastes confidential material into a chat or "
                       "prompt surface with no classifier in front of it.",
        "controls": ["C01", "C03", "C12"],
        "process": ["PR01"],
        "requires": [],
        "privacy": True,
        "model_path": False,
    },
    {
        "id": "LP02",
        "name": "RAG retrieval of secrets from context",
        "sink": "retrieval_corpus",
        "t_alignment": "T03",
        "likelihood": 0.7,
        "exposure_sensitivity": 0.9,
        "description": "A retrieval index spans material the prompt path would "
                       "never have been given, so an unrelated question can "
                       "surface a secret or a restricted record.",
        "controls": ["C10", "C13", "C04"],
        "process": ["PR01", "PR05"],
        "requires": ["retrieval_access"],
        "privacy": True,
        "model_path": False,
    },
    {
        "id": "LP03",
        "name": "Log and support access to prompts and outputs",
        "sink": "log_store",
        "t_alignment": "T05",
        "likelihood": 0.6,
        "exposure_sensitivity": 0.7,
        "description": "Prompts and completions are retained in logs or "
                       "support tooling, turning a transient disclosure into a "
                       "persistent one with a much wider audience.",
        "controls": ["C08", "C09", "C11"],
        "process": ["PR04"],
        "requires": [],
        "privacy": True,
        "model_path": False,
    },
    {
        "id": "LP04",
        "name": "Vendor retention or training on submitted data",
        "sink": "vendor_secondary_use",
        "t_alignment": "T07",
        "likelihood": 0.5,
        "exposure_sensitivity": 1.0,
        "description": "The provider retains submitted content or trains on it, "
                       "so data leaves the customer's boundary under a "
                       "contract term rather than an incident.",
        "controls": ["C04", "C11"],
        "process": ["PR02", "PR04"],
        "requires": [],
        "privacy": True,
        "model_path": False,
    },
    {
        "id": "LP05",
        "name": "Subprocessor chain",
        "sink": "subprocessor",
        "t_alignment": "T12",
        "likelihood": 0.4,
        "exposure_sensitivity": 0.8,
        "description": "A further processor receives the data under terms "
                       "nobody in the initiative reviewed.",
        "controls": ["C11", "C04"],
        "process": ["PR02"],
        "requires": [],
        "privacy": True,
        "model_path": False,
    },
    {
        "id": "LP06",
        "name": "Output re-entry into enterprise systems",
        "sink": "downstream_store",
        "t_alignment": "T09",
        "likelihood": 0.6,
        "exposure_sensitivity": 0.6,
        "description": "Model output is written back to a CRM, ticket queue or "
                       "knowledge base, where it is read as fact and can carry "
                       "a hallucination or a poisoned instruction downstream.",
        "controls": ["C06", "C12", "C15"],
        "process": ["PR05"],
        "requires": ["write_back"],
        "privacy": False,
        "model_path": False,
    },
    {
        "id": "LP07",
        "name": "Model extraction and membership inference",
        "sink": "model_parameters",
        "t_alignment": "T06",
        "likelihood": 0.3,
        "exposure_sensitivity": 0.9,
        "description": "The published weights or a query surface is used to "
                       "recover training records. Model-path only: an API-only "
                       "deployment raises likelihood, not capability.",
        "controls": ["C14", "C13", "C15"],
        "process": ["PR03"],
        "requires": [],
        "privacy": True,
        "model_path": True,
    },
    {
        "id": "LP08",
        "name": "Side-channel disclosure via embeddings or timing",
        "sink": "embedding_store",
        "t_alignment": "T10",
        "likelihood": 0.25,
        "exposure_sensitivity": 0.5,
        "description": "Embeddings leak structure of the input, and response "
                       "timing leaks membership, without ever exposing text.",
        "controls": ["C09", "C08"],
        "process": ["PR03"],
        "requires": ["embedding_access"],
        "privacy": True,
        "model_path": True,
    },
]

PATHWAY_BY_ID: dict[str, dict[str, Any]] = {p["id"]: p for p in LEAKAGE_PATHWAYS}


# --------------------------------------------------------------------------
# process / governance patterns
# --------------------------------------------------------------------------

PROCESS_PATTERNS: list[dict[str, Any]] = [
    {"id": "PR01", "name": "Data protection impact assessment",
     "description": "Record the data classes, the lawful basis and the "
                    "retention position before go-live.",
     "owner_role": "privacy", "cadence": "per change of data class"},
    {"id": "PR02", "name": "Vendor review",
     "description": "Confirm retention, subprocessors, residency and training "
                    "terms against the contract, in writing.",
     "owner_role": "procurement", "cadence": "annual, and on contract change"},
    {"id": "PR03", "name": "Red-team cadence",
     "description": "A scheduled extraction or inversion attempt against the "
                    "deployed surface, not only a paper review.",
     "owner_role": "security", "cadence": "quarterly"},
    {"id": "PR04", "name": "Logging minimum",
     "description": "Decide what is retained, for how long, and who can read "
                    "it, before the first production request.",
     "owner_role": "security", "cadence": "per surface"},
    {"id": "PR05", "name": "Human review of consequential output",
     "description": "Name the decisions a human must make before output is "
                    "acted on without review.",
     "owner_role": "risk", "cadence": "per use case"},
]

PROCESS_BY_ID: dict[str, dict[str, Any]] = {p["id"]: p for p in PROCESS_PATTERNS}


# --------------------------------------------------------------------------
# situational playbooks
# --------------------------------------------------------------------------

#: Each playbook lists the situation tags that select it and the *forced* checks
#: to run. ``forced`` items are not advisory: the situation makes them the
#: minimum, which is why selecting a playbook can raise risk rather than lower
#: it.
PLAYBOOKS: list[dict[str, Any]] = [
    {
        "id": "PB01",
        "name": "External LLM with confidential data over a chat surface",
        "select_when": ["confidential_data", "external_llm", "chat_ui"],
        "match": "any",
        "forced": ["LP01", "LP03", "LP04"],
        "checks": [
            "Put a classifier or blocklist in front of the input surface, or "
            "accept paste of confidential data in writing.",
            "Decide prompt/output retention and who can read it.",
            "Confirm in writing whether the provider trains on submitted data.",
            "Give the surface a distinct, logged identity so its use is visible.",
        ],
    },
    {
        "id": "PB02",
        "name": "Open-weights tabular model on customer features",
        "select_when": ["open_weights", "personal_data", "customer_facing"],
        "match": "any",
        "forced": ["LP07", "LP08"],
        "checks": [
            "Run a membership-inference probe before go-live; it is cheap "
            "against a tabular model and it is the finding that matters.",
            "Decide whether training access exists at all -- it decides which "
            "controls are even available.",
            "Pre-register the inference threshold you will accept.",
        ],
    },
    {
        "id": "PB03",
        "name": "Agent with tool access to internal APIs",
        "select_when": ["tool_calling", "internal_api", "write_back"],
        "match": "any",
        "forced": ["LP06", "LP02"],
        "checks": [
            "Broker credentials per call rather than handing the model a key.",
            "Constrain what the agent can write, and review the write path.",
            "Check that retrieval cannot reach material the tool cannot use.",
        ],
    },
    {
        "id": "PB04",
        "name": "RAG over an internal corpus",
        "select_when": ["rag", "internal_corpus"],
        "match": "any",
        "forced": ["LP02"],
        "checks": [
            "Scope the index by the same authorisation rules as the source "
            "system; a retrieval index is not an access control.",
            "Test that a secret in the corpus is not retrievable by an "
            "unrelated question.",
        ],
    },
]

PLAYBOOK_BY_ID: dict[str, dict[str, Any]] = {p["id"]: p for p in PLAYBOOKS}


def leakage_fingerprint() -> str:
    """Fingerprint of the pathway catalog. Cited on every register row."""
    return _fingerprint({"id": LEAKAGE_ID, "version": LEAKAGE_VERSION,
                         "pathways": LEAKAGE_PATHWAYS,
                         "process": PROCESS_PATTERNS})


def playbook_fingerprint() -> str:
    """Fingerprint of the playbook set."""
    return _fingerprint({"id": PLAYBOOK_ID, "version": PLAYBOOK_VERSION,
                         "playbooks": PLAYBOOKS})


def select_playbooks(tags: list[str] | None) -> list[dict[str, Any]]:
    """Playbooks whose selection tags are present.

    ``match="any"`` selects on a single tag, which is what makes these usable:
    "confidential data over a chat surface" is a conjunction a security lead
    states, not three tags they should have to intersect themselves.
    """
    have = {str(t).strip().lower() for t in (tags or []) if str(t).strip()}
    out = []
    for pb in PLAYBOOKS:
        want = [str(t).lower() for t in pb["select_when"]]
        if not want:
            continue
        hit = [t for t in want if t in have]
        if not hit:
            continue
        out.append({**pb, "matched_tags": hit,
                    "coverage_pct": round(100.0 * len(hit) / len(want))})
    return out