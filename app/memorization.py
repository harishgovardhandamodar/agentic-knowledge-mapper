"""RLHF / preference memorization: catalog, register rows, join, playbook.

Model-engineering (W1) asks what an adversary can extract from weights.
Provider posture (RLHF01-08) asks what tenant content may enter training.
This module bridges the two: preference data memorized at SFT / reward /
RL stages can be extractable even when not all tenant data is.

Design rules:
- No single residual privacy score. W1 findings and PD-retention findings are
  reported side by side; the join is situational.
- Null if no evidence -- never 0.
- method_general weight 0.25, family 0.6, never own.
- Standing (preference exposure) unknown raises uncertainty, not fake precision.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

RM_ID = "akm-rlhf-memorization"
RM_VERSION = "1.0.0"

RM_RISKS: list[dict[str, Any]] = [
    {
        "id": "RM01",
        "title": "Preference-data memorization",
        "description": "Reward-model / pairwise preference examples regurgitated or membership-inferable.",
        "attack_class": "memorization",
        "attack_subtype": "preference_memorization",
        "severity": 80,
        "data_class": "preference_pair",
        "pipeline_stage": "reward_model",
        "layer": "model",
        "mitigations": ["MM01", "MM05", "MM16", "MM12"],
        "org_controllability": "low",
    },
    {
        "id": "RM02",
        "title": "SFT-stage persistence",
        "description": "Demonstrations memorized in SFT remain after RL stage.",
        "attack_class": "memorization",
        "attack_subtype": "sft_memorization",
        "severity": 75,
        "data_class": "sft_demo",
        "pipeline_stage": "sft",
        "layer": "model",
        "mitigations": ["MM01", "MM03", "MM05"],
        "org_controllability": "low",
    },
    {
        "id": "RM03",
        "title": "Feedback-transcript memorization",
        "description": "Thumbs / bug-report transcripts entering post-training are extractable.",
        "attack_class": "extraction",
        "attack_subtype": "rlhf_preference_extraction",
        "severity": 85,
        "data_class": "feedback_transcript",
        "pipeline_stage": "rl_finetune",
        "layer": "model",
        "mitigations": ["MM08", "MM16", "MM06"],
        "org_controllability": "high",
    },
    {
        "id": "RM04",
        "title": "Cross-user leakage via alignment",
        "description": "Alignment data from user A influences outputs leaking A's content.",
        "attack_class": "alignment_data_leakage",
        "attack_subtype": None,
        "severity": 75,
        "data_class": "preference_pair",
        "pipeline_stage": "rl_finetune",
        "layer": "model",
        "mitigations": ["MM02", "MM08", "MM16"],
        "org_controllability": "medium",
    },
    {
        "id": "RM05",
        "title": "Org-tenant contribution → extractability",
        "description": "Org content that entered feedback/training becomes recoverable by third parties.",
        "attack_class": "extraction",
        "attack_subtype": "rlhf_preference_extraction",
        "severity": 85,
        "data_class": "feedback_transcript",
        "pipeline_stage": "rl_finetune",
        "layer": "privacy",
        "situation_dependent": True,
        "mitigations": ["MM08", "MM16", "MM01"],
        "org_controllability": "high",
    },
    {
        "id": "RM06",
        "title": "Safety-review corpus retention × memorization",
        "description": "Long-retained review samples later used in training increase exposure window.",
        "attack_class": "memorization",
        "attack_subtype": "preference_memorization",
        "severity": 80,
        "data_class": "safety_review_sample",
        "pipeline_stage": "reward_model",
        "layer": "privacy",
        "mitigations": ["MM01", "MM03", "MM16"],
        "org_controllability": "medium",
    },
]

RM_BY_ID = {r["id"]: r for r in RM_RISKS}

DATA_CLASSES = ["preference_pair", "sft_demo", "feedback_transcript", "safety_review_sample"]
PIPELINE_STAGES = ["sft", "reward_model", "rl_finetune", "rlaif", "dpo/ipo"]

RM_QUERY_PACK = [
    "RLHF memorization preference data",
    "reward model membership inference",
    "\"human preference\" memorization LLM",
    "SFT memorization after RLHF",
    "DPO IPO memorization vs RLHF",
    "extraction alignment data",
    "{model_family} memorization benchmark",
    "canary preference dataset RLHF",
]

RM_PLAYBOOK_ID = "rlhf_memorization"
RM_PLAYBOOK = {
    "id": RM_PLAYBOOK_ID,
    "title": "RLHF / preference memorization",
    "checks": [
        "Prohibit consumer AI for confidential data",
        "Disable in-product feedback on approved tools where possible",
        "Enterprise/API + ZDR; document endpoint exceptions",
        "DLP / classification before prompt",
        "Vendor questionnaire: preference data, retention, training of reward models on customer content",
        "Contractual no-train + audit rights where negotiable",
        "Canaries in preference sets (lab side, training access)",
        "DP on preference training (cite evidence, don't market)",
        "Minimize retention of review transcripts (MM16)",
        "Prefer methods with published lower memorization of preference data — cite evidence",
    ],
    "validation": "experiment-planner generates checks; mitigation-advisor does not claim unlearning erases all preference memorization.",
}

WRITE_GUARD_PHRASES = [
    "rlhf is safe from memorization",
    "safe from memorization",
    "no memorization risk",
    "your api data is in the reward model",
    "is in the reward model",
]

def _fingerprint(payload: Any) -> str:
    canon = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha1(canon.encode("utf-8")).hexdigest()[:12]

def rm_fingerprint() -> str:
    return _fingerprint({"id": RM_ID, "version": RM_VERSION, "risks": RM_RISKS})

def _evidence_ids_for_attack(attack: dict, evidence_review: dict | None = None) -> list[int]:
    # reuse model_kb helper pattern
    from .model_kb import _evidence_ids  # type: ignore
    try:
        return _evidence_ids(attack, evidence_review)
    except Exception:
        return []

def rm_rows_for_model(assessment: Any, meta: dict, w1: dict | None = None) -> list[dict[str, Any]]:
    """Derive RM register rows from W1 attack findings.

    Only when a finding's class/subtype maps to a RM risk. Each row inherits
    the finding's scope (own/family/modality/method_general) with correct weight;
    method_general never becomes own.
    """
    from . import model_eval as _me
    model_json = json.loads(getattr(assessment, "model_json", None) or "{}") if hasattr(assessment, "model_json") else {}
    attacks = model_json.get("attacks") or [] if isinstance(model_json, dict) else []
    # allow caller to pass w1 directly? not needed; we derive per finding
    rows = []
    for idx, f in enumerate(attacks):
        if not isinstance(f, dict):
            continue
        cls = str(f.get("attack_class") or "")
        subtype = str(f.get("attack_subtype") or "") if f.get("attack_subtype") else None
        # find RM risks that map to this class/subtype
        for rm in RM_RISKS:
            if rm["id"] in ("RM05", "RM06"):
                # RM05/06 are provider-joined, not pure model literature
                continue
            if rm["attack_class"] != cls:
                continue
            # subtype must match if rm has one, else any
            if rm["attack_subtype"] and subtype and rm["attack_subtype"] != subtype.lower():
                continue
            # if rm has subtype but finding has none, still allow if class matches? For preference_memorization, we want to match even without subtype if class is memorization and focus includes rlhf
            # So permissive: if class matches, include
            from .model_kb import scope_of_finding
            scope, evidence_scope = scope_of_finding(f)
            mk = meta.get("model_name") or getattr(assessment, "product_name", "") or "model"
            # sanitize model key
            import re
            mk_key = re.sub(r"[^a-z0-9]+", "-", str(mk).lower()).strip("-") or "model"
            sev = rm["severity"]
            # confidence from finding
            try:
                conf = max(0.0, min(1.0, float(f.get("confidence", 0.5))))
            except Exception:
                conf = 0.5
            rows.append({
                "risk_id": f"RM-{rm['id']}-{mk_key}",
                "rm_id": rm["id"],
                "title": rm["title"],
                "description": rm["description"],
                "attack_class": cls,
                "attack_subtype": subtype or rm["attack_subtype"],
                "severity": sev,
                "scope": scope,
                "evidence_scope": evidence_scope,
                "scope_weight": _me.scope_weight(evidence_scope),
                "confidence": round(conf, 2),
                "confidence_band": "high" if conf >= 0.7 else "medium" if conf >= 0.4 else "low",
                "data_class": rm["data_class"],
                "pipeline_stage": rm["pipeline_stage"],
                "layer": rm["layer"],
                "source_catalog": RM_ID,
                "source_ref": rm["id"],
                "catalog_version": RM_VERSION,
                "catalog_fingerprint": rm_fingerprint(),
                "mitigations": rm["mitigations"],
                "org_controllability": rm["org_controllability"],
                "subject": mk,
                "model_key": mk_key,
                "evidence_ids": _evidence_ids_for_attack(f),
                "assessment_id": getattr(assessment, "id", None),
                "retention_context": None,
                "extractability_confidence": conf,
                "status": "open",
            })
    return rows

def rm05_situational(rlhf_findings: list[dict] | None, situation: dict | None, meta: dict | None = None) -> dict[str, Any]:
    """Provider join for RM05: elevated / reduced / unknown.

    Elevated if consumer feedback allowed + long retention, etc.
    Reduced if API no-train + feedback disabled + ZDR.
    """
    # Normalize findings
    by_id = {str(f.get("id")): f for f in (rlhf_findings or []) if isinstance(f, dict)}
    # Check RLHF dimensions relevant
    # Elevated signals: RLHF01 partial (feedback into training), RLHF02 long retention, RLHF04 consumer default on
    # Reduced signals: API no-train (RLHF05/06 unknown or supported not-training) and feedback disabled
    elevated_signals = []
    reduced_signals = []
    # RLHF01 preference/feedback → training partial => elevated
    if by_id.get("RLHF01", {}).get("standing") == "partial":
        elevated_signals.append("RLHF01 partial")
    if by_id.get("RLHF02", {}).get("standing") == "partial":
        elevated_signals.append("RLHF02 partial")
    if by_id.get("RLHF04", {}).get("standing") == "partial":
        elevated_signals.append("RLHF04 partial")
    # RLHF07 deletion efficacy unknown? not directly
    # Check situation: if consumer chat with external_llm, etc.
    # For reduced: need explicit evidence of no-train + feedback off
    # If standing supported with summary indicating not trained, we treat as reduced
    # Since our assess_rlhf never yields supported deterministically, we need to check for supported with note containing not trained
    for fid in ["RLHF01", "RLHF04", "RLHF05"]:
        f = by_id.get(fid)
        if f and f.get("standing") == "supported" and "not" in (f.get("summary") or "").lower():
            reduced_signals.append(f"{fid} supported not-trained")
    # If situation indicates API only with ZDR and no feedback, reduced
    situation_tags = set((situation or {}).get("tags") or [])
    meta_weights = (meta or {}).get("weights_source") or "unknown"
    if meta_weights == "open_weights":
        # open weights doesn't affect RM05 directly; but we consider reduced if feedback disabled?
        pass
    # Heuristic: if no elevated signals and has reduced signals => reduced
    # If has elevated => elevated
    # Else unknown
    if elevated_signals:
        return {"rating": "elevated", "reasons": elevated_signals, "signals": by_id}
    if reduced_signals:
        return {"rating": "reduced", "reasons": reduced_signals, "signals": by_id}
    # Check explicit feedback disabled via situation controls? DLP etc. Not precise. Default unknown.
    return {"rating": "unknown", "reasons": [], "signals": by_id}

def draft_rm_hypotheses(target_rows: list[dict], adv_rows: list[dict], profile: dict) -> list[dict]:
    """Fallback hypothesis drafts for RM claims."""
    hyps = []
    has_mem = any(r.get("attack_class") in ("memorization", "alignment_data_leakage") or r.get("attack_subtype") in ("preference_memorization", "sft_memorization", "preference_mi") for r in adv_rows)
    if has_mem:
        hyps.append({
            "id": "H-RM01",
            "claim": "Family exhibits extractable memorization of preference-style data in published studies",
            "premise": "Adversarial literature shows preference memorization for this family",
            "mechanism": "SFT/reward model retains preference pairs",
            "consequence": "Membership inference on preference holdout succeeds",
            "falsifier": "negative replication / vendor eval shows no extraction on holdout",
        })
    # Org specific
    hyps.append({
        "id": "H-RM05",
        "claim": "If org disables feedback and uses API no-train tier only, org content is excluded from future preference corpora",
        "premise": "Tier terms exclude tenant feedback from training",
        "mechanism": "Feedback channel closed + ZDR holds",
        "consequence": "Future preference corpora contain zero org transcripts",
        "falsifier": "policy exception X states feedback still sampled for safety",
    })
    return hyps

def guard_memorization_claims(text: str) -> dict[str, Any]:
    """Strip memorization safety claims without evidence; block API-in-reward-model assertions without tier evidence."""
    kept, removed = [], []
    for sent in re.split(r"(?<=[.!?])\s+", text or ""):
        low = sent.lower()
        if len(sent.strip()) < 24:
            kept.append(sent)
            continue
        # Check for forbidden phrases
        if any(p in low for p in WRITE_GUARD_PHRASES) and not any(t in low for t in TIER_EVIDENCE_TERMS):
            removed.append(sent.strip())
            continue
        # Check that "your api data is in the reward model" type claims need tier evidence
        kept.append(sent)
    return {"text": " ".join(kept).strip(), "removed": removed, "removed_count": len(removed)}

WRITE_GUARD_PHRASES = [
    "rlhf is safe from memorization",
    "safe from memorization",
    "no memorization risk",
    "your api data is in the reward model",
    "is in the reward model",
]

TIER_EVIDENCE_TERMS = [
    "consumer", "enterprise", "api tier", "opt-out", "opt out",
    "zero retention", "business tier", "workspace", "dpa", "tier",
]

