"""Model engineering security assessment: deterministic core.

W1 (adversarial research) maps published/plausible attacks to a model or
family; W2 (adoption risk) rates engineering dimensions of adopting it. No
LLM calls here: normalization, taxonomy, versioning and both scoring methods
are pure functions so evalkit can pin them and CI fails on silent drift.

Families are data, not branches: adding one means extending
:data:`MODEL_FAMILIES`, never a new code path.
"""
import hashlib
import json
from typing import Any

MODEL_FAMILIES = ("tabular_fm", "diffusion", "llm", "embedding",
                  "time_series_fm", "multimodal", "other")
MODALITIES = ("tabular", "image", "text", "audio", "multimodal", "other")
WEIGHTS_SOURCES = ("open_weights", "api_only", "hybrid", "unknown")
#: Preference-data exposure sub-signal: whether preference, feedback or
#: review data is known to reach training. Recorded on the meta, never
#: scored -- an "unknown" here must raise uncertainty elsewhere, not move a
#: number here.
PREFERENCE_EXPOSURE = ("unknown", "low", "high")
TRAINING_POSTURES = ("public_web", "licensed", "proprietary", "synthetic",
                     "mixed", "unknown")
DEPLOYMENTS = ("on_prem", "vpc", "saas_api", "edge", "unknown")
WORKFLOWS = ("adversarial_research", "adoption_risk",
             "mitigation_controls")

#: Lightweight evidence typing: new artifact_type values, no new tables.
MODEL_ARTIFACT_TYPES = ("adversarial_paper", "model_card", "benchmark",
                        "cve_advisory", "weights_release", "known_issue")

ATTACK_CLASSES: dict[str, dict[str, Any]] = {
    "membership_inference": {"severity": 70,
                             "label": "Membership inference"},
    "extraction": {"severity": 85,
                   "label": "Training-data extraction / memorization"},
    "inversion": {"severity": 80,
                  "label": "Model / attribute inversion"},
    "evasion": {"severity": 60,
                "label": "Adversarial examples (evasion)"},
    "poisoning": {"severity": 75,
                  "label": "Poisoning / backdoors"},
    "injection": {"severity": 65,
                  "label": "Prompt / embedding injection analogs"},
    "theft": {"severity": 70,
              "label": "Weight stealing / distillation / side-channel"},
    "cascade": {"severity": 65,
                "label": "Cascade failures downstream"},
    "memorization": {"severity": 80,
                     "label": "Memorization (SFT / preference persistence)"},
    "alignment_data_leakage": {
        "severity": 75,
        "label": "Alignment / preference data leakage across users"},
    "other": {"severity": 50,
              "label": "Other attack class"},
}

#: Attack subtypes: a finding's ``attack_subtype`` refines its class without
#: changing the arithmetic -- severity and weight stay at the class level, so
#: a subtype can never inflate a score. Subtypes exist so preference-data
#: risks (RM01-RM06) are addressable by name in registers, experiments and
#: mitigations. Unknown subtypes are ignored, never rejected: evidence with
#: a typo still counts at its class.
ATTACK_SUBTYPES: dict[str, tuple[str, ...]] = {
    "membership_inference": ("preference_mi",),
    "extraction": ("rlhf_preference_extraction",),
    "memorization": ("sft_memorization", "preference_memorization"),
    "alignment_data_leakage": (),
}

#: Scope weights: model-specific evidence counts fully, family evidence less,
#: modality-only least, technique-general (method_general) least of all. A
#: finding never counts more than what it evidences.
_SCOPE_WEIGHTS = {"model_specific": 1.0, "family": 0.6, "modality": 0.4,
                  "method_general": 0.25}


def valid_subtype(attack_class: Any, subtype: Any) -> str | None:
    """The subtype when it belongs to the class, else None.

    Never raises and never invents: an unlisted subtype reads as absent, so
    a typo degrades to the class rather than failing the assessment.
    """
    subs = ATTACK_SUBTYPES.get(str(attack_class or ""), ())
    sub = str(subtype or "").strip().lower()
    return sub if sub in subs else None

ADOPTION_DIMENSIONS: list[tuple[str, str, float]] = [
    ("family_nature", "Nature & family", 0.10),
    ("data_processing", "Data processing", 0.15),
    ("memorization", "Memorization plausibility", 0.20),
    ("adversarial_transfer", "Adversarial transfer", 0.10),
    ("cascade", "Cascade / systemic", 0.10),
    ("known_issues", "Known issues", 0.10),
    ("ops_monitoring", "Operations & monitoring", 0.10),
    ("governance_documentation", "Governance & documentation", 0.15),
]

RATING_SCORES = {"low": 25.0, "medium": 50.0, "high": 75.0, "critical": 95.0}


#: Burden levels: compute, latency, UX and legal cost of deploying the control.
_BURDENS = ("low", "medium", "high")

#: Access a deployment grants. Derived deterministically from weights_source;
#: ``hybrid`` is partial for anything the operator may not control.
def _deployment_access(meta: dict[str, Any]) -> dict[str, str]:
    weights = (meta or {}).get("weights_source") or "unknown"
    if weights == "open_weights":
        training, custody = "yes", "yes"
    elif weights == "hybrid":
        training, custody = "partial", "partial"
    else:
        training, custody = "no", "no"
    return {"training_access": training, "weights_custody": custody,
            "serving_control": "yes", "governance": "yes"}


MITIGATION_CATALOG: list[dict[str, Any]] = [
    {"id": "MM01", "title": "Differential privacy in training (DP-SGD)",
     "description": "Train with per-example clipping and noise so no single "
                    "row measurably shapes the weights.",
     "mitigates_attack_classes": ["extraction", "membership_inference",
                                   "memorization", "alignment_data_leakage"],
     "mitigates_adoption_dimensions": ["memorization", "data_processing"],
     "applies_to_families": ["*"],
     "requires": "training_access", "efficacy_hint": 0.7, "cost_burden": "high",
     "residual_limitations": "Utility loss on rare slices; does not erase "
                             "already-memorized content without retraining.",
     "references": ["Dwork & Roth, The Algorithmic Foundations of DP (2014)"]},
    {"id": "MM02", "title": "Differential privacy at inference",
     "description": "Aggregate or noise answers to repeated queries so query "
                    "campaigns cannot reconstruct training rows.",
     "mitigates_attack_classes": ["extraction", "membership_inference",
                                   "memorization", "alignment_data_leakage"],
     "mitigates_adoption_dimensions": ["memorization"],
     "applies_to_families": ["*"],
     "requires": "serving_control", "efficacy_hint": 0.5,
     "cost_burden": "medium",
     "residual_limitations": "Degrades answer fidelity; needs a query budget "
                             "to mean anything.",
     "references": []},
    {"id": "MM03", "title": "Machine unlearning / deletion pipelines",
     "description": "Remove wrongful or stale rows and their influence: "
                    "retrain, fine-tune-away, or gated filters with proof.",
     "mitigates_attack_classes": ["extraction", "memorization",
                                   "alignment_data_leakage"],
     "mitigates_adoption_dimensions": ["memorization", "governance_documentation"],
     "applies_to_families": ["*"],
     "requires": "training_access", "efficacy_hint": 0.5,
     "cost_burden": "high",
     "residual_limitations": "Incomplete erasure is the norm; verify, do not "
                             "assume.",
     "references": []},
    {"id": "MM04", "title": "Output watermarking",
     "description": "Statistical or cryptographic marks in generations for "
                    "provenance and misuse detection.",
     "mitigates_attack_classes": ["theft", "cascade"],
     "mitigates_adoption_dimensions": ["cascade", "governance_documentation"],
     "applies_to_families": ["diffusion", "llm", "multimodal"],
     "requires": "serving_control", "efficacy_hint": 0.4,
     "cost_burden": "medium",
     "residual_limitations": "Watermark-removal attacks exist; detection is "
                             "probabilistic, not proof.",
     "references": []},
    {"id": "MM05", "title": "Training-data watermarking / canaries",
     "description": "Planted canary rows whose reappearance proves extraction "
                    "or leakage.",
     "mitigates_attack_classes": ["extraction", "membership_inference",
                                   "memorization", "alignment_data_leakage"],
     "mitigates_adoption_dimensions": ["memorization", "ops_monitoring"],
     "applies_to_families": ["*"],
     "requires": "training_access", "efficacy_hint": 0.6,
     "cost_burden": "low",
     "residual_limitations": "Detects leakage; does not prevent it.",
     "references": []},
    {"id": "MM06", "title": "Adversarial training / robust optimization",
     "description": "Train against perturbed inputs so small manipulations do "
                    "not flip outputs.",
     "mitigates_attack_classes": ["evasion"],
     "mitigates_adoption_dimensions": ["adversarial_transfer"],
     "applies_to_families": ["*"],
     "requires": "training_access", "efficacy_hint": 0.6,
     "cost_burden": "high",
     "residual_limitations": "Robust to known perturbations; novel attacks "
                             "still transfer.",
     "references": []},
    {"id": "MM07", "title": "Input validation & rejection",
     "description": "Schema, range and out-of-distribution checks at the edge "
                    "before inference.",
     "mitigates_attack_classes": ["evasion", "poisoning", "injection"],
     "mitigates_adoption_dimensions": ["data_processing", "cascade"],
     "applies_to_families": ["*"],
     "requires": "serving_control", "efficacy_hint": 0.6,
     "cost_burden": "low",
     "residual_limitations": "Rejects the malformed, not the malicious-but-"
                             "valid.",
     "references": []},
    {"id": "MM08", "title": "Output filtering / DLP / policy heads",
     "description": "Screen generations for sensitive echoes, PII and policy "
                    "violations before delivery.",
     "mitigates_attack_classes": ["extraction", "inversion", "injection",
                                   "memorization", "alignment_data_leakage"],
     "mitigates_adoption_dimensions": ["data_processing", "cascade"],
     "applies_to_families": ["*"],
     "requires": "serving_control", "efficacy_hint": 0.6,
     "cost_burden": "medium",
     "residual_limitations": "Filters catch known patterns; paraphrased leaks "
                             "pass through.",
     "references": []},
    {"id": "MM09", "title": "Rate limiting & query budgeting",
     "description": "Per-entity quotas that make extraction and membership "
                    "campaigns expensive.",
     "mitigates_attack_classes": ["extraction", "membership_inference",
                                   "theft", "inversion"],
     "mitigates_adoption_dimensions": ["memorization", "ops_monitoring"],
     "applies_to_families": ["*"],
     "requires": "serving_control", "efficacy_hint": 0.5,
     "cost_burden": "low",
     "residual_limitations": "Slows attackers; does not stop low-and-slow "
                             "campaigns or insider access.",
     "references": []},
    {"id": "MM10", "title": "Weight access control & secure serving",
     "description": "Custody, allow-listing and audit for checkpoint access; "
                    "serve from hardened infrastructure.",
     "mitigates_attack_classes": ["theft", "poisoning"],
     "mitigates_adoption_dimensions": ["cascade", "governance_documentation"],
     "applies_to_families": ["*"],
     "requires": "weights_custody", "efficacy_hint": 0.7,
     "cost_burden": "medium",
     "residual_limitations": "Protects the weights you hold; says nothing "
                             "about copies already out.",
     "references": []},
    {"id": "MM11", "title": "Fine-tune / adapter governance",
     "description": "Approve, version and eval-gate fine-tunes and adapters "
                    "before they serve traffic.",
     "mitigates_attack_classes": ["poisoning", "cascade"],
     "mitigates_adoption_dimensions": ["cascade", "governance_documentation"],
     "applies_to_families": ["*"],
     "requires": "weights_custody", "efficacy_hint": 0.5,
     "cost_burden": "medium",
     "residual_limitations": "Governs sanctioned fine-tunes, not shadow forks.",
     "references": []},
    {"id": "MM12", "title": "Evaluation gates (privacy & robustness)",
     "description": "Block releases that regress on extraction, membership and "
                    "robustness benchmarks.",
     "mitigates_attack_classes": ["extraction", "membership_inference",
                                   "memorization", "alignment_data_leakage",
                                   "evasion"],
     "mitigates_adoption_dimensions": ["ops_monitoring",
                                        "governance_documentation"],
     "applies_to_families": ["*"],
     "requires": "governance", "efficacy_hint": 0.5, "cost_burden": "medium",
     "residual_limitations": "Benchmarks lag novel attacks; a passing gate "
                             "is not a proof.",
     "references": ["OWASP LLM Top 10 (2025)", "NIST AI 100-2e"]},
    {"id": "MM13", "title": "Monitoring & anomaly detection",
     "description": "Watch query and output streams for extraction campaigns, "
                    "drift and poisoning signals.",
     "mitigates_attack_classes": ["extraction", "poisoning", "theft"],
     "mitigates_adoption_dimensions": ["ops_monitoring", "cascade"],
     "applies_to_families": ["*"],
     "requires": "serving_control", "efficacy_hint": 0.5,
     "cost_burden": "medium",
     "residual_limitations": "Detects after the fact; needs someone on call.",
     "references": []},
    {"id": "MM14", "title": "Encryption / confidential compute for inference",
     "description": "Protect data in use during inference (enclaves, "
                    "confidential VMs).",
     "mitigates_attack_classes": ["theft", "inversion"],
     "mitigates_adoption_dimensions": ["data_processing"],
     "applies_to_families": ["*"],
     "requires": "weights_custody", "efficacy_hint": 0.6,
     "cost_burden": "high",
     "residual_limitations": "Protects infrastructure, not model behavior; "
                             "prompts still leave as outputs.",
     "references": []},
    {"id": "MM15", "title": "Documentation & model-card obligations",
     "description": "Publish training-data description, limitations, intended "
                    "uses and eval results with the checkpoint.",
     "mitigates_attack_classes": [],
     "mitigates_adoption_dimensions": ["governance_documentation",
                                        "known_issues"],
     "applies_to_families": ["*"],
     "requires": "governance", "efficacy_hint": 0.3,
     "cost_burden": "low",
     "residual_limitations": "Reduces unknown-unknowns; mitigates nothing "
                             "by itself.",
     "references": ["Mitchell et al., Model Cards (2019)"]},
    {"id": "MM16", "title": "Feedback-channel minimization",
     "description": "Disable or scope product feedback, thumbs and transcript "
                    "attachments on approved tools, and minimize what review "
                    "queues retain: preference data that is never collected "
                    "cannot be memorized.",
     "mitigates_attack_classes": ["memorization",
                                   "alignment_data_leakage"],
     "mitigates_adoption_dimensions": ["memorization", "data_processing"],
     "applies_to_families": ["*"],
     "requires": "serving_control", "efficacy_hint": 0.5,
     "cost_burden": "low",
     "residual_limitations": "Stops future collection only; says nothing "
                             "about preference data already trained on.",
     "references": []},
]


def mitigation_fingerprint() -> str:
    """Fingerprint of the mitigation catalog W3 plans against."""
    return _fingerprint({"id": MITIGATION_ID, "version": MITIGATION_VERSION,
                         "controls": MITIGATION_CATALOG,
                         "deprecated": DEPRECATED["mitigations"]})


def prefilter_mitigations(meta: dict[str, Any]
                          ) -> tuple[list[dict[str, Any]],
                                     list[dict[str, str]]]:
    """Split the catalog into applicable controls and deferrals with reasons.

    Deterministic: family fit first, then deployment access. Partial access
    (hybrid weights) keeps a control applicable with a flagged dependency.
    """
    access = _deployment_access(meta)
    family = (meta or {}).get("model_family") or "other"
    applicable: list[dict[str, Any]] = []
    deferred: list[dict[str, str]] = []
    for c in MITIGATION_CATALOG:
        if c.get("id") in DEPRECATED["mitigations"]:
            continue
        fams = c.get("applies_to_families") or ["*"]
        if "*" not in fams and family not in fams:
            deferred.append({"control_id": c["id"],
                             "reason": "not applicable to "
                                       f"{family} models"})
            continue
        need = c.get("requires") or "governance"
        got = access.get(need, "yes")
        if got == "no":
            why = {"training_access": "requires retraining partnership",
                   "weights_custody": "customer does not operate weights"}.get(
                       need, f"requires {need}")
            deferred.append({"control_id": c["id"], "reason": why})
            continue
        entry = dict(c)
        if got == "partial":
            entry["partial_access_note"] = (
                f"hybrid weights: verify the operated side covers {need}")
        applicable.append(entry)
    return applicable, deferred


def plan_or_empty(meta: dict[str, Any], attacks: list[dict],
                  dimensions: list[dict], evidence: list) -> list[dict[str, Any]]:
    """The ranked plan, or an explicit empty list when there is zero risk
    context (no findings, no rated dimensions, no evidence). An empty plan
    is a reportable outcome -- insufficient evidence -- never a silent
    success, so callers must render the empty case rather than skip it."""
    rated = [d for d in (dimensions or [])
             if isinstance(d, dict)
             and str(d.get("rating") or "unknown").lower() != "unknown"]
    if not (attacks or rated or evidence):
        return []
    return rank_mitigations(meta, attacks, dimensions)


def rank_mitigations(meta: dict[str, Any], attacks: list[dict],
                     dimensions: list[dict]) -> list[dict[str, Any]]:
    """Rank applicable controls by driver pressure, minus burden.

    Pressure comes from what W1/W2 actually found: attack severity × scope ×
    confidence for linked classes, rating weight for linked high/critical
    dimensions. Burden penalizes (low 0, medium 0.2, high 0.5) so two equal
    controls order cheap-first -- proportionate, not maximalist. Returns plan
    items with priority, status, burden, dependencies and limitations.
    """
    applicable, _ = prefilter_mitigations(meta)
    by_class: dict[str, float] = {}
    for f in attacks or []:
        if not isinstance(f, dict):
            continue
        cls = str(f.get("attack_class") or "")
        if not cls or cls in DEPRECATED["attack_classes"]:
            continue
        sev = ATTACK_CLASSES.get(cls, ATTACK_CLASSES["other"])["severity"]
        scope = scope_weight(f.get("applies_to"))
        try:
            conf = max(0.0, min(1.0, float(f.get("confidence", 0.5))))
        except (TypeError, ValueError):
            conf = 0.5
        pressure = sev / 100.0 * scope * conf
        if cls == "other":
            pressure *= 0.5
        by_class[cls] = max(by_class.get(cls, 0.0), pressure)
    dim_pressure: dict[str, float] = {}
    weights = {d_id: w for d_id, _, w in ADOPTION_DIMENSIONS}
    for d in dimensions or []:
        if not isinstance(d, dict):
            continue
        d_id = str(d.get("dimension") or "")
        rating = str(d.get("rating") or "unknown").lower()
        if rating in ("high", "critical") and d_id in weights:
            dim_pressure[d_id] = weights[d_id] * (
                1.5 if rating == "critical" else 1.0)
    burden_hit = {"low": 0.0, "medium": 0.2, "high": 0.5}
    ranked = []
    for c in applicable:
        score = sum(by_class.get(cls, 0.0)
                    for cls in c.get("mitigates_attack_classes") or [])
        score += sum(dim_pressure.get(d_id, 0.0)
                     for d_id in c.get("mitigates_adoption_dimensions") or [])
        score -= burden_hit.get(c.get("cost_burden"), 0.2)
        ranked.append((score, c))
    ranked.sort(key=lambda e: (-e[0], e[1]["id"]))
    plan = []
    for i, (score, c) in enumerate(ranked, 1):
        item: dict[str, Any] = {
            "control_id": c["id"], "priority": i, "status": "proposed",
            "addresses": {
                "attacks": [cls for cls in
                            c.get("mitigates_attack_classes") or []
                            if cls in by_class],
                "dimensions": [d for d in
                               c.get("mitigates_adoption_dimensions") or []
                               if d in dim_pressure]},
            "rationale": "",
            "efficacy_confidence": c.get("efficacy_hint", 0.5),
            "burden": c.get("cost_burden", "medium"),
            "dependencies": ([c["requires"]] if c.get("requires") else [])
                            + (["partial access — verify operated side"]
                               if c.get("partial_access_note") else []),
            "residual_limitations": c.get("residual_limitations", ""),
            "evidence_artifact_ids": [],
            "implementation_notes": c.get("partial_access_note", ""),
        }
        plan.append(item)
    return plan


def score_mitigation_residual(attacks: list[dict], dimensions: list[dict],
                              plan: list[dict],
                              exposure_weight: float = 1.0
                              ) -> dict[str, Any]:
    """W3 ``mitigation_residual_v1``: indicative residual after the plan.

    Each addressed class/dimension is reduced by the best covering control's
    ``efficacy_hint × efficacy_confidence``. Uncovered high-confidence attacks
    stay fully visible. Labeled indicative throughout: efficacy hints are
    priors, not measurements, so this is a planning aid, not a guarantee.
    """
    best: dict[tuple[str, str], float] = {}
    for item in plan or []:
        if not isinstance(item, dict):
            continue
        try:
            eff = max(0.0, min(1.0, float(item.get("efficacy_confidence", 0.5))))
        except (TypeError, ValueError):
            eff = 0.5
        for cls in (item.get("addresses") or {}).get("attacks", []):
            key = ("attack", str(cls))
            best[key] = max(best.get(key, 0.0), eff)
        for d_id in (item.get("addresses") or {}).get("dimensions", []):
            key = ("dimension", str(d_id))
            best[key] = max(best.get(key, 0.0), eff)
    per_class: dict[str, float] = {}
    for f in attacks or []:
        if not isinstance(f, dict):
            continue
        cls = str(f.get("attack_class") or "")
        if not cls or cls in per_class \
                or cls in DEPRECATED["attack_classes"]:
            continue
        sev = ATTACK_CLASSES.get(cls, ATTACK_CLASSES["other"])["severity"]
        scope = scope_weight(f.get("applies_to"))
        try:
            conf = max(0.0, min(1.0, float(f.get("confidence", 0.5))))
        except (TypeError, ValueError):
            conf = 0.5
        base = sev * scope * conf * float(exposure_weight or 1.0)
        per_class[cls] = round(base * (1.0 - best.get(("attack", cls), 0.0)), 1)
    per_dimension: dict[str, float] = {}
    for d in dimensions or []:
        if not isinstance(d, dict):
            continue
        d_id = str(d.get("dimension") or "")
        rating = str(d.get("rating") or "unknown").lower()
        if rating not in RATING_SCORES or d_id in per_dimension:
            continue
        base = RATING_SCORES[rating] * float(exposure_weight or 1.0)
        per_dimension[d_id] = round(
            base * (1.0 - best.get(("dimension", d_id), 0.0)), 1)
    uncovered = [cls for cls in per_class
                 if ("attack", cls) not in best]
    return {"method": "mitigation_residual_v1",
            "mitigation_version": MITIGATION_VERSION,
            "mitigation_fingerprint": mitigation_fingerprint(),
            "per_class": per_class, "per_dimension": per_dimension,
            "uncovered": uncovered,
            "note": "indicative planning aid: efficacy hints are priors, "
                    "not measurements"}


EXPERIMENT_ID = "akm-experiment-plan"
EXPERIMENT_VERSION = "1.1.0"
EXPERIMENT_METHOD = "experiment_plan_v1"

EXPERIMENT_METHOD_TYPES = (
    "membership_inference", "extraction_probe", "canary",
    "unlearning_check", "watermark_detect", "robustness_grid",
    "privacy_accounting", "doc_audit",
)
EXPERIMENT_EFFORTS = ("low", "medium", "high")
EXPERIMENT_PREREQUISITES = ("weights_access", "query_api",
                            "training_data_sample", "vendor_coop")

#: Which experiment types target which open question. Deterministic mapping
#: so the plan is never a generic MLOps checklist.
_DIMENSION_EXPERIMENTS: dict[str, list[str]] = {
    "family_nature": ["doc_audit"],
    "data_processing": ["extraction_probe", "doc_audit"],
    "memorization": ["canary", "extraction_probe", "privacy_accounting"],
    "adversarial_transfer": ["robustness_grid"],
    "cascade": ["robustness_grid"],
    "known_issues": ["doc_audit"],
    "ops_monitoring": ["canary", "robustness_grid"],
    "governance_documentation": ["doc_audit"],
}
_CLASS_EXPERIMENTS: dict[str, list[str]] = {
    "membership_inference": ["membership_inference", "privacy_accounting"],
    "extraction": ["extraction_probe", "canary"],
    "inversion": ["extraction_probe"],
    "evasion": ["robustness_grid"],
    "poisoning": ["robustness_grid", "canary"],
    "injection": ["robustness_grid"],
    "theft": ["watermark_detect"],
    "cascade": ["robustness_grid"],
    "memorization": ["canary", "extraction_probe", "privacy_accounting"],
    "alignment_data_leakage": ["extraction_probe", "privacy_accounting",
                               "canary"],
    "other": ["doc_audit"],
}
_MITIGATION_EXPERIMENTS: dict[str, str] = {
    "MM01": "privacy_accounting", "MM02": "privacy_accounting",
    "MM03": "unlearning_check", "MM04": "watermark_detect",
    "MM05": "canary", "MM06": "robustness_grid",
    "MM07": "robustness_grid", "MM08": "extraction_probe",
    "MM09": "extraction_probe", "MM10": "watermark_detect",
    "MM11": "robustness_grid", "MM12": "robustness_grid",
    "MM13": "canary", "MM14": "extraction_probe",
    "MM15": "doc_audit", "MM16": "doc_audit",
}
_FALSIFIER_METHODS: tuple[tuple[str, str], ...] = (
    ("retention", "unlearning_check"),
    ("retain", "unlearning_check"),
    ("delet", "unlearning_check"),
    ("watermark", "watermark_detect"),
    ("membership", "membership_inference"),
    ("memoriz", "canary"),
    ("extract", "extraction_probe"),
    ("leak", "extraction_probe"),
    ("robust", "robustness_grid"),
    ("adversarial", "robustness_grid"),
    ("phish", "robustness_grid"),
    ("audit", "doc_audit"),
    ("document", "doc_audit"),
    ("log", "doc_audit"),
)


def experiment_fingerprint() -> str:
    """Fingerprint of the experiment method catalogue."""
    return _fingerprint({"id": EXPERIMENT_ID, "version": EXPERIMENT_VERSION,
                         "method_types": EXPERIMENT_METHOD_TYPES,
                         "dimension_map": _DIMENSION_EXPERIMENTS,
                         "class_map": _CLASS_EXPERIMENTS,
                         "mitigation_map": _MITIGATION_EXPERIMENTS})


def _experiment_prereqs(meta: dict[str, Any]) -> list[str]:
    weights = (meta or {}).get("weights_source") or "unknown"
    prereqs = ["query_api"]
    if weights in ("open_weights", "hybrid"):
        prereqs.append("weights_access")
    return prereqs


def plan_experiments(meta: dict[str, Any], attacks: list[dict],
                     dimensions: list[dict], hypotheses: list[dict],
                     mitigation_plan: list[dict]) -> dict[str, Any]:
    """Deterministic experiment plan: every open question gets a probe.

    Ranked by information gain proxies, not effort: unknown dimensions and
    open falsifiers first, MM validation second, already-covered ground
    never repeated. Weight-only methods require weights access; without it
    the experiment carries a ``vendor_coop`` prerequisite instead of being
    silently dropped. A plan with nothing to target is an explicit empty
    list, never a padded one.
    """
    prereqs = _experiment_prereqs(meta)
    has_weights = "weights_access" in prereqs
    exps: list[dict[str, Any]] = []

    def _add(method_type: str, title: str, targets: dict,
             rationale: str, effort: str, extra_prereqs: list[str] | None = None,
             evidence: list | None = None):
        need = list(extra_prereqs or [])
        if method_type in ("membership_inference", "extraction_probe",
                           "canary", "unlearning_check", "watermark_detect",
                           "robustness_grid") and not has_weights \
                and "query_api" not in need:
            need = ["query_api"] + need
        if method_type in ("unlearning_check", "watermark_detect") \
                and not has_weights:
            if "vendor_coop" not in need:
                need = need + ["vendor_coop"]
        for e in exps:
            if e["method_type"] == method_type and e["targets"] == targets:
                return
        exps.append({
            "id": f"EX-{len(exps) + 1:02d}", "title": title,
            "targets": targets, "method_type": method_type,
            "data_requirements": ("checkpoint + query API" if has_weights
                                  else "query API access"),
            "metrics": ["success rate", "false-positive rate"],
            "success_criteria": "pre-registered threshold met",
            "fail_criteria": "threshold missed on two independent runs",
            "effort": effort, "prerequisites": need,
            "linked_evidence_ids": list(evidence or []),
            "status": "proposed", "rationale": rationale})

    for d in dimensions or []:
        if not isinstance(d, dict):
            continue
        if str(d.get("rating") or "unknown").lower() != "unknown":
            continue
        d_id = str(d.get("dimension") or "")
        for m in _DIMENSION_EXPERIMENTS.get(d_id, ["doc_audit"]):
            _add(m, f"{m.replace('_', ' ')} for unknown {d_id}",
                 {"attack_classes": [], "adoption_dimensions": [d_id],
                  "hypothesis_ids": [], "mitigation_ids": []},
                 f"{d_id} is unknown: measure it instead of assuming it",
                 "low" if m == "doc_audit" else "medium")
    for f in attacks or []:
        if not isinstance(f, dict):
            continue
        cls = str(f.get("attack_class") or "")
        if not cls:
            continue
        try:
            conf = max(0.0, min(1.0, float(f.get("confidence", 0.5))))
        except (TypeError, ValueError):
            conf = 0.5
        if conf < 0.4:
            continue
        for m in _CLASS_EXPERIMENTS.get(cls, ["doc_audit"]):
            _add(m, f"{m.replace('_', ' ')} for {cls}",
                 {"attack_classes": [cls], "adoption_dimensions": [],
                  "hypothesis_ids": [], "mitigation_ids": []},
                 f"validate published {cls} against this deployment",
                 "medium",
                 evidence=[a for a in (f.get("evidence_artifact_ids") or [])
                           if isinstance(a, int)][:8])
    for h in hypotheses or []:
        if not isinstance(h, dict):
            continue
        if str(h.get("status") or "untested").lower() not in (
                "untested", "contested"):
            continue
        fals = [str(x) for x in (h.get("falsifiers") or [])
                if str(x).strip()]
        if not fals:
            _add("doc_audit",
                 f"make {(h.get('hypothesis_id') or h.get('id') or '')} testable",
                 {"attack_classes": [], "adoption_dimensions": [],
                  "hypothesis_ids": [h.get("hypothesis_id") or h.get("id")],
                  "mitigation_ids": []},
                 "open falsifier with no test: write the test first",
                 "low")
            continue
        method = "doc_audit"
        blob = " ".join(fals).lower()
        for kw, m in _FALSIFIER_METHODS:
            if kw in blob:
                method = m
                break
        _add(method, f"{method.replace('_', ' ')} for "
                     f"{h.get('hypothesis_id') or h.get('id') or ''}",
             {"attack_classes": [], "adoption_dimensions": [],
              "hypothesis_ids": [h.get("hypothesis_id") or h.get("id")],
              "mitigation_ids": []},
             f"settle falsifier: {fals[0][:120]}",
             "medium" if method != "doc_audit" else "low")
    rank = {"MM01": 0, "MM03": 1, "MM05": 2, "MM04": 3, "MM09": 4}
    top_mm = sorted(
        [p for p in (mitigation_plan or []) if isinstance(p, dict)],
        key=lambda p: (rank.get(str(p.get("control_id")), 9),
                       p.get("priority", 99)))[:5]
    for p in top_mm:
        cid = str(p.get("control_id") or "")
        method = _MITIGATION_EXPERIMENTS.get(cid, "doc_audit")
        _add(method, f"validate {cid}",
             {"attack_classes": [], "adoption_dimensions": [],
              "hypothesis_ids": [], "mitigation_ids": [cid]},
             f"check {cid} does what its efficacy prior claims "
             f"({(p.get('residual_limitations') or '')[:100]})",
             "medium",
             evidence=[a for a in (p.get("evidence_artifact_ids") or [])
                       if isinstance(a, int)][:8])
    roadmap = {"30d": [], "60d": [], "90d": []}
    for e in exps:
        bucket = {"low": "30d", "medium": "60d"}.get(e["effort"], "90d")
        roadmap[bucket].append(f"{e['id']}: {e['title']}")
    return {"method": EXPERIMENT_METHOD, "method_version": EXPERIMENT_VERSION,
            "method_fingerprint": experiment_fingerprint(),
            "experiments": exps, "roadmap": roadmap,
            "note": "plan only: execution is out of band"}


def posture_for(score: float | None) -> str:
    """Same four bands as the product residual scale, so a model number
    reads the same way. ``None`` (no evidence) is not LOW -- it is unknown.
    """
    if score is None:
        return "UNKNOWN — no evidence collected; not a clean bill of health"
    if score >= 75:
        return "HIGH RISK — do not adopt for this data tier without the mitigations below"
    if score >= 50:
        return "ELEVATED RISK — adopt only with guardrails and review"
    if score >= 30:
        return "MODERATE RISK — standard hardening sufficient"
    return "LOW RISK — routine controls sufficient"

MODEL_ADV_ID = "akm-model-adversarial"
MODEL_ADV_VERSION = "2.0.0"
ADOPTION_ID = "akm-adoption-risk"
ADOPTION_VERSION = "1.0.0"

MITIGATION_ID = "akm-model-mitigations"
MITIGATION_VERSION = "2.0.0"

#: Change policy per catalog, enforced by tests/test_versioning.py. Same
#: rule as the product pack: fingerprint moves without a version bump, or
#: numbers move without an evalkit update, and CI fails.
CHANGE_POLICY = {
    "akm-model-adversarial": {
        "major": "add/remove/rename an attack class; change a severity",
        "minor": "re-weight scope weights",
        "patch": "wording or label only — no number may move",
        "version": MODEL_ADV_VERSION,
    },
    "akm-adoption-risk": {
        "major": "add/remove/rename a dimension",
        "minor": "re-weight dimensions or rating scores",
        "patch": "wording or label only — no number may move",
        "version": ADOPTION_VERSION,
    },
    "akm-model-mitigations": {
        "major": "add/remove/rename a control; change applicability rules",
        "minor": "re-tune efficacy hints, burden levels or rank penalties",
        "patch": "wording or references only — no number may move",
        "version": MITIGATION_VERSION,
    },
    "akm-experiment-plan": {
        "major": "add/remove a method type or target axis",
        "minor": "re-tune mapping tables or effort buckets",
        "patch": "wording or rationale templates only",
        "version": EXPERIMENT_VERSION,
    },
}



def _fingerprint(payload: Any) -> str:
    canon = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha1(canon.encode("utf-8")).hexdigest()[:12]


#: Deprecated ids stay listed (never deleted) so old assessments remain
#: interpretable. New assessments ignore them; old rows render from stored
#: JSON. Empty today; entries look like {"MM99": {"replaced_by": "MM09",
#: "reason": "..."}}.
DEPRECATED: dict[str, dict[str, dict[str, str]]] = {
    "attack_classes": {},
    "dimensions": {},
    "mitigations": {},
}


def model_adv_fingerprint() -> str:
    """Fingerprint of the attack taxonomy W1 scores against."""
    return _fingerprint({"id": MODEL_ADV_ID, "version": MODEL_ADV_VERSION,
                         "classes": ATTACK_CLASSES,
                         "deprecated": DEPRECATED["attack_classes"]})


def adoption_fingerprint() -> str:
    """Fingerprint of the dimension list + weights W2 scores against."""
    return _fingerprint({"id": ADOPTION_ID, "version": ADOPTION_VERSION,
                         "dimensions": ADOPTION_DIMENSIONS,
                         "deprecated": DEPRECATED["dimensions"]})


def normalize_model_meta(raw: dict | None) -> dict[str, Any]:
    """Validate model metadata; unknown enums become ``other``/``unknown``.

    Free text is preserved alongside (``model_family_text``) so nothing the
    operator typed is silently dropped by validation.
    """
    raw = raw or {}

    def _enum(value: Any, allowed: tuple[str, ...], fallback: str) -> str:
        v = str(value or "").strip().lower()
        return v if v in allowed else fallback

    family = _enum(raw.get("model_family"), MODEL_FAMILIES, "other")
    workflows = [w for w in (raw.get("workflows") or [])
                 if w in WORKFLOWS + ("experiment_plan",)]
    return {
        "model_name": str(raw.get("model_name") or "").strip(),
        "model_family": family,
        "model_family_text": ("" if family != "other"
                              else str(raw.get("model_family") or "").strip()),
        "modality": _enum(raw.get("modality"), MODALITIES, "other"),
        "weights_source": _enum(raw.get("weights_source"), WEIGHTS_SOURCES,
                                "unknown"),
        "training_data_posture": _enum(raw.get("training_data_posture"),
                                       TRAINING_POSTURES, "unknown"),
        "preference_data_exposure": _enum(raw.get("preference_data_exposure"),
                                          PREFERENCE_EXPOSURE, "unknown"),
        "deployment_pattern": _enum(raw.get("deployment_pattern"),
                                    DEPLOYMENTS, "unknown"),
        "focus_terms": [str(t).strip() for t in
                        (raw.get("focus_terms") or []) if str(t).strip()][:12],
        "workflows": workflows or list(WORKFLOWS),
    }


def _clamp01(x: Any) -> float:
    try:
        return max(0.0, min(1.0, float(x)))
    except (TypeError, ValueError):
        return 0.0


def scope_weight(applies_to: Any) -> float:
    """Weight W1 gives a finding at this evidence scope.

    Public so the knowledge base can label a register row with the same weight
    the score used. If the two ever disagreed, the register would claim a
    stronger or weaker standing than the number it sits beside.
    """
    return _SCOPE_WEIGHTS.get(str(applies_to or ""), 0.4)


def score_adversarial(findings: list[dict],
                      exposure_weight: float = 1.0) -> dict[str, Any]:
    """W1 ``adversarial_coverage_v1``: applicable adversarial evidence as risk.

    Each finding contributes ``severity × scope × confidence``; the headline
    is the mean of the top three contributions (breadth matters, but the
    worst plausible attack dominates), scaled by exposure. No findings means
    no score (``None``) with zero coverage -- never a fake "secure".
    """
    contribs: list[dict[str, Any]] = []
    for i, f in enumerate(findings or []):
        if not isinstance(f, dict):
            continue
        cls = str(f.get("attack_class") or "other")
        if cls in DEPRECATED["attack_classes"]:
            continue
        sev = ATTACK_CLASSES.get(cls, ATTACK_CLASSES["other"])["severity"]
        scope = scope_weight(f.get("applies_to"))
        conf = _clamp01(f.get("confidence", 0.5))
        contribs.append({"attack_id": f.get("attack_id") or f"MA-{i + 1:02d}",
                         "contribution": round(sev * scope * conf, 2)})
    if not contribs:
        return {"method": "adversarial_coverage_v1",
                "model_adv_version": MODEL_ADV_VERSION,
                "model_adv_fingerprint": model_adv_fingerprint(),
                "overall_pct": None,
                "coverage_pct": 0.0,
                "note": "no adversarial evidence found as of this run"}
    top = sorted((c["contribution"] for c in contribs), reverse=True)[:3]
    overall = sum(top) / len(top) * float(exposure_weight or 1.0)
    named_classes = {c for c in ATTACK_CLASSES
                     if c != "other"
                     and c not in DEPRECATED["attack_classes"]}
    covered = {str((f or {}).get("attack_class"))
               for f in (findings or []) if isinstance(f, dict)}
    covered &= named_classes
    return {"method": "adversarial_coverage_v1",
            "model_adv_version": MODEL_ADV_VERSION,
            "model_adv_fingerprint": model_adv_fingerprint(),
            "overall_pct": round(min(100.0, overall), 1),
            "coverage_pct": round(100.0 * len(covered)
                                  / len(named_classes), 1),
            "contributions": contribs}


def score_adoption(dimensions: list[dict],
                   exposure_weight: float = 1.0) -> dict[str, Any]:
    """W2 ``adoption_risk_v1``: weighted dimension ratings as risk.

    ``unknown`` dimensions do not dilute the score: they accumulate into a
    separate ``uncertainty_pct``. All-unknown means no score (``None``), not
    a low one -- absence of evidence is not evidence of safety.
    """
    weights = {d_id: w for d_id, _, w in ADOPTION_DIMENSIONS}
    by_id = {str(d.get("dimension")): d for d in (dimensions or [])
             if isinstance(d, dict)}
    known: list[float] = []
    known_w = 0.0
    unknown_w = 0.0
    rated: list[dict[str, Any]] = []
    for d_id in weights:
        if d_id in DEPRECATED["dimensions"]:
            unknown_w += weights[d_id]
            rated.append({"dimension": d_id, "rating": "unknown"})
            continue
        rating = str((by_id.get(d_id) or {}).get("rating")
                     or "unknown").lower()
        if rating in RATING_SCORES:
            known.append(RATING_SCORES[rating] * weights[d_id])
            known_w += weights[d_id]
        else:
            unknown_w += weights[d_id]
        rated.append({"dimension": d_id, "rating": rating})
    total_w = sum(weights.values())
    if not known:
        return {"method": "adoption_risk_v1",
                "adoption_version": ADOPTION_VERSION,
                "adoption_fingerprint": adoption_fingerprint(),
                "overall_pct": None,
                "uncertainty_pct": 100.0,
                "note": "no dimension could be rated from collected evidence"}
    overall = sum(known) / known_w * float(exposure_weight or 1.0)
    return {"method": "adoption_risk_v1",
            "adoption_version": ADOPTION_VERSION,
            "adoption_fingerprint": adoption_fingerprint(),
            "overall_pct": round(min(100.0, overall), 1),
            "uncertainty_pct": round(100.0 * unknown_w / total_w, 1),
            "rated": rated}
