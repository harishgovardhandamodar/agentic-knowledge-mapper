"""Model-security knowledge base: assessment -> graph nodes + registers.

A model assessment is a report you read once. This module turns it into a
*knowledge base* scoped to one investigation, so the next run on the same model
enriches what is already known instead of starting over:

- **Graph** — nodes are ``artifacts`` rows with a KB ``artifact_type`` and a
  ``stable_key``; edges are ``relationships`` rows whose ``payload_json``
  carries scope, confidence and provenance. No second graph database: the
  Mapper graph, its review queue and its rendering already exist and are
  exactly what an incrementally-collected graph needs.
- **Tables** — inventory, risk register, inheritance map, cascade map, exploit
  view, selection scorecard, coverage gaps. These are JSON snapshots written
  to ``security_assessments.kb_json`` at score time, so a later catalog edit
  cannot rewrite what a stored row saw. ``kb_fingerprint`` makes drift visible.

Two rules the rest of the system depends on:

1. **The KB stores results, it does not score.** Every number here is copied
   from a stored assessment row, with the catalog version and fingerprint that
   produced it. There is no second scoring engine here.
2. **Own / inherited / cascade is a partition, not a blend.** A finding is
   classified once, deterministically, from the scope W1 recorded and from
   composition signals in the brief. Cascade risk is never counted as own: a
   fine-tune of a leaky base is a different problem from that base being leaky,
   and a base-model mitigation does not fix the fine-tune.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from . import model_eval as _me

KB_METHOD = "model_kb_v1"
KB_VERSION = "1.0.0"

#: Paths whose rows the KB may read. A product (``standard``) assessment
#: contributes nothing here: T*/C* scoring and model W1/W2/W3 stay separate, and
#: a product threat is not a model attack node.
MODEL_PATHS = ("model", "model_adversarial", "model_hypothesis",
               "model_engineering")

# --------------------------------------------------------------------------
# node kinds and relations
# --------------------------------------------------------------------------

#: KB node kinds -> graph ``artifact_type``. Existing collection types
#: (``adversarial_paper``, ``model_card``, ``benchmark``, ``cve_advisory``,
#: ``weights_release``, ``known_issue``) are reused rather than duplicated, so
#: the graph legend and review queue treat a model card like any other artifact.
NODE_KINDS: dict[str, str] = {
    "model": "a named checkpoint or served model",
    "model_family": "an architecture family (tabular FM, decoder-only LLM, …)",
    "model_class": "foundation / fine-tune / adapter / distilled",
    "data_domain": "a training-corpus class or PII tier",
    "deployment": "how the model is served (api_only, open_weights+on_prem, …)",
    "attack": "an attack class or threat pattern",
    "known_issue": "an advisory, CVE, or published incident",
    "control_mm": "a model-mitigation control (MM01 …)",
    "experiment": "a planned or externally-executed experiment",
    "hypothesis": "a falsifiable claim under test",
    "initiative": "a data/model initiative models are selected for",
}

#: KB relations. Extended, not replaced: the product graph's vocabulary
#: (``similar_to``, ``cites``, ``supports`` …) is untouched, so nothing about
#: Mapper's graph rendering or its A2A relation extraction changes.
REL_TYPES: dict[str, str] = {
    "instance_of": "model -> family / class",
    "inherits_risk_from": "model -> family or base model (inherited risk)",
    "own_risk": "model -> attack (evidence is model-specific)",
    "cascades_to": "upstream model -> downstream model / product",
    "cascades_from": "downstream model / product -> upstream model",
    "trained_on": "model -> dataset / data domain",
    "processes": "model -> data domain it processes at inference",
    "exposed_as": "model -> deployment",
    "vulnerable_to": "model/family -> attack, payload scope says at what level",
    "mitigated_by": "attack or model -> MM control (proposed or adopted)",
    "evidenced_by": "risk-bearing node -> supporting artifact",
    "tested_by": "hypothesis / attack -> experiment",
    "supersedes": "model version -> prior model",
    "selected_for": "model -> initiative (human decision)",
    "rejected_for": "model -> initiative (human decision)",
}

#: Relations that carry risk semantics and therefore always ship a payload.
RISK_REL_TYPES = ("own_risk", "vulnerable_to", "inherits_risk_from",
                  "cascades_to", "cascades_from", "mitigated_by",
                  "tested_by", "evidenced_by")

#: Coercion rules for relation names, so a caller cannot smuggle in a synonym
#: that silently becomes a second graph concept. Unlisted names are rejected.
REL_COERCION: dict[str, str] = {
    # accept the obvious spellings, store one canonical name
    "inherits-from": "inherits_risk_from",
    "inherits": "inherits_risk_from",
    "cascades": "cascades_to",
    "vulnerable-to": "vulnerable_to",
    "exposed-as": "exposed_as",
    "trained-on": "trained_on",
    "selected-for": "selected_for",
    "rejected-for": "rejected_for",
    "supersede": "supersedes",
}

#: Risk-bearing edges store these in ``payload_json``.
PAYLOAD_FIELDS = ("scope", "evidence_scope", "confidence", "confidence_band",
                  "exposure", "exposure_weight", "catalog_version",
                  "catalog_fingerprint", "assessment_id", "basis", "status",
                  "finding_id", "risk_id", "mechanism")

SCOPES = ("own", "inherited", "cascade")

#: Evidence-strength bands. Deliberately *not* called likelihood: this is how
#: strong the evidence is, not a measured exploit probability. The landscape
#: never claims a production residual from literature alone.
_BANDS = ((0.75, "strong"), (0.45, "moderate"), (0.0, "weak"))


def _band(confidence: Any) -> str:
    try:
        c = float(confidence)
    except (TypeError, ValueError):
        return "unknown"
    for floor, name in _BANDS:
        if c >= floor:
            return name
    return "weak"


def _clamp01(x: Any, default: float = 0.0) -> float:
    try:
        return max(0.0, min(1.0, float(x)))
    except (TypeError, ValueError):
        return default


def _load(raw: Any, default: Any = None) -> Any:
    if raw in (None, ""):
        return default
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return default


def _fingerprint(payload: Any) -> str:
    canon = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      default=str)
    return hashlib.sha1(canon.encode("utf-8")).hexdigest()[:12]


def norm_key(text: Any) -> str:
    """Stable key for a node. Case- and punctuation-insensitive, so
    ``TabPFN v2``, ``tabpfn-v2`` and ``TabPFN  V2`` are one node."""
    return re.sub(r"[^a-z0-9]+", "-", str(text or "").lower()).strip("-")


def canon_relation(name: Any) -> str:
    """Canonical relation name, or ``""`` when the name is not in the KB
    vocabulary. Callers get an explicit refusal rather than a near-synonym."""
    raw = str(name or "").strip()
    if raw in REL_TYPES:
        return raw
    return REL_COERCION.get(raw, "")


def field_basis(value: Any) -> str:
    """``explicit`` when the stored profile carries a real value, ``unknown``
    when it does not. ``normalize_model_meta`` defaults absent fields to
    ``unknown``/``other``, so a non-default value can only have come from the
    operator's brief. Composition signals are the third case and set
    ``inferred`` themselves (see :func:`cascade_signals`)."""
    v = str(value or "").strip().lower()
    return "unknown" if v in ("", "unknown", "other", "none") else "explicit"


# --------------------------------------------------------------------------
# scope: own / inherited / cascade
# --------------------------------------------------------------------------

def scope_of_finding(finding: dict) -> tuple[str, str]:
    """Classify one W1 finding into the register's partition.

    Returns ``(scope, evidence_scope)``. ``evidence_scope`` keeps W1's original
    label so nothing is lost by the three-way partition:

    - ``model_specific`` -> ``own``
    - ``family`` / ``modality`` -> ``inherited`` (family- or modality-level
      evidence, weighted by W1's own scope table, never counted as own)
    - a ``cascade`` attack class, or a finding whose subject is a downstream
      composition -> ``cascade``
    """
    f = finding or {}
    scope = str(f.get("applies_to") or "").strip().lower()
    cls = str(f.get("attack_class") or "other")
    # cascade first, always: a composition row that also carries an
    # evidence_scope must land in cascade, not be diluted into inherited by
    # the scope check below. Composition is a fact about where the risk
    # arrives, not a confidence tier.
    if cls == "cascade" or str(f.get("scope")) == "cascade" \
            or f.get("cascade_mechanism"):
        return "cascade", "composition"
    if scope == "model_specific":
        return "own", "model_specific"
    if scope in ("family", "modality"):
        return "inherited", scope
    # No scope recorded: W1's default weight is the modality tier, so it is
    # inherited-level evidence. Defaulting it to "own" would let an unlabelled
    # finding claim model-specific standing.
    return "inherited", scope or "modality"


#: Composition signals. ``(mechanism, terms, why it matters)``. Matched against
#: the stored brief (product name + use case + focus), so a cascade edge always
#: has a pointer back to the words that implied it.
_CASCADE_SIGNALS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("fine_tune", ("fine-tun", "finetun", "fine tun", "adapter", "lora",
                   "peft", "continued pretraining", "instruction-tuned on"),
     "a fine-tune inherits its base's risk and adds its own data path"),
    ("distill", ("distill", "student model", "teacher model"),
     "distillation compresses the teacher into a new artifact with new exposure"),
    ("compose", ("rag", "retrieval-augmented", "retrieval augmented",
                 "tool-using", "tool using", "agent loop", "multi-agent",
                 "chain", "orchestrat"),
     "composition adds a data and tool surface the model alone does not have"),
    ("serve", ("self-host", "self hosted", "on-prem", "on prem", "vpc",
               "open-weights", "open weights", "republish", "mirror"),
     "re-publishing or serving the weights moves the exposure boundary"),
    ("embed_in_product", ("embed", "embedded", "integrate", "integrated into",
                          "shipped in", "powered by", "underlying model",
                          "vendor model"),
     "risk surfaces to the end product that embeds the model"),
)


def cascade_signals(meta: dict, use_case: str = "", focus: list | None = None,
                    product_name: str = "") -> list[dict[str, Any]]:
    """Composition signals implied by the stored brief.

    ``basis`` is ``explicit`` when the brief names the mechanism outright and
    ``inferred`` when it is implied by other words. Either way the row carries
    the text that produced it, so an operator can disagree with the inference
    without the KB silently keeping it.
    """
    blob = f"{product_name or ''}\n{use_case or ''}\n{' '.join(focus or [])}"
    low = blob.lower()
    out: list[dict[str, Any]] = []
    for mechanism, terms, why in _CASCADE_SIGNALS:
        hit = next((t for t in terms if t in low), "")
        if not hit:
            continue
        # "fine-tune of" / "adapter for" states the mechanism; a bare word in a
        # list of topics is weaker. Both are labelled, neither is hidden.
        strong = any(p in low for p in
                     (f"{hit} of", f"{hit} on", f"fine-tun{hit}",
                      f"{hit}-based", f"{hit} from"))
        out.append({"mechanism": mechanism, "term": hit,
                    "basis": "explicit" if strong or hit in
                    ("fine-tun", "distill", "lora", "peft", "rag") else
                    "inferred",
                    "why": why})
    return out


# --------------------------------------------------------------------------
# snapshot: assessment row -> tables
# --------------------------------------------------------------------------

def _assessment_path(rec) -> str:
    scoring = _load(getattr(rec, "scoring_json", None), {}) or {}
    path = str(scoring.get("assessment_path") or "")
    if path:
        # a recorded path is the record, including a non-model one: honouring it
        # is what keeps a product assessment out of the model KB rather than
        # letting a profiler re-judge it and map it in
        return path
    # An unmarked row predates the path marker. It can only be a product or a
    # plain model-internals target; ask the deterministic profiler, exactly as
    # the dossier and the compare endpoint already do.
    try:
        from . import security as _sec
        prof = _sec.profile_model_subject(
            rec.product_name or "", rec.use_case or "",
            _load(getattr(rec, "focus_json", None), []) or [])
        return "model" if prof.get("is_model_query") else "standard"
    except Exception:
        return "standard"


def _catalogs(rec, scoring: dict) -> dict[str, Any]:
    """Every catalog version + fingerprint that touched this row."""
    model = _load(getattr(rec, "model_json", None), {}) or {}
    w1 = (scoring.get("w1") or {})
    w2 = (scoring.get("w2") or {})
    w3 = (scoring.get("w3") or {})
    return {
        "product_threat_pack": {
            "id": "akm-threat-pack",
            "version": getattr(rec, "threat_pack_version", None),
            "fingerprint": getattr(rec, "threat_pack_fingerprint", None),
        },
        "model_adversarial": {
            "id": _me.MODEL_ADV_ID,
            "version": w1.get("model_adv_version") or _me.MODEL_ADV_VERSION,
            "fingerprint": w1.get("model_adv_fingerprint")
            or _me.model_adv_fingerprint(),
        },
        "adoption_risk": {
            "id": _me.ADOPTION_ID,
            "version": w2.get("adoption_version") or _me.ADOPTION_VERSION,
            "fingerprint": w2.get("adoption_fingerprint")
            or _me.adoption_fingerprint(),
        },
        "model_mitigations": {
            "id": _me.MITIGATION_ID,
            "version": w3.get("mitigation_version") or _me.MITIGATION_VERSION,
            "fingerprint": w3.get("mitigation_fingerprint")
            or _me.mitigation_fingerprint(),
        },
        "experiment_plan": {
            "id": _me.EXPERIMENT_ID,
            "version": _me.EXPERIMENT_VERSION,
            "fingerprint": _me.experiment_fingerprint(),
        },
    }


def _data_domains(meta: dict, rec) -> list[str]:
    """Training/inference data domains for the inventory row.

    The operator may name them (``data_domains``); otherwise the deterministic
    profiler reads the stored brief. Never invented: a brief that names no data
    yields an empty list and the inventory says so.
    """
    named = [str(d).strip() for d in (meta.get("data_domains") or [])
             if str(d).strip()]
    if named:
        return sorted(set(named))
    try:
        from . import security as _sec
        prof = _sec.profile_model_subject(
            rec.product_name or "", rec.use_case or "",
            _load(getattr(rec, "focus_json", None), []) or [])
        out = [str(d) for d in (prof.get("data") or [])]
        if prof.get("personal_data") and "personal data" not in out:
            out.append("personal data")
        if prof.get("trains_on_data") and not out:
            out.append("training data (unspecified)")
        return sorted(set(out))
    except Exception:
        return []


def _model_version(name: str) -> str:
    """Version token from a model name (``gpt-5-2`` -> ``2``, ``TabPFN v2`` ->
    ``2``). Empty when the name carries no version, which is the common case
    and means no supersession claim can be made from the name alone."""
    m = re.search(r"(?:\bv|-)(\d+(?:\.\d+)*)\b", str(name or ""))
    return m.group(1) if m else ""


def _inventory_row(rec, meta: dict, path: str, catalogs: dict,
                   w1: dict, w2: dict, w3: dict) -> dict[str, Any]:
    """Model inventory row (table 1). Fields carry explicit | unknown, and the
    catalog context travels with the row so a landscape mixing scores from two
    catalog versions shows it rather than pretending they are comparable."""
    name = str(meta.get("model_name") or rec.product_name or "").strip()
    try:
        from .security import EXPOSURE_META
        expo = EXPOSURE_META.get(rec.exposure or "", {})
        expo_label = expo.get("label", rec.exposure or "")
        expo_weight = expo.get("weight")
    except Exception:
        expo_label, expo_weight = rec.exposure or "", None
    domains = _data_domains(meta, rec)
    deployment = str(meta.get("deployment_pattern") or "unknown")
    access = _me._deployment_access(meta)
    mk = norm_key(name)
    version = _model_version(name)
    return {
        "model_key": mk,
        "model_name": name or "(unnamed model)",
        # The lineage key is the name with its version token removed, so
        # "TabPFN v2" and "TabPFN v3" are one lineage with an order, not two
        # unrelated models. Empty when the name has no version to strip.
        "lineage_key": norm_key(re.sub(r"(?:\bv|-)\d+(?:\.\d+)*\b", "",
                                       name.lower())) if version else mk,
        "model_version": version,
        "family": meta.get("model_family") or "other",
        "family_text": meta.get("model_family_text") or "",
        "model_class": meta.get("model_class") or "unknown",
        "modality": meta.get("modality") or "unknown",
        "weights_source": meta.get("weights_source") or "unknown",
        "training_data_posture": meta.get("training_data_posture") or "unknown",
        "deployment_pattern": deployment,
        "deployment_access": access.get("access", "unknown"),
        "exposure": rec.exposure or "",
        "exposure_label": expo_label,
        "exposure_weight": expo_weight,
        "data_domains": domains,
        "field_basis": {
            "family": field_basis(meta.get("model_family")),
            "modality": field_basis(meta.get("modality")),
            "weights_source": field_basis(meta.get("weights_source")),
            "training_data_posture": field_basis(meta.get("training_data_posture")),
            "deployment_pattern": field_basis(deployment),
        },
        "assessment_id": rec.id,        "assessment_path": path,
        "created_at": rec.created_at.isoformat() if rec.created_at else None,
        "catalogs": {k: v for k, v in catalogs.items() if not k.startswith("_")},
        # Headline numbers are copied, never recomputed, and stay None when the
        # stored row had no evidence: the KB cannot turn "unknown" into a zero.
        "w1_pct": w1.get("overall_pct"),
        "w1_coverage_pct": w1.get("coverage_pct"),
        "w2_pct": w2.get("overall_pct"),
        "w2_uncertainty_pct": w2.get("uncertainty_pct"),
        "w3_indicative_pct": w3.get("residual_pct"),
        "focus_terms": [str(t) for t in (meta.get("focus_terms") or [])][:12],
        "use_case": str(rec.use_case or "")[:400],
    }


def _evidence_ids(finding: dict, review_map: dict | None) -> list[int]:
    """Artifact ids backing one W1 finding, as ints. The agent already filters
    these against the run's own evidence, so an id here was seen."""
    out = []
    for a in (finding.get("evidence_artifact_ids") or []):
        try:
            out.append(int(a))
        except (TypeError, ValueError):
            continue
    return out[:12]


def _review_standing(finding: dict, review_map: dict | None) -> str:
    """Worst standing among the finding's evidence.

    Landscape triage prefers accepted evidence, so this is what stops a
    pending-reference row from reading like a known finding. A row whose
    evidence is all pending is reported as ``pending``, never dropped and never
    promoted.
    """
    if not review_map:
        return "unknown"
    ids = _evidence_ids(finding, review_map)
    if not ids:
        return "unknown"
    stands = {str(review_map.get(i) or "pending") for i in ids}
    if "rejected" in stands:
        return "rejected"
    if "accepted" in stands:
        return "accepted"
    return "pending"


def _risk_register(rec, meta: dict, w1: dict, w2: dict, catalogs: dict,
                   cascade: list[dict], exposure_weight: float | None,
                   evidence_review: dict | None = None) -> list[dict[str, Any]]:
    """Risk register (table 2): one row per (model, attack class, scope).

    W1 findings supply the rows. Cascade composition supplies its own rows —
    distinct keys, so a cascade row can never be mistaken for the own finding
    it was inferred beside.
    """
    model = _load(getattr(rec, "model_json", None), {}) or {}
    mk = norm_key(meta.get("model_name") or rec.product_name or "")
    adv = catalogs["model_adversarial"]
    rows: list[dict[str, Any]] = []
    for i, f in enumerate(model.get("attacks") or []):
        if not isinstance(f, dict):
            continue
        cls = str(f.get("attack_class") or "other")
        scope, evidence_scope = scope_of_finding(f)
        conf = _clamp01(f.get("confidence", 0.5), 0.5)
        rows.append({
            "risk_id": f"{mk or 'model'}:{cls}:{scope}",
            "model_key": mk,
            "attack_class": cls,
            "attack_label": _me.ATTACK_CLASSES.get(
                cls, _me.ATTACK_CLASSES["other"])["label"],
            "scope": scope,
            "evidence_scope": evidence_scope,
            "severity": _me.ATTACK_CLASSES.get(
                cls, _me.ATTACK_CLASSES["other"])["severity"],
            "scope_weight": _me.scope_weight(evidence_scope),
            "confidence": round(conf, 2),
            "confidence_band": _band(conf),
            "exposure": rec.exposure or "",
            "exposure_weight": exposure_weight,
            "finding_id": str(f.get("attack_id") or f"MA-{i + 1:02d}"),
            "title": str(f.get("title") or f.get("scenario") or "")[:200],
            "note": str(f.get("note") or f.get("rationale") or "")[:400],
            "prerequisites": [str(p) for p in (f.get("prerequisites") or [])][:6]
            if isinstance(f.get("prerequisites"), list) else [],
            "evidence_ids": _evidence_ids(f, evidence_review),
            "evidence_review": _review_standing(f, evidence_review),
            "assessment_id": rec.id,
            "catalog_version": adv["version"],
            "catalog_fingerprint": adv["fingerprint"],
            "basis": "explicit" if evidence_scope == "model_specific"
            else "inferred",
        })
    for sig in cascade:
        rows.append({
            "risk_id": f"{mk or 'model'}:cascade:{sig['mechanism']}",
            "model_key": mk,
            "attack_class": "cascade",
            "attack_label": f"Cascade via {sig['mechanism'].replace('_', ' ')}",
            "scope": "cascade",
            "evidence_scope": "composition",
            "severity": _me.ATTACK_CLASSES["cascade"]["severity"],
            "scope_weight": _me.scope_weight("family"),
            "confidence": None,
            "confidence_band": "unknown",
            "exposure": rec.exposure or "",
            "exposure_weight": exposure_weight,
            "finding_id": "",
            "title": sig["why"],
            "note": f"brief mentions '{sig['term']}'",
            "prerequisites": [],
            "mechanism": sig["mechanism"],
            "evidence_ids": [],
            "evidence_review": "unknown",
            "assessment_id": rec.id,
            "catalog_version": None,
            "catalog_fingerprint": None,
            "basis": sig["basis"],
        })
    return rows


def _inheritance_map(mk: str, meta: dict, rows: list[dict]) -> list[dict]:
    """Inheritance map (table 3): what the model takes from its family, and
    where own evidence overrides that."""
    family = meta.get("model_family") or ""
    family_text = meta.get("model_family_text") or ""
    parent = "family:" + norm_key(family_text or family or "other")
    inherited = sorted({r["attack_class"] for r in rows
                        if r["scope"] == "inherited"})
    own = {r["attack_class"] for r in rows if r["scope"] == "own"}
    overrides = [{"attack_class": a,
                  "effect": "upgraded_to_own_evidence",
                  "detail": "model-specific evidence names this attack"}
                 for a in sorted(own & set(inherited))]
    return [{"model_key": mk, "parent_kind": "family",
             "parent_key": parent,
             "parent_label": family_text or family or "other",
             "inherited_attack_classes": inherited,
             "inherited_count": len(inherited),
             "overrides": overrides}]


def _cascade_map(mk: str, name: str, signals: list[dict]) -> list[dict]:
    """Cascade map (table 4): the mechanisms this model sits inside."""
    rows = []
    for sig in signals:
        rows.append({
            "cascade_id": f"{mk or 'model'}:cascade:{sig['mechanism']}",
            "model_key": mk, "model_name": name,
            "direction": "downstream",
            "mechanism": sig["mechanism"],
            "risk_transmitted": [
                "base-model risk inherited by the derived model",
                "new data surface introduced by the composition",
            ] if sig["mechanism"] in ("fine_tune", "distill") else [
                "risk surfaces to whatever consumes this model"],
            "basis": sig["basis"],
            "evidence_term": sig["term"],
            "note": sig["why"],
            "mitigable_at_base_only": sig["mechanism"] in ("fine_tune",
                                                           "distill"),
            "assessment_id": None,
        })
    return rows


def _exploit_view(db, rec, mk: str) -> list[dict]:
    """Exploit likelihood view (table 5): known issues and adversarial
    references that name this model or its family, with recency and review
    standing. Evidence strength is reported as confidence, never as a measured
    production likelihood."""
    from .models import Artifact
    inv_id = rec.investigation_id
    types = ("cve_advisory", "adversarial_paper", "known_issue", "model_card",
             "benchmark", "weights_release", "cve")
    arts = (db.query(Artifact)
            .filter(Artifact.investigation_id == inv_id)
            .filter(Artifact.artifact_type.in_(types))
            # KB nodes carry a stable_key; collection artifacts never do. Without
            # this the KB would read its own ``known_issue:*`` wrapper as fresh
            # evidence and mint a wrapper for that on the next sync, forever.
            .filter(Artifact.stable_key.is_(None)).all())
    name = str(rec.product_name or "").lower()
    rows: list[dict[str, Any]] = []
    for a in arts:
        title = a.title or ""
        low = title.lower()
        if name and name not in low:
            applies_to = "family"
        else:
            applies_to = "model"
        year = a.date_published.year if a.date_published else None
        rows.append({
            "exploit_id": f"EX-{a.id}",
            "label": title[:160],
            "artifact_id": a.id,
            "artifact_type": a.artifact_type,
            "url": a.url or "",
            "applies_to": applies_to,
            "confidence_band": "strong" if a.review == "accepted" else "unknown",
            "recency_year": year,
            "review": a.review or "pending",
            "source": "collection",
            "model_key": mk,
        })
    ev = _load(getattr(rec, "evidence_json", None), {}) or {}
    for i, item in enumerate(ev.get("known_exploits") or []):
        label = item if isinstance(item, str) else str(
            (item or {}).get("name") or (item or {}).get("title") or "")
        if not label:
            continue
        rows.append({
            "exploit_id": f"KE-{rec.id}-{i + 1}",
            "label": label[:160],
            "artifact_id": None, "artifact_type": "known_exploit",
            "url": (item.get("url", "") if isinstance(item, dict) else ""),
            "applies_to": "model",
            "confidence_band": "unknown",
            "recency_year": None,
            "review": "accepted",
            "source": "assessment",
            "model_key": mk,
        })
    return rows


def _evidence_review_map(db, inv_id: int) -> dict[int, str]:
    from .models import Artifact
    rows = (db.query(Artifact.id, Artifact.review)
            .filter(Artifact.investigation_id == inv_id).all())
    return {int(r[0]): str(r[1] or "pending") for r in rows}


def build_snapshot(db, rec) -> dict[str, Any]:
    """Everything one assessment row contributes to the KB.

    Reads **stored** columns only: the KB never re-runs an agent, and never
    re-scores. Re-running :func:`sync_model_kb` on the same row therefore
    produces the same snapshot, which is what makes the upserts idempotent.
    """
    from .security import EXPOSURE_META
    path = _assessment_path(rec)
    if path not in MODEL_PATHS:
        return {"method": KB_METHOD, "version": KB_VERSION,
                "skipped": True, "reason": f"path {path} is not a model path",
                "assessment_id": getattr(rec, "id", None)}
    scoring = _load(getattr(rec, "scoring_json", None), {}) or {}
    model = _load(getattr(rec, "model_json", None), {}) or {}
    hyp = _load(getattr(rec, "hypothesis_json", None), {}) or {}
    meta = _me.normalize_model_meta(model.get("meta") or {})
    if not meta.get("model_name"):
        meta["model_name"] = str(rec.product_name or "")
    catalogs = _catalogs(rec, scoring)
    exposure_weight = EXPOSURE_META.get(
        rec.exposure or "", {}).get("weight")
    w1 = scoring.get("w1") or {}
    w2 = scoring.get("w2") or {}
    w3 = scoring.get("w3") or {}
    mk = norm_key(meta.get("model_name") or rec.product_name or "")
    signals = cascade_signals(meta, use_case=rec.use_case or "",
                              focus=_load(getattr(rec, "focus_json", None),
                                          []) or [],
                              product_name=rec.product_name or "")
    inventory = _inventory_row(rec, meta, path, catalogs, w1, w2, w3)
    risks = _risk_register(rec, meta, w1, w2, catalogs, signals,
                           exposure_weight,
                           _evidence_review_map(db, rec.investigation_id))
    inheritance = _inheritance_map(mk, meta, risks)
    cascade = _cascade_map(mk, inventory["model_name"], signals)
    exploits = _exploit_view(db, rec, mk)
    mitigation = model.get("mitigation") or {}
    experiments = model.get("experiments") or hyp.get("experiments") or []
    claims = hyp.get("claims") or scoring.get("hypotheses") or []
    experiment_plan_error = ""
    if not experiments and (risks or claims):
        # No stored experiment plan, but the row carries the attacks,
        # dimensions and hypotheses an experiment plan is derived from. Build it
        # with the same deterministic planner the engineering path uses -- from
        # stored columns, not a new run -- so a row assessed before the KB
        # existed still shows what is planned and what is untested instead of an
        # empty plan it never made.
        try:
            plan = _me.plan_experiments(
                meta, [{"attack_id": r.get("finding_id") or r["risk_id"],
                        "attack_class": r.get("attack_class"),
                        "applies_to": r.get("evidence_scope"),
                        "confidence": r.get("confidence")}
                       for r in risks if r.get("attack_class") != "cascade"],
                (model.get("dimensions") or []) + (scoring.get("dimensions") or []),
                claims, mitigation.get("proposed") or [])
            experiments = plan.get("experiments") or []
        except Exception as e:
            # An empty plan and a plan that could not be planned are different
            # facts; record which one this is instead of swallowing it.
            experiments = []
            experiment_plan_error = f"{type(e).__name__}: {e}"[:300]
    # Snapshot fingerprint: register keys + catalog versions. Two rows with the
    # same fingerprint are the same knowledge, whatever else differs.
    fingerprint = _fingerprint({
        "registers": {
            "risk": sorted(r["risk_id"] for r in risks),
            "inheritance": sorted(i["parent_key"] for i in inheritance),
            "cascade": sorted(c["cascade_id"] for c in cascade),
            "inventory": [mk],
        },
        "catalogs": {k: [v.get("version"), v.get("fingerprint")]
                     for k, v in catalogs.items()
                     if not k.startswith("_")},
    })
    return {
        "method": KB_METHOD,
        "version": KB_VERSION,
        "assessment_id": rec.id,
        "investigation_id": rec.investigation_id,
        "assessment_path": path,
        "superseded_by_id": rec.supersedes_id,
        "model_key": mk,
        "inventory": inventory,
        "risk_register": risks,
        "inheritance": inheritance,
        "cascade": cascade,
        "exploits": exploits,
        "mitigation_plan": mitigation.get("plan") or [],
        "mitigation_deferred": mitigation.get("deferred") or [],
        "mitigation_roadmap": mitigation.get("roadmap") or {},
        "dimensions": [
            {"id": d.get("dimension"), "rating": d.get("rating") or "unknown",
             "basis": field_basis(d.get("rating"))}
            for d in (model.get("dimensions") or []) if isinstance(d, dict)],
        "experiments": [e for e in experiments if isinstance(e, dict)],
        "experiment_plan_error": experiment_plan_error,
        "hypotheses": [c for c in claims if isinstance(c, dict)],
        "cascade_signals": signals,
        "catalogs": {k: v for k, v in catalogs.items()
                     if not k.startswith("_")},
        "exposure": rec.exposure or "",
        "fingerprint": fingerprint,
        "counts": {
            "risk_rows": len(risks),
            "own": sum(1 for r in risks if r["scope"] == "own"),
            "inherited": sum(1 for r in risks if r["scope"] == "inherited"),
            "cascade": sum(1 for r in risks if r["scope"] == "cascade"),
            "experiments": len(experiments),
            "hypotheses": len(claims),
            "exploits": len(exploits),
        },
    }


# --------------------------------------------------------------------------
# graph plan + idempotent upsert
# --------------------------------------------------------------------------

def plan_nodes(snap: dict) -> list[dict[str, Any]]:
    """Nodes this snapshot implies. Derived from the snapshot alone, so the
    same row always plans the same nodes."""
    if snap.get("skipped"):
        return []
    inv = snap["inventory"]
    out: list[dict[str, Any]] = []

    def add(kind: str, key: str, title: str, meta: dict,
            description: str = "") -> None:
        out.append({"kind": kind, "key": key, "title": title or key,
                    "meta": meta or {}, "description": description or ""})

    mk = snap["model_key"]
    add("model", mk, inv["model_name"], {
        "family": inv["family"], "model_class": inv["model_class"],
        "modality": inv["modality"], "weights_source": inv["weights_source"],
        "training_data_posture": inv["training_data_posture"],
        "deployment_pattern": inv["deployment_pattern"],
        "deployment_access": inv["deployment_access"],
        "exposure": inv["exposure"], "data_domains": inv["data_domains"],
        "field_basis": inv["field_basis"], "catalogs": inv["catalogs"],
        "lineage_key": inv.get("lineage_key", ""),
        "model_version": inv.get("model_version", ""),
        "w1_pct": inv["w1_pct"], "w2_pct": inv["w2_pct"],
        "w2_uncertainty_pct": inv["w2_uncertainty_pct"],
        "w3_indicative_pct": inv["w3_indicative_pct"],
        "assessment_id": inv["assessment_id"],
    }, f"{inv['model_name']} — {inv['family']} / {inv['deployment_pattern']}")
    fam = snap["inheritance"][0]["parent_key"] if snap["inheritance"] else ""
    if fam:
        add("model_family", fam,
            inv.get("family_text") or inv["family"], {"kind": "family"})
    for d in inv["data_domains"]:
        add("data_domain", "domain:" + norm_key(d), d, {"domain": d})
    if inv["deployment_pattern"] and inv["deployment_pattern"] != "unknown":
        add("deployment", "deployment:" + norm_key(inv["deployment_pattern"]),
            inv["deployment_pattern"], {"pattern": inv["deployment_pattern"],
                                        "access": inv["deployment_access"]})
    seen_classes: set[str] = set()
    for r in snap["risk_register"]:
        if r["attack_class"] in seen_classes:
            continue
        seen_classes.add(r["attack_class"])
        add("attack", "attack:" + r["attack_class"], r["attack_label"],
            {"attack_class": r["attack_class"], "severity": r["severity"]})
    for e in snap["experiments"]:
        eid = str(e.get("id") or "")
        if eid:
            add("experiment", "experiment:" + norm_key(eid), eid,
                {"method_type": e.get("method_type"),
                 "effort": e.get("effort"), "status": e.get("status")
                 or "proposed"})
    for c in snap["hypotheses"]:
        hid = str(c.get("hypothesis_id") or "")
        if hid:
            add("hypothesis", "hypothesis:" + norm_key(hid), hid,
                {"status": c.get("status") or "untested"})
    for m in snap["mitigation_plan"]:
        cid = str(m.get("control_id") or "")
        if cid:
            add("control_mm", "control:" + norm_key(cid), cid,
                {"burden": m.get("burden"), "priority": m.get("priority"),
                 "status": "proposed"})
    for x in snap["exploits"]:
        if x.get("artifact_id") is None:
            continue
        add("known_issue", "known_issue:%d" % x["artifact_id"],
            x["label"], {"artifact_id": x["artifact_id"],
                         "applies_to": x["applies_to"]})
    return out


def plan_edges(snap: dict) -> list[dict[str, Any]]:
    """Edges this snapshot implies, in canonical relation names only."""
    if snap.get("skipped"):
        return []
    inv = snap["inventory"]
    mk = snap["model_key"]
    model_node = mk
    out: list[dict[str, Any]] = []

    def add(src: str, rel: str, dst: str, payload: dict | None = None,
            description: str = "") -> None:
        rel = canon_relation(rel)
        if not rel or src == dst:
            return
        out.append({"source": src, "target": dst, "type": rel,
                    "payload": payload or {}, "description": description})

    fam = snap["inheritance"][0]["parent_key"] if snap["inheritance"] else ""
    if fam:
        add(model_node, "instance_of", fam,
            {"assessment_id": snap["assessment_id"]},
            "instance of family")
        for r in snap["risk_register"]:
            if r["scope"] != "inherited":
                continue
            add(model_node, "inherits_risk_from", fam,
                {"scope": "inherited", "evidence_scope": r["evidence_scope"],
                 "risk_id": r["risk_id"], "attack_class": r["attack_class"],
                 "confidence": r["confidence"],
                 "confidence_band": r["confidence_band"],
                 "assessment_id": snap["assessment_id"],
                 "catalog_version": r["catalog_version"],
                 "catalog_fingerprint": r["catalog_fingerprint"],
                 "basis": r["basis"]},
                f"inherits {r['attack_class']} from family")
            add(fam, "vulnerable_to", "attack:" + r["attack_class"],
                {"scope": "inherited", "evidence_scope": r["evidence_scope"],
                 "risk_id": r["risk_id"], "attack_class": r["attack_class"],
                 "confidence": r["confidence"],
                 "confidence_band": r["confidence_band"],
                 "assessment_id": snap["assessment_id"]},
                f"family-level {r['attack_class']}")
    for r in snap["risk_register"]:
        if r["scope"] == "own":
            add(model_node, "own_risk", "attack:" + r["attack_class"],
                {"scope": "own", "evidence_scope": "model_specific",
                 "risk_id": r["risk_id"], "attack_class": r["attack_class"],
                 "confidence": r["confidence"],
                 "confidence_band": r["confidence_band"],
                 "exposure": r["exposure"], "exposure_weight":
                 r["exposure_weight"], "finding_id": r["finding_id"],
                 "assessment_id": snap["assessment_id"],
                 "catalog_version": r["catalog_version"],
                 "catalog_fingerprint": r["catalog_fingerprint"],
                 "basis": "explicit"},
                f"own evidence: {r['attack_class']}")
        elif r["scope"] == "cascade":
            # A cascade is not the model being weak on its own: it is the
            # composition that creates exposure. The edge is vulnerable_to with
            # scope=cascade, never own_risk, so a mitigation on the base model
            # cannot read as if it closed this row.
            add(model_node, "vulnerable_to", "attack:cascade",
                {"scope": "cascade", "evidence_scope": "composition",
                 "risk_id": r["risk_id"], "mechanism": r.get("mechanism"),
                 "basis": r["basis"], "exposure": r["exposure"],
                 "assessment_id": snap["assessment_id"]},
                f"cascade via {r.get('mechanism')}")
    for d in inv["data_domains"]:
        add(model_node, "trained_on", "domain:" + norm_key(d),
            {"basis": "inferred"},
            "training data domain (from brief, not a data audit)")
    if inv["deployment_pattern"] and inv["deployment_pattern"] != "unknown":
        add(model_node, "exposed_as",
            "deployment:" + norm_key(inv["deployment_pattern"]),
            {"access": inv["deployment_access"],
             "basis": inv["field_basis"]["deployment_pattern"],
             "assessment_id": snap["assessment_id"]})
    for c in snap["cascade"]:
        # fine_tune / distill have a real upstream node: the family or base the
        # derived model came from. Risk flows base -> derived, so the derived
        # model `cascades_from` it and the family `cascades_to` it. The other
        # mechanisms (compose / serve / embed) have no base artifact to point
        # at, so their composition lives in the cascade register instead of an
        # invented edge.
        if c["mechanism"] in ("fine_tune", "distill") and fam:
            add(model_node, "cascades_from", fam,
                {"scope": "cascade", "mechanism": c["mechanism"],
                 "basis": c["basis"], "evidence_term": c["evidence_term"],
                 "cascade_id": c["cascade_id"],
                 "assessment_id": snap["assessment_id"]},
                c["note"])
            add(fam, "cascades_to", model_node,
                {"scope": "cascade", "mechanism": c["mechanism"],
                 "basis": c["basis"], "cascade_id": c["cascade_id"],
                 "assessment_id": snap["assessment_id"]},
                f"risk cascades to a {c['mechanism'].replace('_', ' ')}")
    for m in snap["mitigation_plan"]:
        cid = str(m.get("control_id") or "")
        if not cid:
            continue
        add(model_node, "mitigated_by", "control:" + norm_key(cid),
            {"status": "proposed", "basis": "explicit",
             "assessment_id": snap["assessment_id"]},
            f"{cid} proposed ({m.get('burden', '?')} burden)")
        for atk in ((m.get("addresses") or {}).get("attacks") or []):
            add("attack:" + norm_key(atk), "mitigated_by",
                "control:" + norm_key(cid),
                {"status": "proposed",
                 "assessment_id": snap["assessment_id"]},
                f"{cid} addresses {atk}")
    for e in snap["experiments"]:
        eid = str(e.get("id") or "")
        if not eid:
            continue
        for tgt in ((e.get("targets") or {}).get("attack_classes") or []):
            add("attack:" + norm_key(tgt), "tested_by",
                "experiment:" + norm_key(eid),
                {"scope": "own" if snap["risk_register"] else "inherited",
                 "assessment_id": snap["assessment_id"]},
                f"{eid} tests {tgt}")
        for hid in ((e.get("targets") or {}).get("hypothesis_ids") or []):
            add("hypothesis:" + norm_key(hid), "tested_by",
                "experiment:" + norm_key(eid),
                {"assessment_id": snap["assessment_id"]},
                f"{eid} settles a falsifier")
    # A claim under test gets no graph edge here on purpose: a model is not
    # "tested by" a hypothesis, and inventing the relation would blur own risk
    # with a pending claim. An open falsifier with no experiment surfaces as a
    # coverage gap in the landscape instead, where someone can act on it.
    for x in snap["exploits"]:
        if x.get("artifact_id") is None:
            continue
        add(model_node, "evidenced_by", "known_issue:%d" % x["artifact_id"],
            {"applies_to": x["applies_to"], "review": x["review"],
             "recency_year": x["recency_year"],
             "assessment_id": snap["assessment_id"]},
            x["label"])
    return out


def _upsert_node(db, inv_id: int, plan: dict, assessment_id: int) -> tuple[int, bool]:
    """Idempotent node write. Enriches an existing node in place; the second run
    of an assessment must not add a second model node."""
    from .models import Artifact
    existing = (db.query(Artifact)
                .filter(Artifact.investigation_id == inv_id,
                        Artifact.artifact_type == plan["kind"],
                        Artifact.stable_key == plan["key"]).first())
    meta = _load(existing.node_meta, {}) if existing else {}
    meta = dict(meta or {})
    for k, v in (plan.get("meta") or {}).items():
        # enrichment: a later, richer value wins; an unknown never overwrites a
        # known one, or re-running a vaguer run would erase what we learned.
        if v in (None, "", "unknown", [], {}):
            meta.setdefault(k, v)
        else:
            meta[k] = v
    seen = meta.get("assessment_ids") or []
    if assessment_id not in seen:
        seen.append(assessment_id)
    meta["assessment_ids"] = seen
    desc = plan.get("description") or (existing.description if existing else "")
    if existing:
        existing.node_meta = json.dumps(meta, sort_keys=True)
        existing.assessment_id = assessment_id
        if desc and (existing.description or "") != desc:
            existing.description = desc[:2000]
        return existing.id, False
    row = Artifact(investigation_id=inv_id, title=(plan["title"] or "")[:500],
                   artifact_type=plan["kind"], description=desc[:2000],
                   node_meta=json.dumps(meta, sort_keys=True),
                   stable_key=plan["key"][:200], origin="agent",
                   review="accepted", tags="model_kb," + plan["kind"],
                   relevance=None, assessment_id=assessment_id)
    db.add(row)
    db.flush()
    return row.id, True


def _upsert_edge(db, inv_id: int, plan: dict, ids: dict) -> tuple[int, bool]:
    from .models import Relationship
    src, dst = ids.get(plan["source"]), ids.get(plan["target"])
    if not src or not dst or src == dst:
        return 0, False
    key = f"{plan['source']}|{plan['type']}|{plan['target']}"[:300]
    payload = {k: v for k, v in (plan.get("payload") or {}).items()
               if v not in (None, "", [], {})}
    existing = (db.query(Relationship)
                .filter(Relationship.investigation_id == inv_id,
                        Relationship.stable_key == key).first())
    if existing:
        old = _load(existing.payload_json, {}) or {}
        old.update(payload)
        existing.payload_json = json.dumps(old, sort_keys=True)
        existing.description = (plan.get("description")
                                or existing.description or "")[:500]
        return existing.id, False
    row = Relationship(investigation_id=inv_id, source_id=src, target_id=dst,
                       relationship_type=plan["type"],
                       description=(plan.get("description") or "")[:500],
                       payload_json=json.dumps(payload, sort_keys=True),
                       stable_key=key, origin="agent")
    db.add(row)
    db.flush()
    return row.id, True


def sync_model_kb(db, assessment_id: int) -> dict[str, Any]:
    """Assessment row -> KB nodes, edges and stored snapshot.

    Idempotent by construction: nodes key on
    ``(investigation_id, artifact_type, stable_key)`` and edges on
    ``<source>|<relation>|<target>``, so re-running enriches rather than
    duplicates. Reads stored columns only.
    """
    from .models import SecurityAssessment
    rec = (db.query(SecurityAssessment)
           .filter(SecurityAssessment.id == assessment_id).first())
    if not rec:
        raise LookupError("assessment not found")
    snap = build_snapshot(db, rec)
    if snap.get("skipped"):
        return {"assessment_id": assessment_id, "skipped": True,
                "reason": snap.get("reason"), "nodes_created": 0,
                "edges_created": 0, "nodes_updated": 0, "edges_updated": 0}
    nodes = plan_nodes(snap)
    ids: dict[str, int] = {}
    created_n = upd_n = 0
    for plan in nodes:
        nid, is_new = _upsert_node(db, rec.investigation_id, plan, rec.id)
        ids[plan["key"]] = nid
        created_n += 1 if is_new else 0
        upd_n += 0 if is_new else 1
    created_e = upd_e = 0
    for plan in plan_edges(snap):
        _, is_new = _upsert_edge(db, rec.investigation_id, plan, ids)
        created_e += 1 if is_new else 0
        upd_e += 0 if is_new else 1
    # supersedes needs more than one row, so it is drawn once both versions of
    # a lineage exist: the newest sync re-reads the stored snapshots and orders
    # them. Same no-honesty rule as everywhere else -- unversioned pairs stay
    # unordered rather than guessed.
    sup_e = 0
    # the older version's node was created by its own sync, so it is not in
    # this row's plan: resolve both endpoints by stable key.
    sup_ids = dict(ids)
    for plan in _supersedes_edges(_lineage_snapshots(db, snap)):
        from .models import Artifact as _Art
        for endpoint in ("source", "target"):
            if plan[endpoint] not in sup_ids:
                node = (db.query(_Art)
                        .filter(_Art.investigation_id == rec.investigation_id,
                                _Art.stable_key == plan[endpoint]).first())
                if node:
                    sup_ids[plan[endpoint]] = node.id
        _, is_new = _upsert_edge(db, rec.investigation_id, plan, sup_ids)
        sup_e += 1 if is_new else 0
    rec.kb_json = json.dumps(snap, sort_keys=True)
    rec.kb_fingerprint = snap["fingerprint"]
    db.commit()
    return {"assessment_id": assessment_id, "model_key": snap["model_key"],
            "fingerprint": snap["fingerprint"], "counts": snap["counts"],
            "nodes_created": created_n, "nodes_updated": upd_n,
            "edges_created": created_e + sup_e, "edges_updated": upd_e,
            "supersedes_edges": sup_e}


def _lineage_snapshots(db, snap: dict[str, Any]) -> dict[str, dict]:
    """Stored snapshots of one model lineage, keyed by model key.

    The current snapshot is included whether or not it has been written yet, so
    the newest sync can order it against versions already stored.
    """
    from .models import SecurityAssessment as _SA
    lk = ((snap.get("inventory") or {}).get("lineage_key") or "")
    out: dict[str, dict] = {snap.get("model_key") or "": snap}
    inv_id = int(snap.get("investigation_id") or 0)
    if not lk or not inv_id:
        return out
    for rec in (db.query(_SA).filter(_SA.investigation_id == inv_id).all()):
        stored = _load(getattr(rec, "kb_json", None), None)
        if isinstance(stored, dict) and not stored.get("skipped") \
                and (stored.get("inventory") or {}).get("lineage_key") == lk:
            out[stored.get("model_key") or ""] = stored
    return out


def sync_investigation_kb(db, inv_id: int) -> dict[str, Any]:
    """Sync every model-path assessment in an investigation, oldest first, so a
    re-run lands last and its (newer) measurement wins an enriched field.

    Non-model rows are reported as skipped rather than dropped: an operator who
    ran a product assessment and found nothing in the landscape deserves to see
    that it was considered and deliberately not mapped, not an empty list.
    """
    from .models import SecurityAssessment
    recs = (db.query(SecurityAssessment)
            .filter(SecurityAssessment.investigation_id == inv_id)
            .order_by(SecurityAssessment.id.asc()).all())
    results = []
    skipped = 0
    for rec in recs:
        path = _assessment_path(rec)
        if path not in MODEL_PATHS:
            skipped += 1
            results.append({"assessment_id": rec.id, "skipped": True,
                            "reason": f"assessment path {path!r} is not a model "
                                       f"path; a product assessment is not "
                                       f"mapped into the model-security KB"})
            continue
        results.append(sync_model_kb(db, rec.id))
    return {"investigation_id": inv_id,
            "synced": len(results) - skipped, "skipped": skipped,
            "results": results}


# --------------------------------------------------------------------------
# landscape: investigation-wide aggregation
# --------------------------------------------------------------------------

def _latest_per_model(snaps: list[dict]) -> dict[str, dict]:
    """Newest snapshot per model key. A model assessed twice has one row per
    run; the landscape reads the latest, and the superseded one stays in the
    assessment history rather than being deleted."""
    out: dict[str, dict] = {}
    for s in snaps:
        mk = s.get("model_key") or ""
        if not mk:
            continue
        prev = out.get(mk)
        if prev is None or int(s.get("assessment_id") or 0) >= int(
                prev.get("assessment_id") or 0):
            out[mk] = s
    return out


def _merge_risks(snaps: list[dict]) -> list[dict[str, Any]]:
    """Risk rows for the whole investigation, newest measurement per risk_id.

    Rows are keyed ``model:attack_class:scope``, so a re-assessment enriches the
    same row. When two assessments disagree, the newer one wins and the row
    records that it came from a newer catalog when that is why.
    """
    merged: dict[str, dict] = {}
    for s in sorted(snaps, key=lambda x: int(x.get("assessment_id") or 0)):
        for r in s.get("risk_register") or []:
            if not isinstance(r, dict) or not r.get("risk_id"):
                continue
            merged[r["risk_id"]] = r
    return sorted(merged.values(),
                  key=lambda r: (r.get("scope") or "", r.get("model_key") or "",
                                 r.get("attack_class") or ""))


def partition_risks(rows: list[dict]) -> dict[str, list[dict]]:
    """The Own | Inherited | Cascade partition. Reports and the landscape never
    show one blended list: a reader has to be able to tell which of the three a
    row is, and a cascade row can never be filed under own."""
    out = {"own": [], "inherited": [], "cascade": []}
    for r in rows:
        bucket = out.get(str(r.get("scope") or ""))
        if bucket is None:
            continue
        bucket.append(r)
    for rows_ in out.values():
        rows_.sort(key=lambda r: (-(_clamp01(r.get("confidence"), 0.0)),
                                  str(r.get("attack_class") or "")))
    return out


def _supersedes_edges(latest: dict[str, dict]) -> list[dict[str, Any]]:
    """``supersedes`` between versions of one model lineage.

    Only when the stored name carries a version and the versions compare: an
    unversioned pair is never ordered, because guessing which assessment is
    newer than which would rewrite history on a hunch.
    """
    by_lineage: dict[str, list[dict]] = {}
    for s in latest.values():
        inv = s.get("inventory") or {}
        lk = inv.get("lineage_key") or ""
        ver = inv.get("model_version") or ""
        if lk and ver:
            by_lineage.setdefault(lk, []).append(inv)
    out: list[dict[str, Any]] = []
    for lk, rows in by_lineage.items():
        def _v(r):
            parts = str(r.get("model_version") or "").lstrip("vV").split(".")
            try:
                return tuple(int(p) for p in parts)
            except ValueError:
                return ()
        ordered = sorted(rows, key=_v)
        for older, newer in zip(ordered, ordered[1:]):
            if not _v(newer) or not _v(older) or _v(newer) <= _v(older):
                continue
            out.append({"source": newer["model_key"],
                        "target": older["model_key"],
                        "type": "supersedes",
                        "payload": {"from_version": newer.get("model_version"),
                                    "to_version": older.get("model_version"),
                                    "lineage_key": lk},
                        "description": f"{newer['model_name']} supersedes "
                                       f"{older['model_name']}"})
    return out


def coverage_gaps(snaps: list[dict], latest: dict[str, dict]) -> list[dict]:
    """What the landscape cannot answer yet (work order §5.1.7).

    Each gap names the register rows or models it came from, so "we don't know"
    is traceable rather than a vague disclaimer.
    """
    gaps: list[dict[str, Any]] = []
    # 1. a model whose every finding is inherited or inferred.
    for s in latest.values():
        inv = s.get("inventory") or {}
        mk = inv.get("model_key") or ""
        rows = [r for r in (s.get("risk_register") or [])
                if r.get("model_key") == mk]
        if rows and not any(r.get("scope") == "own" for r in rows):
            gaps.append({"kind": "no_own_evidence", "severity": "medium",
                         "model_keys": [mk],
                         "label": f"{inv.get('model_name') or mk}: no "
                                  f"model-specific adversarial evidence",
                         "detail": "every finding is inherited or inferred; "
                                   "own evidence would need a test on this "
                                   "checkpoint",
                         "register_ids": [r["risk_id"] for r in rows][:8]})
    # 2. W2 dimensions still unknown.
    for s in latest.values():
        inv = s.get("inventory") or {}
        unknown = [d.get("id") for d in (s.get("dimensions") or [])
                   if str(d.get("rating") or "unknown") == "unknown"]
        if unknown:
            gaps.append({"kind": "dimension_unknown", "severity": "medium",
                         "model_keys": [inv.get("model_key") or ""],
                         "label": f"{inv.get('model_name') or ''}: "
                                  f"{len(unknown)} W2 dimension(s) unknown",
                         "detail": ", ".join(str(u) for u in unknown[:12]),
                         "register_ids": []})
    # 3. attacks with neither an MM proposal nor an experiment.
    for s in latest.values():
        inv = s.get("inventory") or {}
        mk = inv.get("model_key") or ""
        covered = {str(x) for x in
                   [((m.get("addresses") or {}).get("attacks") or [])
                    for m in (s.get("mitigation_plan") or [])]
                   for x in (x if isinstance(x, list) else [x])}
        targeted = {str(x) for e in (s.get("experiments") or [])
                    for x in ((e.get("targets") or {}).get("attack_classes") or [])}
        rows = [r for r in (s.get("risk_register") or [])
                if r.get("model_key") == mk and r.get("scope") == "own"]
        bare = sorted({str(r.get("attack_class")) for r in rows
                       if str(r.get("attack_class")) not in covered
                       and str(r.get("attack_class")) not in targeted})
        if bare:
            gaps.append({"kind": "attack_unaddressed", "severity": "high",
                         "model_keys": [mk],
                         "label": f"{inv.get('model_name') or mk}: "
                                  f"{', '.join(bare)} has no MM and no experiment",
                         "detail": "own risk with neither a proposed control "
                                   "nor a planned test",
                         "register_ids": [r["risk_id"] for r in rows
                                          if str(r.get("attack_class")) in bare]})
    # 4. open falsifiers with no experiment targeting them.
    for s in latest.values():
        inv = s.get("inventory") or {}
        targeted = {str(x) for e in (s.get("experiments") or [])
                    for x in ((e.get("targets") or {}).get("hypothesis_ids") or [])}
        open_ids = [str(c.get("hypothesis_id")) for c in (s.get("hypotheses") or [])
                    if str(c.get("status") or "untested") in ("untested", "contested")
                    and str(c.get("hypothesis_id"))]
        untargeted = [h for h in open_ids if h not in targeted]
        if untargeted:
            gaps.append({"kind": "falsifier_unplanned", "severity": "medium",
                         "model_keys": [inv.get("model_key") or ""],
                         "label": f"{inv.get('model_name') or ''}: "
                                  f"{len(untargeted)} open claim(s) with no experiment",
                         "detail": ", ".join(untargeted[:10]),
                         "register_ids": untargeted})
    # 5. models whose only evidence is pending review.
    for s in latest.values():
        inv = s.get("inventory") or {}
        rows = [r for r in (s.get("risk_register") or [])
                if str(r.get("evidence_review")) == "pending"]
        if rows:
            gaps.append({"kind": "evidence_pending", "severity": "medium",
                         "model_keys": [inv.get("model_key") or ""],
                         "label": f"{inv.get('model_name') or ''}: "
                                  f"{len(rows)} row(s) rest on pending evidence",
                         "detail": "pending is not accepted and not rejected; "
                                   "triage excludes it by default",
                         "register_ids": [r["risk_id"] for r in rows][:8]})
    order = {"high": 0, "medium": 1, "low": 2}
    gaps.sort(key=lambda g: (order.get(g.get("severity"), 3),
                             str(g.get("kind")), str(g.get("label"))))
    return gaps


def insight_cards(latest: dict[str, dict], gaps: list[dict]) -> list[dict]:
    """Deterministic engineering insight cards (work order §5.2).

    Every card is derived from a structured field and cites the register rows
    behind it. No LLM: a security team reading these needs them to be the same
    tomorrow, and a card that cannot be traced to a row is a rumour.
    """
    cards: list[dict[str, Any]] = []

    def card(cid, title, body, severity, models, ids, basis="deterministic"):
        cards.append({"id": cid, "title": title, "body": body,
                      "severity": severity, "model_keys": models,
                      "register_ids": ids, "basis": basis})

    for mk, s in sorted(latest.items()):
        inv = s.get("inventory") or {}
        name = inv.get("model_name") or mk
        rows = s.get("risk_register") or []
        own = [r for r in rows if r.get("scope") == "own"]
        inherited = [r for r in rows if r.get("scope") == "inherited"]
        cascade = [r for r in rows if r.get("scope") == "cascade"]
        # weights_source implications
        ws = str(inv.get("weights_source") or "unknown")
        access = str(inv.get("deployment_access") or "unknown")
        if ws == "open_weights" or access == "weights":
            card(f"weights-{mk}", f"{name}: weights are in reach",
                 "Open weights mean weight theft, distillation and white-box "
                 "membership inference are available without vendor "
                 "cooperation. Weight-only attacks are measurable here; API-only "
                 "models defer them instead.", "high", [mk],
                 [r["risk_id"] for r in own if r.get("attack_class") in
                  ("theft", "extraction")])
        elif ws == "api_only" or access == "query_only":
            card(f"api-only-{mk}", f"{name}: API-only surface",
                 "Only the query interface is reachable, so extraction and "
                 "membership inference can only be tested through queries and "
                 "depend on vendor cooperation for anything deeper.",
                 "medium", [mk],
                 [r["risk_id"] for r in own if r.get("attack_class") in
                  ("extraction", "membership_inference")])
        elif ws == "unknown":
            card(f"weights-unknown-{mk}",
                 f"{name}: weights source unknown",
                 "Without a weights/deployment answer, attack applicability is "
                 "inferred rather than established. Resolve it before "
                 "treating any attack row as measured.", "medium", [mk], [])
        # data sensitivity x memorization unknown
        domains = [str(d).lower() for d in (inv.get("data_domains") or [])]
        sensitive = any(w in " ".join(domains) for w in
                        ("personal", "pii", "phi", "customer", "financial",
                         "health", "medical", "proprietary"))
        posture = str(inv.get("training_data_posture") or "unknown")
        has_memorization = any(r.get("attack_class") == "extraction"
                               for r in own + inherited)
        if (sensitive or posture in ("proprietary", "licensed")) and \
                not has_memorization:
            card(f"memorization-{mk}",
                 f"{name}: sensitive data, no memorization evidence",
                 "The brief names sensitive or licensed training data, and no "
                 "memorization/extraction finding exists at any scope. That is "
                 "absence of evidence, not evidence of absence: a canary or "
                 "privacy-accounting experiment is the cheap way to find out.",
                 "medium", [mk], [])
        # cascade warnings
        if cascade:
            mechs = sorted({str(r.get("mechanism") or "composition")
                            for r in cascade})
            card(f"cascade-{mk}", f"{name}: cascade exposure",
                 "Risk arrives through composition ("
                 + ", ".join(mechs) + "), not only through this checkpoint. A "
                 "control applied at the base model does not close the derived "
                 "or downstream surface, so treat these rows separately when "
                 "deciding what to fix.", "high", [mk],
                 [r["risk_id"] for r in cascade])
        # MM roadmap
        road = s.get("mitigation_roadmap") or {}
        if any(road.get(k) for k in ("30d", "60d", "90d")):
            card(f"roadmap-{mk}", f"{name}: MM roadmap",
                 "Proposed controls by horizon — 30d: "
                 f"{len(road.get('30d') or [])} item(s); 60d: "
                 f"{len(road.get('60d') or [])}; 90d: "
                 f"{len(road.get('90d') or [])}. Residual after these stays "
                 "indicative: it is arithmetic over proposals, not a measured "
                 "post-control result.", "low", [mk], [])
        deferred = s.get("mitigation_deferred") or []
        if deferred:
            card(f"deferred-{mk}", f"{name}: {len(deferred)} mitigation(s) deferred",
                 "Deferred controls are inapplicable here and say why: "
                 + "; ".join(str(d.get("reason") or d.get("control_id") or "")[:80]
                             for d in deferred[:4]), "low", [mk], [])
        # experiment gaps
        exps = s.get("experiments") or []
        if exps:
            card(f"experiments-{mk}", f"{name}: {len(exps)} experiment(s) planned",
                 "Plan only. Nothing here executes inside the app; the plan "
                 "names the method, effort and prerequisites, and execution "
                 "stays with whoever owns the weights, the API or the vendor.",
                 "low", [mk],
                 [str(e.get("id")) for e in exps[:8]])
    order = {"high": 0, "medium": 1, "low": 2}
    cards.sort(key=lambda c: (order.get(c.get("severity"), 3), c["id"]))
    return cards


def landscape(db, inv_id: int) -> dict[str, Any]:
    """The landscape for one investigation: inventory, partitioned registers,
    exploits, insight cards, coverage gaps and catalog context.

    Reads stored snapshots; when a model assessment predates the KB the
    snapshot is derived from its stored columns so the landscape is never
    silently empty for a populated investigation.
    """
    from .models import SecurityAssessment
    recs = (db.query(SecurityAssessment)
            .filter(SecurityAssessment.investigation_id == inv_id)
            .order_by(SecurityAssessment.id.asc()).all())
    snaps: list[dict] = []
    for rec in recs:
        if _assessment_path(rec) not in MODEL_PATHS:
            continue
        snap = _load(getattr(rec, "kb_json", None), None)
        if not isinstance(snap, dict) or snap.get("skipped"):
            snap = build_snapshot(db, rec)
        if snap.get("skipped"):
            continue
        snap.setdefault("superseded", False)
        snaps.append(snap)
    latest = _latest_per_model(snaps)
    # which of these rows already carry a stored snapshot, in one query
    snap_ids = [int(r.id) for r in recs
                if getattr(r, "kb_json", None) and _assessment_path(r) in MODEL_PATHS]
    synced = {i for (i,) in db.query(SecurityAssessment.id).filter(
        SecurityAssessment.id.in_(snap_ids or [0])).all()} if snap_ids else set()
    risks = _merge_risks(snaps)
    partition = partition_risks(risks)
    inventory = [s["inventory"] for s in
                 sorted(latest.values(), key=lambda x: str(
                     (x.get("inventory") or {}).get("model_name") or ""))]
    gaps = coverage_gaps(snaps, latest)
    cards = insight_cards(latest, gaps)
    scorecard = selection_scorecard(latest, partition)
    # catalog context: which versions produced which rows, honestly
    cat_versions: dict[str, set] = {}
    for s in latest.values():
        for name, meta in (s.get("catalogs") or {}).items():
            cat_versions.setdefault(name, set()).add(
                f"{meta.get('version')} ({meta.get('fingerprint')})")
    exploited = _merge_exploits(latest)
    superseded = [{"assessment_id": s.get("assessment_id"),
                   "model_key": s.get("model_key"),
                   "superseded_by_id": s.get("superseded_by_id")}
                  for s in snaps
                  if int(s.get("assessment_id") or 0) not in
                  {int(x.get("assessment_id") or 0) for x in latest.values()}]
    return {
        "investigation_id": inv_id,
        "method": KB_METHOD,
        "version": KB_VERSION,
        "inventory": inventory,
        "risk_register": risks,
        "partition": {k: len(v) for k, v in partition.items()},
        "own": partition["own"],
        "inherited": partition["inherited"],
        "cascade": partition["cascade"],
        "inheritance": [i for s in latest.values() for i in (s.get("inheritance") or [])],
        "cascade_map": [c for s in latest.values() for c in (s.get("cascade") or [])],
        "supersedes": _supersedes_edges(latest),
        "exploits": exploited,
        "insights": cards,
        "insight_cards": cards,
        "gaps": gaps,
        "coverage_gaps": gaps,
        "scorecard": scorecard,
        "decisions": _decisions(db, inv_id),
        "catalog_context": {k: sorted(v) for k, v in cat_versions.items()},
        "superseded_assessments": superseded,
        "counts": {"models": len(latest), "risk_rows": len(risks),
                   "own": len(partition["own"]),
                   "inherited": len(partition["inherited"]),
                   "cascade": len(partition["cascade"]),
                   "experiments": sum(len(s.get("experiments") or [])
                                      for s in latest.values()),
                   "experiments_planned": sum(
                       len(s.get("experiments") or []) for s in latest.values()),
                   "hypotheses": sum(len(s.get("hypotheses") or [])
                                     for s in latest.values()),
                   "gaps": len(gaps)},
        "assessments": [{"assessment_id": s.get("assessment_id"),
                         "model_key": s.get("model_key"),
                         "assessment_path": s.get("assessment_path"),
                         "fingerprint": s.get("fingerprint"),
                         "superseded": bool(s.get("superseded")),
                         "kb_synced": int(s.get("assessment_id") or 0) in synced}
                        for s in snaps],
    }


def _decisions(db, inv_id: int) -> list[dict[str, Any]]:
    """Human selection decisions for this investigation, newest first.

    Read back from the ``selected_for`` / ``rejected_for`` edges rather than a
    separate table: the decision *is* a relationship, so the graph and the
    landscape can never disagree about it.
    """
    from .models import Investigation, Artifact, Relationship
    ids = [a.id for a in db.query(Artifact).filter(
        Artifact.investigation_id == inv_id).all()]
    if not ids:
        return []
    rows = (db.query(Relationship)
            .filter(Relationship.investigation_id == inv_id,
                    Relationship.relationship_type.in_(("selected_for",
                                                         "rejected_for")))
            .order_by(Relationship.id.desc()).all())
    if db.query(Investigation).filter(Investigation.id == inv_id).first() \
            is None:
        return []
    out: list[dict[str, Any]] = []
    for r in rows:
        pl = _load(getattr(r, "payload_json", None), {}) or {}
        out.append({"model_key": pl.get("model_key") or r.source_id,
                    "initiative_key": pl.get("initiative_key") or r.target_id,
                    "relation": r.relationship_type,
                    "decision": pl.get("decision") or (
                        "selected" if r.relationship_type == "selected_for"
                        else "rejected"),
                    "actor": pl.get("actor"), "rationale": pl.get("rationale"),
                    "decided_at": pl.get("decided_at") or str(r.created_at),
                    "weights": pl.get("weights") or {},
                    "history": pl.get("history") or [],
                    "relationship_id": r.id})
    return out


def _merge_exploits(latest: dict[str, dict]) -> list[dict]:
    """Exploit view (table 5) for the latest assessment of each model, deduped
    by artifact so one advisory does not appear once per run."""
    out: dict[str, dict] = {}
    for mk, s in latest.items():
        for x in s.get("exploits") or []:
            if not isinstance(x, dict):
                continue
            row = dict(x)
            row["model_keys"] = [mk]
            key = str(x.get("exploit_id"))
            if key in out:
                out[key]["model_keys"].append(mk)
            else:
                out[key] = row
    rows = sorted(out.values(),
                  key=lambda r: (-(r.get("recency_year") or 0),
                                 str(r.get("label") or "")))
    return rows


def selection_scorecard(latest: dict[str, dict],
                        partition: dict[str, list]) -> list[dict]:
    """Selection aids (work order §4): a multi-axis comparison, not a winner.

    No single rank is produced unless the caller supplies weights. The axes are
    the ones a reviewer would otherwise assemble by hand: own high-confidence
    attacks, inherited family risk, cascade exposure, W2 unknowns, mitigation
    burden, experiment gaps.
    """
    out = []
    for mk, s in sorted(latest.items()):
        inv = s.get("inventory") or {}
        own = [r for r in partition.get("own", []) if r.get("model_key") == mk]
        inh = [r for r in partition.get("inherited", []) if r.get("model_key") == mk]
        cas = [r for r in partition.get("cascade", []) if r.get("model_key") == mk]
        own_high = [r for r in own
                    if _clamp01(r.get("confidence"), 0.0) >= 0.75
                    and r.get("evidence_review") in ("accepted", "unknown")]
        plan = s.get("mitigation_plan") or []
        burden = {"low": 0, "medium": 0, "high": 0}
        for m in plan:
            b = str(m.get("burden") or "").lower()
            if b in burden:
                burden[b] += 1
        burden_points = burden["low"] * 1 + burden["medium"] * 2 + burden["high"] * 3
        unknown = [d.get("id") for d in (s.get("dimensions") or [])
                   if str(d.get("rating") or "unknown") == "unknown"]
        exps = s.get("experiments") or []
        out.append({
            "model_key": mk,
            "model_name": inv.get("model_name") or mk,
            "family": inv.get("family"),
            "deployment_pattern": inv.get("deployment_pattern"),
            "deployment_access": inv.get("deployment_access"),
            "weights_source": inv.get("weights_source"),
            "model_class": inv.get("model_class"),
            "modality": inv.get("modality"),
            "exposure": inv.get("exposure"),
            "training_data_posture": inv.get("training_data_posture"),
            "own_high_confidence": [r["risk_id"] for r in own_high],
            "own_high_count": len(own_high),
            "inherited_count": len(inh),
            "inherited_classes": sorted({str(r.get("attack_class")) for r in inh}),
            "cascade_count": len(cas),
            "cascade_mechanisms": sorted({str(r.get("mechanism") or "")
                                          for r in cas}),
            "w2_unknown_dimensions": [str(u) for u in unknown],
            "mm_burden": burden,
            "mm_burden_points": burden_points,
            "mm_proposed": len(plan),
            "mm_deferred": len(s.get("mitigation_deferred") or []),
            "experiment_count": len(exps),
            "experiment_ids": [str(e.get("id")) for e in exps][:12],
            "w1_pct": inv.get("w1_pct"),
            "w2_pct": inv.get("w2_pct"),
            "w2_uncertainty_pct": inv.get("w2_uncertainty_pct"),
            "catalog_note": "mixed catalog versions: " + ", ".join(
                f"{k} {v.get('version')}" for k, v in
                (inv.get("catalogs") or {}).items())
            if len({v.get("version") for v in (inv.get("catalogs") or {}).values()
                    if v.get("version")}) > 1 else "",
        })
    return out


#: Selection axes a caller may weight. Each is a count or burden the landscape
#: already derived, so a weight multiplies something visible in the payload
#: rather than a hidden score. The weight says how much an axis matters; the
#: axis itself says which direction is better, and that is recorded here rather
#: than left to the reader to infer from a sign.
SELECTION_AXES: dict[str, str] = {
    "own_risk": "high-confidence own risk rows (penalised)",
    "inherited_risk": "inherited risk rows (penalised)",
    "cascade": "cascade exposure paths (penalised)",
    "unknown_dimensions": "unrated W2 dimensions (penalised)",
    "mm_burden": "mitigation burden carried (penalised)",
    "experiments": "experiments planned (rewarded)",
    "w1_pct": "W1 adversarial coverage percentage (penalised)",
}

#: +1 when more of the thing is worse (the default, and true of every risk
#: count), -1 when more is better. Ranking is ascending on the total, so a
#: penalty raises the score and pushes a model down. Without this sign an axis
#: documented as "rewarded" would quietly rank the better model lower.
_AXIS_SIGN: dict[str, int] = {"experiments": -1}

_FILTERS: dict[str, str] = {
    "exclude_open_weights": "drop models whose weights are open",
    "require_api_only": "keep only API-only models",
    "require_no_high_memorization": "drop models whose family carries memorization risk",
    "require_no_cascade": "drop models with any cascade exposure",
    "exposure": "keep only the listed exposure tiers",
    "deployment_pattern": "keep only the listed deployment patterns",
    "weights_source": "keep only the listed weights sources",
    "model_class": "keep only the listed model classes",
}


def _axis_value(row: dict, axis: str) -> float:
    """Value one axis contributes for a model, straight from the scorecard."""
    if axis == "own_risk":
        return float(len(row.get("own_high_confidence") or []))
    if axis == "inherited_risk":
        return float(row.get("inherited_count", 0))
    if axis == "cascade":
        return float(row.get("cascade_count", 0))
    if axis == "unknown_dimensions":
        return float(len(row.get("w2_unknown_dimensions") or []))
    if axis == "mm_burden":
        return float(row.get("mm_burden_points", 0))
    if axis == "experiments":
        return float(row.get("experiment_count", 0))
    if axis == "w1_pct":
        v = row.get("w1_pct")
        # a missing score is not zero risk and not full risk: it is unknown, so
        # it contributes nothing rather than a fabricated number
        return float(v) if isinstance(v, (int, float)) else 0.0
    return 0.0


def compare(db, inv_id: int, model_keys: list[str] | None = None,
            filters: dict | None = None, weights: dict | None = None
            ) -> dict[str, Any]:
    """Model comparison for selection.

    ``filters`` are hard gates (an excluded model is reported as excluded, with
    the reason), ``weights`` are optional and only then produce a single ranked
    number. Without weights this is a comparison, not a verdict: the work order
    is explicit that the app must not pick a winner by default.

    An unknown filter or axis name is an error rather than a no-op. Silently
    ignoring ``exposure`` would report a hard gate as applied when it was not.
    """
    f = filters or {}
    w = {str(k): float(v) for k, v in (weights or {}).items()}
    unknown_filters = sorted(set(f) - set(_FILTERS))
    if unknown_filters:
        raise ValueError("unknown filter(s): " + ", ".join(unknown_filters))
    unknown_axes = sorted(set(w) - set(SELECTION_AXES))
    if unknown_axes:
        raise ValueError("unknown axis/axes: " + ", ".join(unknown_axes))
    land = landscape(db, inv_id)
    rows = land["scorecard"]
    if model_keys:
        want = {norm_key(k) for k in model_keys}
        rows = [r for r in rows if r.get("model_key") in want]
    kept: list[dict] = []
    applied: list[dict] = []
    for r in rows:
        row = dict(r)
        reasons = []
        if f.get("exclude_open_weights") and row.get("weights_source") == "open_weights":
            reasons.append("open weights excluded by filter")
        if f.get("require_api_only") and row.get("weights_source") != "api_only":
            reasons.append("api-only required")
        if f.get("require_no_high_memorization"):
            if any("memoriz" in str(c) for c in row.get("inherited_classes", [])):
                reasons.append("family carries memorization risk")
        if f.get("require_no_cascade") and row.get("cascade_count"):
            reasons.append("cascade exposure present")
        for field, label in (("exposure", "exposure"),
                             ("deployment_pattern", "deployment"),
                             ("weights_source", "weights source"),
                             ("model_class", "model class")):
            allowed = f.get(field)
            if allowed and row.get(field) not in {norm_key(str(a))
                                                 for a in allowed}:
                reasons.append(f"{label} {row.get(field) or 'unknown'} "
                               f"is not one of {sorted(str(a) for a in allowed)}")
        row["excluded"] = bool(reasons)
        row["exclusion_reasons"] = reasons
        (applied if row["excluded"] else kept).append(row)
    ranked = None
    if w:
        def _score(r):
            parts = {axis: round(w[axis] * _AXIS_SIGN.get(axis, 1)
                                 * _axis_value(r, axis), 3)
                     for axis in w}
            return round(sum(parts.values()), 3), parts
        scored = [(r, *_score(r)) for r in kept]
        # ascending: a lower total is the better-placed model, because every
        # axis is signed so that "more" means "worse" except where the axis
        # says more is better
        scored.sort(key=lambda t: (t[1], -len(t[0].get("own_high_confidence") or []),
                                   str(t[0].get("model_key"))))
        ranked = [{"model_key": r.get("model_key"), "score": total,
                   "contributions": parts,
                   "rank": i + 1}
                  for i, (r, total, parts) in enumerate(scored)]
    return {"investigation_id": inv_id, "filters": f, "weights": w,
            "case": "scorecard" if ranked else "comparison",
            "axes_used": sorted(w),
            "axes_available": sorted(SELECTION_AXES),
            "axis_signs": {a: _AXIS_SIGN.get(a, 1) for a in sorted(w)},
            "models": kept, "excluded": applied,
            "ranked": ranked,
            "note": "multi-axis comparison; no single winner without weights"
            if not ranked else
            "ranked by the weights you supplied, lowest score first; every "
            "contribution is shown next to the score with the direction it "
            "counts in (axis_signs), and a model with no evidence on an axis "
            "contributes nothing rather than a guess"}


def record_decision(db, inv_id: int, model_key: str, initiative_key: str,
                    decision: str, actor: str, rationale: str = "",
                    weights: dict | None = None) -> dict[str, Any]:
    """Record a selection decision as a graph edge.

    The edge is the durable record (``selected_for`` / ``rejected_for`` from
    model to initiative, origin manual, payload carrying actor, rationale and
    timestamp). It never rewrites a score: a decision is a human judgement about
    a model, not a new measurement of it. The ledger entry is written by the
    request handler, which owns the session and the actor.
    """
    from .models import Artifact, Relationship
    dec = str(decision or "").strip().lower()
    if dec not in ("selected", "rejected"):
        raise ValueError("decision must be selected or rejected")
    if not str(actor or "").strip():
        raise ValueError("actor is required")
    mk, ik = norm_key(model_key), norm_key(initiative_key)
    if not mk or not ik:
        raise ValueError("model_key and initiative_key are required")

    def _node(kind: str, key: str, title: str) -> int:
        row = (db.query(Artifact)
               .filter(Artifact.investigation_id == inv_id,
                       Artifact.artifact_type == kind,
                       Artifact.stable_key == key).first())
        if row:
            return row.id
        row = Artifact(investigation_id=inv_id, title=(title or key)[:500],
                       artifact_type=kind, stable_key=key[:200],
                       origin="manual", review="accepted",
                       tags="model_kb," + kind, relevance=None,
                       node_meta=json.dumps({"kind": kind}, sort_keys=True))
        db.add(row)
        db.flush()
        return row.id

    model_id = _node("model", mk, model_key)
    init_id = _node("initiative", ik, initiative_key)
    rel = canon_relation("selected_for" if dec == "selected" else "rejected_for")
    key = f"{mk}|{rel}|{ik}"[:300]
    from datetime import datetime, timezone
    payload = {"actor": actor, "rationale": rationale[:2000],
               "weights": weights or {}, "decided_at":
               datetime.now(timezone.utc).isoformat(),
               "decision": dec,
               # the keys, not just the node ids: the landscape reads a
               # decision back without having to resolve artifact ids
               "model_key": mk, "initiative_key": ik}
    row = (db.query(Relationship)
           .filter(Relationship.investigation_id == inv_id,
                   Relationship.stable_key == key).first())
    if row:
        old = _load(row.payload_json, {}) or {}
        # keep the earlier decision in the trail rather than overwriting it
        hist = old.get("history") or []
        hist.append({k: old.get(k) for k in ("actor", "rationale",
                                              "weights", "decided_at",
                                              "decision")})
        payload["history"] = hist[-10:]
        row.payload_json = json.dumps(payload, sort_keys=True)
        row.description = f"{dec} for {initiative_key}: {rationale}"[:500]
        edge_id = row.id
    else:
        row = Relationship(investigation_id=inv_id, source_id=model_id,
                           target_id=init_id, relationship_type=rel,
                           description=f"{dec} for {initiative_key}: "
                                       f"{rationale}"[:500],
                           payload_json=json.dumps(payload, sort_keys=True),
                           stable_key=key, origin="manual")
        db.add(row)
        db.flush()
        edge_id = row.id
    db.commit()
    # The audit write is the caller's, not this function's: the ledger entry
    # needs the request's session and actor, which only a request handler has.
    # Writing it here too would put a second, actor-less copy in the trail.
    return {"decision_id": edge_id, "decision": dec, "actor": actor,
            "model_key": mk, "initiative_key": ik, "relation": rel,
            "rationale": rationale}


def landscape_graph(db, inv_id: int) -> dict[str, Any]:
    """Model-security slice of the graph: KB nodes and edges only.

    A filter, not a second graph. Edges carry their payload so a client can
    label an edge with its scope without a second request.
    """
    from .models import Artifact, Relationship
    kinds = tuple(NODE_KINDS)
    rels = tuple(REL_TYPES)
    nodes = (db.query(Artifact)
             .filter(Artifact.investigation_id == inv_id,
                     Artifact.artifact_type.in_(kinds)).all())
    node_ids = {a.id for a in nodes}
    edges = (db.query(Relationship)
             .filter(Relationship.investigation_id == inv_id,
                     Relationship.relationship_type.in_(rels),
                     Relationship.source_id.in_(node_ids),
                     Relationship.target_id.in_(node_ids)).all())
    return {
        "nodes": [{"id": a.id, "stable_key": a.stable_key,
                   "label": (a.title or "")[:60], "title": a.title or "",
                   "kind": a.artifact_type, "review": a.review,
                   "meta": _load(a.node_meta, {}) or {},
                   "assessment_id": a.assessment_id}
                  for a in nodes],
        "edges": [{"id": r.id, "from": r.source_id, "to": r.target_id,
                   "type": r.relationship_type,
                   "label": r.relationship_type,
                   "title": r.description or "",
                   "payload": _load(r.payload_json, {}) or {},
                   "origin": r.origin} for r in edges],
        # same list under the name the generic graph endpoint uses, so a client
        # can consume both shapes without a translation layer of its own
        "relationships": [{"id": r.id, "source_id": r.source_id,
                           "target_id": r.target_id,
                           "relationship_type": r.relationship_type,
                           "description": r.description or "",
                           "payload": _load(r.payload_json, {}) or {},
                           "origin": r.origin} for r in edges],
        "kinds": list(kinds), "relations": list(rels),
        "counts": {"nodes": len(nodes), "edges": len(edges)},
    }
