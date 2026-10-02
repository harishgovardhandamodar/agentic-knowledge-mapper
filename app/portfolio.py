"""Portfolio layer: situation, unified risk register, leakage, advice.

``model_kb`` answers "what is true about this model". This module answers the
questions a security team asks when *adopting* something:

- **Situation profile** — the structured "our use of it": data classes, actors,
  channel, control environment, blast radius. An exposure tier says how bad a
  leak would be; it says nothing about who can reach the surface or what
  already stands in the way. Same model, different situation, different advice.
- **Unified risk register** — product threats (T*), model attacks (MA*),
  leakage pathways (LP*) and CVEs in one triage table with stable ids, so the
  team filters by status/owner instead of reading four reports.
- **Portfolio cascade** — composition *between* initiatives and systems, walked
  transitively, because the interesting risk ("this internal tool sits on a
  family with extraction literature and feeds the CRM") is never in one row.
- **Mitigation advisor** — deterministic catalog mapping first, narrative
  second, and residual honesty always.

Design rules, inherited from the rest of the system:

1. **Unknown stays unknown.** A control nobody evidenced is ``unknown``, and an
   unknown control never lowers risk. Declared-but-not-evidenced is a distinct
   state precisely so it cannot be read as "in place".
2. **The KB stores results; this module derives views.** Every number is copied
   from a stored assessment or a versioned catalog, with version and
   fingerprint attached.
3. **Advice never claims "secured".** Every mapped control carries its residual
   limitation, because a mitigation that works is the exception, not the rule.
4. **Human state is never re-derived.** ``status``, ``owner``, ``review_by`` and
   acceptance live in ``risk_entries``; a re-derivation updates the derived
   fields and leaves the decisions alone.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from . import leakage as _lk
from . import model_eval as _me
from .models import Artifact, Initiative, RiskEntry

PORTFOLIO_METHOD = "portfolio_v1"
PORTFOLIO_VERSION = "1.0.0"

#: Standing of a control claim. ``declared`` is what an operator says;
#: ``evidenced`` is what an artifact supports. They are not the same and the
#: difference is load-bearing: only ``evidenced`` and ``deployed`` reduce risk.
STANDING = ("unknown", "absent", "declared", "evidenced", "deployed")

#: Data classification -> how much a leak of it matters, before situation.
DATA_WEIGHT: dict[str, float] = {
    "public": 0.2,
    "internal": 0.5,
    "confidential": 0.8,
    "restricted": 1.0,
    "regulated_pii": 1.0,
    "secrets": 1.0,
}

CHANNELS = ("chat_ui", "api", "batch", "tool_calling_agent", "rag",
            "internal_tool", "embedded")

BLAST_FIELDS = ("catalogs", "tickets", "customer_channels", "training_sets",
                "downstream_stores", "payment_or_medical")

#: Situation control vocabulary. The first fifteen map 1:1 onto the product
#: control catalog (see ``CONTROL_SITUATION_KEY``) so coverage is a real
#: measurement; the last two describe the deployment rather than a control, and
#: are what tells the advisor whether weight-level advice is even available.
SITUATION_CONTROLS = (
    "classification_gate", "schema_only_prompt", "dlp", "zdr_no_train",
    "prompt_injection_defense", "human_review", "provenance", "logging",
    "region_pinning", "sso_roles", "dpia", "output_review", "sandbox",
    "egress_allowlist", "credential_brokering", "approval_gates",
    "training_access",
)

LAYERS = ("product", "model", "privacy", "supply_chain")

STATUSES = ("open", "mitigating", "accepted", "transferred", "closed")


def _model_meta(model_json: Any) -> dict[str, Any]:
    """The declared model metadata, or an empty dict when there is none."""
    return (_load(model_json, {}) or {}).get("meta") or {}


def _load(raw: Any, default: Any = None) -> Any:
    if raw is None:
        return default
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return default


def stated_situation(raw: Any) -> dict[str, Any]:
    """The operator's stated situation, unwrapping a versioned snapshot.

    The endpoint stores what was said plus audit metadata. Readers must use
    the stated profile, not the envelope, or every recorded profile would
    normalize to unknown.
    """
    s = _load(raw, {}) or {}
    if isinstance(s, dict):
        stated = s.get("situation")
        if isinstance(stated, dict):
            return stated
        return s
    return {}


def _tri(value: Any, default: str = "unknown") -> str:
    """Normalise a tri-state claim. Never invents a value."""
    v = str(value or "").strip().lower()
    return v if v in STANDING else default


def _flag(value: Any) -> bool | None:
    """A yes/no that is allowed to be unknown."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    v = str(value).strip().lower()
    if v in ("yes", "true", "1", "y"):
        return True
    if v in ("no", "false", "0", "n"):
        return False
    return None


# --------------------------------------------------------------------------
# situation profile
# --------------------------------------------------------------------------

def normalize_situation(raw: Any) -> dict[str, Any]:
    """Validated situation profile.

    Every field is optional and every absent field stays ``unknown``/``None``.
    That is deliberate: a half-declared situation must read as half-declared,
    because a filled-in default would let an assessment look better-evidenced
    than it is.
    """
    s = _load(raw, {}) or {}
    if not isinstance(s, dict):
        s = {}
    data = s.get("data") if isinstance(s.get("data"), dict) else {}
    controls = s.get("controls") if isinstance(s.get("controls"), dict) else {}
    blast = s.get("blast_radius") if isinstance(s.get("blast_radius"), dict) else {}
    actors = s.get("actors")
    out = {
        "data": {
            "classification": str(data.get("classification") or "").strip().lower() or None,
            "pii_likelihood": _flag(data.get("pii_likelihood")),
            "secrets_likelihood": _flag(data.get("secrets_likelihood")),
            "volume": str(data.get("volume") or "").strip().lower() or None,
            "residency": str(data.get("residency") or "").strip() or None,
            "lawful_basis_note": str(data.get("lawful_basis_note") or "").strip() or None,
        },
        "actors": sorted({str(a).strip().lower() for a in (actors or [])
                          if str(a).strip()}),
        "channel": str(s.get("channel") or "").strip().lower() or None,
        "controls": {k: _tri(controls.get(k)) for k in SITUATION_CONTROLS},
        "blast_radius": {k: _flag(blast.get(k)) for k in BLAST_FIELDS},
        "obligations": sorted({str(o).strip() for o in (s.get("obligations") or [])
                               if str(o).strip()}),
        "external": _flag(s.get("external")),
    }
    out["channel_valid"] = out["channel"] is None or out["channel"] in CHANNELS
    out["tags"] = situation_tags(out)
    missing = _unknown_fields(out)
    out["unknown_fields"] = missing
    out["material_unknown"] = [f for f in missing if f in MATERIAL_UNKNOWN]
    return out


#: Situation fields whose absence changes the risk number or the advice, as
#: opposed to merely being an unanswered question. Every unknown is reported;
#: only these are worth a sentence in an advice pack, because an advice pack
#: that opens by listing fourteen blanks gets read once and then ignored.
MATERIAL_UNKNOWN = ("data.classification", "channel", "actors",
                    "controls.dlp", "controls.logging", "controls.sso_roles",
                    "controls.zdr_no_train", "controls.training_access")


def _unknown_fields(sit: dict[str, Any]) -> list[str]:
    """Which situation fields nobody has answered.

    Surfaced rather than hidden: "we have not said whether DLP is in place" is
    itself a finding, and a metrics view that hides it will report a coverage
    percentage that means nothing.
    """
    missing = []
    if not sit["data"]["classification"]:
        missing.append("data.classification")
    for k, v in sit["controls"].items():
        if v == "unknown":
            missing.append(f"controls.{k}")
    if not sit["channel"]:
        missing.append("channel")
    if not sit["actors"]:
        missing.append("actors")
    return missing


def situation_tags(sit: dict[str, Any]) -> list[str]:
    """Flat tags for register rows and playbook selection."""
    tags: set[str] = set()
    d = sit.get("data") or {}
    cls = d.get("classification")
    if cls:
        tags.add(cls)
        if cls in DATA_WEIGHT:
            tags.add("confidential_data" if DATA_WEIGHT[cls] >= 0.8 else "internal_data")
    if d.get("pii_likelihood"):
        tags.add("personal_data")
    if d.get("secrets_likelihood"):
        tags.add("secrets")
    if sit.get("external"):
        tags.add("external_llm")
    ch = sit.get("channel")
    if ch:
        tags.add(ch)
        if ch in ("tool_calling_agent", "internal_tool"):
            tags.add("tool_calling")
            tags.add("internal_api")
        if ch == "rag":
            tags.add("rag")
            tags.add("internal_corpus")
    c = sit.get("controls") or {}
    if _tri(c.get("zdr_no_train")) in ("evidenced", "deployed"):
        tags.add("zdr_no_train")
    if _tri(c.get("training_access")) in ("evidenced", "deployed"):
        tags.add("training_access")
    for f, v in (sit.get("blast_radius") or {}).items():
        if v:
            tags.add(f)
    if "customer_channels" in tags:
        tags.add("customer_facing")
    return sorted(tags)


def situation_multiplier(sit: dict[str, Any]) -> dict[str, Any]:
    """How the situation scales risk, and why.

    The one property that matters: only a control that is *evidenced* reduces
    this number. A declared control is recorded as a reason the number stayed
    high, because a claim is not a control.
    """
    factors: list[dict[str, Any]] = []
    d = sit.get("data") or {}
    cls = d.get("classification")
    if cls:
        w = DATA_WEIGHT.get(cls, 0.6)
        factors.append({"factor": f"data class {cls}", "delta": round(w - 0.6, 3)})
    if d.get("secrets_likelihood"):
        factors.append({"factor": "secrets reachable from the surface",
                        "delta": 0.2})
    elif d.get("pii_likelihood"):
        factors.append({"factor": "personal data in scope", "delta": 0.1})
    ch = sit.get("channel")
    if ch in ("chat_ui", "api"):
        factors.append({"factor": f"reachable surface ({ch})", "delta": 0.1})
    if ch == "tool_calling_agent" or "tool_calling" in (sit.get("tags") or []):
        factors.append({"factor": "agent can act, not just answer", "delta": 0.15})
    blast = sit.get("blast_radius") or {}
    n_blast = sum(1 for v in blast.values() if v)
    if n_blast:
        factors.append({"factor": f"{n_blast} blast-radius sink(s) reachable",
                        "delta": round(min(0.2, 0.05 * n_blast), 3)})
    c = sit.get("controls") or {}
    for k in ("dlp", "logging", "sso_roles", "approval_gates"):
        v = _tri(c.get(k))
        if v in ("evidenced", "deployed"):
            factors.append({"factor": f"{k.replace('_', ' ')} evidenced", "delta": -0.1})
        elif v == "declared":
            factors.append({"factor": f"{k.replace('_', ' ')} declared, not evidenced",
                            "delta": 0.0, "unverified": True})
    if _tri(c.get("zdr_no_train")) == "declared":
        factors.append({"factor": "no-train declared, not evidenced", "delta": 0.0,
                        "unverified": True})
    total = 1.0 + sum(f["delta"] for f in factors)
    return {
        "multiplier": round(max(0.4, min(1.8, total)), 3),
        "factors": factors,
        "unverified_controls": [f["factor"] for f in factors if f.get("unverified")],
    }


def has_training_access(sit: dict[str, Any], meta: dict[str, Any] | None = None
                        ) -> tuple[bool, str]:
    """Whether weight-level advice is available at all.

    Returns ``(available, why)``. An API-only deployment cannot take DP-SGD,
    fine-tuning or unlearning advice, and the advisor must not offer it: a
    control the operator cannot deploy is worse than no advice, because it
    displaces the controls they can.
    """
    m = meta or {}
    if str(m.get("weights_source") or "") == "api_only":
        return False, "api_only deployment: no weight or training access"
    t = _tri((sit.get("controls") or {}).get("training_access"))
    if t in ("declared", "evidenced", "deployed"):
        return True, "training access declared"
    if t == "absent":
        return False, "training access declared absent"
    if str(m.get("weights_source") or "") in ("open_weights", "self_hosted"):
        return True, f"weights_source={m.get('weights_source')}"
    return False, ("training access unstated and no local weights: treat weight-level "
                   "advice as unavailable until someone confirms access")


# --------------------------------------------------------------------------
# leakage pathways -> register rows
# --------------------------------------------------------------------------

def _applicable_pathways(sit: dict[str, Any], meta: dict[str, Any]) -> list[dict[str, Any]]:
    """Pathways this situation actually has.

    A pathway nobody declared is not "not a risk" -- it is absent from the
    register because there is no situation to attach it to, and the
    ``situation_unknown`` row keeps that visible.
    """
    tags = set(sit.get("tags") or [])
    out = []
    for p in _lk.LEAKAGE_PATHWAYS:
        applicable = False
        why = ""
        if p["model_path"]:
            ws = str(meta.get("weights_source") or "")
            if p["id"] == "LP08":
                # an embeddings side channel needs embeddings: it is a fact about
                # the corpus and the derived vectors, not about weight access
                applicable = bool(tags & {"rag", "embeddings"})
                why = "embeddings derived from in-scope data" if applicable else ""
            else:
                # extraction risk rises with an API surface rather than
                # disappearing, because the query rate is what makes it work
                applicable = ws in ("open_weights", "self_hosted", "api_only")
                why = f"weights_source={ws or 'unknown'}"
        else:
            if p["id"] == "LP01" and tags & {"chat_ui", "api"}:
                applicable, why = True, "user-facing input surface"
            elif p["id"] == "LP02" and "rag" in tags:
                applicable, why = True, "retrieval over a corpus"
            elif p["id"] == "LP03" and tags & {"chat_ui", "api", "batch"}:
                applicable, why = True, "requests are logged somewhere"
            elif p["id"] == "LP04" and tags & {"external_llm", "confidential_data",
                                               "personal_data", "secrets"}:
                applicable, why = True, "third party receives the data"
            elif p["id"] == "LP05" and tags & {"external_llm"}:
                applicable, why = True, "third-party processing chain"
            elif p["id"] == "LP06" and tags & {"tool_calling", "tickets",
                                                "catalogs", "customer_channels",
                                                "downstream_stores"}:
                applicable, why = True, "output can re-enter enterprise systems"
            elif p["id"] == "LP08" and ("rag" in tags or "embeddings" in tags):
                applicable, why = True, "embeddings derived from the corpus"
        if applicable:
            out.append({**p, "applies_because": why})
    return out


def leakage_rows(sit: dict[str, Any], meta: dict[str, Any],
                 assessment_id: int | None = None,
                 product_key: str = "product") -> list[dict[str, Any]]:
    """Leakage rows for the unified register, with severity shown as its parts."""
    mult = situation_multiplier(sit)["multiplier"]
    rows = []
    for p in _applicable_pathways(sit, meta):
        cover = _pathway_cover(p, sit)
        covered = cover["covered"]
        # 100 = the pathway is certain, maximally amplified, uncovered and at
        # maximum situational exposure. Clamped, because a number above the top
        # of its own scale reads as a different kind of claim.
        sev = round(min(100.0, 100 * p["likelihood"] * p["exposure_sensitivity"]
                        * mult * (1.0 - covered)), 1)
        pk = _product_key(product_key)
        scope_id = assessment_id if assessment_id is not None else pk
        rows.append({
            "risk_id": f"R-LP-{pk}-{p['id']}",
            "stable_key": f"privacy:{scope_id}:{p['id']}:own",
            "layer": "privacy",
            "title": p["name"],
            "source_catalog": _lk.LEAKAGE_ID,
            "source_ref": p["id"],
            "scope": "own",
            "severity": sev,
            "confidence": p["likelihood"],
            "confidence_band": "structural",
            "exposure": str((sit.get("data") or {}).get("classification") or ""),
            "situation_tags": sit.get("tags") or [],
            "evidence_ids": [],
            "assessment_ids": [assessment_id] if assessment_id else [],
            "catalog_version": _lk.LEAKAGE_VERSION,
            "catalog_fingerprint": _lk.leakage_fingerprint(),
            "product_key": pk,
            "likelihood": p["likelihood"],
            "exposure_sensitivity": p["exposure_sensitivity"],
            "situation_multiplier": mult,
            "control_coverage": cover,
            "controls": p["controls"],
            "process": p["process"],
            "applies_because": p["applies_because"],
            "t_alignment": p["t_alignment"],
        })
    return rows


#: Control catalog id -> the situation-profile control key that would evidence
#: it. Kept explicit rather than derived: C08 is "audit + anomaly detection" and
#: the situation calls that field ``logging``, and pretending a name-match is a
#: real mapping would let an unrelated control quietly count as coverage.
CONTROL_SITUATION_KEY: dict[str, str] = {
    "C01": "classification_gate", "C02": "schema_only_prompt",
    "C03": "dlp", "C04": "zdr_no_train", "C05": "prompt_injection_defense",
    "C06": "human_review", "C07": "provenance", "C08": "logging",
    "C09": "region_pinning", "C10": "sso_roles", "C11": "dpia",
    "C12": "output_review", "C13": "sandbox", "C14": "egress_allowlist",
    "C15": "credential_brokering",
}


def _pathway_cover(p: dict[str, Any], sit: dict[str, Any]) -> dict[str, Any]:
    """How much of this pathway's controls the situation evidences.

    Only evidenced/deployed standing counts. A declared control contributes
    nothing here, which is the whole point of keeping the two apart.
    """
    c = sit.get("controls") or {}
    if not p["controls"]:
        return {"covered": 0.0, "evidenced": [], "declared_only": [],
                "unevidenced": []}
    evidenced, declared, missing = [], [], []
    for cid in p["controls"]:
        key = CONTROL_SITUATION_KEY.get(cid)
        st = _tri(c.get(key)) if key else "unknown"
        if st in ("evidenced", "deployed"):
            evidenced.append(cid)
        elif st == "declared":
            declared.append(cid)
        else:
            missing.append(cid)
    return {
        "covered": round(len(evidenced) / len(p["controls"]), 3),
        "evidenced": evidenced, "declared_only": declared,
        "unevidenced": missing,
    }


# --------------------------------------------------------------------------
# control inventory
# --------------------------------------------------------------------------

def normalize_inventory(raw: Any) -> list[dict[str, Any]]:
    """Org control inventory: what already exists.

    Advice is weak if it ignores the estate. An inventory entry says a control
    name is ``deployed|partial|absent|unknown`` so the advisor can prefer
    elevating a partial control over proposing a new programme.
    """
    items = _load(raw, []) or []
    out = []
    for it in items if isinstance(items, list) else []:
        if not isinstance(it, dict):
            continue
        cid = str(it.get("control_id") or it.get("id") or "").strip().upper()
        if not cid:
            continue
        st = str(it.get("status") or "unknown").strip().lower()
        if st not in ("deployed", "partial", "absent", "unknown"):
            st = "unknown"
        out.append({
            "control_id": cid,
            "name": str(it.get("name") or "")[:200],
            "kind": str(it.get("kind") or "product"),  # product|model|process
            "status": st,
            "evidence_ids": [int(x) for x in (it.get("evidence_ids") or [])
                             if str(x).isdigit()][:12],
            "owner": str(it.get("owner") or "") or None,
        })
    return out


def inventory_index(inv: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {i["control_id"]: i for i in inv}


# --------------------------------------------------------------------------
# unified register
# --------------------------------------------------------------------------

def _product_key(name: Any) -> str:
    """URL-safe product key for stable IDs."""
    return (re.sub(r"[^a-z0-9]+", "-", str(name or "product").lower()).strip("-")
            or "product")


def _control_options(risk: dict[str, Any]) -> list[str]:
    """Catalog-level control options for a row, before situation filtering.

    The advisor may withhold some of these for a deployment with no weight
    access or no inventory. The register still names the catalog options, so a
    risk is never shown with an empty "controls" column simply because its
    deployment cannot use them.
    """
    if risk.get("source_catalog") == "akm-rlhf-memorization":
        # RM risks carry their mitigations directly; standing (preference exposure)
        # unknown raises uncertainty, not fake precision
        return list(dict.fromkeys(risk.get("mitigations") or risk.get("controls") or []))
    layer = risk.get("layer")
    if layer == "privacy":
        opts = list((risk.get("controls") or []) + (risk.get("process") or []))
        return list(dict.fromkeys(opts))
    if layer == "product":
        src = str(risk.get("source_ref") or "")
        return [c["id"] for c in _control_catalog()
                if src and src in (c.get("threats") or {})]
    if layer == "model":
        cls = str(risk.get("attack_class") or "").lower()
        opts = [m["id"] for m in _me.MITIGATION_CATALOG
                if cls and cls in {str(x).lower() for x in
                                   (m.get("mitigates_attack_classes") or [])}]
        if str(risk.get("scope") or "") == "cascade" or cls == "cascade":
            opts.extend(["C13", "C14", "C15", "PR05"])
        return list(dict.fromkeys(opts))
    if layer == "supply_chain":
        return ["C15", "PR02"]
    return []


def _product_rows(db, inv_id: int) -> list[dict[str, Any]]:
    """Product threats (T*) from standard assessments, as register rows."""
    from .models import SecurityAssessment
    rows: list[dict[str, Any]] = []
    recs = (db.query(SecurityAssessment)
            .filter(SecurityAssessment.investigation_id == inv_id).all())
    for rec in recs:
        threats = _load(rec.threats_json, []) or []
        if not isinstance(threats, list):
            continue
        for t in threats:
            if not isinstance(t, dict) or not t.get("id"):
                continue
            pk = _product_key(rec.product_name)
            rows.append({
                "risk_id": f"R-{pk}-{t['id']}",
                "stable_key": f"product:{pk}:{t['id']}:own",
                "layer": "product",
                "title": str(t.get("title") or t.get("id") or "")[:300],
                "source_catalog": getattr(rec, "threat_pack_version", None) and "product_threat_pack",
                "source_ref": str(t["id"]),
                "scope": "own",
                "severity": t.get("residual_score"),
                "confidence": t.get("residual_likelihood"),
                "confidence_band": str(t.get("residual_severity") or "unknown"),
                "exposure": rec.exposure,
                "situation_tags": [],
                "evidence_ids": [],
                "assessment_ids": [rec.id],
                "catalog_version": rec.threat_pack_version,
                "catalog_fingerprint": rec.threat_pack_fingerprint,
                "product_key": pk,
                "product_name": rec.product_name,
                "why": f"product threat {t['id']} from the stored threat pack",
            })
    return rows


def _model_rows(land: dict[str, Any]) -> list[dict[str, Any]]:
    """Model attacks (MA*) from the KB register, remapped to the same shape."""
    rows = []
    for r in land.get("risk_register") or []:
        mk = str(r.get("model_key") or "model")
        ref = r.get("finding_id") or r.get("attack_class") or "MA"
        if r.get("mechanism"):  # cascade rows have no finding id of their own
            ref = f"cascade-{r['mechanism']}"
        rows.append({
            "risk_id": f"R-{mk}-{ref}",
            "stable_key": f"model:{mk}:{ref}:{r.get('scope') or 'own'}",
            "attack_class": r.get("attack_class"),
            "mechanism": r.get("mechanism"),
            "layer": "model",
            "title": r.get("attack_label") or r.get("title") or ref,
            "source_catalog": "akm-model-adversarial",
            "source_ref": str(ref),
            "scope": r.get("scope") or "own",
            "severity": r.get("severity"),
            "confidence": r.get("confidence"),
            "confidence_band": r.get("confidence_band") or "unknown",
            "exposure": r.get("exposure"),
            "situation_tags": [],
            "evidence_ids": [int(x) for x in (r.get("evidence_ids") or [])
                             if str(x).isdigit()][:12],
            "assessment_ids": [r["assessment_id"]] if r.get("assessment_id") else [],
            "catalog_version": r.get("catalog_version"),
            "catalog_fingerprint": r.get("catalog_fingerprint"),
            "model_key": r.get("model_key"),
            "why": (f"model attack {ref} with scope {r.get('scope') or 'own'}"),
        })
    return rows


def _cve_rows(db, inv_id: int) -> list[dict[str, Any]]:
    """Known issues (CVEs) as supply-chain rows."""
    from .models import CveFinding
    rows = []
    for c in (db.query(CveFinding)
              .filter(CveFinding.investigation_id == inv_id).all()):
        ref = c.cve_id or f"CVE-{c.id}"
        rows.append({
            "risk_id": f"R-{ref}",
            "stable_key": f"supply_chain:{ref}:own",
            "layer": "supply_chain",
            "title": (c.title or c.description or ref)[:300],
            "source_catalog": "cve",
            "source_ref": str(ref),
            "scope": "own",
            "severity": c.cvss if hasattr(c, "cvss") else None,
            "confidence": None,
            "confidence_band": "unknown",
            "exposure": None,
            "situation_tags": [],
            "evidence_ids": [],
            "assessment_ids": [],
            "catalog_version": None,
            "catalog_fingerprint": None,
            "cve_status": getattr(c, "status", None),
            "why": f"known issue {ref} with standing {getattr(c, 'status', None) or 'unknown'}",
        })
    return rows


def _pdp_rows(db, inv_id: int) -> list[dict[str, Any]]:
    """Provider posture and RLHF findings (PDP*/RLHF*) as register rows.

    Standings, never scores: severity stays None so no band, average or gauge
    can read posture as measured residual. An unknown dimension is a listed
    row with no severity, not an absent row -- "we have not established the
    feedback terms" is itself triageable information.
    """
    from . import provider_posture as _pp
    from .models import SecurityAssessment
    catalogs = {
        _pp.PDP_ID: (_pp.DIMENSION_BY_ID, "findings", None),
        _pp.RLHF_ID: (_pp.RLHF_BY_ID, "rlhf", "preference_feedback"),
    }
    rows = []
    for rec in (db.query(SecurityAssessment)
                .filter(SecurityAssessment.investigation_id == inv_id).all()):
        payload = _load(getattr(rec, "pdp_json", None), None)
        if not isinstance(payload, dict):
            continue
        pk = _product_key(rec.product_name)
        for catalog_id, (dim_by_id, key, subclass) in catalogs.items():
            findings = payload.get(key) or []
            if not findings:
                continue
            version = payload.get(
                "rlhf_version" if key == "rlhf" else "version")
            fingerprint = payload.get(
                "rlhf_fingerprint" if key == "rlhf" else "fingerprint")
            for f in findings:
                if not isinstance(f, dict) or not f.get("id"):
                    continue
                dim = dim_by_id.get(f["id"]) or {}
                layer = dim.get("layer") or "privacy"
                rows.append({
                    "risk_id": f"R-{pk}-{f['id']}",
                    "stable_key": f"{layer}:{rec.id}:{f['id']}:own",
                    "layer": layer,
                    "title": f"{f['id']}: {f.get('dimension') or dim.get('name') or f['id']}",
                    "source_catalog": catalog_id,
                    "source_ref": str(f["id"]),
                    "scope": "own",
                    "severity": None,
                    "confidence": None,
                    "confidence_band": str(f.get("standing") or "unknown"),
                    "exposure": rec.exposure,
                    "situation_tags": ["provider_posture"],
                    "evidence_ids": [int(x) for x in (f.get("evidence_ids") or [])
                                     if str(x).isdigit()][:12],
                    "assessment_ids": [rec.id],
                    "catalog_version": version,
                    "catalog_fingerprint": fingerprint,
                    "product_key": pk,
                    "product_name": rec.product_name,
                    "controls": list(dim.get("controls") or []),
                    "process": list(dim.get("process") or []),
                    "subclass": subclass,
                    "why": (f"provider posture {f['id']} reads "
                            f"{f.get('standing') or 'unknown'}: "
                            f"{f.get('summary') or ''}".strip()),
                })
    return rows


def derive_register(db, inv_id: int, landscape: dict[str, Any] | None = None,
                    persist: bool = True) -> list[dict[str, Any]]:
    """Build the unified register and overlay stored human state.

    Derived rows are merged onto ``risk_entries`` by ``stable_key``. Existing
    human state is preserved; a new row defaults to ``open`` with no owner, and
    that absence is reported rather than filled in.
    """
    from . import model_kb as _kb
    land = landscape if landscape is not None else _kb.landscape(db, inv_id)
    merged = _derived_rows(db, inv_id, land)
    if persist:
        # write first, then read back: a brand-new row has no id until it is
        # inserted, and a caller that got entry_id=None could not record a
        # decision against the risk it was just shown
        _persist_register(db, inv_id, list(merged.values()))
    existing = {x.stable_key: x for x in (db.query(RiskEntry)
                                          .filter(RiskEntry.investigation_id == inv_id)
                                          .all())}
    return _overlay_state(list(merged.values()), existing)


def _rm_rows(db, inv_id: int, land: dict[str, Any]) -> list[dict[str, Any]]:
    """RLHF memorization risks RM01-06 as register rows."""
    from . import memorization as _rm
    from .models import SecurityAssessment
    rows: list[dict[str, Any]] = []
    for rec in (db.query(SecurityAssessment)
                .filter(SecurityAssessment.investigation_id == inv_id).all()):
        model_json = _load(getattr(rec, "model_json", None), {}) or {}
        meta = model_json.get("meta") or {}
        # Derive RM01-04, RM06 from W1 findings with subtypes
        for rm in _rm.rm_rows_for_model(rec, meta):
            # Enrich with assessment linkage
            rm["assessment_ids"] = [rec.id]
            rm["product_name"] = rec.product_name
            rm["exposure"] = rec.exposure
            rm["situation_tags"] = ["rlhf_memorization"]
            # stable key includes RM id and scope
            rm["stable_key"] = f"privacy:{rec.id}:{rm['rm_id']}:{rm.get('scope') or 'own'}"
            rm["risk_id"] = f"R-{_product_key(rec.product_name)}-{rm['rm_id']}"
            rows.append(rm)
        # RM05 provider join: situational rating from RLHF findings
        payload = _load(getattr(rec, "pdp_json", None), None)
        if isinstance(payload, dict) and payload.get("rlhf"):
            # find situation for this assessment
            sit_raw = _load(getattr(rec, "situation_json", None), None)
            sit = normalize_situation(stated_situation(sit_raw) if sit_raw else {})
            rating = _rm.rm05_situational(payload.get("rlhf"), sit, meta)
            if rating["rating"] != "unknown":
                rm05 = _rm.RM_BY_ID["RM05"]
                sev = rm05["severity"] if rating["rating"] == "elevated" else 40
                rows.append({
                    "risk_id": f"R-{_product_key(rec.product_name)}-RM05",
                    "stable_key": f"privacy:{rec.id}:RM05:{rating['rating']}",
                    "rm_id": "RM05",
                    "title": rm05["title"],
                    "description": rm05["description"] + f" [{rating['rating']}: {', '.join(rating['reasons'])}]",
                    "attack_class": rm05["attack_class"],
                    "attack_subtype": rm05["attack_subtype"],
                    "severity": sev,
                    "scope": "own",
                    "evidence_scope": "model_specific" if rating["rating"] == "elevated" else "family",
                    "scope_weight": 1.0 if rating["rating"] == "elevated" else 0.6,
                    "confidence": 0.7 if rating["rating"] == "elevated" else 0.5,
                    "confidence_band": rating["rating"],
                    "data_class": rm05["data_class"],
                    "pipeline_stage": rm05["pipeline_stage"],
                    "layer": rm05["layer"],
                    "source_catalog": _rm.RM_ID,
                    "source_ref": "RM05",
                    "catalog_version": _rm.RM_VERSION,
                    "catalog_fingerprint": _rm.rm_fingerprint(),
                    "mitigations": rm05["mitigations"],
                    "org_controllability": rm05["org_controllability"],
                    "subject": rec.product_name,
                    "model_key": _product_key(rec.product_name),
                    "evidence_ids": [],
                    "assessment_ids": [rec.id],
                    "retention_context": "; ".join(rating["reasons"]),
                    "extractability_confidence": 0.7 if rating["rating"] == "elevated" else 0.4,
                    "situation_tags": ["rlhf_memorization", "provider_posture"],
                    "status": "open",
                })
    return rows


def _derived_rows(db, inv_id: int,
                 land: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Every derived register row, keyed by stable key. No state, no writes."""
    rows = (_product_rows(db, inv_id) + _model_rows(land)
            + _cve_rows(db, inv_id) + _pdp_rows(db, inv_id) + _rm_rows(db, inv_id, land))
    # situation-scoped leakage rows, one set per assessment that declared one
    from .models import SecurityAssessment
    for rec in (db.query(SecurityAssessment)
                .filter(SecurityAssessment.investigation_id == inv_id).all()):
        raw = stated_situation(getattr(rec, "situation_json", None))
        if not raw:
            continue
        meta = ((_load(rec.model_json, {}) or {}).get("meta") or {})
        new_rows = leakage_rows(normalize_situation(raw), meta, rec.id,
                                rec.product_name)
        for nr in new_rows:
            nr["product_name"] = rec.product_name
            nr["why"] = (f"{nr['title']}: {nr['applies_because']}; "
                         f"severity {nr['severity']} "
                         f"(likelihood {nr['likelihood']}, exposure "
                         f"{nr['exposure_sensitivity']}, situation "
                         f"{nr['situation_multiplier']}, uncovered "
                         f"{round(1.0 - nr['control_coverage']['covered'], 3)})")
        rows.extend(new_rows)
    return {r["stable_key"]: r for r in rows}


def _overlay_state(rows: list[dict[str, Any]],
                   existing: dict[str, Any]) -> list[dict[str, Any]]:
    """Derived rows overlaid with stored human state. No writes."""
    out: list[dict[str, Any]] = []
    for r in rows:
        prev = existing.get(r["stable_key"])
        row = dict(r)
        row["control_options"] = _control_options(row)
        row["why"] = row.get("why") or row.get("title")
        row["status"] = prev.status if prev else "open"
        row["owner"] = prev.owner if prev else None
        row["review_by"] = prev.review_by.isoformat() if (prev and prev.review_by) else None
        row["residual_note"] = prev.residual_note if prev else None
        row["mitigation_ids"] = _load(prev.mitigation_ids_json, []) if prev else []
        # Stored evidence links win when present: an operator may attach
        # evidence the derivation cannot see, and a re-derivation must not
        # silently detach it.
        stored_evidence = _load(prev.evidence_ids_json, []) if prev else []
        if stored_evidence:
            row["evidence_ids"] = stored_evidence
        row["accepted_by"] = prev.accepted_by if prev else None
        row["acceptance_note"] = prev.acceptance_note if prev else None
        row["accepted_at"] = prev.accepted_at.isoformat() if (prev and prev.accepted_at) else None
        row["entry_id"] = prev.id if prev else None
        row["owner_missing"] = not row["owner"]
        row["review_missing"] = not row["review_by"]
        # scoring fields: prefer stored, else compute on the fly (no DB write)
        if prev and prev.scoring_method:
            row["inherent_score"] = prev.inherent_score
            row["residual_score"] = prev.residual_score
            row["priority_score"] = prev.priority_score
            row["band"] = prev.band
            row["confidence"] = prev.confidence
            row["scoring_method"] = prev.scoring_method
            row["scoring_fingerprint"] = prev.scoring_fingerprint
            row["score_rationale"] = prev.score_rationale
            row["inputs_hash"] = prev.inputs_hash
            row["scored_at"] = prev.scored_at.isoformat() if prev.scored_at else None
            row["plain_summary"] = prev.plain_summary
            row["cluster_id"] = prev.cluster_id
            row["cluster_label"] = prev.cluster_label
            row["monitor_flags"] = json.loads(prev.monitor_flags_json or "[]") if prev.monitor_flags_json else []
        else:
            try:
                from . import risk_scoring as rs

                scored = rs.score_risk(
                    {
                        "layer": row.get("layer"),
                        "severity": row.get("severity"),
                        "exposure": row.get("exposure"),
                        "scope": row.get("scope"),
                        "evidence_ids": row.get("evidence_ids") or [],
                        "status": row.get("status") or "open",
                        "owner": row.get("owner"),
                        "review_by": row.get("review_by"),
                        "created_at": None,
                        "confidence": row.get("confidence"),
                        "mitigation_ids": row.get("mitigation_ids") or [],
                    }
                )
                row.update(
                    {
                        "inherent_score": scored["inherent_score"],
                        "residual_score": scored["residual_score"],
                        "priority_score": scored["priority_score"],
                        "band": scored["band"],
                        "confidence": scored["confidence"],
                        "scoring_method": scored["scoring_method"],
                        "scoring_fingerprint": scored["scoring_fingerprint"],
                        "score_rationale": scored["score_rationale"],
                        "inputs_hash": scored["inputs_hash"],
                        "scored_at": scored["scored_at"],
                    }
                )
                row["plain_summary"] = row.get("plain_summary") or f"{row.get('title','')} — {row.get('layer')} {row.get('scope')} risk"
                row["monitor_flags"] = []
            except Exception:
                pass
        out.append(row)
    # default sort: priority desc for console, severity desc for classic — keep severity for now, console sorts by priority
    return sorted(out, key=lambda r: (-(r.get("priority_score") or r.get("severity") or 0), r["risk_id"]))


def register_with_state(db, inv_id: int,
                        landscape: dict[str, Any] | None = None
                        ) -> list[dict[str, Any]]:
    """The unified register with stored human state, read-only.

    Same rows :func:`derive_register` returns, but nothing is written: a
    dashboard read must not create register rows as a side effect. Rows with
    no stored counterpart read as ``open`` with no owner, and say so.
    """
    from . import model_kb as _kb
    land = landscape if landscape is not None else _kb.landscape(db, inv_id)
    merged = _derived_rows(db, inv_id, land)
    existing = {x.stable_key: x for x in (db.query(RiskEntry)
                                          .filter(RiskEntry.investigation_id == inv_id)
                                          .all())}
    return _overlay_state(list(merged.values()), existing)


def _persist_register(db, inv_id: int, rows: list[dict[str, Any]]) -> None:
    """Upsert derived fields, never touch human state. Also scores via risk_scoring."""
    from . import risk_scoring as rs

    existing = {x.stable_key: x for x in (db.query(RiskEntry)
                                           .filter(RiskEntry.investigation_id == inv_id).all())}
    for r in rows:
        e = existing.get(r["stable_key"])
        # score via risk_scoring (pure, no DB writes)
        try:
            scored = rs.score_risk(
                {
                    "layer": r.get("layer"),
                    "severity": r.get("severity"),
                    "exposure": r.get("exposure"),
                    "scope": r.get("scope"),
                    "evidence_ids": r.get("evidence_ids") or [],
                    "status": (e.status if e else "open"),
                    "owner": (e.owner if e else None),
                    "review_by": (e.review_by.isoformat() if e and e.review_by else None),
                    "created_at": (e.created_at.isoformat() if e and e.created_at else None),
                    "confidence": r.get("confidence"),
                    "mitigation_ids": json.loads(e.mitigation_ids_json or "[]") if e and e.mitigation_ids_json else [],
                    "treatment_plan": json.loads(e.treatment_plan_json or "{}") if e and e.treatment_plan_json else {},
                }
            )
        except Exception:
            scored = {}
        vals = dict(
            risk_id=r["risk_id"], layer=r["layer"], title=r["title"][:500],
            source_catalog=r.get("source_catalog"), source_ref=r.get("source_ref"),
            scope=r.get("scope") or "own",
            situation_tags_json=json.dumps(r.get("situation_tags") or []),
            exposure=r.get("exposure"), severity=r.get("severity"),
            confidence=scored.get("confidence", r.get("confidence")),
            confidence_band=scored.get("band", r.get("confidence_band") or "unknown"),
            evidence_ids_json=json.dumps(r.get("evidence_ids") or []),
            assessment_ids_json=json.dumps(r.get("assessment_ids") or []),
            catalog_version=r.get("catalog_version"),
            catalog_fingerprint=r.get("catalog_fingerprint"),
        )
        # scoring fields: only if new or inputs changed (idempotent)
        if not e or e.inputs_hash != scored.get("inputs_hash"):
            vals.update(
                {
                    "inherent_score": scored.get("inherent_score"),
                    "residual_score": scored.get("residual_score"),
                    "priority_score": scored.get("priority_score"),
                    "band": scored.get("band"),
                    "scoring_method": scored.get("scoring_method"),
                    "scoring_fingerprint": scored.get("scoring_fingerprint"),
                    "score_rationale": scored.get("score_rationale"),
                    "inputs_hash": scored.get("inputs_hash"),
                    "scored_at": datetime.now(timezone.utc) if scored else None,
                }
            )
        vals["plain_summary"] = r.get("plain_summary") or f"{r.get('title','')} — {r.get('layer')} {r.get('scope')} risk"
        if e is None:
            e = RiskEntry(investigation_id=inv_id, stable_key=r["stable_key"],
                          status="open", **vals)
            db.add(e)
        else:
            for k, v in vals.items():
                setattr(e, k, v)
    db.commit()


def set_risk_state(db, entry_id: int, status: str | None = None,
                   owner: str | None = None, review_by: str | None = None,
                   residual_note: str | None = None,
                   mitigation_ids: list[str] | None = None,
                   accept: bool = False, accepted_by: str | None = None,
                   acceptance_note: str | None = None) -> dict[str, Any]:
    """Move one register row's human state. Ledgered by the caller.

    ``accept`` is a risk acceptance: it records who accepted, which is a
    different person from whoever requested the assessment by policy, and the
    caller is expected to enforce that.
    """
    e = db.get(RiskEntry, entry_id)
    if e is None:
        raise LookupError(f"risk entry {entry_id} not found")
    if status is not None:
        if status not in STATUSES:
            raise ValueError(f"unknown status {status!r}; expected one of {STATUSES}")
        e.status = status
    if owner is not None:
        e.owner = owner or None
    if review_by:
        e.review_by = datetime.fromisoformat(review_by)
    if residual_note is not None:
        e.residual_note = residual_note
    if mitigation_ids is not None:
        e.mitigation_ids_json = json.dumps([str(x) for x in mitigation_ids])
    if accept:
        e.status = "accepted"
        e.accepted_by = accepted_by or None
        e.accepted_at = datetime.utcnow()
        e.acceptance_note = acceptance_note or None
    db.commit()
    return {"entry_id": e.id, "risk_id": e.risk_id, "status": e.status,
            "owner": e.owner, "accepted_by": e.accepted_by,
            "residual_note": e.residual_note}


# --------------------------------------------------------------------------
# portfolio cascade
# --------------------------------------------------------------------------

COMPOSITION = (
    ("fine_tune", "a fine-tune inherits its base's risk and adds its own data path"),
    ("adapter", "an adapter inherits its base's risk and its host's exposure"),
    ("rag", "a retrieval surface re-opens the corpus to the model's output"),
    ("fine-tun", "a fine-tune inherits its base's risk and adds its own data path"),
    ("agent", "an agent can act on the systems the model can only describe"),
    ("tool", "tool access turns a model answer into a system action"),
    ("embed", "embeddings derived from restricted data carry the same exposure"),
    ("shared", "a shared key or prompt library links initiatives that look separate"),
    ("downstream", "output re-enters a downstream store"),
)


def portfolio_cascade(land: dict[str, Any], initiatives: list[dict[str, Any]]
                      ) -> list[dict[str, Any]]:
    """Composition *between* things, walked transitively.

    The per-model cascade map answers "what does this model inherit". This one
    answers the question the team actually has: "if I ship this, what else does
    it touch?" Edges are reported with the path that reached them, because a
    transitive risk is only actionable if you can see the chain.
    """
    edges: list[dict[str, Any]] = []
    inv_by_model: dict[str, list[str]] = {}
    for i in initiatives or []:
        for m in (i.get("models") or []):
            inv_by_model.setdefault(m, []).append(i.get("title") or i.get("id"))
    for inv in initiatives or []:
        title = inv.get("title") or inv.get("id")
        blob = " ".join(str(x) for x in
                        [inv.get("business_use_case"), inv.get("systems"),
                         " ".join(inv.get("models") or []),
                         " ".join(inv.get("data_classes") or [])]).lower()
        for term, why in COMPOSITION:
            if term in blob:
                edges.append({
                    "edge_id": f"CASC:{term}:{title}",
                    "from": title,
                    "to": None,
                    "mechanism": term.replace("-", "_"),
                    "why": why,
                    "basis": "explicit",
                    "shared_with": sorted(set(
                        x for m in (inv.get("models") or [])
                        for x in inv_by_model.get(m, []) if x != title)),
                    "depth": 1,
                    "via": [title],
                })
    # Transitive edges follow a shared entity, not a shared keyword. Two
    # initiatives that ship the same model are linked whether or not their
    # briefs use the same word: if one of them composes (a fine-tune, an agent),
    # that composed path reaches the other through the shared model, and the
    # second team does not own it. Grouping by mechanism instead would have
    # missed exactly the case worth knowing.
    composed = {e["from"] for e in edges}
    shared_models: dict[str, set[str]] = {}
    for inv in initiatives or []:
        title = inv.get("title") or inv.get("id")
        for m in (inv.get("models") or []):
            shared_models.setdefault(m, set()).add(title)
    for model, titles in shared_models.items():
        if len(titles) < 2:
            continue
        for a in sorted(titles):
            for b in sorted(titles):
                if a == b or (a not in composed and b not in composed):
                    continue
                src, dst = (a, b) if a in composed else (b, a)
                edges.append({
                    "edge_id": f"CASC:shared-model:{model}:{dst}",
                    "from": dst, "to": src, "mechanism": "shared_model",
                    "shared_model": model,
                    "why": f"{dst} and {src} both ship {model}, and {src} "
                           f"composes it; the composed path reaches {dst} "
                           f"through a model neither team reviews end to end",
                    "basis": "transitive", "depth": 2,
                    "via": [dst, model, src],
                })
    seen, uniq = set(), []
    for e in edges:
        if e["edge_id"] in seen:
            continue
        seen.add(e["edge_id"])
        uniq.append(e)
    return sorted(uniq, key=lambda e: (e["depth"], e["edge_id"]))


# --------------------------------------------------------------------------
# mitigation advisor
# --------------------------------------------------------------------------

def _control_catalog() -> list[dict[str, Any]]:
    from . import security as _sec
    return list(_sec._CONTROL_CATALOG)


def _control_by_id() -> dict[str, dict[str, Any]]:
    from . import security as _sec
    return {c["id"]: c for c in _sec._CONTROL_CATALOG}


def map_controls(risk: dict[str, Any], sit: dict[str, Any],
                 meta: dict[str, Any]) -> list[dict[str, Any]]:
    """Deterministic risk -> control mapping. No LLM in this function.

    Three passes, in order of honesty:

    1. **Catalog mapping.** A leakage pathway names its controls and process
       patterns directly. A product threat maps through the control catalog's
       own ``threats`` weights. A model attack maps through the MM catalog's
       ``mitigates_attack_classes``.
    2. **Constraint filter.** A control requiring training access is dropped
       when the deployment has none, and the drop is reported.
    3. **Inventory delta.** A control the org already partly has is put first,
       with the gap named, because elevating a half-built control beats
       starting a new programme.
    """
    inv = inventory_index(sit.get("control_inventory") or [])
    training_ok, training_why = has_training_access(sit, meta)
    out: list[dict[str, Any]] = []
    seen: set[str] = set()

    def _add(cid: str, why: str, kind: str) -> None:
        if cid in seen:
            return
        seen.add(cid)
        have = inv.get(cid)
        req = ""
        residual = ""
        title = cid
        if kind == "model":
            mm = next((m for m in _me.MITIGATION_CATALOG if m["id"] == cid), None)
            if not mm:
                return
            req = str(mm.get("requires") or "")
            residual = str(mm.get("residual_limitations") or "")
            title = str(mm.get("title") or cid)
            if req == "training_access" and not training_ok:
                out.append({"control_id": cid, "dropped": True, "why": why,
                            "requires": req, "reason_dropped": training_why,
                            "residual_limitation": residual,
                            "inventory_status": (inv.get(cid) or {}).get("status", "unknown"),
                            "inventory_delta": _inventory_delta((inv.get(cid) or {}).get("status")),
                            "kind": "model", "title": title})
                return
        elif kind == "process":
            pr = _lk.PROCESS_BY_ID.get(cid)
            if not pr:
                return
            residual = ""
            title = pr["name"]
        else:
            c = _control_by_id().get(cid)
            if not c:
                return
            residual = ""
            title = str(c.get("name") or cid)
        out.append({
            "control_id": cid, "title": title, "kind": kind,
            "why": why,
            "requires": req,
            "residual_limitation": residual,
            "inventory_status": (have or {}).get("status", "unknown"),
            "inventory_delta": _inventory_delta((have or {}).get("status")),
            "dropped": False,
        })

    src = risk.get("source_ref") or ""
    # RLHF memorization rows (RM catalog) carry their mitigations directly;
    # they are not leakage pathways and must not be treated as "no pathway"
    if risk.get("source_catalog") == "akm-rlhf-memorization":
        for cid in (risk.get("mitigations") or risk.get("controls") or []):
            _add(cid, f"mitigates {src} ({risk.get('title') or src})", "model")
        # RM also maps via attack class for completeness
        cls = str(risk.get("attack_class") or "").lower()
        for m in _me.MITIGATION_CATALOG:
            if cls and cls in {str(x).lower() for x in (m.get("mitigates_attack_classes") or [])}:
                _add(m["id"], f"mitigates {cls}", "model")
    if risk.get("layer") == "privacy":
        p = _lk.PATHWAY_BY_ID.get(src)
        if p:
            for cid in p["controls"]:
                _add(cid, f"covers {p['name']} ({p['id']})", "product")
            for cid in p["process"]:
                _add(cid, f"governs {p['name']}", "process")
    elif risk.get("layer") == "product":
        for c in _control_catalog():
            w = (c.get("threats") or {}).get(src)
            if w:
                _add(c["id"], f"covers threat {src} (catalog weight {w})",
                     "product")
    elif risk.get("layer") == "model":
        # the MM catalog is keyed by attack class, and a row's source_ref is the
        # finding id (MA-01), so the class has to be read off the row rather
        # than inferred from the reference
        cls = str(risk.get("attack_class") or "").lower()
        for m in _me.MITIGATION_CATALOG:
            if cls and cls in {str(x).lower() for x in
                               (m.get("mitigates_attack_classes") or [])}:
                _add(m["id"], f"mitigates {cls}", "model")
        if str(risk.get("scope") or "") == "cascade" or cls == "cascade":
            # no MM control mitigates composition: a base-model control does not
            # close a path the composition created. Offer what is left, and say
            # plainly that the composition itself is unmitigated.
            for cid in ("C13", "C14", "C15"):
                _add(cid, "constrains the composed path", "product")
            _add("PR05", "name who reviews the composed action", "process")
    elif risk.get("layer") == "supply_chain":
        _add("C15", "dependency and provenance tracking", "product")
        _add("PR02", "vendor review", "process")
    order = {"deployed": 0, "partial": 1, "absent": 2, "unknown": 3}
    out.sort(key=lambda c: (c["dropped"], order.get(c.get("inventory_status"), 3),
                            c["control_id"]))
    return out


def _inventory_delta(status: str | None) -> str:
    return {
        "deployed": "already deployed: verify it covers this case",
        "partial": "partially deployed: closing the gap is cheaper than greenfield",
        "absent": "not deployed: needs a build",
        "unknown": "status unstated: an unstated control is not a control",
    }.get(status or "unknown", "status unstated: an unstated control is not a control")


def advise(db, inv_id: int, register: list[dict[str, Any]] | None = None,
           landscape: dict[str, Any] | None = None,
           controls_present: list[str] | None = None,
           max_burden: str | None = None,
           initiative_id: int | None = None) -> dict[str, Any]:
    """Advice pack for the open rows of one investigation or initiative.

    The mapping is deterministic; ``narrative`` is the only part that may be
    LLM-written, and it is optional -- the pack is complete without it, because
    a priority narrative that fails to generate must not cost the operator the
    control mapping they can act on.
    """
    from . import model_kb as _kb
    land = landscape if landscape is not None else _kb.landscape(db, inv_id)
    reg = register if register is not None else derive_register(db, inv_id, land)
    ini = None
    scope_aids: set[int] | None = None
    if initiative_id is not None:
        ini = get_initiative(db, inv_id, initiative_id)
        scoped = _initiative_assessments(db, inv_id, initiative_id)
        scope_aids = {r.id for r in scoped}
        reg = [r for r in reg
               if _as_ints(r.get("assessment_ids")) & scope_aids]
        sit = normalize_situation(
            _scoped_first(scoped, "situation_json") or _first_situation(db, inv_id))
        meta = ((_load(_scoped_first(scoped, "model_json"), {}) or {}).get("meta")
                or _first_meta(db, inv_id))
        sit["control_inventory"] = normalize_inventory(
            ini.control_inventory_json)
    else:
        sit = normalize_situation(_first_situation(db, inv_id))
        meta = _first_meta(db, inv_id)
        sit["control_inventory"] = normalize_inventory(
            _first_inventory(db, inv_id))
    mult = situation_multiplier(sit)

    items: list[dict[str, Any]] = []
    for r in reg:
        if r.get("status") in ("closed", "transferred"):
            continue
        mapped = map_controls(r, sit, meta)
        live = [m for m in mapped if not m["dropped"]]
        dropped = [m for m in mapped if m["dropped"]]
        items.append({
            "risk_id": r["risk_id"],
            "layer": r["layer"],
            "title": r["title"],
            "why": (r.get("applies_because")
                   or f"{r.get('layer')} risk {r['risk_id']} from "
                   f"{r.get('source_catalog')} {r.get('source_ref')}"),
            "scope": r.get("scope"),
            "severity": r.get("severity"),
            "status": r.get("status"),
            "controls": live,
            "controls_unavailable": dropped,
            "preventive": [m["control_id"] for m in live if m["kind"] != "process"][:4],
            "detective": [m["control_id"] for m in live if m["kind"] == "process"][:4],
            "corrective": [m["control_id"] for m in live
                           if m["kind"] == "product" and m["inventory_status"] in
                           ("partial", "absent")][:4],
            "residual_limitations": sorted({m["residual_limitation"]
                                            for m in live
                                            if m.get("residual_limitation")}),
            "quick_win": bool(live) and any(
                m["inventory_status"] == "partial" for m in live),
            "structural": bool(live) and all(
                m["inventory_status"] in ("absent", "unknown") for m in live),
            "needs_acceptance_draft": (r.get("severity") or 0) >= 70
            and r.get("status") == "open",
            "evidence_ids": r.get("evidence_ids") or [],
        })
    playbooks = _lk.select_playbooks(sit.get("tags"))
    covered = {p for pb in playbooks for p in pb["forced"]}
    lims = _limitations(sit, items)
    if ini is not None:
        if not scope_aids:
            lims.append("This initiative has no linked assessments, so there "
                        "is nothing in scope to advise on. Link assessments "
                        "before reading this as good news.")
        else:
            lims.append(f"Scoped to initiative {ini.title}: only risks from "
                        f"its {len(scope_aids)} linked assessment(s) are "
                        "advised on, using its own control inventory.")
    return {
        "investigation_id": inv_id,
        "initiative_id": ini.id if ini is not None else None,
        "method": PORTFOLIO_METHOD,
        "version": PORTFOLIO_VERSION,
        "situation": sit,
        "situation_multiplier": mult,
        "advice": items,
        "playbooks": playbooks,
        "playbook_coverage_pct": round(
            100.0 * len(covered) / max(1, len(_lk.LEAKAGE_PATHWAYS))),
        "unverified_controls": mult["unverified_controls"],
        "catalogs": {
            _lk.LEAKAGE_ID: {"version": _lk.LEAKAGE_VERSION,
                             "fingerprint": _lk.leakage_fingerprint()},
            _lk.PLAYBOOK_ID: {"version": _lk.PLAYBOOK_VERSION,
                              "fingerprint": _lk.playbook_fingerprint()},
            _me.MITIGATION_ID: {"version": _me.MITIGATION_VERSION,
                                "fingerprint": _me.mitigation_fingerprint()},
        },
        "limitations": lims,
        "note": "Control mapping is deterministic and derived from the stored "
                "register and the versioned catalogs. A control that requires "
                "training access is not offered when the deployment has none; "
                "declared-but-unevidenced controls are reported as gaps, not as "
                "coverage.",
    }


def _limitations(sit: dict[str, Any], items: list[dict[str, Any]]) -> list[str]:
    """The honest caveats, stated whether or not anyone asked."""
    out = []
    material = sit.get("material_unknown") or []
    if material:
        out.append("The situation profile is incomplete in ways that change the "
                   "answer: " + ", ".join(material)
                   + ". Advice for an unstated situation is a starting point, "
                     "not a sign-off.")
    extra = len(sit.get("unknown_fields") or []) - len(material)
    if extra > 0:
        out.append(f"{extra} further control standing(s) are unstated and "
                   "counted as uncovered.")
    if not items:
        out.append("No open risks were derived. That means nothing was assessed, "
                   "not that nothing is wrong.")
    if any(i["controls_unavailable"] for i in items):
        out.append("Some controls were withheld because this deployment has no "
                   "training or weight access. They are listed rather than "
                   "quietly dropped, because knowing a control is unavailable is "
                   "itself a decision to record.")
    out.append("A mapped control reduces a risk; it does not close it. Residual "
               "risk stays in the register until a human accepts it.")
    return out


def _first_situation(db, inv_id: int) -> Any:
    from .models import SecurityAssessment
    rec = (db.query(SecurityAssessment)
           .filter(SecurityAssessment.investigation_id == inv_id,
                   SecurityAssessment.situation_json.isnot(None))
           .order_by(SecurityAssessment.id.desc()).first())
    return stated_situation(rec.situation_json) if rec else None


def _first_meta(db, inv_id: int) -> dict[str, Any]:
    from .models import SecurityAssessment
    rec = (db.query(SecurityAssessment)
           .filter(SecurityAssessment.investigation_id == inv_id,
                   SecurityAssessment.model_json.isnot(None))
           .order_by(SecurityAssessment.id.desc()).first())
    if not rec:
        return {}
    return (_load(rec.model_json, {}) or {}).get("meta") or {}


def _first_inventory(db, inv_id: int) -> Any:
    ini = (db.query(Initiative)
           .filter(Initiative.investigation_id == inv_id)
           .order_by(Initiative.id.desc()).first())
    return ini.control_inventory_json if ini else None


def get_initiative(db, inv_id: int, initiative_id: int) -> Initiative:
    """An initiative in this investigation, or a lookup failure.

    Raises ``LookupError`` rather than returning None: advice scoped to the
    wrong initiative is worse than no advice, so the caller must handle a miss
    instead of silently falling back to the whole investigation.
    """
    ini = db.get(Initiative, initiative_id)
    if ini is None or ini.investigation_id != inv_id:
        raise LookupError(f"initiative {initiative_id} not found")
    return ini


def _initiative_assessments(db, inv_id: int, initiative_id: int):
    from .models import SecurityAssessment
    return (db.query(SecurityAssessment)
            .filter(SecurityAssessment.investigation_id == inv_id,
                    SecurityAssessment.initiative_id == initiative_id)
            .order_by(SecurityAssessment.id).all())


def _scoped_first(recs, field: str) -> Any:
    for rec in sorted(recs, key=lambda r: r.id, reverse=True):
        if getattr(rec, field, None):
            return getattr(rec, field)
    return None


def _as_ints(values: Any) -> set[int]:
    out: set[int] = set()
    for v in values or []:
        try:
            out.add(int(v))
        except (TypeError, ValueError):
            continue
    return out


def initiative_summaries(db, inv_id: int) -> list[dict[str, Any]]:
    """One aggregate per initiative: linked work, linked risks, open count.

    A risk belongs to an initiative through the assessments that initiative
    points at, not through a single initiative id on a shared row: two
    initiatives can assess the same model, and the row they share cannot live
    in only one of them. Risks with no linked assessment are not counted here;
    they stay in the investigation-wide register where they can be triaged.
    """
    inis = (db.query(Initiative)
            .filter(Initiative.investigation_id == inv_id)
            .order_by(Initiative.id).all())
    if not inis:
        return []
    rows = derive_register(db, inv_id, persist=False)
    existing = {x.stable_key: x for x in (db.query(RiskEntry)
                                          .filter(RiskEntry.investigation_id == inv_id)
                                          .all())}
    from .models import SecurityAssessment
    recs = (db.query(SecurityAssessment)
            .filter(SecurityAssessment.investigation_id == inv_id).all())
    by_ini: dict[int | None, list[Any]] = {}
    for rec in recs:
        by_ini.setdefault(rec.initiative_id, []).append(rec)
    out = []
    for ini in inis:
        linked_recs = by_ini.get(ini.id, [])
        aids = {r.id for r in linked_recs}
        situations = sum(1 for r in linked_recs if r.situation_json)
        linked = []
        for row in rows:
            if not (_as_ints(row.get("assessment_ids")) & aids):
                continue
            prev = existing.get(row["stable_key"])
            linked.append({
                "stable_key": row["stable_key"],
                "layer": row["layer"],
                "severity": row.get("severity"),
                "status": prev.status if prev else "open",
                "owner": prev.owner if prev else None,
                "review_by": bool(prev and prev.review_by),
            })
        by_layer: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for r in linked:
            by_layer[r["layer"]] = by_layer.get(r["layer"], 0) + 1
            by_status[r["status"]] = by_status.get(r["status"], 0) + 1
        sevs = [r["severity"] for r in linked if r["severity"] is not None]
        out.append({
            "id": ini.id,
            "assessments": len(linked_recs),
            "assessments_with_situation": situations,
            "risks": len(linked),
            "open_risks": sum(1 for r in linked if r["status"] == "open"),
            "unowned_risks": sum(1 for r in linked if not r["owner"]),
            "risks_with_review_date": sum(1 for r in linked if r["review_by"]),
            "by_layer": by_layer,
            "by_status": by_status,
            "max_severity": max(sevs) if sevs else None,
        })
    return out


# --------------------------------------------------------------------------
# intel feed + metrics
# --------------------------------------------------------------------------

def intel_feed(db, inv_id: int, since_days: int = 30,
               stale_days: int = 90) -> dict[str, Any]:
    """What changed since the last review.

    Four triggers, all derived from stored rows so the feed cannot invent a
    change: new CVEs since the window, artifacts marked drift, assessments
    older than the staleness threshold, and catalog drift between a stored row
    and today's catalog.
    """
    from .models import Artifact, SecurityAssessment
    since = datetime.utcnow() - timedelta(days=since_days)
    stale_cut = datetime.utcnow() - timedelta(days=stale_days)
    new_cves = (db.query(Artifact)
                .filter(Artifact.investigation_id == inv_id,
                        Artifact.artifact_type == "cve_advisory",
                        Artifact.created_at >= since).all())
    drifted = (db.query(Artifact)
               .filter(Artifact.investigation_id == inv_id,
                       Artifact.drift == 1).all())
    from . import provider_posture as _pp
    new_posture = [{
        "id": a.id, "title": a.title,
        "safety": _pp.is_safety_typed({"id": a.id, "title": a.title,
                                       "tags": a.tags,
                                       "artifact_type": a.artifact_type}),
        "review": a.review} for a in (db.query(Artifact).filter(
            Artifact.investigation_id == inv_id,
            Artifact.review == "accepted",
            Artifact.created_at >= since).all())
        if _pp.is_posture_evidence({"id": a.id, "title": a.title,
                                     "tags": a.tags,
                                     "artifact_type": a.artifact_type})]
    recs = (db.query(SecurityAssessment)
            .filter(SecurityAssessment.investigation_id == inv_id).all())
    stale = [{"assessment_id": r.id, "product_name": r.product_name,
              "age_days": (datetime.utcnow() - r.created_at).days
              if r.created_at else None,
              "why": "evidence collected after this score makes it stale"}
             for r in recs if r.created_at and r.created_at < stale_cut]
    return {
        "investigation_id": inv_id,
        "window_days": since_days,
        "stale_after_days": stale_days,
        "new_known_issues": [{"id": a.id, "title": a.title, "url": a.url,
                              "review": a.review} for a in new_cves],
        "drifted_artifacts": [{"id": a.id, "title": a.title,
                               "relevance_reason": a.relevance_reason}
                              for a in drifted],
        "stale_assessments": stale,
        "catalog_drift": _catalog_drift(recs),
        "new_posture_sources": new_posture,
        "quiet": not (new_cves or drifted or stale or _catalog_drift(recs)
                      or new_posture),
        "note": "Derived from stored rows and today's catalogs. A quiet feed "
                "means nothing changed that this system can see, not that the "
                "landscape is unchanged.",
    }


def _catalog_drift(recs: list[Any]) -> list[dict[str, Any]]:
    """Rows whose stored catalog stamp differs from today's catalog."""
    out = []
    from . import threatpack
    current = threatpack.pack_fingerprint()
    for r in recs:
        stored = getattr(r, "threat_pack_fingerprint", None)
        if stored and stored != current:
            out.append({"assessment_id": r.id, "field": "threat_pack_fingerprint",
                        "stored": stored, "current": current})
    return out


def metrics(register: list[dict[str, Any]], landscape: dict[str, Any] | None = None,
            advice: dict[str, Any] | None = None,
            fresh_days: int = 90) -> dict[str, Any]:
    """The aggregates a security team actually manages by.

    No composite "AI security score". Every figure here is a count a reader can
    recompute from the register, and the ones that are unmeasurable are
    reported as unknown rather than folded into a number.
    """
    land = landscape or {}
    n = len(register)
    by_status = {s: 0 for s in STATUSES}
    for r in register:
        by_status[r.get("status") or "open"] = by_status.get(r.get("status") or "open", 0) + 1
    by_layer: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for r in register:
        by_layer[r["layer"]] = by_layer.get(r["layer"], 0) + 1
        band = ("critical" if (r.get("severity") or 0) >= 80 else
                "high" if (r.get("severity") or 0) >= 60 else
                "medium" if (r.get("severity") or 0) >= 40 else "low")
        by_severity[band] = by_severity.get(band, 0) + 1
    invs = land.get("inventory") or []
    dated = [r.get("w1_pct") for r in invs if r.get("w1_pct") is not None]
    models_w2_unknown = sum(
        1 for r in (land.get("scorecard") or [])
        if r.get("w2_unknown_dimensions"))
    models = len(invs)
    return {
        "register_total": n,
        "by_status": by_status,
        "by_layer": by_layer,
        "by_severity": by_severity,
        "pct_with_owner": _pct(sum(1 for r in register if r.get("owner")), n),
        "pct_with_review_date": _pct(sum(1 for r in register if r.get("review_by")), n),
        "pct_with_mitigation": _pct(sum(1 for r in register
                                        if r.get("mitigation_ids")), n),
        "accepted_vs_open": {"accepted": by_status.get("accepted", 0),
                             "open": by_status.get("open", 0)},
        "models_total": models,
        "pct_models_w2_known": (round(100.0 * (models - models_w2_unknown) / models, 1)
                                if models else None),
        "playbook_coverage_pct": (advice or {}).get("playbook_coverage_pct"),
        "unverified_control_claims": len((advice or {}).get("unverified_controls") or []),
        "freshness": {"threshold_days": fresh_days,
                      "note": "evidence age is reported per assessment row, not "
                              "aggregated into a single freshness score"},
    }


def _pct(num: int, den: int) -> float | None:
    """Percentage, or None when the denominator is empty.

    None, not 0 and not 100: "no risks are owned" is not 0% coverage when there
    are no risks to own, and reporting 0% would read as a failure where the
    truth is that the question does not apply.
    """
    return round(100.0 * num / den, 1) if den else None