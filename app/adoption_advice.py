"""Adoption advice: does *the organisation asking* change the answer?

``security.py`` answers "how risky is this product at exposure tier X".
``portfolio.py`` answers "what should we do about the open rows of our register".
Neither reads the *adopting organisation*: a product feature that is a
calculated risk for a retail intranet is a different proposition inside a
systemically important financial-market infrastructure, subject to DORA,
cross-border transfer rules and supervisory scrutiny. The same measured
residual, two different adoption decisions.

This module is the deterministic core of that reading. Given a user's request
(or interest) and the nature of the organisation behind it, it:

1. **profiles the organisation** -- sector, supervisory regimes, systemic role,
   data sensitivity, third-party posture, cross-border reach -- from free text,
   leaving everything it cannot read ``unknown``;
2. **profiles the interest** -- product, capabilities, and which question is
   actually being asked (security risk, fit, compliance, cost);
3. **discovers prior analyses** for the product family, so the advice *cites*
   the measured assessment (e.g. "Collibra AI Writing Assistant on Restricted
   Data") instead of inventing fresh numbers;
4. **composes a verdict** -- adopt / adopt-with-conditions / pilot-only /
   do-not-adopt / insufficient-evidence -- with the conditions that follow from
   the organisation's nature, each carrying its residual limitation.

Design rules, inherited from the rest of the system:

1. **Unknown stays unknown.** A field nobody stated is ``unknown`` and is
   reported; no default is filled in to make an organisation look assessed.
2. **Prior numbers are quoted, never re-derived.** A score here is a copy of a
   stored assessment's headline with its own method and fingerprint attached.
3. **Advice never claims "secured".** Every recommended condition carries its
   residual limitation, because a mitigation that works completely is the
   exception.
4. **No LLM is required.** The pack is complete without one; a narrative can be
   added later, it cannot be the thing that makes the advice correct.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from difflib import SequenceMatcher
from typing import Any

ADOPTION_ADVICE_ID = "akm-adoption-advice"
ADOPTION_ADVICE_VERSION = "1.1.0"

#: Change policy, enforced by tests/test_adoption_advice.py. Same rule as the
#: other catalogs: a number may not move without a version bump.
CHANGE_POLICY = {
    "major": "add/remove/rename a sector, regime or condition",
    "minor": "re-weight a scrutiny delta or a verdict band",
    "patch": "wording or label only -- no number may move",
    "version": ADOPTION_ADVICE_VERSION,
}


# --------------------------------------------------------------------------
# organisation nature: vocabulary
# --------------------------------------------------------------------------

#: Sector -> (label, scrutiny delta, match terms). The delta is how much this
#: kind of organisation raises the consequence of a given residual; it is a
#: property of the sector, not a measurement of any product.
ORG_SECTORS: dict[str, dict[str, Any]] = {
    "financial_market_infrastructure": {
        "label": (
            "financial market infrastructure (payments, clearing, "
            "settlement, messaging)"
        ),
        "delta": 0.30,
        "terms": (
            "swift",
            "financial market infrastructure",
            "market infrastructure",
            "central securities depository",
            "central securities depositor",
            "clearing house",
            "clearinghouse",
            "central counterparty",
            "settlement system",
            "payment system",
            "payment network",
            "interbank",
        ),
    },
    "banking": {
        "label": "banking / credit institution",
        "delta": 0.22,
        "terms": (
            "bank",
            "banking",
            "credit institution",
            "retail bank",
            "investment bank",
            "building society",
        ),
    },
    "insurance": {
        "label": "insurance / reinsurance",
        "delta": 0.18,
        "terms": ("insurer", "insurance", "reinsurance", "underwriter"),
    },
    "healthcare": {
        "label": "healthcare / life sciences",
        "delta": 0.22,
        "terms": (
            "hospital",
            "healthcare",
            "health care",
            "clinic",
            "patient",
            "medical",
            "life sciences",
            "pharma",
        ),
    },
    "public_sector": {
        "label": "public sector / government",
        "delta": 0.20,
        "terms": (
            "government",
            "public sector",
            "ministry",
            "agency",
            "municipal",
            "defence",
            "defense",
            "civil service",
        ),
    },
    "energy_utilities": {
        "label": "energy / utilities",
        "delta": 0.20,
        "terms": (
            "utility",
            "utilities",
            "energy grid",
            "power grid",
            "electricity",
            "oil and gas",
            "water utility",
        ),
    },
    "telecom": {
        "label": "telecommunications",
        "delta": 0.16,
        "terms": (
            "telecom",
            "telecommunications",
            "mobile network",
            "network operator",
        ),
    },
    "technology": {
        "label": "technology / software",
        "delta": 0.08,
        "terms": (
            "software company",
            "technology company",
            "tech company",
            "saas provider",
            "platform provider",
        ),
    },
    "retail": {
        "label": "retail / consumer",
        "delta": 0.05,
        "terms": ("retailer", "retail", "e-commerce", "ecommerce", "consumer goods"),
    },
}

#: Supervisory / contractual regime -> (label, delta, terms). Regimes add
#: because an obligation is a demand on the deployment, but each is capped by
#: the overall clamp so stacking catalogues cannot run the number away.
ORG_REGIMES: dict[str, dict[str, Any]] = {
    "dora": {
        "label": "EU DORA (digital operational resilience)",
        "delta": 0.15,
        "terms": ("dora", "digital operational resilience"),
    },
    "gdpr": {
        "label": "EU GDPR",
        "delta": 0.10,
        "terms": ("gdpr", "general data protection regulation"),
    },
    "nis2": {
        "label": "EU NIS2",
        "delta": 0.12,
        "terms": ("nis2", "nis 2", "network and information security directive"),
    },
    "pci_dss": {
        "label": "PCI DSS",
        "delta": 0.10,
        "terms": ("pci dss", "pci-dss", "cardholder data"),
    },
    "mifid_ii": {
        "label": "MiFID II",
        "delta": 0.12,
        "terms": ("mifid", "mifid ii", "markets in financial instruments"),
    },
    "psd2": {
        "label": "PSD2",
        "delta": 0.08,
        "terms": ("psd2", "payment services directive"),
    },
    "basel_iii": {
        "label": "Basel III / prudential",
        "delta": 0.10,
        "terms": ("basel", "prudential regulation", "capital requirements"),
    },
    "eu_ai_act": {
        "label": "EU AI Act",
        "delta": 0.10,
        "terms": ("ai act", "eu ai act"),
    },
    "hipaa": {
        "label": "HIPAA",
        "delta": 0.12,
        "terms": ("hipaa", "protected health information"),
    },
    "sox": {
        "label": "SOX / financial reporting controls",
        "delta": 0.06,
        "terms": ("sarbanes", "sox"),
    },
    "fca": {
        "label": "UK FCA",
        "delta": 0.08,
        "terms": ("fca", "financial conduct authority"),
    },
    "soc2": {"label": "SOC 2", "delta": 0.04, "terms": ("soc 2", "soc2")},
}

#: Data sensitivity, most protective first: the first match wins, so
#: "restricted/confidential" reads as restricted rather than the looser tier.
_SENSITIVITY_TERMS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("restricted", ("restricted", "top secret", "trade secret", "legal hold")),
    (
        "confidential",
        ("confidential", "proprietary", "non-public", "internal financials"),
    ),
    ("internal", ("internal data", "internal-only", "internal only")),
    ("public", ("public data", "open data", "synthetic data")),
)

_SYSTEMIC_TERMS = (
    "systemic",
    "systemically important",
    "g-sib",
    "g-sibs",
    "sifi",
    "too big to fail",
    "critical infrastructure",
    "critical national infrastructure",
    "critical function",
    "financial stability",
)

_PII_TERMS = (
    "personal data",
    "pii",
    "personal information",
    "personally identifiable",
    "customer data",
    "patient data",
    "employee data",
)

_SECRETS_TERMS = ("credential", "secret", "api key", "private key", "password", "token")

_CROSS_BORDER_TERMS = (
    "cross-border",
    "cross border",
    "crossborder",
    "multi-jurisdiction",
    "multijurisdiction",
    "data transfer",
    "transfer mechanism",
    "schrems",
    "standard contractual clauses",
    "sccs",
    "offshore",
)

_THIRD_PARTY_TERMS = (
    "third party",
    "third-party",
    "thirdparty",
    "subprocessor",
    "sub-processor",
    "outsourc",
    "saas",
    "cloud provider",
    "external model",
    "api provider",
    "vendor",
    "supplier",
)

_JURISDICTIONS: dict[str, tuple[str, ...]] = {
    "eu": ("eu", "european union", "eea"),
    "uk": ("uk", "united kingdom", "britain"),
    "us": ("us", "united states", "usa"),
    "singapore": ("singapore",),
    "switzerland": ("switzerland",),
    "india": ("india",),
}

#: Org-nature fields whose absence changes the number or the conditions. Every
#: unknown is listed; only these justify a sentence in the pack, because a pack
#: that opens with a wall of blanks gets read once and ignored.
MATERIAL_ORG_UNKNOWN = ("sector", "systemic", "data_sensitivity")


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------


def _norm_key(value: Any) -> str:
    """A vocabulary key from free text: lowercase, alnum runs joined by ``_``."""
    return "_".join(re.findall(r"[a-z0-9]+", str(value or "").lower()))


def _as_list(value: Any) -> list[Any]:
    if value is None or value == "":
        return []
    if isinstance(value, list | tuple | set):
        return [v for v in value if v not in (None, "")]
    return [value]


def _flag(value: Any) -> bool | None:
    """A yes/no that is allowed to stay unknown. Never invents a value."""
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


def _hit(blob: str, terms: tuple[str, ...]) -> str:
    """The first term present as a whole word, else ``""``."""
    for term in terms:
        if re.search(r"\b" + re.escape(term) + r"\b", blob):
            return term
    return ""


def _load(raw: Any, default: Any = None) -> Any:
    if raw is None:
        return default
    if isinstance(raw, dict | list):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return default


# --------------------------------------------------------------------------
# organisation profile
# --------------------------------------------------------------------------


def profile_organisation(
    text: str = "",
    *,
    sector: Any = None,
    regime: Any = None,
    systemic: Any = None,
    data_sensitivity: Any = None,
    jurisdiction: Any = None,
    cross_border: Any = None,
    third_party_reliance: Any = None,
    obligations: Any = None,
) -> dict[str, Any]:
    """Read the nature of the organisation from a request, with explicit
    overrides.

    Explicit fields win over text: a caller that knows the sector should not
    have its answer changed by a stray word in a brief. Everything not read and
    not stated stays ``None``/``unknown``.
    """
    blob = str(text or "").lower()
    signals: list[str] = []

    # -- sector ------------------------------------------------------------
    sec = _norm_key(sector) if sector not in (None, "") else ""
    sec = sec if sec in ORG_SECTORS else ""
    if not sec:
        for sid, meta in ORG_SECTORS.items():
            term = _hit(blob, meta["terms"])
            if term:
                sec = sid
                signals.append(f"sector={sid} (from '{term}')")
                break

    # -- supervisory regimes ----------------------------------------------
    regs: set[str] = set()
    for item in _as_list(regime):
        key = _norm_key(item)
        if key in ORG_REGIMES:
            regs.add(key)
        else:
            for rid, meta in ORG_REGIMES.items():
                if key and (
                    key in _norm_key(meta["label"]) or _hit(key, meta["terms"])
                ):
                    regs.add(rid)
    if not regs:
        for rid, meta in ORG_REGIMES.items():
            term = _hit(blob, meta["terms"])
            if term:
                regs.add(rid)
                signals.append(f"regime={rid} (from '{term}')")

    # -- systemic role -----------------------------------------------------
    sys_flag = _flag(systemic)
    if sys_flag is None:
        term = _hit(blob, _SYSTEMIC_TERMS)
        if term:
            sys_flag = True
            signals.append(f"systemic (from '{term}')")

    # -- data sensitivity --------------------------------------------------
    sens = _norm_key(data_sensitivity) if data_sensitivity not in (None, "") else ""
    sens = sens if sens in {s for s, _ in _SENSITIVITY_TERMS} else ""
    if not sens:
        for level, terms in _SENSITIVITY_TERMS:
            term = _hit(blob, terms)
            if term:
                sens = level
                signals.append(f"data_sensitivity={level} (from '{term}')")
                break
    pii_term = _hit(blob, _PII_TERMS)
    secrets_term = _hit(blob, _SECRETS_TERMS)
    if pii_term:
        signals.append(f"personal data (from '{pii_term}')")
    if secrets_term:
        signals.append(f"secrets (from '{secrets_term}')")

    # -- jurisdiction / cross-border --------------------------------------
    juris = str(jurisdiction or "").strip().lower() or None
    if not juris:
        for jid, terms in _JURISDICTIONS.items():
            term = _hit(blob, terms)
            if term:
                juris = jid
                signals.append(f"jurisdiction={jid} (from '{term}')")
                break
    xborder = _flag(cross_border)
    if xborder is None:
        term = _hit(blob, _CROSS_BORDER_TERMS)
        if term:
            xborder = True
            signals.append(f"cross-border (from '{term}')")

    # -- third-party posture ----------------------------------------------
    third = _flag(third_party_reliance)
    if third is None:
        term = _hit(blob, _THIRD_PARTY_TERMS)
        if term:
            third = True
            signals.append(f"third-party reliance (from '{term}')")

    obligations_out = [str(o).strip() for o in _as_list(obligations) if str(o).strip()]
    for rid in sorted(regs):
        label = ORG_REGIMES[rid]["label"]
        if label not in obligations_out:
            obligations_out.append(label)

    out: dict[str, Any] = {
        "sector": sec or None,
        "sector_label": ORG_SECTORS[sec]["label"] if sec else "unstated",
        "regimes": sorted(regs),
        "systemic": sys_flag,
        "data_sensitivity": sens or None,
        "pii": True if pii_term else None,
        "secrets": True if secrets_term else None,
        "jurisdiction": juris,
        "cross_border": xborder,
        "third_party_reliance": third,
        "obligations": obligations_out,
        "signals": signals,
    }
    missing = [f for f in MATERIAL_ORG_UNKNOWN if out.get(f) in (None, "")]
    out["unknown_fields"] = missing
    out["material_unknown"] = missing
    out["tags"] = _org_tags(out)
    out["summary"] = _org_summary(out)
    return out


def _org_tags(org: dict[str, Any]) -> list[str]:
    tags: set[str] = set()
    if org.get("sector"):
        tags.add(org["sector"])
    tags.update(org.get("regimes") or [])
    if org.get("systemic"):
        tags.add("systemic")
    if org.get("cross_border"):
        tags.add("cross_border")
    if org.get("third_party_reliance"):
        tags.add("third_party")
    if org.get("pii"):
        tags.add("personal_data")
    if org.get("secrets"):
        tags.add("secrets")
    if org.get("data_sensitivity"):
        tags.add(f"{org['data_sensitivity']}_data")
    return sorted(tags)


def _org_summary(org: dict[str, Any]) -> str:
    bits = [org.get("sector_label") or "unstated sector"]
    if org.get("systemic"):
        bits.append("systemically important / critical function")
    if org.get("regimes"):
        bits.append(
            "subject to " + ", ".join(ORG_REGIMES[r]["label"] for r in org["regimes"])
        )
    if org.get("data_sensitivity"):
        bits.append(f"{org['data_sensitivity']} data")
    if org.get("cross_border"):
        bits.append("cross-border processing")
    return "; ".join(bits)


def organisation_scrutiny(org: dict[str, Any]) -> dict[str, Any]:
    """How the organisation's nature scales the consequence of a residual.

    Org nature only ever *raises* the bar: unlike a situation profile there are
    no controls here to lower it. The multiplier is clamped because a stack of
    catalogues is not proportional evidence of operational impact.
    """
    factors: list[dict[str, Any]] = []
    if org.get("sector"):
        meta = ORG_SECTORS[org["sector"]]
        factors.append(
            {"factor": meta["label"], "delta": meta["delta"], "kind": "sector"}
        )
    if org.get("systemic"):
        factors.append(
            {
                "factor": "systemically important / critical function",
                "delta": 0.25,
                "kind": "systemic",
            }
        )
    for rid in org.get("regimes") or []:
        factors.append(
            {
                "factor": ORG_REGIMES[rid]["label"],
                "delta": ORG_REGIMES[rid]["delta"],
                "kind": "regime",
            }
        )
    sens = org.get("data_sensitivity")
    if sens in ("restricted", "regulated_pii"):
        factors.append(
            {"factor": f"{sens} data in scope", "delta": 0.20, "kind": "data"}
        )
    elif sens == "confidential":
        factors.append(
            {"factor": "confidential data in scope", "delta": 0.10, "kind": "data"}
        )
    if org.get("secrets"):
        factors.append(
            {"factor": "credentials/secrets in scope", "delta": 0.15, "kind": "data"}
        )
    elif org.get("pii"):
        factors.append(
            {"factor": "personal data in scope", "delta": 0.10, "kind": "data"}
        )
    if org.get("cross_border"):
        factors.append(
            {"factor": "cross-border processing", "delta": 0.10, "kind": "transfer"}
        )
    if org.get("third_party_reliance"):
        factors.append(
            {"factor": "third-party reliance", "delta": 0.05, "kind": "supply_chain"}
        )
    total = 1.0 + sum(f["delta"] for f in factors)
    mult = round(max(1.0, min(1.8, total)), 3)
    if mult >= 1.45:
        band = "high"
    elif mult >= 1.15:
        band = "medium"
    else:
        band = "low"
    return {
        "multiplier": mult,
        "band": band,
        "factors": factors,
        "material_unknown": org.get("material_unknown") or [],
    }


# --------------------------------------------------------------------------
# interest profile
# --------------------------------------------------------------------------

#: Generic words that must never be mistaken for a product name when tokens are
#: mined out of a request.
_PRODUCT_STOPWORDS = {
    "the",
    "and",
    "for",
    "with",
    "from",
    "that",
    "this",
    "what",
    "when",
    "into",
    "using",
    "used",
    "use",
    "like",
    "plan",
    "plans",
    "planning",
    "tool",
    "tools",
    "feature",
    "features",
    "assistant",
    "report",
    "reports",
    "advice",
    "adopt",
    "adoption",
    "evaluate",
    "evaluating",
    "organisation",
    "organisations",
    "organization",
    "organizations",
    "company",
    "looking",
    "specifically",
    "leverage",
    "leverages",
    "leveraging",
    "risk",
    "risks",
    "security",
    "data",
    "provide",
    "would",
    "could",
    "should",
    "about",
    "them",
    "their",
}

#: Nouns that mark the word before them as naming a product ("colibra tools",
#: "the Foo platform"). Used only to choose *which* query token to treat as the
#: product when nothing explicit or stored was found -- never to invent one.
_PRODUCT_NOUNS = {
    "tool",
    "tools",
    "feature",
    "features",
    "product",
    "products",
    "platform",
    "platforms",
    "assistant",
    "assistants",
    "app",
    "apps",
    "application",
    "applications",
    "software",
    "service",
    "services",
    "suite",
    "suites",
    "solution",
    "solutions",
    "model",
    "models",
    "system",
    "systems",
    "widget",
    "agent",
    "bot",
}

#: Verbs that mark the word after them as the thing being adopted ("adopt
#: Collibra", "onboarding the Foo"). Same caveat as ``_PRODUCT_NOUNS``.
_ADOPTION_VERBS = {
    "adopt",
    "adopting",
    "onboard",
    "onboarding",
    "deploy",
    "deploying",
    "use",
    "using",
    "evaluate",
    "evaluating",
    "trial",
    "piloting",
    "integrate",
    "integrating",
}


_QUESTION_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "security_risk",
        (
            "security risk",
            "security",
            "threat",
            "risk",
            "leak",
            "leakage",
            "breach",
            "attack",
            "misuse",
        ),
    ),
    (
        "compliance",
        (
            "compliance",
            "compliant",
            "regulat",
            "audit",
            "dora",
            "gdpr",
            "nis2",
            "ai act",
            "supervis",
        ),
    ),
    (
        "adoption_fit",
        (
            "adopt",
            "adoption",
            "onboard",
            "roll out",
            "rollout",
            "implement",
            "integrate",
            "introduce",
            "deploy",
        ),
    ),
    ("cost", ("cost", "licence", "license", "price", "pricing", "budget")),
)

_CAPABILITY_TERMS: tuple[tuple[str, str], ...] = (
    ("writing assistant", "ai_writing_assistant"),
    ("catalog", "data_catalog"),
    ("lineage", "data_lineage"),
    ("glossary", "business_glossary"),
    ("governance", "data_governance"),
    ("quality", "data_quality"),
    ("privacy", "privacy"),
    ("policy", "policy_management"),
    ("workflow", "workflow"),
    ("metadata", "metadata"),
    ("search", "search"),
    ("steward", "stewardship"),
)


def profile_interest(
    text: str = "", *, product: Any = None, capability: Any = None
) -> dict[str, Any]:
    """Read what the user wants and about which product.

    ``product`` may be supplied explicitly; when it is not, significant tokens
    are mined from the text as fuzzy candidates -- discovery matches them
    against stored analyses case-insensitively, so a lower-case or slightly
    misspelled vendor name ("colibra") can still find its prior analysis.
    """
    blob = str(text or "").lower()
    signals: list[str] = []

    caps = [canon for term, canon in _CAPABILITY_TERMS if term in blob]
    explicit_caps = [str(c).strip() for c in _as_list(capability) if str(c).strip()]
    capabilities = sorted(dict.fromkeys(explicit_caps + caps))

    question = None
    for key, terms in _QUESTION_RULES:
        term = next((t for t in terms if t in blob), "")
        if term:
            question = key
            signals.append(f"question={key} (from '{term}')")
            break

    candidates = _product_tokens(text)
    if product:
        candidates = sorted(set(candidates) | set(_product_tokens(product)))

    out = {
        "product": str(product).strip() if product else None,
        "capabilities": capabilities,
        "question": question,
        "product_candidates": candidates,
        "signals": signals,
    }
    bits = []
    if out["product"]:
        bits.append(out["product"])
    if capabilities:
        bits.append("capabilities: " + ", ".join(capabilities))
    if question:
        bits.append(question.replace("_", " "))
    out["summary"] = " · ".join(bits) if bits else "interest not identified"
    return out


def _product_tokens(text: Any) -> list[str]:
    """Significant tokens of a text, as fuzzy product-name candidates."""
    toks = re.findall(r"[a-z0-9]+", str(text or "").lower())
    seen: list[str] = []
    for t in toks:
        if len(t) >= 4 and t not in _PRODUCT_STOPWORDS and t not in seen:
            seen.append(t)
    return seen


def _best_product_candidate(text: Any, candidates: list[str]) -> str | None:
    """The query token that most plausibly names the product, in original case.

    Only a candidate sitting next to a product noun ("colibra tools") or right
    after an adoption verb ("adopt Collibra") qualifies. When nothing qualifies,
    ``None`` is returned and the verdict keeps saying the product was not
    identified -- a stray significant word ("tell me about governance") must not
    be promoted into a product name.
    """
    words = re.findall(r"[A-Za-z0-9]+", str(text or ""))
    low = [w.lower() for w in words]
    wanted = {str(c).lower() for c in candidates}
    for i, w in enumerate(low):
        if w not in wanted:
            continue
        nxt = low[i + 1] if i + 1 < len(low) else ""
        prv = low[i - 1] if i >= 1 else ""
        if nxt in _PRODUCT_NOUNS or prv in _ADOPTION_VERBS:
            return words[i]
    return None


def _similar(a: str, b: str) -> bool:
    """Whether two tokens plausibly name the same thing.

    Case is already handled (both lower-cased). Substring containment catches
    "collibra" vs "collibra ai"; a sequence ratio near 1 catches a one-character
    typo like "colibra" vs "collibra" without matching unrelated words.
    """
    if a == b:
        return True
    if len(a) >= 5 and len(b) >= 5 and (a in b or b in a):
        return True
    return SequenceMatcher(None, a, b).ratio() >= 0.85


def _tokens_match(a: list[str], b: list[str]) -> bool:
    return any(_similar(x, y) for x in a for y in b)


# --------------------------------------------------------------------------
# prior analyses
# --------------------------------------------------------------------------


def _exposure_label(exposure: Any) -> str:
    fallback = {
        "restricted_data": "Restricted data",
        "confidential_data": "Confidential data",
        "internal": "Internal",
        "public": "Public",
    }
    try:
        from .security import EXPOSURE_META

        return EXPOSURE_META.get(exposure, {}).get("label") or str(exposure)
    except Exception:
        return fallback.get(str(exposure), str(exposure))


def _blockers(threats: Any, scoring: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for t in threats or []:
        if not isinstance(t, dict):
            continue
        rs = t.get("residual_score")
        sev = str(t.get("residual_severity") or "").lower()
        if (isinstance(rs, int | float) and rs >= 75) or sev in ("high", "critical"):
            out.append(
                {
                    "id": t.get("id"),
                    "title": t.get("title"),
                    "residual_score": rs,
                    "severity": sev or None,
                }
            )
    w2 = (scoring or {}).get("w2") or {}
    for d in w2.get("rated") or []:
        if str(d.get("rating") or "").lower() in ("high", "critical"):
            out.append(
                {
                    "id": d.get("dimension"),
                    "title": d.get("dimension"),
                    "severity": d.get("rating"),
                }
            )
    return out


def _score_meaning(pct: Any) -> str:
    if pct is None:
        return "no headline score stored"
    if pct >= 75:
        return "HIGH -- do not adopt for this data tier without the conditions below"
    if pct >= 50:
        return "ELEVATED -- adopt only with guardrails and review"
    if pct >= 30:
        return "MODERATE -- standard hardening sufficient"
    return "LOW -- routine controls sufficient"


def _analysis_row(
    rec: Any, inv_title: str, matched_on: str, same_investigation: bool
) -> dict[str, Any]:
    scoring = _load(getattr(rec, "scoring_json", None), {}) or {}
    threats = _load(getattr(rec, "threats_json", None), []) or []
    headline = (
        rec.residual_pct
        if getattr(rec, "residual_pct", None) is not None
        else getattr(rec, "overall_pct", None)
    )
    label = _exposure_label(getattr(rec, "exposure", None))
    title = inv_title or f"{rec.product_name or 'Target product'} on {label}"
    return {
        "assessment_id": getattr(rec, "id", None),
        "investigation_id": getattr(rec, "investigation_id", None),
        "investigation_title": inv_title or None,
        "title": title,
        "product_name": getattr(rec, "product_name", None),
        "exposure": getattr(rec, "exposure", None),
        "exposure_label": label,
        "assessment_path": scoring.get("assessment_path") or "standard",
        "overall_pct": getattr(rec, "overall_pct", None),
        "residual_pct": getattr(rec, "residual_pct", None),
        "headline_pct": headline,
        "score_meaning": _score_meaning(headline),
        "posture": getattr(rec, "posture", None) or "",
        "threats": len(threats),
        "blockers": _blockers(threats, scoring),
        "pack_version": getattr(rec, "threat_pack_version", None),
        "pack_fingerprint": getattr(rec, "threat_pack_fingerprint", None),
        "matched_on": matched_on,
        "same_investigation": bool(same_investigation),
        "created_at": str(getattr(rec, "created_at", "") or ""),
    }


def find_prior_analyses(
    db: Any, product: Any, *, investigation_id: int | None = None, limit: int = 8
) -> list[dict[str, Any]]:
    """Existing analyses that bear on a product, newest first.

    Matching is deliberately fuzzy so a user can name an analysis the way a
    person would -- "the Collibra AI Writing Assistant on Restricted Data
    report" -- and have the stored row found even if the request lower-cases or
    slightly misspells the vendor. A row matches if it shares a significant
    token with the product through its family, its product name, or its
    investigation title.
    """
    from .models import Investigation, SecurityAssessment

    if isinstance(product, list | tuple | set):
        probe = _product_tokens(" ".join(str(p) for p in product))
    else:
        probe = _product_tokens(product)
    if not probe:
        return []
    inv_titles = {i.id: (i.title or "") for i in db.query(Investigation).all()}
    recs = (
        db.query(SecurityAssessment)
        .order_by(SecurityAssessment.created_at.desc())
        .limit(400)
        .all()
    )
    out: list[dict[str, Any]] = []
    for rec in recs:
        family = getattr(rec, "product_family", None) or ""
        matched = ""
        if family and _tokens_match(probe, _product_tokens(family)):
            matched = "product_family"
        elif _tokens_match(probe, _product_tokens(rec.product_name or "")):
            matched = "product_name"
        else:
            title = inv_titles.get(rec.investigation_id, "")
            if _tokens_match(probe, _product_tokens(title)):
                matched = "investigation_title"
        if not matched:
            continue
        out.append(
            _analysis_row(
                rec,
                inv_titles.get(rec.investigation_id, ""),
                matched,
                same_investigation=(rec.investigation_id == investigation_id),
            )
        )
    out.sort(key=lambda a: a.get("created_at") or "", reverse=True)
    out.sort(key=lambda a: a["same_investigation"], reverse=True)
    return out[:limit]


# --------------------------------------------------------------------------
# conditions
# --------------------------------------------------------------------------


def _conditions(
    org: dict[str, Any], *, product_risk_pct: float | None
) -> list[dict[str, Any]]:
    """Conditions the organisation's nature demands, each with its residual.

    Conditions are deterministic functions of the profile, not of an LLM. A
    condition is proposed when the profile makes it material; its residual
    limitation travels with it, because "we added DLP" is not "we are safe".
    """
    sens = org.get("data_sensitivity")
    regimes = set(org.get("regimes") or [])
    out: list[dict[str, Any]] = []

    def add(cid: str, title: str, why: str, residual: str, source: str) -> None:
        out.append(
            {
                "id": cid,
                "title": title,
                "why": why,
                "residual_limitation": residual,
                "source": source,
            }
        )

    if sens in ("restricted", "confidential"):
        add(
            "AA01",
            "Classification gate and allow-list before the surface",
            f"{sens} content may reach the model output, so the input surface "
            "must be restricted to classified, allow-listed material.",
            "A gate is only as good as the labels it reads; one misclassified "
            "input defeats it.",
            "organisation nature",
        )
        add(
            "AA09",
            "DLP and egress allow-list on prompts and responses",
            "Confidentiality loss is the primary failure mode at this tier.",
            "DLP misses paraphrased secrets and novel formats; it reduces, "
            "never eliminates, leakage.",
            "organisation nature",
        )
    if org.get("secrets"):
        add(
            "AA02",
            "Broker credentials; never let the assistant hold them",
            "Secrets are reachable from the surface, so they will be pasted.",
            "A broker bounds exposure but does not stop a user pasting a "
            "secret it should never have seen.",
            "organisation nature",
        )
    if org.get("pii") or regimes & {"gdpr", "hipaa", "eu_ai_act"}:
        add(
            "AA07",
            "DPIA / data-protection assessment before production",
            "Personal data processing triggers a documented assessment.",
            "A DPIA records a decision; it is not itself a control.",
            "organisation nature",
        )
    if org.get("cross_border") or org.get("jurisdiction"):
        add(
            "AA03",
            "Residency and transfer mechanism pinned in contract " "and config",
            "Processing crosses a border, so location and transfer basis must "
            "be fixed, not assumed.",
            "Residency attestations often omit backup, replication and "
            "support-access regions.",
            "organisation nature",
        )
    if org.get("third_party_reliance") or org.get("secrets") or sens:
        add(
            "AA04",
            "No-train and zero-retention terms, evidenced not declared",
            "A third party receives the data, so retention and training use "
            "must be contractually barred and technically confirmed.",
            "A no-train clause does not prove deletion, nor stop on-path "
            "logging by a subcontractor.",
            "organisation nature",
        )
    if (
        org.get("systemic")
        or org.get("sector") in ("financial_market_infrastructure", "banking")
        or "dora" in regimes
    ):
        add(
            "AA05",
            "Resilience, exit plan and concentration limits (DORA-style)",
            "A critical function cannot depend on a supplier it cannot leave.",
            "An exit plan untested at scale is a document, not resilience.",
            "organisation nature",
        )
        add(
            "AA10",
            "Supervisory audit trail and incident reporting path",
            "Supervisors will ask who did what and when.",
            "An audit trail proves an action occurred, not that it was " "appropriate.",
            "organisation nature",
        )
    if sens == "restricted" or org.get("systemic"):
        add(
            "AA06",
            "Human review in the loop for restricted outputs",
            "At this consequence, an unreviewed output is not acceptable.",
            "Review degrades to rubber-stamping as volume grows.",
            "organisation nature",
        )
    add(
        "AA08",
        "Least-privilege roles and SSO-bound access",
        "The surface must not exceed the user's own entitlements.",
        "Role drift and shared accounts quietly exceed the intended boundary.",
        "baseline",
    )
    add(
        "AA11",
        "Logging and provenance on every model interaction",
        "Without a record, neither misuse nor benefit is provable.",
        "Logs prove the interaction happened, not that it was appropriate.",
        "baseline",
    )
    if product_risk_pct is not None and product_risk_pct >= 50:
        add(
            "AA12",
            "Staged rollout behind a bounded pilot with stop criteria",
            f"The measured residual ({product_risk_pct:g}/100) does not "
            "support an unbounded production launch.",
            "A pilot ticks a box unless it has a pre-agreed abort threshold.",
            "prior analysis",
        )
    return out


# --------------------------------------------------------------------------
# verdict
# --------------------------------------------------------------------------

_VERDICT_LABELS = {
    "adopt": "Adopt -- with the baseline conditions",
    "adopt_with_conditions": "Adopt only with the conditions below",
    "pilot_only": "Bounded pilot only -- not production at this profile",
    "do_not_adopt": "Do not adopt at this organisation profile without change",
    "insufficient_evidence": "Insufficient evidence to advise adoption",
}


def _verdict(
    product_name: str | None,
    product_risk_pct: float | None,
    pressure: float | None,
    blockers: list[dict[str, Any]],
    org: dict[str, Any],
    has_prior: bool,
    product_from: str | None = None,
) -> dict[str, Any]:
    if not product_name:
        return {
            "key": "insufficient_evidence",
            "label": _VERDICT_LABELS["insufficient_evidence"],
            "why": "No product or capability was identified, so there is "
            "nothing to advise adopting.",
        }
    if not has_prior:
        if product_from == "query_candidate":
            return {
                "key": "insufficient_evidence",
                "label": _VERDICT_LABELS["insufficient_evidence"],
                "why": f"No prior assessment for {product_name} (read from the "
                "request) was found, so the product's residual risk is unknown. "
                "Absence of evidence is not evidence of safety: confirm the "
                "product and assess it before adopting.",
            }
        return {
            "key": "insufficient_evidence",
            "label": _VERDICT_LABELS["insufficient_evidence"],
            "why": f"No prior assessment for {product_name} was found, so "
            "the product's residual risk is unknown. Absence of "
            "evidence is not evidence of safety: assess before "
            "adopting.",
        }
    if (
        blockers
        or (product_risk_pct is not None and product_risk_pct >= 75)
        or (pressure is not None and pressure >= 75)
    ):
        why = (
            "The organisation profile raises the consequence of an already "
            "material residual"
            if not blockers
            else "High-or-critical items remain after controls"
        )
        return {
            "key": "do_not_adopt",
            "label": _VERDICT_LABELS["do_not_adopt"],
            "why": why + ".",
        }
    if pressure is not None and pressure >= 50:
        return {
            "key": "pilot_only",
            "label": _VERDICT_LABELS["pilot_only"],
            "why": "Organisation scrutiny scales the residual into "
            "elevated territory; a bounded pilot is the most that "
            "is defensible today.",
        }
    if pressure is not None and pressure >= 30:
        return {
            "key": "adopt_with_conditions",
            "label": _VERDICT_LABELS["adopt_with_conditions"],
            "why": "The residual is moderate once the organisation's "
            "nature is applied; the conditions below are the price "
            "of adoption.",
        }
    if org.get("material_unknown"):
        return {
            "key": "adopt_with_conditions",
            "label": _VERDICT_LABELS["adopt_with_conditions"],
            "why": "The measured residual is low, but the organisation's "
            "nature is partly unstated; confirm the missing fields "
            "before treating this as a clearance.",
        }
    return {
        "key": "adopt",
        "label": _VERDICT_LABELS["adopt"],
        "why": "The measured residual is low and the organisation profile "
        "does not raise it; baseline conditions apply.",
    }


# --------------------------------------------------------------------------
# pack
# --------------------------------------------------------------------------


def adoption_advice(
    db: Any = None,
    *,
    query: str = "",
    organisation: dict[str, Any] | None = None,
    product: str | None = None,
    capability: Any = None,
    exposure: str | None = None,
    investigation_id: int | None = None,
    prior_analyses: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Evaluate a request against the nature of the organisation asking.

    ``db`` is optional: without it no prior analyses are discovered and the
    verdict is ``insufficient_evidence`` whenever the product is unknown, which
    is the honest answer when nothing was looked up. ``prior_analyses`` lets a
    caller that already holds the rows pass them in (and lets tests stay
    database-free).
    """
    overrides = {
        k: v
        for k, v in (organisation or {}).items()
        if k
        in (
            "sector",
            "regime",
            "systemic",
            "data_sensitivity",
            "jurisdiction",
            "cross_border",
            "third_party_reliance",
            "obligations",
        )
    }
    org = profile_organisation(query, **overrides)
    interest = profile_interest(query, product=product, capability=capability)

    candidates: list[str] = []
    if product:
        candidates.append(product)
    candidates.extend(interest.get("product_candidates") or [])
    if prior_analyses is not None:
        prior = list(prior_analyses)
    elif db is not None and candidates:
        prior = find_prior_analyses(db, candidates, investigation_id=investigation_id)
    else:
        prior = []

    primary = prior[0] if prior else None
    product_name = (
        (str(product).strip() if product else None)
        or (primary or {}).get("product_name")
        or interest.get("product")
    )
    # Nothing explicit and nothing stored matched, but the request itself may
    # name the product ("adoption advice for colibra tools"). Promote that token
    # so the verdict can say *which* thing has no assessment, rather than
    # claiming nothing was identified. Stray significant words are not promoted.
    if product_name is None and not prior:
        product_name = _best_product_candidate(query, candidates)

    if product:
        product_from = "explicit"
    elif primary:
        product_from = "prior_analysis"
    elif product_name:
        product_from = "query_candidate"
    else:
        product_from = None

    risk_values = [
        a["headline_pct"] for a in prior if a.get("headline_pct") is not None
    ]
    product_risk_pct = max(risk_values) if risk_values else None

    blockers: list[dict[str, Any]] = []
    for a in prior:
        for b in a.get("blockers") or []:
            if b not in blockers:
                blockers.append(b)

    scrutiny = organisation_scrutiny(org)
    pressure = (
        round(min(100.0, product_risk_pct * scrutiny["multiplier"]), 1)
        if product_risk_pct is not None
        else None
    )

    verdict = _verdict(
        product_name,
        product_risk_pct,
        pressure,
        blockers,
        org,
        bool(prior),
        product_from,
    )
    conditions = _conditions(org, product_risk_pct=product_risk_pct)

    gaps: list[str] = []
    if product_name and not prior:
        gaps.append(
            f"No stored analysis for '{product_name}'; run a security "
            "assessment before relying on this pack."
        )
    if org.get("material_unknown"):
        gaps.append(
            "Organisation nature unstated: "
            + ", ".join(org["material_unknown"])
            + " -- the conditions above are conditional on these."
        )
    if exposure and not prior:
        gaps.append(
            f"Exposure tier supplied ({exposure}) but no assessment was "
            "found to measure it."
        )
    for b in blockers[:5]:
        gaps.append(
            f"Residual blocker {b.get('id')}: {b.get('title')}"
            + (
                f" ({b.get('residual_score')}/100)"
                if b.get("residual_score") is not None
                else ""
            )
        )

    limitations = [
        "This pack is deterministic and organisation-aware; it is not a "
        "control-level assessment and does not replace one.",
        "The organisation's nature is read from the request text and any "
        "explicit fields; unstated fields are treated as unstated.",
        "Prior-analysis numbers are quoted from stored rows, not re-derived, "
        "and move only when those rows do.",
        "No condition here is a clean bill of health; each carries the "
        "limitation that remains when it is in place.",
    ]

    pack: dict[str, Any] = {
        "method": "adoption_advice_v1",
        "version": ADOPTION_ADVICE_VERSION,
        "fingerprint": adoption_advice_fingerprint(),
        "generated_at": datetime.now(UTC).isoformat(),
        "query": query,
        "organisation": org,
        "interest": interest,
        "product": product_name,
        "product_from": product_from,
        "exposure": exposure,
        "scrutiny": scrutiny,
        "prior_analyses": prior,
        "primary_analysis": primary,
        "product_risk_pct": product_risk_pct,
        "adoption_pressure_pct": pressure,
        "blockers": blockers,
        "verdict": verdict,
        "conditions": conditions,
        "amplifiers": scrutiny["factors"],
        "gaps": gaps,
        "limitations": limitations,
    }
    pack["markdown"] = render_adoption_advice_markdown(pack)
    return pack


def render_adoption_advice_markdown(pack: dict[str, Any]) -> str:
    """Markdown rendering of an adoption-advice pack."""
    org = pack.get("organisation") or {}
    product = pack.get("product") or "the requested capability"
    L: list[str] = []
    A = L.append

    A(f"# Adoption advice — {product}")
    A("")
    A(
        f"_Organisation:_ {org.get('summary') or 'unstated'} · "
        f"_Question:_ {(pack.get('interest') or {}).get('question') or 'unstated'} "
        f"· _Method:_ {pack['method']} v{pack['version']} "
        f"(`{pack['fingerprint']}`) · _Generated:_ "
        f"{str(pack.get('generated_at') or '')[:19]} UTC"
    )
    if pack.get("product_from") == "query_candidate":
        A("")
        A(
            f"> **{product}** was read from your request, not named "
            "explicitly; confirm the product before acting on this advice."
        )
    A("")
    A("---")
    A("")

    A("## Verdict")
    A("")
    v = pack["verdict"]
    A(f"**{v['label']}.** {v['why']}")
    A("")
    if pack.get("product_risk_pct") is not None:
        A(
            f"Measured residual (worst prior analysis): "
            f"{pack['product_risk_pct']:g}/100 · "
            f"organisation scrutiny ×{pack['scrutiny']['multiplier']:g} "
            f"({pack['scrutiny']['band']}) · adoption pressure "
            f"{pack['adoption_pressure_pct']:g}/100."
        )
    else:
        A(
            "No measured residual is available, so no adoption pressure was "
            "computed. The verdict rests on that absence."
        )
    A("")

    A("## Organisation nature")
    A("")
    A("| Field | Reading |")
    A("|---|---|")
    A(f"| Sector | {org.get('sector_label') or 'unstated'} |")
    A(f"| Systemically important | " f"{_tri_text(org.get('systemic'))} |")
    A(f"| Data sensitivity | {org.get('data_sensitivity') or 'unstated'} |")
    A(
        f"| Supervisory regimes | "
        f"{', '.join(org.get('regimes') or []) or 'unstated'} |"
    )
    A(f"| Jurisdiction | {org.get('jurisdiction') or 'unstated'} |")
    A(f"| Cross-border | {_tri_text(org.get('cross_border'))} |")
    A(f"| Third-party reliance | " f"{_tri_text(org.get('third_party_reliance'))} |")
    if org.get("material_unknown"):
        A("")
        A(
            f"**Material unknowns:** {', '.join(org['material_unknown'])}. The "
            "conditions below are conditional on these."
        )
    A("")

    A("## Why the organisation raises the bar")
    A("")
    if pack.get("amplifiers"):
        A("| Factor | Δ scrutiny |")
        A("|---|---|")
        for f in pack["amplifiers"]:
            A(f"| {f['factor']} | +{f['delta']:g} |")
    else:
        A(
            "No amplifying factors were read from the profile, which is itself "
            "an unstated-nature result rather than a clean bill of health."
        )
    A("")

    A("## Referenced prior analysis")
    A("")
    priors = pack.get("prior_analyses") or []
    if priors:
        A("The advice below quotes, and does not re-derive, these stored " "results.")
        A("")
        A("| Analysis | Product | Exposure | Residual | Posture | Matched on |")
        A("|---|---|---|---|---|---|")
        for a in priors:
            res = (
                f"{a['headline_pct']:g}/100"
                if a.get("headline_pct") is not None
                else "—"
            )
            A(
                f"| {a['title']} | {a.get('product_name') or '—'} | "
                f"{a.get('exposure_label') or '—'} | {res} | "
                f"{a.get('posture') or a.get('score_meaning') or '—'} | "
                f"{a.get('matched_on')} |"
            )
    else:
        A(
            "No stored analysis matched the request, so this pack advises on the "
            "organisation's nature alone and cannot speak to the product's "
            "measured residual."
        )
        if pack.get("interest", {}).get("product_candidates"):
            A("")
            A(
                "Candidate terms searched: "
                + ", ".join(pack["interest"]["product_candidates"])
                + "."
            )
    A("")

    A("## Conditions")
    A("")
    A("Each condition names what it buys and what remains when it is in place.")
    A("")
    A("| # | Condition | Why | Residual limitation | Source |")
    A("|---|---|---|---|---|")
    for c in pack.get("conditions") or []:
        A(
            f"| {c['id']} | {c['title']} | {c['why']} | "
            f"{c['residual_limitation']} | {c['source']} |"
        )
    A("")

    if pack.get("gaps"):
        A("## What is missing")
        A("")
        for g in pack["gaps"]:
            A(f"- {g}")
        A("")

    A("## Limitations")
    A("")
    for line in pack.get("limitations") or []:
        A(f"- {line}")
    A("")
    A("---")
    A(
        "*Organisation nature scales consequence, it does not measure the "
        "product. The product numbers are quoted; the conditions are the part "
        "you can act on, and each keeps its residual.*"
    )
    return "\n".join(L)


def _tri_text(value: Any) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "unstated"


def adoption_advice_fingerprint() -> str:
    """Fingerprint of the vocabularies and condition ids a pack is built from."""
    payload = {
        "id": ADOPTION_ADVICE_ID,
        "version": ADOPTION_ADVICE_VERSION,
        "sectors": ORG_SECTORS,
        "regimes": ORG_REGIMES,
        "sensitivity": _SENSITIVITY_TERMS,
    }
    canon = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha1(canon.encode("utf-8")).hexdigest()[:12]
