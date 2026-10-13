"""Council of research agents: seat-planned, critic-reviewed queries.

Every investigation's research runs through this council, replacing
ad-hoc query accumulation with an attributable process:

* seats propose query families from the brief (news, papers, official
  docs, CVE advisories, provider policy, incident events) -- each seat
  only speaks when its predicate says the brief needs it;
* the critic then dedupes, tops up uncovered seats within the query
  cap, and records gaps (a relevant seat with no slot is a stated gap,
  never silent);
* the record (seats proposed/covered, critic actions) travels with the
  plan into ``AgentRun.plan`` and run stats, so any query can be traced
  back to the seat that proposed it.

All predicates and templates are deterministic; the LLM plan still
comes first and the council only completes it. Query dicts gain a
``seat`` key (``"llm"`` for model-planned ones); downstream code reads
only ``text``/``sources``, so the tag is free provenance.
"""

from __future__ import annotations

import re
from typing import Any

MAX_QUERIES = 6


def subject_of(inv) -> str:
    """The research subject: first keyword, else the title."""
    kw = ((getattr(inv, "keywords", "") or "").split(",")[0]).strip()
    if kw:
        return kw[:80]
    return ((getattr(inv, "title", "") or "")[:60] or "research")


def _blob(inv) -> str:
    return (f"{getattr(inv, 'title', '') or ''}\n"
            f"{getattr(inv, 'keywords', '') or ''}\n"
            f"{getattr(inv, 'description', '') or ''}")


def _is_incident(inv) -> bool:
    try:
        from . import incident as _inc
        return bool(_inc.is_incident_brief(
            getattr(inv, "title", "") or "",
            getattr(inv, "keywords", "") or "",
            getattr(inv, "description", "") or ""))
    except Exception:
        return False


def _is_provider(inv) -> bool:
    try:
        from . import provider_posture as _pp
        return bool(_pp.is_provider_investigation(
            getattr(inv, "title", "") or "",
            getattr(inv, "keywords", "") or "",
            getattr(inv, "description", "") or ""))
    except Exception:
        return False


def _is_model(inv) -> bool:
    try:
        from . import security as _sec
        prof = _sec.profile_model_subject(
            getattr(inv, "title", "") or "",
            getattr(inv, "description", "") or "",
            (getattr(inv, "keywords", "") or "").split(","))
        return bool(prof.get("is_model_query"))
    except Exception:
        return False


def _cve_subjects(inv) -> dict:
    try:
        from . import cve as _cve
        return _cve.extract_subjects(
            title=getattr(inv, "title", "") or "",
            keywords=getattr(inv, "keywords", "") or "",
            description=getattr(inv, "description", "") or "") or {}
    except Exception:
        return {}


def _has_official_subject(inv) -> bool:
    subs = _cve_subjects(inv)
    return bool(subs.get("products") or subs.get("vendors"))


def _has_cve_subject(inv) -> bool:
    subs = _cve_subjects(inv)
    return bool(subs.get("products") or subs.get("vendors")
                or subs.get("packages") or subs.get("cve_hints"))


def _seat_queries(seat: str, subject: str) -> list[str]:
    if seat == "news":
        return [f"{subject} latest news",
                f"{subject} analysis discussion"]
    if seat == "papers":
        return [f"{subject} paper benchmark evaluation"]
    if seat == "official":
        return [f"{subject} official docs security trust",
                f"{subject} status page changelog"]
    if seat == "cve":
        return [f"{subject} CVE security advisory",
                f"{subject} vulnerability disclosure patch"]
    if seat == "provider":
        return [f"{subject} privacy policy data usage",
                f"{subject} enterprise retention terms"]
    if seat == "incident":
        return [f"{subject} outage timeline what happened",
                f"{subject} status page incident history",
                f"{subject} official statement postmortem"]
    return []


def _seat_sources(seat: str, enabled: set[str]) -> list[str]:
    if seat == "papers":
        return ["arxiv"] if "arxiv" in enabled else sorted(enabled)
    if seat in ("news", "cve", "incident"):
        both = ["rss", "web"]
        if all(s in enabled for s in both):
            return both
        return sorted(enabled)
    return ["web"] if "web" in enabled else sorted(enabled)


_SEATS = ("news", "papers", "official", "cve", "provider", "incident")

_PREDICATES = {
    "news": lambda inv: True,
    "papers": _is_model,
    "official": _has_official_subject,
    "cve": _has_cve_subject,
    "provider": _is_provider,
    "incident": _is_incident,
}

# A seat counts as covered by a tagged query from its ensurer or by any
# query already speaking its domain: coverage is about the family, not
# the exact template string, so an existing docs query satisfies the
# official seat without a duplicate.
_COVERAGE_RES = {
    "news": None,
    "papers": re.compile(r"arxiv|paper|benchmark|memoriz|membership "
                         r"inference|extract|watermark|unlearn|rlhf|"
                         r"reward model|canary", re.IGNORECASE),
    "official": re.compile(r"\bdoc(s|umentation)?\b|trust|official|"
                           r"status page|whitepaper|architecture|"
                           r"changelog|site:", re.IGNORECASE),
    "cve": re.compile(r"\bcve\b|advisory|vulnerab|patch|ghsa|disclosure",
                      re.IGNORECASE),
    "provider": re.compile(r"privacy policy|retention|\bdpa\b|terms|"
                           r"opt.?out|subprocessor|enterprise",
                           re.IGNORECASE),
    "incident": re.compile(r"outage|timeline|status|postmortem|trigger|"
                           r"root cause|what happened", re.IGNORECASE),
}

# Seats the council may top up itself. News never tops up: general
# coverage is the LLM plan's job, and a generic brief must pass through
# untouched rather than gain noise queries.
_TOPUP_SEATS = ("papers", "official", "cve", "provider", "incident")


def review(inv, clean: list[dict],
           enabled: set[str]) -> tuple[list[dict], dict]:
    """Critic pass over a planned query list.

    Tags LLM-planned queries with their seat, drops exact duplicates,
    and tops up relevant-but-uncovered specialist seats within the cap
    (news never tops up: a generic brief passes through untouched).
    Returns the (possibly extended) list and the council record.
    Mutates ``clean`` in place; never exceeds ``MAX_QUERIES``.
    """
    subject = subject_of(inv)
    for q in clean:
        if isinstance(q, dict):
            q.setdefault("seat", "llm")
    record: dict[str, Any] = {"seats": [], "critic": {"dropped": [],
                                                      "gaps": []}}
    kept: list[dict] = []
    for q in clean:
        if not isinstance(q, dict):
            continue
        norm = str(q.get("text") or "").strip().lower()
        if norm in [str(r.get("text") or "").strip().lower() for r in kept]:
            record["critic"]["dropped"].append(q.get("text"))
            continue
        kept.append(q)
    clean[:] = kept
    have = " ".join(str(q.get("text") or "") for q in clean).lower()
    tags = {str(q.get("seat") or "") for q in clean}
    seen = {str(q.get("text") or "").strip().lower() for q in clean}
    for seat in _SEATS:
        try:
            relevant = bool(_PREDICATES[seat](inv))
        except Exception:
            relevant = False
        rx = _COVERAGE_RES[seat]
        covered = (len(clean) > 0 if rx is None
                   else seat in tags or bool(rx.search(have)))
        proposed = _seat_queries(seat, subject) if relevant else []
        record["seats"].append({"id": seat, "relevant": relevant,
                                "proposed": proposed,
                                "covered": covered})
        if not relevant or covered or seat not in _TOPUP_SEATS:
            continue
        if len(clean) >= MAX_QUERIES:
            record["critic"]["gaps"].append(
                f"{seat}: relevant but no query slot left")
            continue
        for text in proposed:
            if text.lower() in have or text.lower() in seen:
                continue
            srcs = _seat_sources(seat, enabled)
            if not srcs:
                record["critic"]["gaps"].append(
                    f"{seat}: no enabled source")
                break
            clean.append({"text": text[:120], "sources": srcs,
                          "seat": seat})
            have += " " + text.lower()
            seen.add(text.lower())
            break
    return clean, record
