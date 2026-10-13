"""Incident post-mortem support: timeline, trigger, root cause.

A command like "what really happened on the X outage, what triggered
it? root cause, explain with mermaid diagrams" is an incident question,
not a product-security question. Routed through the generic pipeline it
comes back as CVE lists and residual scores -- confident, irrelevant,
and diagrammed with threat flows instead of what happened. This module
gives incident queries their own deterministic track:

* intent detection + a fixed 5-topic plan (timeline, trigger, root
  cause, impact/containment, response/lessons),
* event-oriented query shaping for the research planner,
* a deterministic reconstruction from collected artifacts: dated
  events, trigger candidates with evidence, a causal chain, explicit
  gaps -- and mermaid ``timeline`` + causal-flow figures grounded in
  those artifacts.

Nothing here invents: undated material stays unordered, an unconfirmed
cause stays unknown, and thin evidence returns ``insufficient_evidence``
instead of a story. No LLM is involved.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date
from typing import Any

INCIDENT_VERSION = "1.0.0"

CHANGE_POLICY = {
    "major": "verdict levels, topic set, or evidence rules changed",
    "minor": "new patterns, thresholds, or diagram shapes (verdicts stable)",
    "patch": "wording, caps, or parsing robustness without meaning change",
    "version": INCIDENT_VERSION,
}

INCIDENT_TAG = "incident-reconstruction"

_MONTHS = ("jan january feb february mar march apr april may jun june "
           "jul july aug august sep sept september oct october nov "
           "november dec december")

_DATE_RES = (
    re.compile(r"\b(20\d\d)[-/](\d{1,2})[-/](\d{1,2})\b"),
    re.compile(r"\b(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|"
               r"jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:t(?:ember)?)?|"
               r"oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\s+(\d{1,2}),?"
               r"\s+(20\d\d)\b", re.IGNORECASE),
    re.compile(r"\b(\d{1,2})\s+(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|"
               r"apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|"
               r"sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|"
               r"dec(?:ember)?)\s+(20\d\d)\b", re.IGNORECASE),
    re.compile(r"\b(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|"
               r"jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:t(?:ember)?)?|"
               r"oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\s+(20\d\d)\b",
               re.IGNORECASE),
)

_SENT_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")

_TRIGGER_RES = (
    (3, "root cause", re.compile(r"root cause[^.?!]{0,120}", re.I)),
    (3, "trigger", re.compile(r"trigger(?:ed|s)? by ([^.?!]{5,140})",
                               re.I)),
    (3, "cause", re.compile(r"caused by ([^.?!]{5,140})", re.I)),
    (2, "cause", re.compile(r"due to ([^.?!]{5,140})", re.I)),
    (2, "change", re.compile(
        r"(deployed|deployment|release[sd]?|updat(?:e|ed)|upgrade[sd]?|"
        r"migrat(?:ed|ion)|config(?:uration)? change|rolled out)"
        r"[^.?!]{0,120}", re.I)),
    (2, "trigger", re.compile(r"set off ([^.?!]{5,140})", re.I)),
    (1, "effect", re.compile(r"led to ([^.?!]{5,140})", re.I)),
)

_IMPACT_RES = (
    re.compile(r"([^.?!]{0,40}(?:affect(?:ed|s)?|impact(?:ed|s)?|"
               r"disrupt(?:ed|s)?)[^.?!]{5,140})", re.I),
    re.compile(r"([^.?!]{0,20}(?:users?|customers?)[^.?!]{0,60}"
               r"(?:unable|without|lost|exposed)[^.?!]{0,80})", re.I),
    re.compile(r"((?:down|offline)[^.?!]{0,20}for[^.?!]{5,80})", re.I),
)

_STRONG_TERMS = (
    "outage", "breach", "downtime", "disruption", "postmortem",
    "post-mortem", "what happened", "what triggered", "went down",
    "service disruption", "data breach",
)

_EVENT_NOUNS = ("incident", "event", "outage", "failure", "trigger",
                "disruption", "breach")

_INCIDENT_WORDS = ("incident", "outage", "breach", "downtime", "timeline",
                   "postmortem", "trigger", "root cause")

INCIDENT_KEYWORDS = ("incident, outage, timeline, trigger, root cause, "
                     "status page, official statement, postmortem")

INCIDENT_FOCUS = ("timeline", "trigger", "root cause", "impact",
                  "official statements", "status page", "dates", "order")


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def is_incident_command(command: str) -> bool:
    """True when the command asks what happened in an event, not whether
    a product is safe. Strong incident terms decide alone; "root cause"
    and "trigger" need an event noun so security scoping questions stay
    on the generic track."""
    text = _norm(command)
    if any(t in text for t in _STRONG_TERMS):
        return True
    if "root cause" in text or "trigger" in text:
        return any(n in text for n in _EVENT_NOUNS)
    return False


def is_incident_brief(title: str = "", keywords: str = "",
                      description: str = "") -> bool:
    """True when an investigation brief is incident reconstruction work
    (the marker the incident plan writes, or incident terms throughout)."""
    blob = _norm(f"{title} {keywords} {description}")
    if "incident_reconstruction" in blob:
        return True
    hits = sum(1 for w in _INCIDENT_WORDS if w in blob)
    return hits >= 2


def _clean_subject(command: str) -> str:
    """Pull the event subject out of an incident question.

    "what really happened on OpenAI - Huggingface incident, what
    triggered it? root cause, explain with mermaid diagrams" becomes
    "OpenAI - Huggingface": strip the interrogative frame, the trailing
    ask clauses, and the incident nouns themselves.
    """
    text = re.sub(r"\s+", " ", (command or "")).strip()
    text = re.split(r"[?;]", text)[0]
    text = re.sub(r"^(what|when|where|why|how)\b[^,]*?\b("
                  r"on|about|with|in|to|of|for|at)\b\s+", "", text,
                  flags=re.IGNORECASE)
    text = re.sub(r",?\s*(what|which|who|how|why)\b.*$", "", text,
                  flags=re.IGNORECASE)
    text = re.sub(r"\b(the|a|an)\s+(openai|open ai)\b", r"\2", text,
                  flags=re.IGNORECASE)
    text = re.sub(r"\b(incident|outage|breach|downtime|disruption|"
                  r"postmortem|post-mortem|event|timeline|root cause|"
                  r"explain.*|mermaid.*|diagrams?)\b", "", text,
                  flags=re.IGNORECASE)
    text = re.sub(r"\s+", " ", text).strip(" -:,")
    return text[:120].strip() or "the incident"


def incident_plan(command: str,
                  exposure: str = "confidential_data") -> dict | None:
    """Deterministic manager plan for an incident question.

    Returns None for anything else, so the normal parse paths stay
    untouched. Five fixed topics cover the post-mortem shape (timeline,
    trigger, root cause, impact/containment, response/lessons); every
    brief carries the incident marker the research planner reads.
    """
    if not is_incident_command(command or ""):
        return None
    subject = _clean_subject(command)
    brief_head = (f"Incident reconstruction: {subject}. Reconstruct from "
                  f"dated evidence only -- status pages, official "
                  f"statements, reputable incident reporting. Undated "
                  f"material stays unordered; unconfirmed causes stay "
                  f"unknown.")
    specs = (
        ("timeline", "incident timeline: what happened, in what order",
         "dated events in order, first report, detection, escalation"),
        ("trigger", "trigger: the event or change that set it off",
         "triggering change or event, deploys, config changes, upstream"),
        ("root cause", "root cause and contributing factors",
         "root cause, contributing factors, what is still unconfirmed"),
        ("impact", "impact and containment: who was affected, what "
         "stopped it",
         "affected users and systems, duration, containment, recovery"),
        ("response", "response and lessons: statements, fixes, follow-ups",
         "official statements, remediation, follow-up actions, lessons"),
    )
    topics = []
    for key, title_tail, brief_tail in specs:
        topics.append({
            "title": f"{subject} {title_tail}"[:120],
            "subject": subject[:120],
            "task": "incident_reconstruction",
            "description": (f"{brief_head} Focus: {brief_tail}."),
            "keywords": f"{subject}, incident_reconstruction, "
                        f"{INCIDENT_KEYWORDS}",
            "focus": [key, *list(INCIDENT_FOCUS[:4])][:8],
            "anti_focus": ["product vulnerability lists",
                           "unrelated CVE scoring"],
            "exposure": None,
        })
    return {
        "domain": "incident_reconstruction",
        "exposure": exposure,
        "incident": True,
        "topics": topics,
        "summary": {
            "title": f"Incident reconstruction: {subject}"[:300],
            "description": f"Timeline, trigger, and root cause for: "
                           f"{command[:200]}"},
        "parsed_by": "incident-template",
    }


def _month_num(name: str) -> int:
    names = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug",
             "sep", "oct", "nov", "dec")
    return names.index(name[:3].lower()) + 1


def _find_dates(text: str) -> list[tuple[date, bool]]:
    """(date, is_approximate) for every calendar date in the text."""
    out: list[tuple[date, bool]] = []
    for m in _DATE_RES[0].finditer(text or ""):
        try:
            out.append((date(int(m.group(1)), int(m.group(2)),
                             int(m.group(3))), False))
        except ValueError:
            continue
    for m in _DATE_RES[1].finditer(text or ""):
        try:
            out.append((date(int(m.group(3)), _month_num(m.group(1)),
                             int(m.group(2))), False))
        except ValueError:
            continue
    for m in _DATE_RES[2].finditer(text or ""):
        try:
            out.append((date(int(m.group(3)), _month_num(m.group(2)),
                             int(m.group(1))), False))
        except ValueError:
            continue
    for m in _DATE_RES[3].finditer(text or ""):
        try:
            out.append((date(int(m.group(2)), _month_num(m.group(1)), 1),
                        True))
        except ValueError:
            continue
    return out


def _sentences(*texts: str) -> list[str]:
    out = []
    for text in texts:
        for s in _SENT_SPLIT.split(text or ""):
            s = re.sub(r"\s+", " ", s).strip()
            if len(s) >= 20:
                out.append(s)
    return out


def _mm_safe(text: str, limit: int = 80) -> str:
    return re.sub(r"[`\"{}()#;]", " ",
                  re.sub(r"\s+", " ", text or "").strip())[:limit]


def _artifacts(db, inv_id: int) -> list:
    from .models import Artifact
    try:
        return (db.query(Artifact)
                .filter(Artifact.investigation_id == inv_id)
                .order_by(Artifact.id).all())
    except Exception:
        return []


def _subject(inv) -> str:
    kw = (getattr(inv, "keywords", "") or "").split(",")[0].strip()
    if kw and "incident_reconstruction" not in kw.lower():
        return kw[:80]
    title = getattr(inv, "title", "") or ""
    title = re.sub(r"\bincident\s+(timeline|reconstruction)\b:? ?", "",
                   title, flags=re.IGNORECASE)
    title = re.sub(r"\b(trigger|root cause|impact.*|response.*)$", "",
                   title, flags=re.IGNORECASE).strip(" -:,")
    return (title[:80] or kw[:80] or "the incident")


def analyze(db, inv_id: int) -> dict[str, Any]:
    """Reconstruct an incident from one investigation's artifacts.

    Deterministic: dated events order the timeline, trigger sentences
    score candidates with their evidence attached, and anything
    unconfirmed is labelled unknown. Thin evidence returns
    ``insufficient_evidence`` rather than a story.
    """
    from .models import Investigation
    try:
        inv = db.query(Investigation).filter(
            Investigation.id == inv_id).first()
    except Exception:
        inv = None
    if inv is None:
        return {"verdict": {"key": "insufficient_evidence",
                            "label": "no such investigation"},
                "version": INCIDENT_VERSION,
                "fingerprint": incident_fingerprint()}
    subject = _subject(inv)
    arts = _artifacts(db, inv_id)
    events: list[dict] = []
    undated = 0
    trigger_cands: list[dict] = []
    impacts: list[dict] = []
    for a in arts:
        title = getattr(a, "title", "") or ""
        desc = getattr(a, "description", "") or ""
        content = getattr(a, "content", "") or ""
        url = getattr(a, "url", "") or ""
        rel = getattr(a, "relevance", None)
        rel = float(rel) if isinstance(rel, int | float) else 0.5
        blob = f"{title}\n{desc}\n{content[:4000]}"
        dates = _find_dates(blob)
        try:
            pub = getattr(a, "date_published", None)
            pub_date = pub.date() if hasattr(pub, "date") else None
        except Exception:
            pub_date = None
        if dates:
            seen: set[date] = set()
            for d, approx in dates:
                if d in seen:
                    continue
                seen.add(d)
                events.append({"date": d.isoformat(), "approx": approx,
                               "label": title[:100] or "reported event",
                               "url": url, "artifact_id": a.id,
                               "relevance": rel})
        elif pub_date is not None:
            events.append({"date": pub_date.isoformat(), "approx": True,
                           "label": title[:100] or "reported event",
                           "url": url, "artifact_id": a.id,
                           "relevance": rel})
        else:
            undated += 1
        for s in _sentences(title, desc, content[:2000]):
            for weight, kind, rx in _TRIGGER_RES:
                m = rx.search(s)
                if m:
                    text = (m.group(1) if m.lastindex else m.group(0)
                            ).strip()
                    trigger_cands.append(
                        {"text": text[:200], "kind": kind,
                         "score": weight + rel,
                         "evidence": title[:120] or url[:120],
                         "artifact_id": a.id})
                    break
            for rx in _IMPACT_RES:
                m = rx.search(s)
                if m and len(impacts) < 8:
                    impacts.append({"text": m.group(1).strip()[:200],
                                    "evidence": title[:120] or url[:120],
                                    "artifact_id": a.id})
                    break
    dated = sorted(events, key=lambda e: (e["date"], -e["relevance"]))
    dated = [e for e in dated if e["date"] <= date.today().isoformat()]
    dated = dated[:12]
    by_art: dict[int, int] = {}
    for c in trigger_cands:
        by_art[c["artifact_id"]] = by_art.get(c["artifact_id"], 0) + 1
    for c in trigger_cands:
        c["support"] = by_art[c["artifact_id"]]
    trigger_cands.sort(key=lambda c: (c["score"], c["support"]),
                       reverse=True)
    trigger = None
    if trigger_cands:
        best = trigger_cands[0]
        conf = ("high" if best["support"] >= 2 and best["score"] >= 3.0
                else "medium" if best["score"] >= 2.5 else "low")
        trigger = {"text": best["text"], "kind": best["kind"],
                   "confidence": conf, "evidence": best["evidence"],
                   "artifact_id": best["artifact_id"]}
    root = None
    if trigger is not None and trigger["confidence"] in ("high", "medium"):
        root = {"text": trigger["text"], "confidence": trigger["confidence"],
                "evidence": trigger["evidence"],
                "artifact_id": trigger["artifact_id"]}
    gaps = []
    if len(dated) < 3:
        gaps.append(f"only {len(dated)} dated event(s): the order is "
                    f"provisional")
    if undated:
        gaps.append(f"{undated} undated report(s) excluded from ordering")
    if trigger is None:
        gaps.append("no trigger evidence in the collected artifacts")
    elif trigger["confidence"] == "low":
        gaps.append("trigger is a single weak mention: unconfirmed")
    if root is None:
        gaps.append("root cause unconfirmed: collect vendor statements "
                    "and status-page history")
    if len(dated) >= 3 and trigger is not None and \
            trigger["confidence"] in ("high", "medium"):
        verdict = {"key": "reconstructed",
                   "label": "timeline and trigger grounded in artifacts"}
    elif dated or trigger is not None:
        verdict = {"key": "partial",
                   "label": "fragmentary evidence: order or cause is thin"}
    else:
        verdict = {"key": "insufficient_evidence",
                   "label": "no event evidence collected: nothing to "
                            "reconstruct"}
    pack = {"subject": subject, "investigation_id": inv_id,
            "verdict": verdict,
            "dated_events": dated, "undated_count": undated,
            "trigger": trigger, "root_cause": root,
            "impacts": impacts[:5], "gaps": gaps,
            "artifact_count": len(arts),
            "version": INCIDENT_VERSION,
            "fingerprint": incident_fingerprint()}
    pack["diagrams"] = {"timeline": _timeline_mermaid(pack),
                        "causal": _causal_mermaid(pack)}
    return pack


def _timeline_mermaid(pack: dict) -> str:
    """Event order as a mermaid timeline (undated material excluded)."""
    subject = _mm_safe(pack.get("subject") or "incident", 60)
    lines = ["timeline", f"    title {subject}: what happened"]
    dated = pack.get("dated_events") or []
    if not dated:
        lines.append("    section evidence")
        lines.append("    no dated events : nothing collected yet")
        return "\n".join(lines) + "\n"
    lines.append("    section events")
    for e in dated:
        day = e["date"] + (" ~" if e.get("approx") else "")
        lines.append(f"    {day} : {_mm_safe(e.get('label') or 'event')}")
    if pack.get("undated_count"):
        lines.append("    section undated reports")
        lines.append(f"    excluded from order : "
                     f"{pack['undated_count']} report(s)")
    return "\n".join(lines) + "\n"


def _causal_mermaid(pack: dict) -> str:
    """Trigger, cause, and impact as a flowchart with unknowns explicit."""
    lines = ["flowchart TD"]
    trig = (pack.get("trigger") or {}).get("text")
    root = (pack.get("root_cause") or {}).get("text")
    tconf = (pack.get("trigger") or {}).get("confidence", "unknown")
    rconf = (pack.get("root_cause") or {}).get("confidence", "unknown")
    lines.append(f'    T["trigger ({tconf}): '
                 f'{_mm_safe(trig or "unknown: no trigger evidence")}'
                 f'"]')
    lines.append(f'    R["root cause ({rconf}): '
                 f'{_mm_safe(root or "unknown: unconfirmed")}'
                 f'"]')
    lines.append("    T -->|led to| R")
    impacts = pack.get("impacts") or []
    if impacts:
        for i, imp in enumerate(impacts[:4]):
            lines.append(f'    I{i}["impact: {_mm_safe(imp.get("text"))}"]')
            lines.append(f"    R --> I{i}")
    else:
        lines.append('    I0["impact: unknown: no impact evidence"]')
        lines.append("    R --> I0")
    return "\n".join(lines) + "\n"


def render_markdown(pack: dict) -> str:
    """The reconstruction as report markdown with fenced figures."""
    L = [f"## Incident reconstruction: "
         f"{pack.get('subject') or 'the incident'}", ""]
    v = pack.get("verdict") or {}
    L.append(f"**Verdict: {v.get('key', '?')}** -- "
             f"{v.get('label', '')}")
    L.append("")
    L.append(f"Grounded in {pack.get('artifact_count', 0)} collected "
             f"artifact(s): {len(pack.get('dated_events') or [])} dated "
             f"event(s), {pack.get('undated_count', 0)} undated.")
    L.append("")
    if pack.get("dated_events"):
        L.append("### Timeline")
        L.append("")
        for e in pack["dated_events"]:
            day = e["date"] + (" (approx)" if e.get("approx") else "")
            L.append(f"- **{day}** -- {e.get('label', '')}")
        L.append("")
        L.append("```mermaid timeline")
        L.append((pack.get("diagrams") or {}).get("timeline", "").rstrip())
        L.append("```")
        L.append("")
    trig = pack.get("trigger") or {}
    if trig.get("text"):
        L.append(f"### Trigger ({trig.get('confidence', '?')} confidence)")
        L.append("")
        L.append(f"{trig['text']}")
        L.append("")
        L.append(f"_Evidence: {trig.get('evidence', '')}_")
        L.append("")
    root = pack.get("root_cause") or {}
    if root.get("text"):
        L.append(f"### Root cause ({root.get('confidence', '?')} "
                 f"confidence)")
        L.append("")
        L.append(f"{root['text']}")
        L.append("")
        L.append(f"_Evidence: {root.get('evidence', '')}_")
        L.append("")
    L.append("### Causal chain")
    L.append("")
    L.append("```mermaid causal")
    L.append((pack.get("diagrams") or {}).get("causal", "").rstrip())
    L.append("```")
    L.append("")
    if pack.get("impacts"):
        L.append("### Reported impacts")
        L.append("")
        for imp in pack["impacts"]:
            L.append(f"- {imp.get('text', '')}")
        L.append("")
    if pack.get("gaps"):
        L.append("### Gaps (what would confirm or overturn this)")
        L.append("")
        for g in pack["gaps"]:
            L.append(f"- {g}")
        L.append("")
    return "\n".join(L).strip() + "\n"


def store_analysis(db, inv_id: int) -> dict[str, Any]:
    """Analyze and persist the reconstruction; idempotent per topic.

    A second call returns the stored artifact rather than duplicating
    it, so compile re-runs and repeated endpoint calls stay stable.
    """
    from .models import Artifact
    try:
        existing = (db.query(Artifact)
                    .filter(Artifact.investigation_id == inv_id,
                            Artifact.tags.like(f"%{INCIDENT_TAG}%"))
                    .order_by(Artifact.id.desc()).first())
    except Exception:
        existing = None
    pack = analyze(db, inv_id)
    if existing is not None and existing.content:
        return {"artifact_id": existing.id, "existing": True, "pack": pack}
    art = Artifact(
        investigation_id=inv_id,
        title=f"Incident reconstruction: {pack.get('subject')}",
        artifact_type="research",
        description=(f"Deterministic reconstruction "
                     f"({pack['verdict']['key']}) from collected artifacts."),
        content=render_markdown(pack),
        source="agentic-manager",
        tags=INCIDENT_TAG)
    db.add(art)
    db.commit()
    db.refresh(art)
    return {"artifact_id": art.id, "existing": False, "pack": pack}


def incident_fingerprint() -> str:
    """Pin the deterministic content: topic specs, patterns, thresholds."""
    canon = {"version": INCIDENT_VERSION,
             "topics": ("timeline", "trigger", "root cause", "impact",
                        "response"),
             "strong_terms": sorted(_STRONG_TERMS),
             "trigger_weights": [(w, k) for w, k, _ in _TRIGGER_RES],
             "rules": {"dated_for_reconstructed": 3,
                       "timeline_cap": 12, "impacts_cap": 5}}
    return hashlib.sha256(json.dumps(canon, sort_keys=True).encode()
                          ).hexdigest()[:12]
