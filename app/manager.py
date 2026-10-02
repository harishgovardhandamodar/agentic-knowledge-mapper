"""Agentic Manager: one command fans out to N investigations + a summary.

A command like "run detailed security investigations on AI agents in
finance, especially payments / trade / DeFi / crypto" is understood
(LLM first, deterministic splitter when the model is unreachable) and
served: one investigation per topic, each with a research run and a
security assessment launched, plus a summary investigation that compiles
finished children on demand.

Nothing runs in the background: launches are fire-and-forget threads owned
by the agent/security runners, statuses are derived live from their tables
on every read, and the summary compiles only when asked. A restart
mid-flight leaves recoverable rows, never a stuck watcher.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

from . import llm
from .agent import launch_run
from .models import (AgentEvent, AgentRun, Artifact, Investigation,
                     SecurityAssessment)
from .security import EXPOSURE_META, profile_model_subject
from .security_agent import launch_security_assessment

MAX_TOPICS = 6
SYNTH_TAG = "manager-synthesis"
COMPILE_TRUNC = 1500

_LEAD = re.compile(
    r"^(?:please\s+)?(?:run|start|launch|do|execute|perform)?\s*"
    r"(?:a\s+|an\s+)?(?:detailed\s+)?(?:new\s+)?"
    r"(?:security\s+)?(?:investigations?|investigational|research|stud(?:y|ies)|"
    r"analys(?:is|es))\s+(?:on|about|into|for|of)?\s*",
    re.IGNORECASE)
_SPLIT = re.compile(r"\s*/\s*|\s*;\s*|\n+|\s*\d+[.)]\s+")

_FOCUS_STOP = frozenset(
    ("agents agent ai data system systems platform application app service "
     "services tool tools new detailed run runs running investigation "
     "investigations research study studies security focus focused focusing "
     "rather than instead except group team the and for with from that this these those its are was were "
     "has have had will would can not all any per via into over under "
     "on about of to in a an").split())

# Focus-directive clauses: "focus on X", "with emphasis on Y" add focus;
# "rather than Z", "instead of W" mark anti-focus -- directions the user
# explicitly ruled out. Anti-focus travels into the use case text so the
# assessment reads it, and stays out of the focus terms so it can never
# lift a threat the user excluded.
_FOCUS_CLAUSE = re.compile(
    r"\b(?:focus(?:sing|ed)?|with\s+(?:a\s+)?focus|with\s+emphasis|centered|concentrat\w+)\s+on\b",
    re.IGNORECASE)
_ANTI_CLAUSE = re.compile(
    r"\b(?:rather\s+than|instead\s+of|excluding|except(?:\s+for)?)\b",
    re.IGNORECASE)


def _same_text(a: str, b: str) -> bool:
    """Near-identical ignoring case, punctuation and whitespace -- for the
    pasted-twice command ("X — X"), where the second half adds nothing."""
    norm = lambda s: re.sub(r"[^a-z0-9]+", "", (s or "").lower())
    return bool(norm(a)) and norm(a) == norm(b)


def _dedupe_command(text: str) -> str:
    """Collapse a command pasted twice ("X — X", "X. X", "X: X") to X.

    Run #7 arrived as the same sentence twice joined by an em dash; without
    this the topic title is the duplication truncated mid-word and the
    description repeats itself, and every downstream field inherits the mess.
    """
    t = re.sub(r"\s+", " ", (text or "")).strip()
    m = re.match(r"^(.+?)\s+[—–\-:]\s+(.+)$", t)
    if m and _same_text(m.group(1), m.group(2)):
        return m.group(1).strip()
    sents = [s.strip() for s in re.split(r"(?<=[.!?])\s+", t) if s.strip()]
    if len(sents) == 2 and _same_text(sents[0], sents[1]):
        return sents[0]
    return t


def _extract_intent(text: str) -> dict[str, Any]:
    """Split a cleaned command into subject, focus and anti-focus.

    "Tabular Foundation Models. Focus on advancements on capabilities rather
    than performance improvement" -> subject "Tabular Foundation Models",
    focus [advancements, capabilities], anti-focus [performance, ...].
    The subject names the thing assessed; the focus clause names what about
    it matters; the anti clause names what the user ruled out. All three
    travel into the plan so product_name, use_case and focus terms describe
    the intent instead of echoing the raw command.
    """
    focus_extra: list[str] = []
    anti_focus: list[str] = []
    rest = text
    m = _FOCUS_CLAUSE.search(rest)
    if m:
        rest, focus_part = rest[:m.start()].strip(), rest[m.end():].strip()
        am = _ANTI_CLAUSE.search(focus_part)
        if am:
            focus_part, anti_part = (focus_part[:am.start()].strip(),
                                     focus_part[am.end():].strip())
            anti_focus = _focus_terms(anti_part)
        else:
            am = _ANTI_CLAUSE.search(rest)
            if am:
                anti_part = rest[am.end():].strip()
                rest = rest[:am.start()].strip()
                anti_focus = _focus_terms(anti_part)
        focus_extra = _focus_terms(focus_part)
    else:
        am = _ANTI_CLAUSE.search(rest)
        if am:
            anti_part = rest[am.end():].strip()
            rest = rest[:am.start()].strip()
            anti_focus = _focus_terms(anti_part)
    subject = re.sub(r"\s+", " ", rest).strip().rstrip(".")[:120]
    return {"subject": subject, "focus": focus_extra, "anti_focus": anti_focus}


def _focus_terms(title: str) -> list[str]:
    """Content words of a topic title: focus areas for applicability."""
    return [t for t in re.split(r"[^a-z0-9+]+", (title or "").lower())
            if len(t) > 2 and t not in _FOCUS_STOP][:8]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def split_command(command: str) -> dict[str, Any]:
    """Deterministic fallback parse: slashes/semicolons/lines split topics.

    "… finance domain, especially A / B / C" yields domain "… finance
    domain" and topics A, B, C; without "especially" the whole (de-verbed)
    command is split. Same shape as the LLM parse, flagged heuristic.
    A pasted-twice command collapses first; a single part keeps its subject
    as the title so the product assessed is named, not the command string.
    """
    text = _dedupe_command(command)
    domain, rest = "", text
    m = re.search(r"\bespecially\b", text, re.IGNORECASE)
    if m:
        domain, rest = text[:m.start()], text[m.end():]
    rest = _LEAD.sub("", rest).strip().rstrip(".")
    if not domain:
        domain = _LEAD.sub("", text).strip().rstrip(".")
    parts = [p.strip().rstrip(".") for p in _SPLIT.split(rest) if p.strip()]
    intent = _extract_intent(rest)
    topics = []
    for p in parts:
        if not p:
            continue
        # Part focus excludes any anti-focus tail ("... rather than X"): the
        # exclusion belongs to anti_focus, never to focus, or a ruled-out
        # direction would lift the very threats it should sink.
        p_focus_src = _ANTI_CLAUSE.split(p, maxsplit=1)[0]
        focus = _focus_terms(p_focus_src) + [f for f in intent["focus"]
                                             if f not in _focus_terms(p_focus_src)]
        if len(parts) == 1 and intent["subject"]:
            title, subject = intent["subject"], intent["subject"]
            description = p
        else:
            title, subject = p[:120], p[:120]
            description = (f"{p} — {domain}" if domain else p)
        if intent["anti_focus"]:
            description += ("\nExplicitly out of scope: "
                            + ", ".join(intent["anti_focus"]))
        topics.append({"title": title[:120], "subject": subject[:120],
                       "description": description,
                       "keywords": p, "focus": focus[:8],
                       "anti_focus": intent["anti_focus"][:8],
                       "exposure": None})
    domain = re.sub(r"\s+", " ", domain).strip().rstrip(".")[:200]
    return {"domain": domain, "exposure": "confidential_data",
            "topics": topics,
            "summary": {"title": f"Summary: {domain or text[:60]}",
                        "description": f"Synthesis of: {', '.join(t['title'] for t in topics)}"},
            "parsed_by": "heuristic"}


def _llm_parse(command: str) -> dict[str, Any]:
    out = llm.chat_json([
        {"role": "system",
         "content": ("You split a research command into scoped investigations. "
                     "Reply JSON only: {\"domain\": str, "
                     "\"exposure\": one of restricted_data|confidential_data|internal|public, "
                     "\"topics\": [{\"title\": str (<=120 chars, name the SUBJECT "
                     "being investigated, never the command verb phrase), "
                     "\"subject\": str (the thing assessed, e.g. a model family, "
                     "product, or dataset -- no verbs like 'run' or 'investigate'), "
                     "\"task\": str (what to do with it, e.g. security investigation), "
                     "\"description\": str, "
                     "\"keywords\": str, \"focus\": [str], "
                     "\"anti_focus\": [str] (directions the command explicitly "
                     "rules out, e.g. after 'rather than' -- empty when none), "
                     "\"exposure\": one of restricted_data|confidential_data|internal|public|null (null = plan default)}, "
                     "\"summary\": {\"title\": str, \"description\": str}}. "
                     "If the command repeats itself, use it once. "
                     "Cover each named sub-topic as its own topic; no filler topics.")},
        {"role": "user", "content": _dedupe_command(command)[:2000]}],
        max_tokens=1200, temperature=0.2)
    if not isinstance(out, dict):
        raise ValueError("model did not return a plan object")
    topics = out.get("topics") or []
    norm = []
    for t in topics:
        if not isinstance(t, dict):
            continue
        exp = t.get("exposure")
        norm.append({"title": str(t.get("title") or "")[:120],
                     "subject": str(t.get("subject") or "")[:120],
                     "task": str(t.get("task") or "")[:200],
                     "description": str(t.get("description") or ""),
                     "keywords": str(t.get("keywords") or "")[:1000],
                     "focus": [str(f) for f in (t.get("focus") or [])][:8],
                     "anti_focus": [str(f) for f in (t.get("anti_focus") or [])][:8],
                     "exposure": (exp if exp in EXPOSURE_META else None)})
    summary = out.get("summary") or {}
    return {"domain": str(out.get("domain") or "")[:200],
            "exposure": str(out.get("exposure") or "confidential_data"),
            "topics": norm,
            "summary": {"title": str(summary.get("title") or "")[:300],
                        "description": str(summary.get("description") or "")},
            "parsed_by": "llm"}


def parse_command(command: str) -> dict[str, Any]:
    """Understand a command.

    Provider posture commands match a deterministic template first: a
    multi-provider data question has a known-good shape (one topic per named
    lab, policy-first focus), and routing it through the generic LLM parse
    risks a verb-phrase subject or a benchmark-flavoured plan. LLM first
    otherwise; the deterministic splitter whenever the model is unreachable
    *or* its plan validates to nothing. Only raises when both paths fail.
    """
    command = (command or "").strip()
    if not command:
        raise ValueError("command is empty")
    try:
        from . import provider_posture as _pp
        template = _pp.provider_plan(command)
        if template is not None:
            return validate_plan(template)
    except Exception:
        pass
    try:
        return validate_plan(_llm_parse(command))
    except Exception:
        pass
    return validate_plan(split_command(command))


def validate_plan(plan: dict[str, Any]) -> dict[str, Any]:
    """Cap, clean and dedupe a plan. Raises ValueError when unusable."""
    if not isinstance(plan, dict):
        raise ValueError("plan must be an object")
    topics = []
    seen = set()
    for t in (plan.get("topics") or []):
        if not isinstance(t, dict):
            continue
        title = str(t.get("title") or "").strip()
        if not title or title.lower() in seen:
            continue
        seen.add(title.lower())
        exp = t.get("exposure")
        topics.append({"title": title[:120],
                       "subject": str(t.get("subject") or "")[:120],
                       "task": str(t.get("task") or "")[:200],
                       "description": str(t.get("description") or title),
                       "keywords": str(t.get("keywords") or title)[:1000],
                       "focus": [str(f) for f in (t.get("focus") or [])][:8],
                       "anti_focus": [str(f) for f in (t.get("anti_focus") or [])][:8],
                       "exposure": (exp if exp in EXPOSURE_META else None)})
    if not topics:
        raise ValueError("no usable topics in command")
    truncated = False
    if len(topics) > MAX_TOPICS:
        topics = topics[:MAX_TOPICS]
        truncated = True
    exposure = str(plan.get("exposure") or "confidential_data")
    if exposure not in EXPOSURE_META:
        exposure = "confidential_data"
    summary = plan.get("summary") or {}
    out = {"domain": str(plan.get("domain") or "")[:200],
           "exposure": exposure,
           "topics": topics,
           "summary": {"title": str(summary.get("title") or
                                   f"Summary: {topics[0]['title']} +{len(topics) - 1}")[:300],
                       "description": str(summary.get("description") or "")},
           "parsed_by": plan.get("parsed_by") or "unknown",
           "truncated": truncated}
    return out


def _run_row(db, run) -> dict[str, Any]:
    plan = {}
    try:
        plan = json.loads(run.plan_json or "{}")
    except Exception:
        plan = {}
    topics = plan.get("topics") or []
    children = []
    all_done = True
    for t in topics:
        inv_id = t.get("investigation_id")
        inv = db.query(Investigation).filter(
            Investigation.id == inv_id).first() if inv_id else None
        runs = (db.query(AgentRun).filter(AgentRun.investigation_id == inv_id)
                .order_by(AgentRun.id.desc()).all()) if inv_id else []
        assessment = None
        if inv_id:
            rec = (db.query(SecurityAssessment)
                   .filter(SecurityAssessment.investigation_id == inv_id)
                   .order_by(SecurityAssessment.id.desc()).first())
            if rec is not None:
                assessment = {"id": rec.id,
                              "overall_pct": rec.overall_pct,
                              "residual_pct": rec.residual_pct,
                              "has_markdown": bool(rec.markdown)}
        research_runs = [r for r in runs if (r.trigger or "manual") != "security"]
        research_done = (inv is not None and inv.status == "ready") or \
            (research_runs and all(r.status in ("done", "error") for r in research_runs)) \
            or (not research_runs and plan.get("options", {}).get("research") is False)
        assess_done = (plan.get("options", {}).get("assessment") is False) or \
            (assessment is not None)
        done = research_done and assess_done
        all_done = all_done and done
        children.append({
            "title": t.get("title"), "investigation_id": inv_id,
            "investigation_status": inv.status if inv else None,
            "research": {"runs": len(research_runs),
                         "done": research_done,
                         "latest": research_runs[0].status if research_runs else None},
            "assessment": assessment,
            "assessment_done": assess_done,
            "done": done,
        })
    compiled = False
    synthesis_artifact_id = None
    summary_id = run.summary_investigation_id
    if summary_id:
        synth = (db.query(Artifact)
                 .filter(Artifact.investigation_id == summary_id,
                         Artifact.tags.like(f"%{SYNTH_TAG}%"))
                 .order_by(Artifact.id.desc()).first())
        compiled = synth is not None
        synthesis_artifact_id = synth.id if synth is not None else None
    return {"id": run.id, "command": run.command, "status": run.status,
            "created_at": run.created_at.isoformat() if run.created_at else None,
            "summary_investigation_id": summary_id,
            "synthesis_artifact_id": synthesis_artifact_id,
            "topics": topics, "children": children,
            "all_done": all_done, "compiled": compiled}


def run_plan(db, plan: dict[str, Any], options: dict[str, Any] | None = None,
             command: str = "") -> dict[str, Any]:
    """Create investigations, launch research + assessments, link a summary."""
    from .models import ManagerRun
    plan = validate_plan(plan)
    options = {"research": True, "assessment": True, **(options or {})}
    plan["options"] = options
    run = ManagerRun(command=command or plan.get("command") or "",
                     plan_json=json.dumps(plan), status="running")
    db.add(run)
    db.commit()
    db.refresh(run)
    footer = f"\n\nPart of manager run #{run.id}."
    for t in plan["topics"]:
        subject = (t.get("subject") or "").strip() or t["title"][:120]
        use_case = t.get("description", "")
        directives = []
        if t.get("focus"):
            directives.append("Focus areas: " + ", ".join(t["focus"]))
        if t.get("anti_focus"):
            directives.append("Explicitly out of scope: "
                              + ", ".join(t["anti_focus"]))
        if directives:
            use_case = (use_case + "\n" + "\n".join(directives)).strip()
        inv = Investigation(
            title=t["title"][:300],
            keywords=t.get("keywords", "")[:1000],
            description=(use_case + footer),
            status="draft")
        db.add(inv)
        db.commit()
        db.refresh(inv)
        t["investigation_id"] = inv.id
        if options.get("research"):
            launch_run(inv.id, trigger=f"manager:{run.id}")
        if options.get("assessment"):
            # A model subject gets THREE assessments, not one: is the model
            # sound, what could someone build with it, and which of the claims
            # those two imply is actually true. Different agents, different
            # weights, a different number of questions -- averaging them would
            # bury all three. launch_security_assessment is called once per
            # mode; the per-investigation busy lock only stops a duplicate of
            # the same job, and the three keys differ, so all queue.
            #
            # Order matters for the third: it reads the STORED rows of the
            # first two, and the job queue claims in (next_attempt_at, id)
            # order, so queuing it last is what puts it after them. If an
            # earlier flow is waiting out a retry backoff the third can still
            # start first -- it then reads whatever rows exist and reports an
            # explicit gap claim rather than an empty register.
            _prof = profile_model_subject(subject[:120], use_case,
                                          t.get("focus", []))
            _is_provider = (t.get("task") or "") == "provider_data_posture"
            # A provider topic asks about data handling, not weight
            # extraction: one product-style assessment, never the three
            # model-engineering modes, even when the lab name profiles as a
            # model subject.
            _modes = ([""] if _is_provider
                      else (["target", "adversarial", "hypothesis"]
                            if _prof["is_model_query"] else [""]))
            for _mode in _modes:
                _params = {"product_name": subject[:120],
                           "use_case": use_case,
                           "exposure": (t.get("exposure") or plan["exposure"]),
                           "declared_controls": [],
                           "doc_urls": [],
                           "focus": t.get("focus", []),
                           "assessment_mode": _mode}
                if _is_provider:
                    # A provider posture assessment is judged against the
                    # org's actual exposure, not a blank profile: org
                    # confidential data possibly containing PII, reached over
                    # the API by employees and service accounts. Stated
                    # defaults -- the operator corrects them per org.
                    from . import provider_posture as _pp
                    _params["situation"] = dict(_pp.PROVIDER_SITUATION)
                launch_security_assessment(inv.id, _params,
                                           requested_by=f"manager run {run.id}")
    summary = plan.get("summary") or {}
    names = ", ".join(f"#{t.get('investigation_id')} {t['title']}"
                      for t in plan["topics"])
    summ = Investigation(
        title=(summary.get("title") or f"Manager run #{run.id} summary")[:300],
        keywords=(plan.get("domain") or "")[:1000],
        description=((summary.get("description") or "") +
                     f"\n\nSynthesizes manager run #{run.id}: {names}."
                     f"\nCommand: {run.command}"),
        status="draft")
    db.add(summ)
    db.commit()
    db.refresh(summ)
    run.summary_investigation_id = summ.id
    run.plan_json = json.dumps(plan)
    db.commit()
    return _run_row(db, run)


def compile_run(db, run_id: int) -> dict[str, Any]:
    """Synthesize finished children into the summary investigation.

    409 while anything still runs; idempotent (an existing synthesis is
    returned, never duplicated).
    """
    from .models import ManagerRun
    run = db.query(ManagerRun).filter(ManagerRun.id == run_id).first()
    if run is None:
        raise LookupError("manager run not found")
    row = _run_row(db, run)
    pending = [c["title"] for c in row["children"] if not c["done"]]
    if pending:
        raise PendingChildren(pending)
    summary_id = run.summary_investigation_id
    synth = (db.query(Artifact)
             .filter(Artifact.investigation_id == summary_id,
                     Artifact.tags.like(f"%{SYNTH_TAG}%"))
             .order_by(Artifact.id.desc()).first())
    if synth is not None:
        return {"artifact_id": synth.id, "summary_investigation_id": summary_id,
                "markdown": synth.content, "existing": True}
    def _child_gaps(inv_id: int) -> list[str]:
        """Open questions that travel with a child into the synthesis.

        Score meanings stay separate here too: these are gaps, not numbers,
        so they append to the brief as facts rather than entering any
        aggregation.
        """
        gaps = []
        try:
            failed = db.query(AgentRun).filter(
                AgentRun.investigation_id == inv_id,
                AgentRun.status == "error").count()
        except Exception:
            failed = 0
        if failed:
            gaps.append(f"{failed} run(s) failed or interrupted")
        try:
            pending = db.query(Artifact).filter(
                Artifact.investigation_id == inv_id,
                Artifact.review != "accepted").count()
        except Exception:
            pending = 0
        if pending:
            gaps.append(f"{pending} artifact(s) still pending review")
        try:
            latest = db.query(SecurityAssessment).filter(
                SecurityAssessment.investigation_id == inv_id).order_by(
                SecurityAssessment.id.desc()).first()
        except Exception:
            latest = None
        if latest is not None:
            try:
                scoring = json.loads(latest.scoring_json or "{}") or {}
            except Exception:
                scoring = {}
            path = scoring.get("assessment_path") or "standard"
            if path == "model_engineering":
                try:
                    model_json = json.loads(
                        getattr(latest, "model_json", None) or "{}") or {}
                except Exception:
                    model_json = {}
                deferred = (model_json.get("mitigation") or {}).get(
                    "deferred") or []
                if deferred:
                    gaps.append(f"{len(deferred)} deferred mitigation(s): "
                                + ", ".join(
                                    d.get("control_id", "?")
                                    for d in deferred[:4]))
            elif path == "model_hypothesis":
                try:
                    from . import dossier as _dossier
                    claims = _dossier.hypothesis_register(latest)
                except Exception:
                    claims = []
                open_h = [c.get("hypothesis_id") or c.get("id") for c in claims
                          if (c.get("status") or "untested") in
                          ("untested", "contested")]
                if open_h:
                    gaps.append(f"open falsifiers: {', '.join(open_h[:5])}")
            try:
                stats = {}
                if latest.run_id:
                    run = db.query(AgentRun).filter(
                        AgentRun.id == latest.run_id).first()
                    stats = json.loads((run.stats if run else None)
                                       or "{}") or {}
            except Exception:
                stats = {}
            if not isinstance(stats, dict) or \
                    stats.get("assessment_id") is None:
                gaps.append("latest assessment has incomplete stats")
        return gaps

    briefs = []
    topics_risks: list[tuple[str, list[dict[str, Any]]]] = []
    topic_gaps: list[tuple[str, list[str]]] = []
    for c in row["children"]:
        inv = db.query(Investigation).filter(
            Investigation.id == c["investigation_id"]).first()
        rec = (db.query(SecurityAssessment)
               .filter(SecurityAssessment.investigation_id == c["investigation_id"])
               .order_by(SecurityAssessment.id.desc()).first())
        md = ""
        threats: list[Any] = []
        if rec is not None:
            if rec.markdown:
                md = rec.markdown[:COMPILE_TRUNC]
            try:
                threats = json.loads(rec.threats_json or "[]")
            except Exception:
                threats = []
        arts = (db.query(Artifact)
                .filter(Artifact.investigation_id == c["investigation_id"]).count())
        risks = topic_top_risks(threats)
        topics_risks.append((c["title"], risks))
        gaps = _child_gaps(c["investigation_id"])
        if gaps:
            topic_gaps.append((c["title"], gaps))
        briefs.append(
            f"## {c['title']}\n"
            f"Residual {getattr(rec, 'residual_pct', None)} "
            f"(overall {getattr(rec, 'overall_pct', None)}), "
            f"{arts} artifacts.\n{md}"
            + (f"\nOpen gaps: {'; '.join(gaps)}." if gaps else ""))
    plan = {}
    try:
        plan = json.loads(run.plan_json or "{}")
    except Exception:
        plan = {}
    overlaps = find_overlaps(topics_risks)
    lapses = find_lapses(topics_risks)
    tables = render_summary_tables(topics_risks, overlaps, lapses)
    text = llm.chat(
        [{"role": "system",
          "content": ("You are given fact tables (top risks, overlaps, lapses) "
                      "plus assessment briefs. Do NOT repeat the tables. Reply "
                      "markdown with: overall verdict in two sentences, "
                      "cross-cutting patterns across topics, what the evidence "
                      "does not cover, and concrete next steps. Ground every "
                      "claim in the briefs; invent nothing.")},
         {"role": "user",
          "content": f"Command: {run.command}\n\n{tables}\n\n" + "\n\n".join(briefs)}],
        max_tokens=3000, temperature=0.2)
    gaps_section = ""
    if topic_gaps:
        gaps_section = ("\n## Open gaps by topic\n\n"
                        "Not scores — work still owed, carried into the "
                        "stored synthesis so it survives the LLM paraphrase.\n\n"
                        + "".join(f"### {title}\n"
                                  + "".join(f"- {g}\n" for g in gaps)
                                  for title, gaps in topic_gaps))
    markdown = (tables + gaps_section + _provider_section(db, plan, row)
                + "\n## Synthesis\n\n" + (text or "").strip() + "\n")
    art = Artifact(investigation_id=summary_id,
                   title=f"Manager synthesis (run #{run.id})",
                   artifact_type="research",
                   description=f"Synthesis of {len(briefs)} investigations.",
                   content=markdown, source="agentic-manager",
                   tags=SYNTH_TAG)
    db.add(art)
    summ = db.query(Investigation).filter(
        Investigation.id == summary_id).first()
    if summ is not None:
        summ.status = "ready"
    run.status = "compiled"
    db.commit()
    db.refresh(art)
    return {"artifact_id": art.id, "summary_investigation_id": summary_id,
            "markdown": markdown, "existing": False}


class PendingChildren(Exception):
    def __init__(self, pending: list[str]):
        super().__init__("children still running")
        self.pending = pending


def _provider_section(db, plan: dict[str, Any],
                      row: dict[str, Any]) -> str:
    """Deterministic provider-posture compare for posture runs.

    Returns "" for non-posture runs. Like the gaps section, this is computed,
    not generated, so the compare table survives the LLM paraphrase intact --
    and a run with no PDP findings still says which questions are open rather
    than rendering an empty table.
    """
    from . import provider_posture as _pp
    topics = plan.get("topics") or []
    if (plan.get("domain") or "") != "provider_data_privacy_agi" and not any(
            (t.get("task") or "") == "provider_data_posture" for t in topics
            if isinstance(t, dict)):
        return ""
    children = row.get("children") or []
    per_provider: list[tuple[str, list[dict[str, Any]]]] = []
    for t, c in zip(topics, children):
        if not isinstance(t, dict) or not isinstance(c, dict):
            continue
        inv_id = (c.get("investigation_id")
                  or (t.get("investigation_id") if isinstance(t, dict) else None))
        findings: list[dict[str, Any]] = []
        if inv_id:
            rec = (db.query(SecurityAssessment)
                   .filter(SecurityAssessment.investigation_id == inv_id)
                   .order_by(SecurityAssessment.id.desc()).first())
            if rec is not None:
                try:
                    findings = json.loads(getattr(rec, "pdp_json", None)
                                          or "[]")
                except Exception:
                    findings = []
                if isinstance(findings, dict):
                    findings = findings.get("findings") or []
        provider = str(t.get("subject") or t.get("title") or "?")
        per_provider.append((provider, findings if isinstance(findings, list)
                             else []))
    if not per_provider:
        return ""
    L = ["\n## Provider data posture compare", "",
         "Standing per dimension and provider. `partial` means a source "
         "exists, not that the practice is confirmed; `unknown` means no "
         "accepted evidence was assessed. No scores here by design -- a "
         "number would read as safety from lab training, which nothing "
         "measured.", ""]
    header = "| Dimension | " + " | ".join(p for p, _ in per_provider) + " |"
    L.append(header)
    L.append("|" + "---|" * (len(per_provider) + 1))
    for d in _pp.PDP_DIMENSIONS:
        cells = []
        for _, findings in per_provider:
            f = next((x for x in findings if x.get("id") == d["id"]), None)
            cells.append(f.get("standing", "unknown") if f else "unknown")
        L.append(f"| {d['id']} {d['name']} | " + " | ".join(cells) + " |")
    L.append("")
    L.append("### Am I a datapoint? (per provider)")
    L.append("")
    for provider, findings in per_provider:
        L.append(f"#### {provider}")
        L.append("")
        cmap = _pp.contribution_map([])
        L.append(_pp.datapoint_summary(provider, findings, cmap))
        L.append("")
    L.append("### Indirect contribution map")
    L.append("")
    L.append("```mermaid")
    L.append(_pp.contribution_mermaid(_pp.contribution_map([]),
                                      provider="provider"))
    L.append("```")
    L.append("")
    L.append("Dashed paths are possible-but-unevidenced shapes; solid paths "
             "activate only from stated situations or findings. The public "
             "web is common to all labs.")
    L.append("")
    return "\n".join(L)


def manager_links(db) -> dict[str, Any]:
    """Child investigation -> summary mapping for the AKM sidebar.

    Latest run wins when an investigation appears in several plans.
    Pure reads; the sidebar degrades to a flat list when this fails.
    """
    from .models import ManagerRun
    links: dict[str, Any] = {}
    summaries: dict[str, Any] = {}
    for run in db.query(ManagerRun).order_by(ManagerRun.id).all():
        try:
            plan = json.loads(run.plan_json or "{}")
        except Exception:
            continue
        topics = plan.get("topics") or []
        topic_ids = [t.get("investigation_id") for t in topics
                     if isinstance(t, dict) and t.get("investigation_id")]
        sid = run.summary_investigation_id
        if sid:
            summaries[str(sid)] = {"run_id": run.id,
                                   "command": run.command or "",
                                   "topic_ids": topic_ids}
        for iid in topic_ids:
            links[str(iid)] = {"summary_id": sid, "run_id": run.id}
    return {"links": links, "summaries": summaries}


TOP_RISKS_PER_TOPIC = 5
LAPSE_COVERAGE_PCT = 50.0


def topic_top_risks(threats: list[Any], n: int = TOP_RISKS_PER_TOPIC) -> list[dict[str, Any]]:
    """Worst-first threat rows, trimmed to the fields the summary needs."""
    rows = [t for t in (threats or []) if isinstance(t, dict) and t.get("id")]
    rows.sort(key=lambda t: -(t.get("residual_score") or 0)
              if isinstance(t.get("residual_score"), (int, float)) else -1)
    return [{"id": t.get("id"), "title": t.get("title", ""),
             "residual_severity": t.get("residual_severity"),
             "residual_score": t.get("residual_score"),
             "coverage": t.get("coverage"),
             "controls": t.get("controls") or []} for t in rows[:n]]


def find_overlaps(topics_risks: list[tuple[str, list[dict[str, Any]]]]) -> list[dict[str, Any]]:
    """Threat ids striking in 2+ topics: the common risks. Sorted by reach,
    then worst residual."""
    by_id: dict[str, dict[str, Any]] = {}
    for topic, risks in topics_risks:
        for r in risks:
            cell = by_id.setdefault(r["id"], {"id": r["id"], "title": r["title"],
                                              "topics": [], "residuals": []})
            cell["topics"].append(topic)
            if isinstance(r.get("residual_score"), (int, float)):
                cell["residuals"].append(r["residual_score"])
    out = [c for c in by_id.values() if len(c["topics"]) >= 2]
    for c in out:
        c["max_residual"] = max(c["residuals"]) if c["residuals"] else None
    out.sort(key=lambda c: (-len(c["topics"]),
                            -(c["max_residual"] or 0)))
    return out


def find_lapses(topics_risks: list[tuple[str, list[dict[str, Any]]]]) -> list[dict[str, Any]]:
    """High/Critical residuals with less than half coverage: the lapses."""
    out = []
    for topic, risks in topics_risks:
        for r in risks:
            cov = r.get("coverage")
            cov = float(cov) if isinstance(cov, (int, float)) else 100.0
            if r.get("residual_severity") in ("Critical", "High") \
                    and cov < LAPSE_COVERAGE_PCT:
                out.append({"topic": topic, **r})
    out.sort(key=lambda r: (-(r.get("residual_score") or 0)))
    return out


def render_summary_tables(topics_risks: list[tuple[str, list[dict[str, Any]]]],
                          overlaps: list[dict[str, Any]],
                          lapses: list[dict[str, Any]]) -> str:
    """Deterministic fact sections: present even when the model is terse."""
    L = ["## Top risks by topic", ""]
    for topic, risks in topics_risks:
        L.append(f"### {topic}")
        L.append("")
        L.append("| Threat | Severity | Residual | Coverage | Controls |")
        L.append("|---|---|---|---|---|")
        for r in risks:
            cov = r.get("coverage")
            cov_s = f"{cov:g}%" if isinstance(cov, (int, float)) else "–"
            res = r.get("residual_score")
            res_s = f"{res:g}" if isinstance(res, (int, float)) else "–"
            ctls = ", ".join(r.get("controls") or []) or "–"
            L.append(f"| {r['id']} {r['title']} | {r.get('residual_severity') or '–'} "
                     f"| {res_s} | {cov_s} | {ctls} |")
        L.append("")
    L += ["## Overlaps — common risks", ""]
    if overlaps:
        L.append("| Threat | Topics | Worst residual |")
        L.append("|---|---|---|")
        for o in overlaps:
            mr = f"{o['max_residual']:g}" if isinstance(o.get("max_residual"), (int, float)) else "–"
            L.append(f"| {o['id']} {o['title']} | {len(o['topics'])}: "
                     f"{', '.join(o['topics'])} | {mr} |")
    else:
        L.append("No threat id strikes in more than one topic.")
    L += ["", "## Lapses", ""]
    if lapses:
        L.append("| Topic | Threat | Severity | Residual | Coverage |")
        L.append("|---|---|---|---|---|")
        for r in lapses:
            res = r.get("residual_score")
            res_s = f"{res:g}" if isinstance(res, (int, float)) else "–"
            cov = r.get("coverage")
            cov_s = f"{cov:g}%" if isinstance(cov, (int, float)) else "–"
            L.append(f"| {r['topic']} | {r['id']} {r['title']} | "
                     f"{r.get('residual_severity') or '–'} | {res_s} | {cov_s} |")
    else:
        L.append("No High/Critical residual under half coverage.")
    L.append("")
    return "\n".join(L)


# Stage -> subagent role, per runner kind. Unknown stages fall through to
# the stage name itself so a new event never renders blank.
SUBAGENTS = {
    "manager": {"command": "orchestrator", "plan": "orchestrator",
                "create": "orchestrator", "launch": "orchestrator",
                "compile": "synthesizer"},
    "research": {"plan": "planner", "search": "research-collector",
                 "analyze": "analyzer", "map": "mapper",
                 "summary": "writer", "cve": "cve-sweeper",
                 "queue": "queue"},
    "security": {"plan": "security-orchestrator", "gate": "control-analyst",
                 "controls": "control-analyst", "score": "scoring",
                 "search": "research-collector", "analyze": "threat-intel",
                 "map": "mapper", "summary": "report-writer",
                 "queue": "queue", "cve": "cve-sweeper"},
}

MAX_EVENTS_PER_LANE = 50


def subagent(kind: str, stage: Any) -> str:
    stage = str(stage or "")
    return SUBAGENTS.get(kind, {}).get(stage, stage or "unknown")


def _iso(ts: Any) -> str | None:
    """ISO timestamp, normalized to naive UTC so DB rows and fresh markers
    sort and subtract comparably (SQLite returns naive datetimes)."""
    try:
        if ts is None:
            return None
        if getattr(ts, "tzinfo", None) is not None:
            ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
        return ts.isoformat()
    except Exception:
        return None


def run_timeline(db, run_id: int) -> dict[str, Any]:
    """Execution flow of a manager run: lanes, timestamped subagent actions,
    and a flow strip for the overview. Pure reads; safe to poll."""
    from .models import ManagerRun
    run = db.query(ManagerRun).filter(ManagerRun.id == run_id).first()
    if run is None:
        raise LookupError("manager run not found")
    row = _run_row(db, run)
    try:
        plan = json.loads(run.plan_json or "{}")
    except Exception:
        plan = {}
    topics = plan.get("topics") or []

    lanes = [{"id": "manager", "label": "Manager", "kind": "manager"}]
    for i, t in enumerate(topics):
        lanes.append({"id": f"topic-{t.get('investigation_id') or i}",
                      "label": t.get("title") or f"Topic {i + 1}",
                      "kind": "topic",
                      "investigation_id": t.get("investigation_id")})
    summary_title = ((plan.get("summary") or {}).get("title")
                     or "Summary")
    lanes.append({"id": "summary", "label": summary_title, "kind": "summary",
                  "investigation_id": run.summary_investigation_id})

    events: list[dict[str, Any]] = []

    def ev(ts, lane, agent, stage, label, status="done", ref=None):
        if ts is None:
            return
        events.append({"t": _iso(ts), "lane": lane, "agent": agent,
                       "stage": stage, "label": str(label or "")[:280],
                       "status": status, "ref": ref or {}})

    ev(run.created_at, "manager", "orchestrator", "command",
       f"Command received ({len(run.command or '')} chars)", "done",
       {"type": "run", "id": run.id})
    ev(run.created_at, "manager", "orchestrator", "plan",
       f"Plan: {len(topics)} topics "
       f"({(plan.get('parsed_by') or 'unknown')})", "done",
       {"type": "run", "id": run.id})

    for i, t in enumerate(topics):
        inv_id = t.get("investigation_id")
        lane = f"topic-{inv_id or i}"
        inv = db.query(Investigation).filter(
            Investigation.id == inv_id).first() if inv_id else None
        if inv is not None:
            ev(inv.created_at, lane, "orchestrator", "create",
               f"Investigation #{inv.id} created", "done",
               {"type": "investigation", "id": inv.id})
        if not inv_id:
            continue
        runs = (db.query(AgentRun)
                .filter(AgentRun.investigation_id == inv_id)
                .order_by(AgentRun.id).all())
        for r in runs:
            kind = "security" if (r.trigger or "") == "security" \
                else "research"
            agent = ("security-agent" if kind == "security"
                     else "investigation-agent")
            ev(r.started_at or (r.events[0].created_at if r.events else None),
               lane, agent, "run",
               f"{agent} run #{r.id} started"
               + (f" ({r.trigger})" if r.trigger else ""), "done",
               {"type": "run", "id": r.id})
            for e in (db.query(AgentEvent)
                      # Join, don't just filter by run_id: bulk deletes elsewhere
                      # (query.delete() skips ORM cascades) can orphan events
                      # whose run is gone, and rowid reuse would then attach
                      # ghosts to a later run with the same id.
                      .join(AgentRun, AgentEvent.run_id == AgentRun.id)
                      .filter(AgentEvent.run_id == r.id)
                      .order_by(AgentEvent.id).all()):
                ev(e.created_at, lane, subagent(kind, e.stage), e.stage,
                   e.message, "done", {"type": "run", "id": r.id})
            if (r.status or "") not in ("done", "error"):
                ev(_now(), lane, agent, "run",
                   f"Run #{r.id} {r.status}…", "running",
                   {"type": "run", "id": r.id})
            else:
                ev(r.finished_at, lane, agent, "run",
                   f"Run #{r.id} {r.status}", "done",
                   {"type": "run", "id": r.id})
        rec = (db.query(SecurityAssessment)
               .filter(SecurityAssessment.investigation_id == inv_id)
               .order_by(SecurityAssessment.id.desc()).first())
        if rec is not None:
            ev(rec.created_at, lane, "scoring", "score",
               f"Assessment #{rec.id}: residual {rec.residual_pct}/100", "done",
               {"type": "assessment", "id": rec.id})

    if run.summary_investigation_id:
        synth = (db.query(Artifact)
                 .filter(Artifact.investigation_id == run.summary_investigation_id,
                         Artifact.tags.like(f"%{SYNTH_TAG}%"))
                 .order_by(Artifact.id.desc()).first())
        if synth is not None:
            ev(synth.created_at, "summary", "synthesizer", "compile",
               f"Summary compiled (artifact #{synth.id})", "done",
               {"type": "artifact", "id": synth.id})

    events.sort(key=lambda e: (e["t"] or "", e["lane"]))
    by_lane: dict[str, list] = {}
    for e in events:
        by_lane.setdefault(e["lane"], []).append(e)
    truncated: dict[str, int] = {}
    capped: list[dict[str, Any]] = []
    for lane_id, evs in by_lane.items():
        if len(evs) > MAX_EVENTS_PER_LANE:
            half = MAX_EVENTS_PER_LANE // 2
            truncated[lane_id] = len(evs) - MAX_EVENTS_PER_LANE
            evs = evs[:half] + evs[-(MAX_EVENTS_PER_LANE - half):]
        capped.extend(evs)
    capped.sort(key=lambda e: (e["t"] or "", e["lane"]))

    options = plan.get("options", {})
    children = row.get("children") or []
    r_done = sum(1 for c in children if (c.get("research") or {}).get("done"))
    r_total = sum(1 for _ in children) if options.get("research", True) else 0
    a_done = sum(1 for c in children if c.get("assessment_done"))
    a_total = sum(1 for _ in children) if options.get("assessment", True) else 0
    summ_state = "done" if row.get("compiled") else (
        "active" if row.get("all_done") else "pending")
    flow = [
        {"key": "command", "label": "Command", "state": "done",
         "detail": f"{len(run.command or '')} chars"},
        {"key": "plan", "label": "Plan",
         "state": "done",
         "detail": f"{len(topics)} topics ({plan.get('parsed_by') or '?'})"},
        {"key": "topics", "label": "Investigations",
         "state": "done" if children else "pending",
         "detail": f"{len(children)} created"},
        {"key": "research", "label": "Research",
         "state": ("done" if r_total and r_done >= r_total else
                   "active" if r_done else "pending") if r_total else "pending",
         "detail": f"{r_done}/{r_total} done" if r_total else "skipped"},
        {"key": "assessment", "label": "Assessments",
         "state": ("done" if a_total and a_done >= a_total else
                   "active" if a_done else "pending") if a_total else "pending",
         "detail": f"{a_done}/{a_total} done" if a_total else "skipped"},
        {"key": "summary", "label": "Summary", "state": summ_state,
         "detail": ("compiled" if row.get("compiled") else
                    "ready to compile" if row.get("all_done") else "waiting")},
    ]
    return {"run_id": run.id, "t0": _iso(run.created_at),
            "lanes": lanes, "events": capped, "flow": flow,
            "truncated": truncated}
