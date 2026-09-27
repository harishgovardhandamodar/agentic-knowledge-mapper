"""Proactive recommendations, computed from what is already on disk.

The system holds everything needed to tell a user what to do next -- the brief,
the collected corpus, the residual scoring, the control catalogue, the yield
history -- and computes none of it. Everything here is pull-only, on demand, and
runs without a model call.

The reason that matters is that these numbers are the *result* of an analysis
somebody paid for. A control-leverage figure is the difference between two calls
to ``score_assessment``, a pure function, so recommending "C04 would cut your
residual by 6.1" is arithmetic on an existing result rather than a fresh guess.
Each recommendation therefore names the evidence it came from, so a user can
tell the difference between "you have 0 coverage of X" and something invented.

Four recommenders, each answering a question a person would otherwise have to
ask the data by hand:

* ``coverage_gaps`` -- which dimensions of the brief have nothing at all.
* ``control_leverage`` -- which single control would most reduce residual risk.
* ``stale_brief`` -- when the corpus has moved on from the brief.
* ``digest`` -- all of the above, ranked, in one call.

None of them schedule anything or mutate state. Recommending is cheap and
reversible; acting is the caller's decision.
"""
import json
from datetime import datetime, timedelta, timezone

from .drift import brief_terms, ngrams

#: Below this many artifacts a brief is too thin to draw a coverage conclusion
#: from. Recommending a gap in a corpus of two items is noise, not insight.
MIN_CORPUS_FOR_COVERAGE = 3

#: Days after which a brief is called stale, relative to its newest artifact.
STALE_AFTER_DAYS = 30

#: Two n-grams of shared vocabulary is the bar for "this artifact is about the
#: same thing as the brief". Same reasoning as the drift prefilter.
_MIN_NGRAM_OVERLAP = 2

_SEV = {"high": 2, "medium": 1, "low": 0}


def _sev(s):
    return _SEV.get(s, 0)


def _terms(text):
    return brief_terms(text or "", "", "")


def _artifacts(db, inv_id):
    from .models import Artifact
    return (db.query(Artifact)
            .filter(Artifact.investigation_id == inv_id).all())


def coverage_gaps(db, inv_id, limit: int = 10) -> list:
    """Brief dimensions with nothing collected against them.

    A term counts as covered when an artifact shares its stem, not its exact
    spelling. Exact-token matching reports "reward misspecification" as a gap
    when the corpus is full of "reward hacking" papers, which is the noise that
    would make a user stop reading the digest.

    A gap is only reported when the corpus is large enough for its absence to
    mean something, and each one carries the term that is missing so the
    suggestion is actionable rather than a shrug.
    """
    from .models import Investigation
    inv = db.get(Investigation, inv_id)
    if inv is None:
        return []
    arts = _artifacts(db, inv_id)
    if len(arts) < MIN_CORPUS_FOR_COVERAGE:
        return []

    brief = _terms(f"{inv.title} {inv.keywords} {inv.description}")
    if not brief:
        return []
    covered = set()
    corpus_grams = set()
    for a in arts:
        text = f"{a.title} {a.tags or ''} {a.description or ''}"
        covered |= _terms(text)
        corpus_grams |= ngrams(text)

    gaps = []
    for term in sorted(brief - covered):
        # A term the corpus already touches at the stem level is a wording
        # difference, not a hole in the research.
        if len(ngrams(term) & corpus_grams) >= _MIN_NGRAM_OVERLAP:
            continue
        gaps.append({
            "term": term,
            "kind": "coverage",
            "severity": "medium" if len(term) > 5 else "low",
            "why": (f"no collected artifact touches '{term}', which the brief "
                    f"names explicitly"),
            "suggestion": f"run a collection pass targeting '{term}'",
        })
    gaps.sort(key=lambda g: (-_sev(g["severity"]), g["term"]))
    return gaps[:limit]


def stale_brief(db, inv_id, now=None) -> list:
    """The brief has not been revisited since the corpus last moved.

    Reported only when artifacts have actually arrived since, so this is "you
    have new evidence your brief predates" rather than "your brief is old" --
    which on its own is not a finding.
    """
    from .models import Investigation
    inv = db.get(Investigation, inv_id)
    if inv is None:
        return []
    arts = [a for a in _artifacts(db, inv_id) if a.created_at]
    if not arts:
        return []
    now = now or datetime.now(timezone.utc)

    def aware(dt):
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

    latest = max(aware(a.created_at) for a in arts)
    brief_at = aware(inv.created_at) if inv.created_at else None
    if brief_at is None:
        return []
    days = (latest - brief_at).days
    if days < STALE_AFTER_DAYS:
        return []
    new_since = sum(1 for a in arts if aware(a.created_at) > brief_at)
    return [{
        "kind": "stale_brief",
        "severity": "high" if days >= STALE_AFTER_DAYS * 2 else "medium",
        "why": (f"{new_since} artifacts have been collected in the {days} days "
                f"since the brief was written"),
        "suggestion": ("re-read the brief and confirm the questions it asks are "
                       "still the questions worth asking"),
    }]


def control_leverage(db, inv_id, assessment_id=None) -> list:
    """Which single inactive control would most reduce residual risk.

    Each figure is the difference between two evaluations of the same pure
    ``score_assessment`` function -- the one stored, and the one that would
    result from adding that one control. No model is consulted and no number
    here is estimated; it is the exact change the engine would produce.

    Ranked by absolute residual reduction, so the top entry is the single
    highest-value control the user could enable.
    """
    from .models import SecurityAssessment
    q = db.query(SecurityAssessment)
    if assessment_id is not None:
        rec = q.filter(SecurityAssessment.id == assessment_id).first()
        if rec is None:
            return []
    else:
        rec = (q.filter(SecurityAssessment.investigation_id == inv_id)
               .order_by(SecurityAssessment.id.desc()).first())
    if rec is None:
        return []

    try:
        stored = json.loads(rec.threats_json or "[]")
    except Exception:
        return []
    if not stored:
        return []
    try:
        scoring = json.loads(rec.scoring_json or "{}")
    except Exception:
        scoring = {}
    try:
        controls = json.loads(rec.controls_json or "{}")
    except Exception:
        controls = {}
    active = {str(c).upper() for c in
              (controls.get("active_controls") or scoring.get("active_controls") or [])}

    # The stored residual rows do not carry inherent likelihood, and it is
    # recoverable: residual_likelihood = L*(1-coverage), floored. Rebuild the
    # baseline the same way rescore_security_assessment does, so the numbers
    # here are comparable to what that endpoint would return.
    from .security import (_THREAT_CATALOG, EXPOSURE_META, _scale_likelihood,
                           control_catalog, score_assessment)
    exposure = rec.exposure if rec.exposure in EXPOSURE_META else "confidential_data"
    weight = float(EXPOSURE_META[exposure]["weight"])
    inherent = [{"id": t[0], "title": t[1], "stride": t[2], "owasp": t[3],
                 "likelihood": float(_scale_likelihood(t[4], weight)),
                 "impact": float(t[5]), "description": t[6],
                 "mitigations": list(t[7])}
                for t in _THREAT_CATALOG]
    applicability = None
    if isinstance(scoring.get("applicability"), dict):
        applicability = scoring["applicability"]
    if not applicability:
        try:
            plan = controls.get("control_plan") or {}
            if isinstance(plan.get("applicability"), dict):
                applicability = plan["applicability"]
        except Exception:
            applicability = None

    base = score_assessment(exposure, inherent, active_controls=sorted(active),
                            applicability=applicability)
    out = []
    for c in control_catalog():
        cid = str(c.get("id", "")).upper()
        if not cid or cid in active:
            continue
        trial = score_assessment(exposure, inherent,
                                 active_controls=sorted(active | {cid}),
                                 applicability=applicability)
        cut = round(base["residual_pct"] - trial["residual_pct"], 1)
        if cut <= 0:
            # Diminishing returns: a control can be real and still move nothing
            # once its coverage is already provided. Not worth surfacing.
            continue
        out.append({
            "kind": "control_leverage",
            "control_id": cid,
            "severity": "high" if cut >= 5 else ("medium" if cut >= 2 else "low"),
            "residual_cut": cut,
            "residual_after": trial["residual_pct"],
            "why": (f"enabling {cid} takes residual risk from "
                    f"{base['residual_pct']}% to {trial['residual_pct']}%"),
            "suggestion": f"enable control {cid}",
        })
    out.sort(key=lambda r: (-r["residual_cut"], r["control_id"]))
    return out


def barren_queries(db, inv_id) -> list:
    """Query shapes that have been asked repeatedly and returned nothing.

    The collector's own memory turned inside out: instead of "here is what to
    try next", "here is what has been costing you and paying nothing".
    """
    from . import yield_ as yld
    rows = yld.shape_stats(db, inv_id)
    out = []
    for s in rows:
        if s["kept"] > 0 or s["attempts"] < 2:
            continue
        out.append({
            "kind": "barren_query",
            "shape": s["shape"],
            "severity": "medium" if s["attempts"] >= 3 else "low",
            "why": (f"'{s['shape']}' found {s['found']} candidates and kept 0 "
                    f"across {s['attempts']} attempts ({s['llm_calls']} model "
                    f"calls spent)"),
            "suggestion": f"stop asking '{s['shape']}', or rephrase the question",
        })
    out.sort(key=lambda g: -_sev(g["severity"]))
    return out


def digest(db, inv_id, *, assessment_id=None, limit: int = 8) -> dict:
    """Every recommendation, ranked, in one call.

    ``recommended`` is the headline: when it is empty, there is genuinely nothing
    to suggest, which is a different statement from "the system has no opinion"
    and worth being able to make.
    """
    recs = []
    recs += coverage_gaps(db, inv_id)
    recs += stale_brief(db, inv_id)
    recs += control_leverage(db, inv_id, assessment_id=assessment_id)
    recs += barren_queries(db, inv_id)
    recs.sort(key=lambda r: (-_sev(r["severity"]), r["kind"], r.get("term", "")))
    by_kind = {}
    for r in recs:
        by_kind[r["kind"]] = by_kind.get(r["kind"], 0) + 1
    return {
        "investigation": inv_id,
        "total": len(recs),
        "recommended": recs[:limit],
        "truncated": max(0, len(recs) - limit),
        "by_kind": by_kind,
        "by_severity": {
            s: sum(1 for r in recs if r["severity"] == s)
            for s in ("high", "medium", "low")
        },
    }
