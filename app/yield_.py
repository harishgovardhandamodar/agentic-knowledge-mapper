"""What each shape of query has cost and returned, per investigation.

The agent loop's only stopping rule is a fixed round and item budget, so it
spends that budget the same way every time: the planner proposes follow-ups
from a blank slate, nothing carries over between runs, and a query shape that
has returned nothing three rounds running is asked again on the fourth.

This module is the missing memory. It records, per investigation and per
*query shape*, how many candidates the search found, how many survived
analysis, and how many model calls that cost. The loop then orders its planned
queries by observed yield and deprioritises shapes that have repeatedly paid
nothing, which means a fixed budget finally buys more information instead of
the same dead searches.

Two rules keep the signal honest:

* **Cumulative, not per-run.** A shape that kept 0 of 3 from 6 attempts is
  known-bad in a way one round can never show.
* **The signal is a ranking, never a veto.** ``rank_queries`` sorts and trims;
  it does not decide what is worth asking. Suppressing a query shape outright
  would mean an investigation could never discover that a topic it once found
  nothing for has since become interesting.

Stdlib + SQLAlchemy only, like the rest of the persistence layer.
"""
import re
from datetime import UTC, datetime

from .models import QueryShapeYield

#: Words carrying no signal about what a query is *asking for*. Stripping them
#: is what turns "the 2023 alignment tax in practice" and "alignment tax
#: practice" into one shape instead of two rows that each look untried.
_SHAPE_NOISE = frozenset(
    "a an and are as at be been by for from has have how in into is it its of on "
    "or that the their this to was were what when where which who why with "
    "latest best top new recent report paper papers study guide overview "
    "introduction tutorial docs documentation".split())

#: Characters that survive normalization. Anything else is a separator, so
#: "alignment-tax", "alignment/tax" and "alignment tax" agree.
_KEEP = re.compile(r"[^a-z0-9]+")

#: Yield above this is worth repeating first; below ``DEPRIORITIZE_YIELD`` a
#: shape is pushed to the back of the order. The band in between is left in
#: planner order, so a novel shape is never starved by an untried one that
#: happens to sort first.
GOOD_YIELD = 0.15
DEPRIORITIZE_YIELD = 0.02


def shape_of(query: str) -> str:
    """Normalize a query to the shape it represents.

    Order-independent and stopword-free, so word order and filler do not create
    distinct shapes. Capped at the two most distinctive terms, because the tail
    of a long query is usually a constraint ("in 2023", "for beginners") that
    says nothing about the topic.
    """
    words = [w for w in _KEEP.split((query or "").lower()) if w]
    words = [w for w in words
             if w not in _SHAPE_NOISE and len(w) > 2 and not w.isdigit()]
    if not words:
        words = [w for w in _KEEP.split((query or "").lower()) if w]
    if not words:
        return ""
    # Longest first: the most specific term is the best label for the shape.
    # Bare digits are already gone, so a year cannot crowd out a real term on
    # length alone -- "2023" is four characters, "tax" is three.
    words = sorted(set(words), key=lambda w: (-len(w), w))[:2]
    return " ".join(sorted(words))


def yield_of(attempts: int, kept: int, found: int) -> float:
    """Kept-per-attempt, discounted by how much was even there to keep.

    Raw keep rate rewards a shape that returned three weak candidates and kept
    one over a shape that returned forty strong ones and kept four. Dividing by
    the candidate count as well makes the number comparable across shapes whose
    search result sizes differ by an order of magnitude, which is the normal
    case across a web search.
    """
    if not attempts or kept <= 0:
        return 0.0
    supply = max(1.0, float(found or 0))
    return (kept / float(attempts)) * (min(float(kept), supply) / supply)


def cost_of(llm_calls: int, kept: int) -> float:
    """Artifacts bought per model call. Higher is cheaper.

    Kept separate from ``yield_of`` because these answer different questions:
    a shape can find a lot and keep a lot yet be expensive per artifact, which
    matters when the budget is the binding constraint rather than the round
    count.
    """
    if not llm_calls:
        return 0.0
    return kept / float(llm_calls)


def record_yield(db, investigation_id: int, queries: list, *, found: int = 0,
                 kept: int = 0, llm_calls: int = 0) -> list:
    """Credit this round's outcome to every query shape it was spent on.

    One round's result is attributed to the round's whole query set, split
    evenly. Per-query attribution is not available -- the search runs all
    queries and the candidates come back as one undifferentiated list -- and
    pretending otherwise would put confident-looking numbers on the ledger that
    the data cannot support.
    """
    shapes = [s for s in (shape_of(q.get("text") if isinstance(q, dict) else q)
                          for q in (queries or [])) if s]
    if not shapes:
        return []
    now = datetime.now(UTC)
    share_f = float(found) / len(shapes)
    share_k = float(kept) / len(shapes)
    share_c = float(llm_calls) / len(shapes)
    touched = []
    for shape in shapes:
        row = (db.query(QueryShapeYield)
               .filter(QueryShapeYield.investigation_id == investigation_id,
                       QueryShapeYield.shape == shape).first())
        if row is None:
            example = next((q.get("text") for q in queries
                            if isinstance(q, dict)
                            and shape_of(q.get("text")) == shape), None)
            # Counters are set explicitly rather than left to the column
            # defaults: those only apply on INSERT, so a freshly built row reads
            # back as None until it is flushed, and `+= 1` on None raises.
            row = QueryShapeYield(investigation_id=investigation_id, shape=shape,
                                  example=(example or "")[:500] or None,
                                  attempts=0, found=0, kept=0, llm_calls=0)
            db.add(row)
            db.flush()
        row.attempts += 1
        # Rounded so a split share does not leave fractional rows behind.
        row.found += int(round(share_f))
        row.kept += int(round(share_k))
        row.llm_calls += int(round(share_c))
        row.last_seen_at = now
        touched.append(row)
    db.commit()
    return touched


def shape_stats(db, investigation_id: int) -> list:
    """Every recorded shape for an investigation, with its derived numbers."""
    rows = (db.query(QueryShapeYield)
            .filter(QueryShapeYield.investigation_id == investigation_id).all())
    out = []
    for r in rows:
        y = yield_of(r.attempts, r.kept, r.found)
        out.append({
            "shape": r.shape,
            "example": r.example,
            "attempts": r.attempts,
            "found": r.found,
            "kept": r.kept,
            "llm_calls": r.llm_calls,
            "yield": round(y, 4),
            "cost_efficiency": round(cost_of(r.llm_calls, r.kept), 4),
            "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
        })
    out.sort(key=lambda s: (-s["yield"], s["shape"]))
    return out


def rank_queries(db, investigation_id: int, queries: list) -> list:
    """Reorder planned queries by what their shape has historically returned.

    Shapes with a good track record move to the front; repeatedly fruitless ones
    move to the back but are **kept**, because a shape that has found nothing
    yet is exactly the one that might be worth trying again after the corpus has
    changed. Unseen shapes keep their planner position relative to each other,
    and rank ahead of known-bad ones -- novelty is not penalized.
    """
    queries = list(queries or [])
    if not queries:
        return []
    stats = {s["shape"]: s for s in shape_stats(db, investigation_id)}

    def key(item):
        i, q = item
        shape = shape_of(q.get("text") if isinstance(q, dict) else q)
        s = stats.get(shape)
        if s is None:
            # Unseen sits above barren and below proven. A shape with no history
            # has not earned a deprioritisation, and a barren one has not earned
            # a promotion either, so novelty lands between the two.
            band, y = 1, 0.0
        elif s["yield"] >= GOOD_YIELD:
            band, y = 2, s["yield"]
        elif s["yield"] < DEPRIORITIZE_YIELD:
            band, y = 0, s["yield"]
        else:
            band, y = 1, s["yield"]
        # Negated band: sorted() is ascending and proven has to come first.
        return (-band, -y, i)

    return [q for _, q in sorted(enumerate(queries), key=key)]


def suggest_queries(db, investigation_id: int, limit: int = 5) -> list:
    """Untried shapes, most specific first.

    The loop's other way to spend a round productively: rather than re-asking
    what already worked, propose a shape with no history in this investigation.
    """
    seen = {s["shape"] for s in shape_stats(db, investigation_id)}
    from .models import Investigation
    inv = db.get(Investigation, investigation_id)
    if inv is None:
        return []
    from .drift import brief_terms
    terms = sorted(brief_terms(inv.title, inv.keywords, inv.description))
    out, used = [], set()
    for i in range(0, len(terms) - 1):
        pair = " ".join(sorted(terms[i:i + 2]))
        if pair in seen or pair in used:
            continue
        used.add(pair)
        text = f"{terms[i]} {terms[i + 1]} {inv.title}"[:120]
        out.append({"shape": pair, "text": text})
        if len(out) >= limit:
            break
    return out


def clear_yields(db, investigation_id: int) -> int:
    """Forget what has been tried. Explicit, because the memory is the point."""
    n = (db.query(QueryShapeYield)
         .filter(QueryShapeYield.investigation_id == investigation_id)
         .delete(synchronize_session=False))
    db.commit()
    return n


#: Rounds every observed shape is guaranteed before yield decides the rest. This
#: is the difference between a ranking and a starvation: ``rank_queries`` only
#: reorders, but a *budget* split can hand a barren shape zero rounds forever,
#: and a shape that found nothing before is exactly the one a changed corpus can
#: revive. One round is cheap; the discovery it protects is not.
REVISIT_ROUNDS = 1

#: Event thresholds for re-running an assessment. Deliberately few and coarse:
#: a trigger that fires on noise trains the operator to ignore it.
DEFAULT_TRIGGERS = {"drift": 0.35, "new_sources": 5, "max_age_days": 30}


def allocate_rounds(stats, rounds: int, *, revisit: int = REVISIT_ROUNDS) -> list:
    """Split a round budget across observed shapes in proportion to their yield.

    ``stats`` is the output of :func:`shape_stats` (or any list of dicts with
    ``shape`` and ``yield``). Every shape gets the ``revisit`` floor first, then
    the remaining rounds are divided by yield using largest-remainder rounding,
    so the split is exact -- the plan spends *exactly* ``rounds`` and never a
    fractional round. This is what turns the recorded memory into an actual
    decision instead of a sort order.
    """
    rows = list(stats or [])
    n = len(rows)
    if n == 0 or rounds <= 0:
        return []
    revisit = max(0, int(revisit))
    floor = min(revisit, rounds // n)
    alloc = [floor] * n
    remaining = rounds - floor * n
    if remaining > 0:
        weights = [max(0.0, float(s.get("yield") or 0.0)) for s in rows]
        total = sum(weights)
        if total <= 0:
            # Nothing has ever yielded: the floor plus an even split is the only
            # defensible answer, and it keeps every shape alive to be observed.
            weights = [1.0] * n
            total = float(n)
        raw = [remaining * w / total for w in weights]
        alloc = [a + int(r) for a, r in zip(alloc, raw, strict=False)]
        left = rounds - sum(alloc)
        order = sorted(range(n), key=lambda i: (-(raw[i] - int(raw[i])), i))
        for i in order[:left]:
            alloc[i] += 1
    out = [{"shape": rows[i]["shape"], "example": rows[i].get("example"),
            "yield": round(float(rows[i].get("yield") or 0.0), 4),
            "rounds": alloc[i]} for i in range(n)]
    out.sort(key=lambda e: (-e["rounds"], e["shape"]))
    return out


def plan_rounds(db, investigation_id: int, rounds: int) -> dict:
    """A concrete spend plan for the next ``rounds``, from recorded yield.

    Returns the per-shape allocation plus the round split, so a caller can name
    where the budget goes and why. When nothing has been recorded yet the plan is
    empty and the caller keeps its default behaviour -- the planner advises, it
    does not invent history.
    """
    stats = shape_stats(db, investigation_id)
    alloc = allocate_rounds(stats, rounds)
    return {
        "rounds": rounds,
        "allocated": sum(a["rounds"] for a in alloc),
        "plan": alloc,
        "unseen_shapes": max(0, rounds - sum(a["rounds"] for a in alloc)),
    }


def stale_shapes(stats, *, now: datetime, max_age_days: int = 30) -> list:
    """Shapes not observed since ``max_age_days`` -- due for a re-probe.

    Ageing is the counterweight to yield: a shape once barren may simply have
    been asked before the corpus held anything. This surfaces those, oldest
    first, without touching the live ranking.
    """
    out = []
    for s in stats or []:
        iso = s.get("last_seen_at")
        if not iso:
            continue
        try:
            last = datetime.fromisoformat(iso)
        except ValueError:
            continue
        if last.tzinfo is None:
            last = last.replace(tzinfo=UTC)
        age = (now - last).total_seconds() / 86400.0
        if age >= max_age_days:
            out.append({"shape": s["shape"], "age_days": round(age, 1)})
    out.sort(key=lambda e: -e["age_days"])
    return out


def reassessment_triggers(*, drift_score: float = 0.0, new_sources: int = 0,
                          threat_pack_changed: bool = False,
                          days_since_run: float | None = None,
                          thresholds: dict | None = None) -> dict:
    """Decide whether changed conditions warrant re-running an assessment.

    An assessment is a snapshot, but the world it describes keeps moving: the
    corpus drifts, new sources arrive, the threat pack gets a version. Re-running
    on a timer is either wasteful or too late; re-running on an *event* is the
    right trigger. Each firing reason is named so the re-run can say what
    changed, and two independent reasons (or a threat-pack bump, which
    invalidates the whole crosswalk) escalate urgency.
    """
    t = {**DEFAULT_TRIGGERS, **(thresholds or {})}
    reasons = []
    if drift_score >= t["drift"]:
        reasons.append(f"corpus drift {drift_score:.2f} >= {t['drift']}")
    if new_sources >= t["new_sources"]:
        reasons.append(f"{new_sources} new sources >= {t['new_sources']}")
    if threat_pack_changed:
        reasons.append("threat pack version changed")
    if days_since_run is not None and days_since_run >= t["max_age_days"]:
        reasons.append(f"age {days_since_run:.0f}d >= {t['max_age_days']}d")
    if threat_pack_changed or len(reasons) >= 2:
        urgency = "high"
    elif reasons:
        urgency = "normal"
    else:
        urgency = "none"
    return {"triggered": bool(reasons), "reasons": reasons, "urgency": urgency}
