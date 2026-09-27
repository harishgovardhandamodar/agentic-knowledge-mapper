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
from datetime import datetime, timezone

from .models import QueryShapeYield
from .database import SessionLocal

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
    now = datetime.now(timezone.utc)
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
        out.append({"shape": pair, "text": f"{terms[i]} {terms[i + 1]} {inv.title}"[:120]})
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
