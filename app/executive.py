"""Executive / leadership dashboard: availability, distribution, robustness.

The management plane on top of the analyst Landscape. Landscape answers "what
is true about this model"; this module answers the questions a CISO, security
lead or manager asks about the whole portfolio:

- **Availability** — do we have a usable, fresh landscape? Coverage, staleness,
  unknowns, sync health. Traffic lights plus tables, never one number.
- **Distribution** — where does risk concentrate? By layer, scope, family,
  exposure, initiative, pattern, status, plus deterministic insight cards.
- **Robustness** — how well are identified risks owned, mitigated, validated
  and kept current? Mapping rates, acceptance discipline, approval hygiene,
  pack hygiene. Always with a limitations block: nothing here claims the
  absence of breach.

Design rules, inherited from the rest of the system:

1. **Read-only aggregates, no new scoring.** Every number is a count a reader
   can recompute from the rows it names. The register is read with stored human
   state overlaid and nothing persisted.
2. **No composite "secure %".** Percentages always carry their sample size
   ("12 of 20 models"); an empty denominator reports ``null``, not zero.
3. **Unknown inflates attention, never robustness.** Pending artifacts are not
   evidence; a row nobody owns is a finding, not a gap in the chart.
4. **No cross-path merging.** Model misuse potential and hypothesis confidence
   are never averaged into product residual; layers stay separate everywhere.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any

EXECUTIVE_METHOD = "executive_v1"
EXECUTIVE_VERSION = "1.0.0"

#: Severity bands, shared with the portfolio metrics so a "High" means the
#: same thing on both tabs.
HIGH = 60.0
CRITICAL = 80.0

DEFAULT_WINDOW_DAYS = 90
APPROVAL_SLA_DAYS = 7
REASSESS_SLA_DAYS = 30
TOP_N = 8


def _load(raw: Any, default: Any = None) -> Any:
    if raw is None:
        return default
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return default


def _pct(num: int, den: int) -> dict[str, Any]:
    """A percentage that always carries its sample size.

    ``None``, not 0: "no risks are owned" is not 0% coverage when there are no
    risks to own. Every consumer must render ``n`` and ``of`` next to the
    number -- a bare percent without a denominator is how unknowns hide.
    """
    return {"pct": (round(100.0 * num / den, 1) if den else None),
            "n": num, "of": den}


def _age_days(ts: Any) -> int | None:
    if not ts:
        return None
    try:
        return max(0, (datetime.utcnow() - ts).days)
    except Exception:
        return None


def _median(values: list[float]) -> float | None:
    if not values:
        return None
    s = sorted(values)
    n = len(s)
    return round((s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2.0), 1)


# --------------------------------------------------------------------------
# scope
# --------------------------------------------------------------------------

def resolve_scope(db, inv_id: int, window_days: int = DEFAULT_WINDOW_DAYS,
                  initiative_id: int | None = None,
                  layer: str | None = None, exposure: str | None = None,
                  accepted_only: bool = True) -> dict[str, Any]:
    """The dashboard's read scope. Validated, never defaulted silently.

    ``accepted_only`` (default on) counts only accepted artifacts as evidence;
    turning it off includes pending artifacts and the numbers move
    predictably -- which the attention queue and the tests both pin.
    """
    from .models import Initiative, Investigation
    inv = db.get(Investigation, inv_id)
    if inv is None:
        raise LookupError(f"investigation {inv_id} not found")
    ini = None
    if initiative_id is not None:
        ini = db.get(Initiative, initiative_id)
        if ini is None or ini.investigation_id != inv_id:
            raise LookupError(f"initiative {initiative_id} not found")
    try:
        window = max(1, int(window_days))
    except (TypeError, ValueError):
        window = DEFAULT_WINDOW_DAYS
    if layer and layer not in ("product", "model", "privacy", "supply_chain"):
        raise ValueError(f"unknown layer: {layer}")
    return {
        "investigation_id": inv_id, "window_days": window,
        "cutoff": datetime.utcnow() - timedelta(days=window),
        "initiative_id": initiative_id,
        "initiative_title": ini.title if ini else None,
        "layer": layer, "exposure": exposure,
        "accepted_only": bool(accepted_only),
    }


def _assessments(db, inv_id: int) -> list[Any]:
    from .models import SecurityAssessment
    return (db.query(SecurityAssessment)
            .filter(SecurityAssessment.investigation_id == inv_id)
            .order_by(SecurityAssessment.id).all())


def _is_model_assessment(rec: Any) -> bool:
    return bool(getattr(rec, "model_json", None))


def scoped_register(db, inv_id: int, scope: dict[str, Any],
                    landscape: dict[str, Any] | None = None
                    ) -> list[dict[str, Any]]:
    """Register rows inside the scope, with stored human state, read-only."""
    from . import portfolio as _pf
    rows = _pf.register_with_state(db, inv_id, landscape)
    if scope.get("initiative_id") is not None:
        aids = {r.id for r in _assessments(db, inv_id)
                if r.initiative_id == scope["initiative_id"]}
        rows = [r for r in rows
                if _pf._as_ints(r.get("assessment_ids")) & aids]
    if scope.get("layer"):
        rows = [r for r in rows if r.get("layer") == scope["layer"]]
    if scope.get("exposure"):
        # a row with no recorded exposure cannot satisfy an exposure filter;
        # excluding it is honest, and the count of excluded rows is reported
        rows = [r for r in rows if r.get("exposure") == scope["exposure"]]
    return rows


def _evidence_index(db, inv_id: int, accepted_only: bool = True
                    ) -> dict[int, dict[str, Any]]:
    """Artifacts by id, with standing. Pending is not evidence.

    ``accepted_only=False`` admits pending artifacts too, so the toggle moves
    the freshness and validation numbers predictably instead of being decor.
    Rejected artifacts are never evidence under either setting.
    """
    from .models import Artifact
    out = {}
    for a in (db.query(Artifact)
              .filter(Artifact.investigation_id == inv_id).all()):
        if a.review == "rejected":
            continue
        if accepted_only and a.review != "accepted":
            continue
        out[a.id] = {"accepted": a.review == "accepted",
                     "age_days": _age_days(a.created_at or a.date_published),
                     "drift": bool(a.drift),
                     "type": a.artifact_type, "title": a.title}
    return out


# --------------------------------------------------------------------------
# availability
# --------------------------------------------------------------------------

def availability(db, inv_id: int, scope: dict[str, Any] | None = None,
                 landscape: dict[str, Any] | None = None,
                 rows: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Do we have a usable, fresh landscape? Lights plus tables."""
    from . import model_kb as _kb
    from .model_kb import norm_key
    scope = scope or resolve_scope(db, inv_id)
    land = landscape if landscape is not None else _kb.landscape(db, inv_id)
    recs = _assessments(db, inv_id)
    cutoff = scope["cutoff"]

    inits = _initiatives(db, inv_id)
    assessed_ids = {r.initiative_id for r in recs
                    if r.initiative_id and r.created_at and r.created_at >= cutoff}
    uncovered_inits = [{"id": i.id, "title": i.title, "owner": i.owner,
                        "link": {"view": "portfolio", "tab": "initiatives",
                                 "initiative_id": i.id}}
                       for i in inits if i.id not in assessed_ids]
    initiative_coverage = _pct(len(inits) - len(uncovered_inits), len(inits))

    # models: inventoried keys vs assessments whose stored metadata names them
    inv_models = [m.get("model_key") for m in (land.get("inventory") or [])
                  if m.get("model_key")]
    covered_models: set[str] = set()
    for r in recs:
        meta = (_load(r.model_json, {}) or {}).get("meta") or {}
        name = meta.get("model_name") or ""
        if name:
            covered_models.add(norm_key(name))
        snap = _load(getattr(r, "kb_json", None), None)
        if isinstance(snap, dict) and snap.get("model_key"):
            covered_models.add(str(snap["model_key"]))
    uncovered_models = [m for m in inv_models if m not in covered_models]
    model_coverage = _pct(len(inv_models) - len(uncovered_models),
                          len(inv_models))

    # products: assessed names vs ones with a catalog assessment behind them
    products: dict[str, dict[str, Any]] = {}
    for r in recs:
        if _is_model_assessment(r):
            continue
        p = products.setdefault(r.product_name or "unnamed", {"catalog": False})
        if getattr(r, "threat_pack_version", None):
            p["catalog"] = True
    uncovered_products = sorted(k for k, v in products.items()
                                if not v["catalog"])
    product_coverage = _pct(len(products) - len(uncovered_products),
                            len(products))

    rows = rows if rows is not None else scoped_register(db, inv_id, scope, land)
    open_rows = [r for r in rows if r.get("status") == "open"]
    complete = [r for r in open_rows if r.get("owner") and r.get("review_by")]
    completeness = _pct(len(complete), len(open_rows))

    ev = _evidence_index(db, inv_id, scope["accepted_only"])
    high_open = [r for r in open_rows if (r.get("severity") or 0) >= HIGH]
    ages, missing = [], 0
    for r in high_open:
        found = [ev[e]["age_days"] for e in (r.get("evidence_ids") or [])
                 if e in ev and ev[e]["age_days"] is not None]
        if found:
            ages.extend(found)
        else:
            missing += 1
    freshness = {"median_age_days": _median(ages), "samples": len(ages),
                 "open_high_without_evidence": missing,
                 "accepted_only": scope["accepted_only"],
                 "note": ("Median age of accepted evidence behind open High+ "
                          "risks. Pending artifacts are excluded while "
                          "accepted-only is on.")}

    accepted_ts = sorted(
        ((a.created_at or a.date_published) for a in _artifacts(db, inv_id)
         if a.review == "accepted" and (a.created_at or a.date_published)),
        reverse=True)
    stale = []
    for r in recs:
        if not r.created_at:
            continue
        newer = [t for t in accepted_ts if t > r.created_at]
        if newer:
            stale.append({"assessment_id": r.id,
                          "product_name": r.product_name,
                          "assessed_days_ago": _age_days(r.created_at),
                          "newer_evidence": len(newer),
                          "link": {"view": "landscape", "tab": "risk",
                                   "assessment_id": r.id}})

    # W2 unknowns across the scorecard
    from . import model_eval as _me
    dims_total = len(_me.ADOPTION_DIMENSIONS)
    unknown = sum(len(s.get("w2_unknown_dimensions") or [])
                  for s in (land.get("scorecard") or []))
    models_scored = len(land.get("scorecard") or [])
    unknown_burden = _pct(unknown, models_scored * dims_total)

    model_recs = [r for r in recs if _is_model_assessment(r)]
    synced = 0
    for r in model_recs:
        snap = _load(getattr(r, "kb_json", None), None)
        if isinstance(snap, dict) and not snap.get("skipped"):
            synced += 1
    kb_health = _pct(synced, len(model_recs))

    lights = [
        _light("initiative coverage", initiative_coverage["pct"],
               f"{initiative_coverage['n']} of {initiative_coverage['of']} "
               "initiatives assessed in-window"),
        _light("model coverage", model_coverage["pct"],
               f"{model_coverage['n']} of {model_coverage['of']} "
               "inventoried models assessed"),
        _light("register completeness", completeness["pct"],
               f"{completeness['n']} of {completeness['of']} open risks "
               "have an owner and a review date"),
        _light("evidence freshness",
               100.0 if not high_open else
               (0.0 if missing else 100.0) if freshness["median_age_days"] is None
               else (100.0 if freshness["median_age_days"] <= scope["window_days"]
                     else 50.0),
               f"median evidence age "
               f"{freshness['median_age_days']}d over "
               f"{freshness['samples']} samples; "
               f"{missing} open High+ without evidence"),
        _light("staleness", 100.0 if not stale else 0.0,
               f"{len(stale)} assessment(s) predate accepted evidence"),
        _light("KB sync health", kb_health["pct"],
               f"{kb_health['n']} of {kb_health['of']} model assessments "
               "synced"),
    ]
    return {
        "method": EXECUTIVE_METHOD, "version": EXECUTIVE_VERSION,
        "scope": _public_scope(scope),
        "lights": lights,
        "initiative_coverage": initiative_coverage,
        "uncovered_initiatives": uncovered_inits,
        "model_coverage": model_coverage,
        "uncovered_models": uncovered_models,
        "product_coverage": product_coverage,
        "uncovered_products": uncovered_products,
        "register_completeness": completeness,
        "evidence_freshness": freshness,
        "stale_assessments": stale,
        "unknown_burden": {**unknown_burden,
                           "models_scored": models_scored,
                           "dimensions_each": dims_total},
        "kb_sync_health": kb_health,
        "note": ("Availability is a set of lights plus the tables behind "
                 "them, not one number. An empty denominator reads as "
                 "unknown, never as covered."),
    }


def _light(area: str, pct: float | None, reason: str) -> dict[str, Any]:
    if pct is None:
        state = "unknown"
    elif pct >= 99.5:
        state = "green"
    elif pct >= 70.0:
        state = "amber"
    else:
        state = "red"
    return {"area": area, "state": state, "pct": pct, "reason": reason}


def _initiatives(db, inv_id: int) -> list[Any]:
    from .models import Initiative
    return (db.query(Initiative)
            .filter(Initiative.investigation_id == inv_id)
            .order_by(Initiative.id).all())


def _artifacts(db, inv_id: int) -> list[Any]:
    from .models import Artifact
    return (db.query(Artifact)
            .filter(Artifact.investigation_id == inv_id).all())


def _public_scope(scope: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in scope.items() if k != "cutoff"}


# --------------------------------------------------------------------------
# distribution
# --------------------------------------------------------------------------

def _count_by(rows: list[dict[str, Any]], key) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for r in rows:
        k = key(r)
        cell = out.setdefault(str(k), {"total": 0, "open": 0, "open_high": 0})
        cell["total"] += 1
        if r.get("status") == "open":
            cell["open"] += 1
            if (r.get("severity") or 0) >= HIGH:
                cell["open_high"] += 1
    return out


def distribution(db, inv_id: int, scope: dict[str, Any] | None = None,
                 landscape: dict[str, Any] | None = None,
                 rows: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Where risk and effort sit. Layers stay separate; nothing is averaged."""
    from . import model_kb as _kb
    from .models import AgentRun
    scope = scope or resolve_scope(db, inv_id)
    land = landscape if landscape is not None else _kb.landscape(db, inv_id)
    rows = rows if rows is not None else scoped_register(db, inv_id, scope, land)

    by_layer = _count_by(rows, lambda r: r.get("layer") or "unknown")
    by_scope = _count_by(rows, lambda r: r.get("scope") or "own")
    by_status = _count_by(rows, lambda r: r.get("status") or "open")
    by_exposure = _count_by(
        rows, lambda r: r.get("exposure") or "unknown")

    assess_by_id = {r.id: r for r in _assessments(db, inv_id)}
    inits = {i.id: i.title for i in _initiatives(db, inv_id)}

    def _family(r: dict[str, Any]) -> str:
        if r.get("layer") == "model":
            aids = [int(x) for x in (r.get("assessment_ids") or [])
                    if str(x).isdigit()]
            rec = assess_by_id.get(aids[0]) if aids else None
            meta = (_load(getattr(rec, "model_json", None), {}) or {}
                    ).get("meta") or {} if rec else {}
            return str(meta.get("model_family") or r.get("model_key")
                       or "unknown")
        if r.get("layer") == "supply_chain":
            return "supply-chain"
        return str(r.get("product_name") or "unknown")

    by_family = _count_by(rows, _family)
    top_families = sorted(by_family.items(),
                          key=lambda kv: (-kv[1]["open_high"], -kv[1]["total"])
                          )[:TOP_N]

    def _pattern(r: dict[str, Any]) -> str:
        if r.get("layer") == "model":
            return f"model:{r.get('attack_class') or r.get('source_ref')}"
        return str(r.get("source_ref") or "unknown")

    by_pattern = _count_by(rows, _pattern)
    top_patterns = sorted(by_pattern.items(),
                          key=lambda kv: (-kv[1]["open_high"], -kv[1]["total"])
                          )[:TOP_N]

    def _initiative(r: dict[str, Any]) -> str:
        aids = [int(x) for x in (r.get("assessment_ids") or [])
                if str(x).isdigit()]
        titles = sorted({inits.get(assess_by_id[a].initiative_id, "unlinked")
                         for a in aids if a in assess_by_id
                         and assess_by_id[a].initiative_id} or {"unlinked"})
        return titles[0] if len(titles) == 1 else f"{titles[0]} (+{len(titles)-1})"

    by_initiative = _count_by(rows, _initiative)

    # assessment volume from stored runs, per day in-window
    runs = (db.query(AgentRun)
            .filter(AgentRun.investigation_id == inv_id).all())
    volume: dict[str, dict[str, int]] = {}
    run_status: dict[str, int] = {}
    awaiting = 0
    for run in runs:
        run_status[run.status] = run_status.get(run.status, 0) + 1
        if run.status == "awaiting_approval":
            awaiting += 1
        day = (run.started_at or run.finished_at)
        if day and day >= scope["cutoff"]:
            cell = volume.setdefault(day.strftime("%Y-%m-%d"),
                                     {"done": 0, "error": 0, "other": 0})
            cell["done" if run.status == "done"
                 else "error" if run.status == "error" else "other"] += 1

    cards = _insight_cards(rows, by_family, by_scope)
    return {
        "method": EXECUTIVE_METHOD, "version": EXECUTIVE_VERSION,
        "scope": _public_scope(scope),
        "register_total": len(rows),
        "by_layer": by_layer, "by_scope": by_scope,
        "by_status": by_status, "by_exposure": by_exposure,
        "by_family": by_family,
        "top_families": [{"name": k, **v} for k, v in top_families],
        "by_pattern": by_pattern,
        "top_patterns": [{"pattern": k, **v} for k, v in top_patterns],
        "by_initiative": by_initiative,
        "assessment_volume": {"per_day": volume, "by_status": run_status,
                              "awaiting_approval": awaiting},
        "insight_cards": cards,
        "note": ("Counts, never a blended score. Model misuse potential and "
                 "hypothesis confidence are not averaged into product "
                 "residual anywhere on this tab."),
    }


def _insight_cards(rows: list[dict[str, Any]],
                   by_family: dict[str, dict[str, int]],
                   by_scope: dict[str, dict[str, int]]) -> list[dict[str, Any]]:
    """Deterministic concentration statements, each with its numbers."""
    cards = []
    high_model = [r for r in rows if r.get("layer") == "model"
                  and r.get("status") == "open"
                  and (r.get("severity") or 0) >= HIGH]
    if high_model:
        fams = {}
        for r in high_model:
            fams[r.get("model_key") or "unknown"] = \
                fams.get(r.get("model_key") or "unknown", 0) + 1
        top = sorted(fams.items(), key=lambda kv: -kv[1])[:2]
        cards.append({
            "text": (f"{len(high_model)} open High model risk(s) spread over "
                     f"{len(fams)} model(s); the top "
                     f"{len(top)} account(s) for {sum(v for _, v in top)} "
                     f"of them ({', '.join(k for k, _ in top)})."),
            "link": {"view": "portfolio", "layer": "model",
                     "status": "open"},
        })
    casc = [r for r in rows if r.get("scope") == "cascade"
            and r.get("status") == "open"]
    if casc:
        cards.append({
            "text": (f"{len(casc)} open cascade risk(s): composition created "
                     f"them, so no base-model control closes them. Review "
                     f"the composed path, not the model card."),
            "link": {"view": "portfolio", "layer": "model",
                     "status": "open"},
        })
    unowned = [r for r in rows if r.get("status") == "open"
               and not r.get("owner") and (r.get("severity") or 0) >= HIGH]
    if unowned:
        cards.append({
            "text": (f"{len(unowned)} open High+ risk(s) have no owner. "
                     f"Unowned risk is a finding, not a gap in the chart."),
            "link": {"view": "portfolio", "status": "open"},
        })
    return cards


# --------------------------------------------------------------------------
# robustness
# --------------------------------------------------------------------------

def robustness(db, inv_id: int, scope: dict[str, Any] | None = None,
               landscape: dict[str, Any] | None = None,
               rows: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """How well identified risks are owned, mitigated, validated, current."""
    from . import model_eval as _me
    from . import portfolio as _pf
    from . import threatpack as _tp
    from .models import AgentRun, CveFinding, Job
    scope = scope or resolve_scope(db, inv_id)
    land = landscape if landscape is not None else _land(db, inv_id)
    rows = rows if rows is not None else scoped_register(db, inv_id, scope, land)
    open_high = [r for r in rows if r.get("status") == "open"
                 and (r.get("severity") or 0) >= HIGH]

    mapped = [r for r in open_high
              if (r.get("control_options") or r.get("mitigation_ids"))]
    mapping_rate = _pct(len(mapped), len(open_high))

    def _validated(r: dict[str, Any]) -> bool:
        cov = r.get("control_coverage") or {}
        if cov.get("evidenced"):
            return True
        return bool(r.get("mitigation_ids"))

    validated = [r for r in mapped if _validated(r)]
    validation_rate = _pct(len(validated), len(mapped))

    accepted = [r for r in rows if r.get("status") == "accepted"]
    disciplined = [r for r in accepted
                   if r.get("accepted_by") and r.get("acceptance_note")
                   and r.get("review_by")]
    acceptance = _pct(len(disciplined), len(accepted))

    pack = _pf.advise(db, inv_id, register=rows, landscape=land)
    lift_items = [a for a in pack["advice"] if a["controls"]]
    lifted = [a for a in lift_items
              if any(c.get("inventory_status") in ("deployed", "partial")
                     for c in a["controls"])]
    inventory_lift = _pct(len(lifted), len(lift_items))

    now = datetime.utcnow()
    awaiting = []
    for run in (db.query(AgentRun)
                .filter(AgentRun.investigation_id == inv_id,
                        AgentRun.status == "awaiting_approval").all()):
        age = _age_days(run.started_at)
        awaiting.append({"run_id": run.id, "trigger": run.trigger,
                         "age_days": age,
                         "over_sla": age is not None
                         and age > APPROVAL_SLA_DAYS,
                         "link": {"view": "runs", "run_id": run.id}})
    violations, unverifiable = [], 0
    run_ids = {r.id for r in
               (db.query(AgentRun)
                .filter(AgentRun.investigation_id == inv_id).all())}
    jobs = (db.query(Job).filter(Job.run_id.in_(run_ids)).all()
            if run_ids else [])
    for job in jobs:
        params = (_load(job.payload_json, {}) or {}).get("params", {})
        if not isinstance(params, dict):
            continue
        asked, approved = params.get("requested_by"), params.get("approved_by")
        if not approved:
            continue
        if not asked:
            unverifiable += 1
        elif _same_actor(asked, approved):
            violations.append({"job_id": job.id, "run_id": job.run_id,
                               "actor": approved})
    approval_hygiene = {
        "awaiting": awaiting,
        "awaiting_over_sla": sum(1 for a in awaiting if a["over_sla"]),
        "sla_days": APPROVAL_SLA_DAYS,
        "self_approval_violations": violations,
        "unverifiable_approvals": unverifiable,
    }

    closure = _hypothesis_closure(db, inv_id)
    reassess = _reassess_followup(db, inv_id, scope)

    current_pack = _tp.PACK_VERSION
    pack_dist: dict[str, int] = {}
    superseded: list[int] = []
    for r in _assessments(db, inv_id):
        v = getattr(r, "threat_pack_version", None)
        if _is_model_assessment(r):
            continue
        pack_dist[str(v or "unstamped")] = \
            pack_dist.get(str(v or "unstamped"), 0) + 1
        if v and v != current_pack:
            superseded.append(r.id)
    pack_hygiene = {
        "current_pack_version": current_pack,
        "distribution": pack_dist,
        "superseded_assessment_ids": sorted(superseded),
        "note": ("Assessments on a superseded pack are not wrong; they were "
                 "scored under different arithmetic and should be re-read "
                 "before being quoted."),
    }

    limitations = [
        "Literature-only evidence bounds what any control claim can mean: a "
        "mapped control reduces a modeled risk, it does not report a measured "
        "production residual.",
        "Declared-but-unevidenced controls count as gaps here, never as "
        "coverage.",
        "MM residuals are indicative: benchmarks lag novel attacks and a "
        "passing gate is not a proof.",
        "Robustness is process depth, not a claim of zero breach. No widget "
        "on this tab implies measured production risk.",
    ]
    return {
        "method": EXECUTIVE_METHOD, "version": EXECUTIVE_VERSION,
        "scope": _public_scope(scope),
        "mitigation_mapping_rate": mapping_rate,
        "validation_rate": validation_rate,
        "acceptance_discipline": acceptance,
        "inventory_lift": inventory_lift,
        "approval_hygiene": approval_hygiene,
        "hypothesis_closure": closure,
        "reassess_on_change": reassess,
        "pack_hygiene": pack_hygiene,
        "limitations": limitations,
    }


def _same_actor(a: Any, b: Any) -> bool:
    return str(a or "").strip().lower() == str(b or "").strip().lower() \
        and bool(str(a or "").strip())


def _hypothesis_closure(db, inv_id: int) -> dict[str, Any]:
    """Open falsifiers with a planned experiment, per claim register."""
    from . import dossier as _dz
    open_f, covered = 0, 0
    assessments = 0
    for rec in _assessments(db, inv_id):
        if not getattr(rec, "hypothesis_json", None):
            continue
        assessments += 1
        claims = _dz.hypothesis_register(rec)
        planned = _load(getattr(rec, "hypothesis_json", None), {}) or {}
        targets = {t for e in (planned.get("experiments") or [])
                   if isinstance(e, dict)
                   for t in ((e.get("targets") or {}).get("hypothesis_ids")
                             or [])}
        for c in claims:
            fals = [str(f).strip() for f in (c.get("falsifiers") or [])
                    if str(f).strip()]
            if not fals or c.get("status") in ("supported", "refuted"):
                continue
            open_f += 1
            if (c.get("hypothesis_id") or c.get("id")) in targets:
                covered += 1
    return {"open_falsifiers": open_f, "with_planned_experiment": covered,
            "closure": _pct(covered, open_f),
            "assessments_with_hypotheses": assessments,
            "note": ("A falsifier with no experiment is an open question, "
                     "not a closed one.")}


def _reassess_followup(db, inv_id: int, scope: dict[str, Any]
                       ) -> dict[str, Any]:
    """Intel triggers that produced a follow-up assessment within SLA."""
    from .models import CveFinding
    recs = _assessments(db, inv_id)
    by_subject: dict[str, list[Any]] = {}
    for r in recs:
        meta = (_load(r.model_json, {}) or {}).get("meta") or {}
        subj = str(meta.get("model_name") or r.product_name or "unknown")
        by_subject.setdefault(subj, []).append(r)
    for v in by_subject.values():
        v.sort(key=lambda r: r.created_at or datetime.min)
    triggers = 0
    followed = 0
    pending_items = []
    accepted_ts = sorted(
        ((a.created_at or a.date_published) for a in _artifacts(db, inv_id)
         if a.review == "accepted" and (a.created_at or a.date_published)))
    for subj, series in by_subject.items():
        for i, r in enumerate(series):
            if not r.created_at:
                continue
            trigger_at = next((t for t in accepted_ts if t > r.created_at),
                              None)
            if trigger_at is None:
                continue
            triggers += 1
            later = [x for x in series[i + 1:]
                     if x.created_at
                     and (x.created_at - trigger_at).days <= REASSESS_SLA_DAYS]
            if later:
                followed += 1
            else:
                pending_items.append({
                    "assessment_id": r.id, "subject": subj,
                    "trigger_days_ago": _age_days(trigger_at),
                    "link": {"view": "landscape", "tab": "risk",
                             "assessment_id": r.id}})
    cves = (db.query(CveFinding)
            .filter(CveFinding.investigation_id == inv_id).all())
    return {"triggers": triggers, "followed_up": followed,
            "followup_rate": _pct(followed, triggers),
            "sla_days": REASSESS_SLA_DAYS,
            "pending": pending_items,
            "open_cves": len(cves)}


def _land(db, inv_id: int) -> dict[str, Any]:
    from . import model_kb as _kb
    return _kb.landscape(db, inv_id)


# --------------------------------------------------------------------------
# attention queue
# --------------------------------------------------------------------------

def attention(db, inv_id: int, scope: dict[str, Any] | None = None,
              landscape: dict[str, Any] | None = None,
              rows: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Ranked actions. Rank formula is documented per item, not hidden.

    Risk items score ``severity`` (0-100). Process items score on fixed,
    stated bands: overdue approvals 70+age (capped), new CVEs 60, missing
    acceptance review 50, stale assessments 40, uncovered initiatives 30.
    """
    scope = scope or resolve_scope(db, inv_id)
    land = landscape if landscape is not None else _land(db, inv_id)
    rows = rows if rows is not None else scoped_register(db, inv_id, scope, land)
    items: list[dict[str, Any]] = []
    for r in rows:
        sev = r.get("severity") or 0
        if r.get("status") == "open" and sev >= HIGH and not r.get("owner"):
            items.append({
                "kind": "unowned_open_high", "rank_score": round(sev, 1),
                "rank_why": f"severity {sev}, no owner",
                "title": f"{r['risk_id']} ({r['layer']}) has no owner",
                "detail": r.get("title") or "",
                "link": {"view": "portfolio", "risk_id": r["risk_id"],
                         "status": "open"}})
        if r.get("status") == "open" and sev >= HIGH and not \
                (r.get("control_options") or r.get("mitigation_ids")):
            items.append({
                "kind": "unmapped_open_high", "rank_score": round(sev, 1),
                "rank_why": f"severity {sev}, no mapped control",
                "title": f"{r['risk_id']} ({r['layer']}) has no mapped control",
                "detail": "Open the mitigation advisor for this risk id.",
                "link": {"view": "portfolio", "tab": "advice",
                         "risk_id": r["risk_id"]}})
        if r.get("status") == "accepted" and not r.get("review_by"):
            items.append({
                "kind": "acceptance_missing_review", "rank_score": 50.0,
                "rank_why": "accepted with no review date",
                "title": (f"{r['risk_id']} accepted by "
                          f"{r.get('accepted_by') or '?'} with no review date"),
                "detail": r.get("acceptance_note") or "",
                "link": {"view": "portfolio", "risk_id": r["risk_id"],
                         "status": "accepted"}})
    rob = robustness(db, inv_id, scope, land, rows)
    for a in rob["approval_hygiene"]["awaiting"]:
        if a["over_sla"]:
            items.append({
                "kind": "approval_over_sla",
                "rank_score": 70.0 + min(a["age_days"] or 0, 30),
                "rank_why": (f"awaiting approval for {a['age_days']}d "
                             f"(SLA {APPROVAL_SLA_DAYS}d)"),
                "title": f"Approval waiting {a['age_days']}d "
                         f"(run {a['run_id']})",
                "detail": "",
                "link": a["link"]})
    for v in rob["approval_hygiene"]["self_approval_violations"]:
        items.append({
            "kind": "self_approval", "rank_score": 95.0,
            "rank_why": "requester approved their own run",
            "title": f"Self-approval on run {v['run_id']} by {v['actor']}",
            "detail": "",
            "link": {"view": "runs", "run_id": v["run_id"]}})
    avail = availability(db, inv_id, scope, land, rows)
    for s in avail["stale_assessments"]:
        items.append({
            "kind": "stale_assessment", "rank_score": 40.0,
            "rank_why": (f"{s['newer_evidence']} newer evidence item(s) "
                         "than the score"),
            "title": (f"{s['product_name']} scored {s['assessed_days_ago']}d "
                      "ago, evidence moved on"),
            "detail": "",
            "link": s["link"]})
    for u in avail["uncovered_initiatives"]:
        items.append({
            "kind": "uncovered_initiative", "rank_score": 30.0,
            "rank_why": "no assessment in-window",
            "title": f"Initiative '{u['title']}' has no assessment in-window",
            "detail": "",
            "link": {"view": "portfolio", "tab": "initiatives",
                     "initiative_id": u["id"]}})
    from .models import CveFinding
    for c in (db.query(CveFinding)
              .filter(CveFinding.investigation_id == inv_id).all()):
        items.append({
            "kind": "open_cve", "rank_score": 60.0,
            "rank_why": f"known issue {c.cve_id} open",
            "title": f"{c.cve_id}: {(c.title or '')[:100]}",
            "detail": "",
            "link": {"view": "cves", "cve_id": c.cve_id}})
    items.sort(key=lambda i: (-i["rank_score"], i["kind"], i["title"]))
    return {"method": EXECUTIVE_METHOD, "version": EXECUTIVE_VERSION,
            "scope": _public_scope(scope), "items": items,
            "total": len(items),
            "note": ("Ranked by stated bands, highest first. A queue with no "
                     "items means nothing triggered, not that nothing is "
                     "wrong.")}


# --------------------------------------------------------------------------
# summary, snapshots, trends, brief
# --------------------------------------------------------------------------

def summary(db, inv_id: int, scope: dict[str, Any] | None = None
            ) -> dict[str, Any]:
    """The header strip: lights, open High/Critical, approvals, stale."""
    from . import model_kb as _kb
    scope = scope or resolve_scope(db, inv_id)
    land = _land(db, inv_id)
    rows = scoped_register(db, inv_id, scope, land)
    avail = availability(db, inv_id, scope, land, rows)
    dist = distribution(db, inv_id, scope, land, rows)
    open_high = [r for r in rows if r.get("status") == "open"
                 and (r.get("severity") or 0) >= HIGH]
    open_critical = [r for r in open_high if (r.get("severity") or 0)
                     >= CRITICAL]
    return {
        "method": EXECUTIVE_METHOD, "version": EXECUTIVE_VERSION,
        "scope": _public_scope(scope),
        "lights": avail["lights"],
        "open_high": len(open_high),
        "open_critical": len(open_critical),
        "register_total": len(rows),
        "pending_approvals": dist["assessment_volume"]["awaiting_approval"],
        "stale_count": len(avail["stale_assessments"]),
        "unowned_high": sum(1 for r in open_high if not r.get("owner")),
        "by_layer_open_high": {k: v["open_high"]
                               for k, v in dist["by_layer"].items()},
        "note": ("One screen for coverage, concentration, staleness and "
                 "pending decisions. Drill into the sections below; every "
                 "number names its rows."),
    }


def snapshot_metrics(db, inv_id: int,
                     scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """The compact rollup a daily snapshot stores for trends."""
    scope = scope or resolve_scope(db, inv_id)
    land = _land(db, inv_id)
    rows = scoped_register(db, inv_id, scope, land)
    open_high = [r for r in rows if r.get("status") == "open"
                 and (r.get("severity") or 0) >= HIGH]
    owned = [r for r in rows if r.get("owner")]
    assessed = len({a for r in rows for a in (r.get("assessment_ids") or [])})
    return {
        "date": datetime.utcnow().strftime("%Y-%m-%d"),
        "register_total": len(rows),
        "open_high": len(open_high),
        "owned_share": _pct(len(owned), len(rows)),
        "assessments": len(_assessments(db, inv_id)),
        "initiatives": len(_initiatives(db, inv_id)),
        "models": len(land.get("inventory") or []),
    }


def write_snapshot(db, inv_id: int, metrics: dict[str, Any] | None = None,
                   scope_hash: str = "default") -> dict[str, Any]:
    """Persist one daily rollup. Idempotent per day per scope."""
    from .models import DashboardSnapshot
    metrics = metrics if metrics is not None else snapshot_metrics(db, inv_id)
    day = metrics.get("date") or datetime.utcnow().strftime("%Y-%m-%d")
    exists = (db.query(DashboardSnapshot)
              .filter(DashboardSnapshot.investigation_id == inv_id,
                      DashboardSnapshot.scope_hash == scope_hash).all())
    if any((s.created_at or datetime.min).strftime("%Y-%m-%d") == day
           for s in exists):
        return {"written": False, "reason": "snapshot for today exists",
                "date": day}
    row = DashboardSnapshot(investigation_id=inv_id, scope_hash=scope_hash,
                            metrics_json=json.dumps(metrics))
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"written": True, "id": row.id, "date": day}


def snapshots(db, inv_id: int, days: int = 90) -> list[dict[str, Any]]:
    """Stored rollups in-window, oldest first. Gaps stay gaps."""
    from .models import DashboardSnapshot
    cutoff = datetime.utcnow() - timedelta(days=max(1, days))
    out = []
    for s in (db.query(DashboardSnapshot)
              .filter(DashboardSnapshot.investigation_id == inv_id,
                      DashboardSnapshot.created_at >= cutoff)
              .order_by(DashboardSnapshot.created_at).all()):
        m = _load(s.metrics_json, {}) or {}
        m["snapshot_id"] = s.id
        out.append(m)
    return out


def brief_markdown(db, inv_id: int, scope: dict[str, Any] | None = None
                   ) -> str:
    """Board-safe leadership brief from the same payloads as the tab."""
    from .models import Investigation
    scope = scope or resolve_scope(db, inv_id)
    inv = db.get(Investigation, inv_id)
    land = _land(db, inv_id)
    rows = scoped_register(db, inv_id, scope, land)
    summ = summary(db, inv_id, scope)
    avail = availability(db, inv_id, scope, land, rows)
    dist = distribution(db, inv_id, scope, land, rows)
    rob = robustness(db, inv_id, scope, land, rows)
    attn = attention(db, inv_id, scope, land, rows)
    L: list[str] = []
    A = L.append
    A(f"# Leadership brief — {inv.title if inv else inv_id}")
    A("")
    A(f"_Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC · "
      f"investigation #{inv_id} · {EXECUTIVE_METHOD} v{EXECUTIVE_VERSION} · "
      f"window {scope['window_days']}d · "
      f"accepted-only evidence {'on' if scope['accepted_only'] else 'off'}_")
    A("")
    A("## Coverage at a glance")
    A("")
    for light in summ["lights"]:
        mark = {"green": "OK", "amber": "WATCH",
                "red": "ACT", "unknown": "?"}[light["state"]]
        A(f"- **[{mark}] {light['area']}** — {light['reason']}")
    A(f"- **Open High+**: {summ['open_high']} "
      f"({summ['open_critical']} Critical) of {summ['register_total']} risks")
    A(f"- **Pending approvals**: {summ['pending_approvals']} · "
      f"**Stale assessments**: {summ['stale_count']}")
    A("")
    A("## Where risk concentrates")
    A("")
    for fam in dist["top_families"][:5]:
        A(f"- {fam['name']}: {fam['total']} risk(s), "
          f"{fam['open_high']} open High+")
    for card in dist["insight_cards"]:
        A(f"- {card['text']}")
    A("")
    A("## How well risks are handled")
    A("")
    for label, m in (("Mitigation mapped (open High+)",
                      rob["mitigation_mapping_rate"]),
                     ("Validated (of mapped)", rob["validation_rate"]),
                     ("Acceptance disciplined", rob["acceptance_discipline"]),
                     ("Inventory reuse in advice", rob["inventory_lift"])):
        if m["pct"] is None:
            A(f"- {label}: unknown ({m['n']} of {m['of']})")
        else:
            A(f"- {label}: {m['pct']}% ({m['n']} of {m['of']})")
    A(f"- Approvals awaiting: "
      f"{len(rob['approval_hygiene']['awaiting'])} "
      f"({rob['approval_hygiene']['awaiting_over_sla']} over SLA); "
      f"self-approval violations: "
      f"{len(rob['approval_hygiene']['self_approval_violations'])}")
    A("")
    A("## Attention queue (top 10)")
    A("")
    if not attn["items"]:
        A("- Nothing triggered. That means no trigger fired, not that "
          "nothing is wrong.")
    for item in attn["items"][:10]:
        A(f"- **{item['title']}** — {item['rank_why']}")
    A("")
    A("## Limitations (read before quoting)")
    A("")
    for lim in rob["limitations"]:
        A(f"- {lim}")
    A("")
    A(f"Pack hygiene: {rob['pack_hygiene']['current_pack_version']} current; "
      f"{len(rob['pack_hygiene']['superseded_assessment_ids'])} "
      f"assessment(s) on superseded packs.")
    return "\n".join(L) + "\n"

