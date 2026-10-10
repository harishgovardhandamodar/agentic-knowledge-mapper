"""Tidy dataset export: one investigation as documented, versioned tables.

Every analysis a research group might want to do in R or Python is currently
impossible without scraping the API row by row. This module flattens one
investigation into a small set of tidy tables -- assessments, threats,
controls, artifacts, reviews -- each a list of flat dicts with stable column
names, plus a manifest carrying the schema version and a fingerprint of the
content. Re-exporting the same rows yields the same fingerprint, so a paper
can cite the dataset by hash rather than by "we downloaded it in October".

Design rules, all of which exist to keep a downstream analyst from being
misled:

* A missing value is ``None``, never a default. A legacy row that predates a
  column reports unknown, not zero -- the same rule the API applies.
* Scores are exported alongside the pack version and fingerprint that produced
  them. A residual without its pack is two results wearing one id.
* The calibration block travels with every assessment row. A residual without
  its floor flag and provenance is the exact overclaim the engine was built
  to stop.
* JSON columns are parsed; unparseable ones yield ``None`` for every derived
  field rather than failing the whole export.

Stdlib only. The caller (an API handler) supplies the rows; this module never
touches the database, so it is testable without a fixture database.
"""
from __future__ import annotations

import json
from typing import Any

#: Bump when a table gains, loses, or renames a column, so a consumer can
#: branch on it instead of guessing. The manifest carries this.
DATASET_VERSION = "1"

#: Tables in export order. Fixed so a diff of two exports is meaningful.
TABLES = ("assessments", "threats", "controls", "artifacts", "reviews")


def _load(raw: Any) -> Any:
    try:
        return json.loads(raw) if raw else None
    except Exception:
        return None


def _iso(value: Any) -> str | None:
    try:
        return value.isoformat() if value is not None else None
    except Exception:
        return None


def assessment_row(rec: Any) -> dict[str, Any]:
    """One flat row per assessment, with its calibration block inline."""
    scoring = _load(getattr(rec, "scoring_json", None)) or {}
    floor = scoring.get("floor") or {}
    ev = scoring.get("efficacy_evidence") or {}
    return {
        "assessment_id": getattr(rec, "id", None),
        "investigation_id": getattr(rec, "investigation_id", None),
        "product_name": getattr(rec, "product_name", None),
        "exposure": getattr(rec, "exposure", None),
        "assessment_path": scoring.get("assessment_path"),
        "inherent_pct": getattr(rec, "inherent_pct", None),
        "residual_pct": getattr(rec, "residual_pct", None),
        "posture": getattr(rec, "posture", None),
        "threat_pack_version": getattr(rec, "threat_pack_version", None),
        "threat_pack_fingerprint": getattr(rec, "threat_pack_fingerprint", None),
        "floor_capped": scoring.get("floor_capped"),
        "floor_capped_count": floor.get("floor_capped_count"),
        "controls_beyond_floor": floor.get("controls_beyond_floor"),
        "controls_effective": floor.get("controls_effective"),
        "n_controls": ev.get("n_controls"),
        "n_validated_controls": len(ev.get("validated_controls") or []),
        "n_unvalidated_controls": len(ev.get("unvalidated_controls") or []),
        "created_at": _iso(getattr(rec, "created_at", None)),
    }


def threat_rows(rec: Any) -> list[dict[str, Any]]:
    """One row per scored threat, keyed to its assessment."""
    scoring = _load(getattr(rec, "scoring_json", None)) or {}
    out = []
    for t in scoring.get("threats") or []:
        if not isinstance(t, dict):
            continue
        out.append({
            "assessment_id": getattr(rec, "id", None),
            "threat_id": t.get("id"),
            "title": t.get("title"),
            "stride": t.get("stride"),
            "owasp": t.get("owasp"),
            "likelihood": t.get("likelihood"),
            "impact": t.get("impact"),
            "inherent_score": t.get("inherent_score"),
            "residual_score": t.get("residual_score"),
            "residual_severity": t.get("residual_severity"),
            "coverage": t.get("coverage"),
            "controls": list(t.get("controls") or []),
            "applicability": t.get("applicability"),
            "applicable": t.get("applicable"),
            "floor_capped": t.get("floor_capped"),
        })
    return out


def control_rows(rec: Any) -> list[dict[str, Any]]:
    """One row per declared control, with its trial counts where recorded."""
    scoring = _load(getattr(rec, "scoring_json", None)) or {}
    ctl = _load(getattr(rec, "controls_json", None)) or {}
    active = ctl.get("active_controls") or scoring.get("active_controls") or []
    records = ((scoring.get("efficacy_evidence") or {}).get("records") or {})
    floor_ids = set((scoring.get("floor") or {})
                     .get("controls_beyond_floor_ids") or [])
    out = []
    for cid in active:
        prov = records.get(cid) or {}
        out.append({
            "assessment_id": getattr(rec, "id", None),
            "control_id": cid,
            "declared_efficacy": prov.get("declared"),
            "posterior_mean": prov.get("posterior_mean"),
            "basis": prov.get("basis"),
            "n_observations": prov.get("n_observations"),
            "n_held": prov.get("n_held"),
            "n_breached": prov.get("n_breached"),
            "validated": prov.get("validated"),
            "beyond_floor": cid in floor_ids,
        })
    return out


def artifact_row(art: Any, investigation_id: Any = None) -> dict[str, Any]:
    """One row per artifact. Content is never exported -- digests, not text.

    A dataset that carried full artifact text would be a redistribution
    mechanism for third-party content. Hashes let a consumer deduplicate and
    join without that.
    """
    import hashlib

    def _digest(text: Any) -> str | None:
        if not text:
            return None
        try:
            return hashlib.sha256(str(text).encode()).hexdigest()[:16]
        except Exception:
            return None

    return {
        "artifact_id": getattr(art, "id", None),
        "investigation_id": (getattr(art, "investigation_id", None)
                             or investigation_id),
        "title": getattr(art, "title", None),
        "artifact_type": getattr(art, "artifact_type", None),
        "source": getattr(art, "source", None),
        "domain": _domain_of(getattr(art, "url", None)),
        "relevance": getattr(art, "relevance", None),
        "review": getattr(art, "review", None),
        "drift": getattr(art, "drift", None),
        "origin": getattr(art, "origin", None),
        "content_digest": _digest(getattr(art, "content", None)),
        "date_published": _iso(getattr(art, "date_published", None)),
    }


def _domain_of(url: Any) -> str | None:
    try:
        host = str(url or "").split("//", 1)[1].split("/", 1)[0]
        return host.split(":")[0].lower() or None
    except Exception:
        return None


def review_rows(reviews: list[dict[str, Any]],
                artifact_id: Any = None) -> list[dict[str, Any]]:
    """One row per recorded review, with the reviewer named.

    Accepts the history-table rows (dicts with reviewer/verdict/note/created).
    A legacy single-verdict artifact with no history contributes no review row
    rather than an unattributed one -- an anonymous accept is not data about
    agreement.
    """
    out = []
    for r in reviews or []:
        if not isinstance(r, dict):
            continue
        if not r.get("reviewer"):
            continue
        out.append({
            "artifact_id": r.get("artifact_id", artifact_id),
            "reviewer": r.get("reviewer"),
            "verdict": r.get("verdict") or r.get("review"),
            "note_present": bool(r.get("note")),
            "created_at": (r.get("created_at").isoformat()
                           if hasattr(r.get("created_at"), "isoformat")
                           else r.get("created_at")),
        })
    return out


def build_dataset(investigation_id: Any, assessments: list[Any],
                  artifacts: list[Any],
                  reviews_by_artifact: dict[Any, list[dict[str, Any]]] | None = None,
                  ) -> dict[str, Any]:
    """Assemble the five tables plus a fingerprinted manifest."""
    from . import repro as R

    reviews_by_artifact = reviews_by_artifact or {}
    tables: dict[str, list[dict[str, Any]]] = {
        "assessments": [assessment_row(r) for r in assessments],
        "threats": [t for r in assessments for t in threat_rows(r)],
        "controls": [c for r in assessments for c in control_rows(r)],
        "artifacts": [artifact_row(a, investigation_id) for a in artifacts],
        "reviews": [rw for a in artifacts
                    for rw in review_rows(reviews_by_artifact.get(a.id, []),
                                          artifact_id=a.id)],
    }
    manifest = R.manifest(
        inputs={"tables": {k: R.canonical(v) for k, v in tables.items()}},
        versions={"dataset_schema": DATASET_VERSION},
        label=f"investigation-{investigation_id}-dataset")
    return {
        "investigation_id": investigation_id,
        "dataset_version": DATASET_VERSION,
        "tables": tables,
        "counts": {k: len(v) for k, v in tables.items()},
        "manifest": manifest,
        "columns": {k: sorted({c for row in v for c in row})
                    for k, v in tables.items()},
        "note": ("Missing values are null, never defaulted. Scores travel "
                 "with the pack version that produced them; residuals travel "
                 "with their floor flag and provenance."),
    }
