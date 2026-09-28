"""Known-issue (CVE) collection for investigations.

Every investigation accumulates mentions of specific vulnerabilities --
"EchoLeak (CVE-2025-32711)" in a security report, a CVE in a paper or a
snippet -- and those mentions used to stay buried in prose. This module lifts
them into first-class records:

* a ``CveFinding`` row per (investigation, CVE) with date, description,
  standing, severity and impact -- what the Known Issues tab lists;
* a lightweight ``Artifact`` of type ``cve`` per finding, so the knowledge
  graph shows them as their own colored nodes with edges back to the artifact
  that mentioned them.

Enrichment is best-effort and fail-open, like everything that touches the
network here: NVD first, CIRCL as fallback, and an honest ``unknown`` record
when neither answers. A CVE with no enrichment is still collected -- an ID
with no metadata beats no ID at all.

Collection runs in two places: on demand (``POST .../cves/collect``), and
automatically at the end of every agent run, so new investigations pick it up
without anyone remembering to click. Both paths are idempotent -- re-running
collects only what is new.
"""
import json
import re
import time
from datetime import datetime, timezone

import httpx

from .database import SessionLocal
from .models import Artifact, CveFinding, Investigation, Relationship, SecurityAssessment

#: CVE-YYYY-NNNNN, case-insensitive on input, stored upper-case.
CVE_RE = re.compile(r"\bCVE-(?:19|20)\d{2}-\d{4,7}\b", re.IGNORECASE)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CIRCL_URL = "https://cve.circl.lu/api/cve"
NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/"

#: Politeness gap between metadata calls. NVD allows a handful of requests per
#: window without a key; hammering it gets this IP throttled for everyone.
FETCH_GAP_S = 2.0

SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"]
SEVERITY_RELEVANCE = {"critical": 0.95, "high": 0.8, "medium": 0.6,
                      "low": 0.4, "unknown": 0.3}


def _now():
    return datetime.now(timezone.utc)


def extract_cves(*texts) -> list:
    """CVE ids mentioned across the given texts, upper-cased, first-seen order."""
    seen = []
    for text in texts:
        if not text:
            continue
        for m in CVE_RE.finditer(str(text)):
            cve = m.group(0).upper()
            if cve not in seen:
                seen.append(cve)
    return seen


def severity_of(score) -> str:
    """CVSS base score to a severity band. No score, no claim."""
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


def _parse_nvd(payload: dict, cve_id: str) -> dict | None:
    vulns = payload.get("vulnerabilities") or []
    if not vulns:
        return None
    cve = (vulns[0] or {}).get("cve") or {}
    if (cve.get("id") or "").upper() != cve_id:
        return None
    desc = ""
    for d in cve.get("descriptions") or []:
        if (d.get("lang") or "").lower() == "en" and d.get("value"):
            desc = d["value"]
            break
    if not desc and cve.get("descriptions"):
        desc = (cve["descriptions"][0] or {}).get("value") or ""
    score, vector = None, ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = cve.get("metrics", {}).get(key) or []
        if metrics:
            data = (metrics[0] or {}).get("cvssData") or {}
            score = data.get("baseScore", score)
            vector = data.get("vectorString", vector) or vector
            if score is not None:
                break
    severity = severity_of(score)
    impact = ""
    if vector:
        # CVSS vector carries the CIA triad, e.g. .../C:H/I:H/A:N -- the
        # shortest honest statement of what breaks.
        triad = re.findall(r"/([CIA]):([HLN])", vector)
        if triad:
            words = {"C": "confidentiality", "I": "integrity", "A": "availability"}
            lvl = {"H": "high", "L": "low", "N": "none"}
            impact = "Impact: " + ", ".join(
                f"{words[k]} {lvl.get(v, v)}" for k, v in triad)
    published = None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            published = datetime.strptime(
                (cve.get("published") or "")[:19], fmt)
            break
        except (ValueError, TypeError):
            continue
    return {
        "cve_id": cve_id,
        "title": f"{cve_id}",
        "description": (desc or "")[:2000],
        "published_date": published,
        "status": (cve.get("vulnStatus") or "unknown")[:50],
        "severity": severity,
        "cvss": float(score) if score is not None else None,
        "impact": impact[:500],
        "source_url": f"{NVD_DETAIL_URL}{cve_id}",
    }


def _parse_circl(payload: dict, cve_id: str) -> dict | None:
    if not isinstance(payload, dict) or not payload.get("id"):
        return None
    if (payload.get("id") or "").upper() != cve_id:
        return None
    score = payload.get("cvss")
    published = None
    try:
        published = datetime.strptime(
            (payload.get("Published") or "")[:19], "%Y-%m-%dT%H:%M:%S")
    except (ValueError, TypeError):
        published = None
    return {
        "cve_id": cve_id,
        "title": f"{cve_id}",
        "description": (payload.get("summary") or "")[:2000],
        "published_date": published,
        "status": "unknown",
        "severity": severity_of(score),
        "cvss": float(score) if score is not None else None,
        "impact": "",
        "source_url": f"{NVD_DETAIL_URL}{cve_id}",
    }


def fetch_enrichment(cve_id: str, client=None) -> dict:
    """Best-effort metadata for one CVE. NVD, then CIRCL, then unknown.

    ``client`` is injectable for tests; otherwise a short-timeout httpx client
    is used and every failure mode collapses to the unknown record. A CVE that
    cannot be enriched is still worth collecting -- the ID is the finding, the
    metadata is a bonus.
    """
    cve_id = (cve_id or "").upper()
    if not CVE_RE.fullmatch(cve_id):
        raise ValueError(f"not a CVE id: {cve_id!r}")
    close = False
    if client is None:
        client = httpx.Client(timeout=10)
        close = True
    try:
        try:
            r = client.get(NVD_URL, params={"cveId": cve_id})
            if r.status_code == 200:
                found = _parse_nvd(r.json(), cve_id)
                if found:
                    return found
        except Exception:
            pass
        try:
            r = client.get(f"{CIRCL_URL}/{cve_id}")
            if r.status_code == 200:
                found = _parse_circl(r.json(), cve_id)
                if found:
                    return found
        except Exception:
            pass
    finally:
        if close:
            try:
                client.close()
            except Exception:
                pass
    return {
        "cve_id": cve_id,
        "title": cve_id,
        "description": "",
        "published_date": None,
        "status": "unknown",
        "severity": "unknown",
        "cvss": None,
        "impact": "",
        "source_url": f"{NVD_DETAIL_URL}{cve_id}",
    }


def _mention_texts(db, investigation_id: int) -> list:
    """Everywhere a CVE mention can hide, with its source artifact attached.

    Returns (cve_id, source_artifact_id) pairs in first-seen order: artifact
    titles, descriptions, contents and tags, plus the security assessments'
    reports, which routinely name CVEs the collected artifacts only imply.
    """
    out = []
    for a in db.query(Artifact).filter(
            Artifact.investigation_id == investigation_id).all():
        for cve in extract_cves(a.title, a.description, a.content, a.tags):
            out.append((cve, a.id))
    for rec in db.query(SecurityAssessment).filter(
            SecurityAssessment.investigation_id == investigation_id).all():
        try:
            scoring = json.loads(rec.scoring or "{}")
        except Exception:
            scoring = {}
        for cve in extract_cves(rec.markdown, json.dumps(scoring),
                                json.dumps(getattr(rec, "threats", None) or "")):
            out.append((cve, None))
    # First mention wins the edge; later duplicates add nothing.
    seen, deduped = set(), []
    for cve, src in out:
        if cve not in seen:
            seen.add(cve)
            deduped.append((cve, src))
    return deduped


def collect_investigation_cves(db, investigation_id: int, *, enrich=True,
                               fetcher=None) -> dict:
    """Collect new CVE findings for one investigation. Idempotent.

    Returns ``{"collected": [...], "total": n}`` with the newly added CVE ids.
    ``fetcher`` replaces the network enrichment (tests); with ``enrich=False``
    every finding is recorded as unknown-standing.
    """
    inv = db.query(Investigation).filter(
        Investigation.id == investigation_id).first()
    if not inv:
        raise ValueError(f"investigation not found: {investigation_id}")
    existing = {r.cve_id for r in db.query(CveFinding).filter(
        CveFinding.investigation_id == investigation_id).all()}
    collected = []
    first = True
    for cve_id, source_id in _mention_texts(db, investigation_id):
        if cve_id in existing:
            continue
        if enrich:
            if not first:
                time.sleep(FETCH_GAP_S)
            first = False
            try:
                meta = fetcher(cve_id) if fetcher else fetch_enrichment(cve_id)
            except Exception:
                # Enrichment must never lose the finding: the CVE id was
                # mentioned, so it is recorded with unknown standing.
                meta = {"cve_id": cve_id, "title": cve_id, "description": "",
                        "published_date": None, "status": "unknown",
                        "severity": "unknown", "cvss": None, "impact": "",
                        "source_url": f"{NVD_DETAIL_URL}{cve_id}"}
        else:
            meta = {"cve_id": cve_id, "title": cve_id, "description": "",
                    "published_date": None, "status": "unknown",
                    "severity": "unknown", "cvss": None, "impact": "",
                    "source_url": f"{NVD_DETAIL_URL}{cve_id}"}
        severity = (meta.get("severity") or "unknown").lower()
        if severity not in SEVERITY_ORDER:
            severity = "unknown"
        title = (meta.get("title") or cve_id)[:500]
        if title == cve_id and meta.get("description"):
            title = f"{cve_id} — {(meta['description'][:120])}"
            title = title[:500]
        art = Artifact(
            investigation_id=investigation_id, title=title,
            artifact_type="cve", url=meta.get("source_url"),
            description=(meta.get("description") or "")[:2000],
            source="cve-collector", tags="cve",
            relevance=SEVERITY_RELEVANCE.get(severity, 0.3),
            review="accepted", origin="cve",
            date_published=meta.get("published_date"))
        db.add(art)
        db.flush()  # need the node id for the edge below
        if source_id:
            db.add(Relationship(
                investigation_id=investigation_id, source_id=source_id,
                target_id=art.id, relationship_type="references",
                description=f"Mentions {cve_id}", origin="cve"))
        db.add(CveFinding(
            investigation_id=investigation_id, cve_id=cve_id, title=title,
            description=(meta.get("description") or "")[:2000],
            published_date=meta.get("published_date"),
            status=(meta.get("status") or "unknown")[:50],
            severity=severity, cvss=meta.get("cvss"),
            impact=(meta.get("impact") or "")[:500],
            source_url=meta.get("source_url"), artifact_id=art.id))
        db.commit()
        existing.add(cve_id)
        collected.append(cve_id)
    total = db.query(CveFinding).filter(
        CveFinding.investigation_id == investigation_id).count()
    return {"collected": collected, "total": total}


def collect_all_investigations(*, enrich=True, fetcher=None) -> dict:
    """Sweep every investigation. One bad investigation must not stop the rest."""
    db = SessionLocal()
    try:
        ids = [r.id for r in db.query(Investigation.id).all()]
    finally:
        db.close()
    per_inv, errors = {}, {}
    for inv_id in ids:
        db = SessionLocal()
        try:
            try:
                per_inv[inv_id] = collect_investigation_cves(
                    db, inv_id, enrich=enrich, fetcher=fetcher)
            except Exception as exc:  # noqa: BLE001 - sweep past one bad apple
                db.rollback()
                errors[inv_id] = f"{type(exc).__name__}: {exc}"
        finally:
            db.close()
    return {"investigations": per_inv, "errors": errors}


def finding_out(r: CveFinding) -> dict:
    return {
        "id": r.id, "cve_id": r.cve_id, "title": r.title,
        "description": r.description or "",
        "published_date": r.published_date.isoformat() if r.published_date else None,
        "status": r.status, "severity": r.severity, "cvss": r.cvss,
        "impact": r.impact or "", "source_url": r.source_url,
        "artifact_id": r.artifact_id,
    }
