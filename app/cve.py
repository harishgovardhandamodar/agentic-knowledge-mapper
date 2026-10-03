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
    return _parse_nvd_entry(cve)


def _parse_nvd_entry(cve: dict) -> dict:
    """Parse one NVD ``cve`` object into the record shape used everywhere."""
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
    cve_id = (cve.get("id") or "").upper()
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


# ------------------------------------------------- known-issues (swarm) -----

#: GHSA advisory ids, e.g. GHSA-xxxx-xxxx-xxxx (lowercase hex chunks).
GHSA_RE = re.compile(r"\bGHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}\b", re.I)

#: What a known issue can be when it has no CVE number.
KNOWN_ISSUE_KINDS = frozenset({
    "vendor_bulletin", "incident_report", "ghsa", "tracker"})

#: Small set of provider/vendor names the deterministic extractor recognises,
#: so "OpenSSL advisory" and "Anthropic incident" searches fire without an LLM.
KNOWN_VENDORS = frozenset({
    "openai", "anthropic", "google", "microsoft", "meta", "aws", "azure",
    "cloudflare", "mozilla", "openssl", "apache", "linux", "tensorflow",
    "pytorch", "huggingface", "langchain", "npm", "redis", "nginx",
})

#: Tokens too generic to be a product name.
_SUBJECT_STOPWORDS = frozenset({
    "the", "and", "for", "with", "model", "product", "api", "security",
    "vulnerability", "vulnerabilities", "cve", "advisory", "incident",
    "review", "assessment", "risk", "data", "system", "analysis", "research",
})

#: Light keyword → threat-id map for the optional threat-intel step. Keyword
#: hits never force applicability; they only offer a suggestion to link.
_THREAT_KEYWORDS = {
    "T01": ("accidental paste", "paste", "clipboard", "sensitive content"),
    "T02": ("training", "retention", "zero-retention", "data retention",
            "model training"),
    "T03": ("misclassif", "mislabelled", "mislabeled", "propagat"),
    "T04": ("over-permissive", "schema semantics", "leak schema"),
    "T05": ("prompt injection", "injection", "jailbreak", "prompt"),
    "T06": ("insider", "exfiltration", "exfiltrat"),
    "T07": ("subprocessor", "third-party", "third party", "vendor breach"),
    "T08": ("audit trail", "repudiation", "missing audit"),
    "T09": ("hallucinat", "stale", "fabricat", "unsupported claim"),
    "T10": ("privilege", "role misconfig", "over-scoped", "elevated"),
    "T11": ("data-residency", "cross-border", "residency", "transfer"),
    "T12": ("gdpr", "iso 27001", "soc 2", "non-compliance", "regulatory"),
}


def extract_subjects(*, title: str = "", keywords: str = "",
                     description: str = "", product_name: str = "",
                     model_meta: dict | None = None,
                     package_hints: list | None = None) -> dict:
    """Deterministic subject extraction: who/what to search CVEs for.

    Never invents a CVE id -- ``cve_hints`` are ids already present in the
    text. Products are the ``product_name`` plus single capitalized tokens;
    a token whose lower-case form names a known vendor lands in both lists so
    ``{vendor} security advisory`` queries fire. Packages come from explicit
    hints or ``pypi:/npm:/…``-style tokens.
    """
    blob = " ".join(filter(None, [title, keywords, description, product_name]))
    cve_hints = extract_cves(title, keywords, description, product_name)

    products: list[str] = []
    if product_name:
        products.append(product_name.strip())
    for tok in re.findall(r"\b[A-Z][A-Za-z0-9+.-]{1,49}\b", blob):
        low = tok.lower()
        if low in _SUBJECT_STOPWORDS or len(low) < 3:
            continue
        if low in {p.lower() for p in products}:
            continue
        products.append(tok)
        if len(products) >= 5:
            break
    vendors = [p for p in products if p.lower() in KNOWN_VENDORS]
    for p in products:
        low = p.lower()
        if any(low.endswith(s) for s in (".ai", "labs", "corp", "inc", "llc")) \
                and p not in vendors:
            vendors.append(p)
            if len(vendors) >= 5:
                break

    packages: list[str] = list(package_hints or [])
    for tok in re.findall(
            r"\b(?:pypi|npm|github|go|rubygem|packagist)[:/]?[\w.-]+",
            blob, re.I):
        if tok.lower() not in {p.lower() for p in packages}:
            packages.append(tok)

    keywords = []
    for tok in re.findall(r"[A-Za-z][A-Za-z0-9+.-]{2,39}", blob):
        low = tok.lower()
        if low in _SUBJECT_STOPWORDS or low in keywords:
            continue
        keywords.append(tok)
        if len(keywords) >= 8:
            break
    return {
        "vendors": vendors,
        "products": products,
        "packages": packages,
        "cve_hints": cve_hints,
        "keywords": keywords,
    }


def build_known_issue_queries(subjects: dict) -> list:
    """The query shapes a known-issues pass runs, one per subject dimension."""
    queries: list = []
    for p in subjects.get("products", [])[:3]:
        queries.append({"shape": "cve_product", "query": f"{p} CVE"})
        queries.append({"shape": "advisory_product", "query": f"{p} security advisory"})
        queries.append({"shape": "ghsa", "query": f"{p} GHSA"})
    for v in subjects.get("vendors", [])[:3]:
        queries.append({"shape": "advisory_vendor", "query": f"{v} security advisory"})
    for pkg in subjects.get("packages", [])[:3]:
        queries.append({"shape": "ghsa", "query": f"{pkg} GHSA"})
    for hint in subjects.get("cve_hints", [])[:5]:
        queries.append({"shape": "cve_hint", "query": hint})
    return queries


def search_nvd_keyword(keyword: str, *, client=None,
                       results_per_page: int = 15) -> list:
    """NVD keyword search, returning parsed CVE records (best-effort).

    A connection failure propagates so the caller can record the source as
    degraded; an HTTP error or an empty result set returns ``[]``.
    """
    close = False
    if client is None:
        client = httpx.Client(timeout=15)
        close = True
    try:
        try:
            r = client.get(NVD_URL, params={
                "keywordSearch": keyword, "resultsPerPage": results_per_page})
        except Exception:
            raise
        if r.status_code != 200:
            return []
        vulns = (r.json() or {}).get("vulnerabilities") or []
        out = []
        for v in vulns:
            cve = (v or {}).get("cve") or {}
            if not cve.get("id"):
                continue
            meta = _parse_nvd_entry(cve)
            if meta.get("cve_id"):
                out.append(meta)
        return out
    finally:
        if close:
            try:
                client.close()
            except Exception:
                pass


def classify_issue(title: str, text: str) -> str:
    """The best-known kind for a non-CVE issue, from its own wording."""
    t = f"{title or ''} {text or ''}".lower()
    if "ghsa" in t:
        return "ghsa"
    if "security advisory" in t or "bulletin" in t:
        return "vendor_bulletin"
    if "incident" in t or "outage" in t or "breach" in t:
        return "incident_report"
    if "tracker" in t or "oss" in t:
        return "tracker"
    return "vendor_bulletin"


def extract_ghsa(*texts) -> list:
    """GHSA advisory ids across texts, lower-cased, first-seen order."""
    seen = []
    for text in texts:
        if not text:
            continue
        for m in GHSA_RE.finditer(str(text)):
            g = m.group(0).lower()
            if g not in seen:
                seen.append(g)
    return seen


def map_cve_to_threats(text: str) -> list:
    """Light keyword → threat-id mapping for known-issue text.

    A hint, not a verdict: keyword hits never force applicability. The caller
    decides whether the evidence supports the link.
    """
    t = str(text or "").lower()
    return sorted({tid for tid, kws in _THREAT_KEYWORDS.items()
                   if any(k in t for k in kws)})


def _default_advisory_search(query: str, max_results: int = 6) -> list:
    """Best-effort web/RSS advisory search via the app's own providers."""
    from . import search as _s
    hits = []
    for fn in (_s.search_web, _s.search_rss):
        try:
            for r in fn(query)[:max_results]:
                hits.append({
                    "title": r.get("title") or "",
                    "url": r.get("url") or r.get("link") or "",
                    "description": r.get("description") or r.get("snippet") or "",
                    "content": r.get("content") or "",
                })
        except Exception:
            continue
    # Dedupe by url, keep order.
    seen, out = set(), []
    for h in hits:
        url = h["url"]
        if not url or url in seen:
            continue
        seen.add(url)
        out.append(h)
    return out[:max_results]


def upsert_known_issues(db, investigation_id: int, *, cve_hits: list,
                        issue_hits: list, product_name: str = "",
                        fetcher=None, enrich: bool = True) -> dict:
    """Persist CVE hits and non-CVE known issues for one investigation.

    CVEs land in ``cve_findings`` (deduped by ``(investigation_id, cve_id)``)
    plus a ``cve`` artifact; non-CVE issues land as ``known_issue`` artifacts
    carrying their kind and external ids in ``node_meta``. A duplicate CVE is
    counted, never re-written. Never mints a fake CVE number.
    """
    existing_cves = {r.cve_id for r in db.query(CveFinding).filter(
        CveFinding.investigation_id == investigation_id).all()}
    existing_urls = {a.url for a in db.query(Artifact).filter(
        Artifact.investigation_id == investigation_id,
        Artifact.artifact_type == "known_issue").all() if a.url}

    result = {"cves": [], "issues": [], "duplicate_cves": 0,
              "duplicate_issues": 0}
    for meta in cve_hits or []:
        cve_id = (meta.get("cve_id") or "").upper()
        if not CVE_RE.fullmatch(cve_id):
            continue
        if cve_id in existing_cves:
            result["duplicate_cves"] += 1
            continue
        if enrich and not (meta.get("description") or meta.get("cvss")):
            try:
                meta = (fetcher(cve_id) if fetcher
                        else fetch_enrichment(cve_id))
            except Exception:
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
            source="known-issues-scout", tags="cve",
            relevance=SEVERITY_RELEVANCE.get(severity, 0.3),
            review="pending", origin="agent",
            date_published=meta.get("published_date"))
        db.add(art)
        db.flush()
        db.add(CveFinding(
            investigation_id=investigation_id, cve_id=cve_id, title=title,
            description=(meta.get("description") or "")[:2000],
            published_date=meta.get("published_date"),
            status=(meta.get("status") or "unknown")[:50],
            severity=severity, cvss=meta.get("cvss"),
            impact=(meta.get("impact") or "")[:500],
            source_url=meta.get("source_url"), artifact_id=art.id))
        db.commit()
        existing_cves.add(cve_id)
        result["cves"].append(cve_id)

    for issue in issue_hits or []:
        url = issue.get("url") or ""
        if url and url in existing_urls:
            result["duplicate_issues"] += 1
            continue
        title = (issue.get("title") or "Known issue")[:500]
        text = f"{title} {issue.get('description') or ''}"
        kind = classify_issue(title, issue.get("description") or "")
        if kind not in KNOWN_ISSUE_KINDS:
            kind = "vendor_bulletin"
        side = {
            "issue_kind": kind,
            "external_ids": extract_ghsa(text),
            "cve_ids": extract_cves(text),
            "confidence": round(float(issue.get("confidence") or 0.7), 2),
            "threat_hints": map_cve_to_threats(text),
        }
        art = Artifact(
            investigation_id=investigation_id, title=title,
            artifact_type="known_issue", url=url,
            description=(issue.get("description") or "")[:2000],
            source="known-issues-scout",
            tags=", ".join(["known_issue", kind] + extract_ghsa(text)),
            relevance=round(float(issue.get("relevance") or 0.6), 3),
            review="pending", origin="agent",
            node_meta=json.dumps(side))
        db.add(art)
        db.commit()
        existing_urls.add(url)
        result["issues"].append({
            "artifact_id": art.id, "title": title, "url": url,
            "kind": kind, "external_ids": side["external_ids"],
            "confidence": side["confidence"],
            "threat_hints": side["threat_hints"],
        })
    return result


def collect_known_issues(db, investigation_id: int, *,
                         subjects: dict | None = None,
                         product_name: str = "", model_meta: dict | None = None,
                         max_cves: int = 25, max_non_cve_issues: int = 15,
                         nvd_client=None, search_fn=None,
                         fetcher=None, enrich: bool = True) -> dict:
    """The known-issues swarm pass: extract subjects, search NVD + web/RSS,
    upsert CVEs and known issues. Fail-open by contract: a down source is
    recorded as degraded, never raised, and never fails the parent run.

    ``search_fn`` replaces the advisory web search (tests); ``nvd_client`` and
    ``fetcher`` replace the NVD/enrichment network calls.
    """
    inv = db.query(Investigation).filter(
        Investigation.id == investigation_id).first()
    if not inv:
        raise ValueError(f"investigation not found: {investigation_id}")
    if subjects is None:
        subjects = extract_subjects(
            title=inv.title or "", keywords=inv.keywords or "",
            description=inv.description or "", product_name=product_name,
            model_meta=model_meta)
    queries = build_known_issue_queries(subjects)
    if not queries:
        return {"skipped": True, "reason": "no_subject",
                "subjects": subjects, "queries": [],
                "cves": [], "issues": [], "degraded_sources": []}

    degraded: list[str] = []
    cve_hits: list = []
    issue_hits: list = []
    seen_cve: set[str] = set()

    search = search_fn or _default_advisory_search
    for q in queries:
        if q["shape"] == "cve_hint":
            cid = (q["query"] or "").upper()
            if cid not in seen_cve:
                seen_cve.add(cid)
                cve_hits.append({"cve_id": cid, "title": cid,
                                 "description": "", "source_url":
                                 f"{NVD_DETAIL_URL}{cid}"})
            continue
        # NVD keyword search for the product/vendor/ghsa shapes.
        try:
            for meta in search_nvd_keyword(q["query"], client=nvd_client):
                cid = meta.get("cve_id")
                if cid and cid not in seen_cve:
                    seen_cve.add(cid)
                    cve_hits.append(meta)
        except Exception:
            degraded.append("nvd_keyword")
        time.sleep(FETCH_GAP_S)
        # Web/RSS advisory search for the non-hint shapes.
        try:
            for hit in search(q["query"]):
                text = (f"{hit.get('title') or ''} "
                        f"{hit.get('description') or ''} "
                        f"{hit.get('content') or ''}")
                found = extract_cves(text)
                if found:
                    for cid in found:
                        if cid not in seen_cve:
                            seen_cve.add(cid)
                            cve_hits.append({
                                "cve_id": cid, "title": cid,
                                "description": text[:1200],
                                "source_url": hit.get("url") or "",
                            })
                elif hit.get("url"):
                    issue_hits.append({
                        "title": hit.get("title") or "Known issue",
                        "url": hit.get("url"),
                        "description": hit.get("description") or "",
                        "confidence": 0.7,
                    })
        except Exception:
            degraded.append("web_search")

    cve_hits = cve_hits[:max_cves]
    issue_hits = issue_hits[:max_non_cve_issues]
    upserted = upsert_known_issues(
        db, investigation_id, cve_hits=cve_hits, issue_hits=issue_hits,
        product_name=product_name, fetcher=fetcher, enrich=enrich)
    return {
        "subjects": subjects,
        "queries": queries,
        "cves": upserted["cves"],
        "issues": upserted["issues"],
        "duplicate_cves": upserted["duplicate_cves"],
        "duplicate_issues": upserted["duplicate_issues"],
        "degraded_sources": sorted(set(degraded)),
        "note": ("Best-effort: a degraded source is recorded, never fatal. "
                 "Assigned CVEs are stored canonically and deduped; issues "
                 "without a CVE keep their own kind and external ids."),
    }
