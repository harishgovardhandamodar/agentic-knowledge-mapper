"""Tests for CVE collection: extraction, idempotency, and the workflow hook.

The properties that matter: every CVE mention becomes exactly one finding no
matter how many times collection runs, a failed enrichment still records the
finding (with unknown standing, never a guess), and the agent run picks CVEs
up on its own so new investigations do not depend on anyone clicking.
"""
import json
import os
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("AKM_DATABASE_URL", "sqlite:///" + os.path.join(
    tempfile.mkdtemp(prefix="akm-cve-test-"), "test.db"))

from app import agent as agent_mod  # noqa: E402
from app import cve as cve_mod  # noqa: E402
from app import database  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.models import (Artifact, AgentRun, CveFinding, Investigation,  # noqa: E402
                        Relationship)

database.init_db()


def _meta(cve_id, **kw):
    out = {"cve_id": cve_id, "title": cve_id, "description": "desc",
           "published_date": None, "status": "Analyzed", "severity": "high",
           "cvss": 7.5, "impact": "Impact: confidentiality high",
           "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"}
    out.update(kw)
    return out


def _investigation(db, title="cve-target"):
    inv = Investigation(title=title, keywords="k", description="d")
    db.add(inv)
    db.commit()
    db.refresh(inv)
    return inv.id


class TestExtraction(unittest.TestCase):
    def test_finds_ids_case_insensitively_without_duplicates(self):
        self.assertEqual(
            cve_mod.extract_cves("a CVE-2025-32711 b cve-2025-32711 c CVE-2024-1"),
            ["CVE-2025-32711"])

    def test_ignores_non_cve_numbers(self):
        self.assertEqual(cve_mod.extract_cves("KE-01, T05, version 2025"), [])

    def test_severity_bands(self):
        self.assertEqual(
            [cve_mod.severity_of(x) for x in (10, 9.0, 8.9, 7.0, 6.9, 4.0,
                                              3.9, 0.1, 0, None, "x")],
            ["critical"] * 2 + ["high"] * 2 + ["medium"] * 2 +
            ["low"] * 2 + ["unknown"] * 3)


class TestNvdParsing(unittest.TestCase):
    def test_parses_a_minimal_nvd_document(self):
        doc = {"vulnerabilities": [{"cve": {
            "id": "CVE-2025-32711",
            "descriptions": [{"lang": "en", "value": "EchoLeak exfiltrates."}],
            "published": "2025-06-11T10:00:00.000",
            "vulnStatus": "Analyzed",
            "metrics": {"cvssMetricV31": [{"cvssData": {
                "baseScore": 9.0, "baseSeverity": "CRITICAL",
                "vectorString": "CVSS:3.1/AV:N/AC:L/C:H/I:H/A:N"}}]}}}]}
        out = cve_mod._parse_nvd(doc, "CVE-2025-32711")
        self.assertEqual(out["severity"], "critical")
        self.assertEqual(out["cvss"], 9.0)
        self.assertIn("confidentiality high", out["impact"])
        self.assertEqual(out["status"], "Analyzed")
        self.assertIsNotNone(out["published_date"])

    def test_wrong_id_is_rejected(self):
        self.assertIsNone(cve_mod._parse_nvd({"vulnerabilities": []},
                                             "CVE-2025-32711"))


class TestCollection(unittest.TestCase):
    def setUp(self):
        self.db = SessionLocal()
        for table in (CveFinding, Relationship, Artifact, AgentRun,
                      Investigation):
            self.db.query(table).delete()
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def test_mentions_become_findings_and_graph_nodes(self):
        inv_id = _investigation(self.db)
        src = Artifact(investigation_id=inv_id, title="t",
                       description="See CVE-2025-32711 for details",
                       artifact_type="paper")
        self.db.add(src)
        self.db.commit()
        out = cve_mod.collect_investigation_cves(
            self.db, inv_id, fetcher=_meta)
        self.assertEqual(out, {"collected": ["CVE-2025-32711"], "total": 1})
        finding = self.db.query(CveFinding).one()
        self.assertEqual((finding.severity, finding.status, finding.cvss),
                         ("high", "Analyzed", 7.5))
        node = self.db.query(Artifact).filter(
            Artifact.artifact_type == "cve").one()
        self.assertEqual(node.review, "accepted")  # stays out of triage
        self.assertEqual(finding.artifact_id, node.id)
        edge = self.db.query(Relationship).one()
        self.assertEqual((edge.source_id, edge.target_id),
                         (src.id, node.id))

    def test_reruns_collect_only_what_is_new(self):
        inv_id = _investigation(self.db)
        self.db.add(Artifact(investigation_id=inv_id, title="CVE-2025-32711",
                             artifact_type="news"))
        self.db.commit()
        cve_mod.collect_investigation_cves(self.db, inv_id, fetcher=_meta)
        self.db.query(Artifact).filter(
            Artifact.artifact_type != "cve").update(
            {"description": "now also CVE-2024-0001"})
        self.db.commit()
        out = cve_mod.collect_investigation_cves(self.db, inv_id, fetcher=_meta)
        self.assertEqual(out, {"collected": ["CVE-2024-0001"], "total": 2})

    def test_a_failed_enrichment_still_records_the_id(self):
        """The ID is the finding; metadata is a bonus."""
        inv_id = _investigation(self.db)
        self.db.add(Artifact(investigation_id=inv_id,
                             title="mentions CVE-2025-99999",
                             artifact_type="news"))
        self.db.commit()

        def boom(cve_id):
            raise RuntimeError("nvd is down")

        out = cve_mod.collect_investigation_cves(
            self.db, inv_id, fetcher=boom)
        self.assertEqual(out["collected"], ["CVE-2025-99999"])
        finding = self.db.query(CveFinding).one()
        self.assertEqual((finding.severity, finding.status),
                         ("unknown", "unknown"))

    def test_unknown_investigation_is_an_error(self):
        with self.assertRaises(ValueError):
            cve_mod.collect_investigation_cves(self.db, 999999, enrich=False)

    def test_finding_out_serialises(self):
        inv_id = _investigation(self.db)
        self.db.add(Artifact(investigation_id=inv_id, title="CVE-2025-0001",
                             artifact_type="news"))
        self.db.commit()
        cve_mod.collect_investigation_cves(self.db, inv_id, enrich=False)
        out = cve_mod.finding_out(self.db.query(CveFinding).one())
        self.assertEqual(out["cve_id"], "CVE-2025-0001")
        self.assertIsNone(out["published_date"])
        self.assertTrue(out["source_url"].endswith("CVE-2025-0001"))


class TestWorkflowHook(unittest.TestCase):
    def test_a_finished_run_collects_cves_through_the_hook(self):
        """New investigations get CVE findings from the run, not from a click.

        Drives the real hook function with enrichment stubbed at the network
        edge, and checks the finding, the graph node, and the run event.
        """
        db = SessionLocal()
        try:
            inv_id = _investigation(db, "hooked")
            run = AgentRun(investigation_id=inv_id, status="done",
                           trigger="manual", plan="{}")
            db.add(run)
            db.add(Artifact(investigation_id=inv_id, title="CVE-2025-32711",
                            artifact_type="paper"))
            db.commit()
            with mock.patch("app.cve.fetch_enrichment",
                            side_effect=lambda i: _meta(i)):
                collected = agent_mod._collect_run_cves(db, run, db.query(
                    Investigation).filter(Investigation.id == inv_id).one())
            self.assertEqual(collected, ["CVE-2025-32711"])
            self.assertEqual(db.query(CveFinding).filter(
                CveFinding.investigation_id == inv_id).count(), 1)
            self.assertEqual(db.query(Artifact).filter(
                Artifact.investigation_id == inv_id,
                Artifact.artifact_type == "cve").count(), 1)
            msgs = [e.message for e in db.query(agent_mod.AgentEvent).filter(
                agent_mod.AgentEvent.run_id == run.id).all()]
            self.assertTrue(any("Known issues" in m for m in msgs), msgs)
        finally:
            db.close()

    def test_a_broken_sweep_never_breaks_the_run(self):
        db = SessionLocal()
        try:
            inv_id = _investigation(db, "hooked-broken")
            run = AgentRun(investigation_id=inv_id, status="done",
                           trigger="manual", plan="{}")
            db.add(run)
            db.commit()
            with mock.patch("app.cve.collect_investigation_cves",
                            side_effect=RuntimeError("db is gone")):
                self.assertEqual(agent_mod._collect_run_cves(
                    db, run, db.query(Investigation).filter(
                        Investigation.id == inv_id).one()), [])
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
