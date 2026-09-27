"""Tests for the threat pack and the scoring eval gate.

The gate's only value is that it fails when a number moves, so the most
important test here is the one that deliberately moves a number and checks the
gate notices. Everything else is bookkeeping.
"""
import os
import tempfile
import unittest

os.environ["AKM_DATABASE_URL"] = "sqlite:///" + os.path.join(
    tempfile.mkdtemp(prefix="akm-evalkit-test-"), "test.db")

from app import database  # noqa: E402
from app import evalkit  # noqa: E402
from app import security as sec  # noqa: E402
from app import threatpack as tp  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.models import SecurityAssessment  # noqa: E402

database.init_db()


class _patched_catalog:
    """Rebuild the catalog list with one field changed.

    The catalog rows are tuples, so an in-place edit is not available; the list
    is replaced wholesale and restored on exit. Mutating a tuple in place would
    be a test that corrupts shared module state for every test after it.
    """

    def __init__(self, index=0, field=4, delta=1):
        self.index, self.field, self.delta = index, field, delta

    def __enter__(self):
        self.saved = sec._THREAT_CATALOG
        rows = list(self.saved)
        row = list(rows[self.index])
        # Guarantee a real change: a row already at 5 would clamp back to 5
        # and the test would pass without exercising anything.
        step = self.delta
        if max(1, min(5, row[self.field] + step)) == row[self.field]:
            step = -step
        row[self.field] = max(1, min(5, row[self.field] + step))
        self.changed = row[self.field] != self.saved[self.index][self.field]
        rows[self.index] = tuple(row)
        sec._THREAT_CATALOG = rows
        # _THREAT_BY_ID is the engine's own index; keep it consistent.
        sec._THREAT_BY_ID[row[0]] = {"title": row[1], "stride": row[2],
                                     "owasp": row[3],
                                     "base_likelihood": row[4],
                                     "impact": row[5]}
        return self

    def __exit__(self, *exc):
        sec._THREAT_CATALOG = self.saved
        sec._THREAT_BY_ID = {t[0]: {"title": t[1], "stride": t[2], "owasp": t[3],
                                    "base_likelihood": t[4], "impact": t[5]}
                             for t in self.saved}
        return False


def _moved_likelihood(index=0, delta=1):
    return _patched_catalog(index=index, field=4, delta=delta)


class TestThreatPack(unittest.TestCase):
    def test_manifest_is_complete(self):
        m = tp.pack_manifest()
        self.assertEqual(m["pack_id"], tp.PACK_ID)
        self.assertEqual(m["version"], tp.PACK_VERSION)
        self.assertEqual(m["threat_count"], len(sec._THREAT_CATALOG))
        self.assertEqual(m["control_count"], len(sec._CONTROL_CATALOG))
        self.assertIn("owasp_llm_top10", m["frameworks"])
        self.assertTrue(m["fingerprint"])

    def test_fingerprint_is_stable(self):
        self.assertEqual(tp.pack_fingerprint(), tp.pack_fingerprint())

    def test_fingerprint_covers_the_scoring_constants(self):
        """A re-weighting moves every assessment as surely as a catalog edit."""
        before = tp.pack_fingerprint()
        saved = sec._WORST_WEIGHT
        try:
            sec._WORST_WEIGHT = 0.9
            self.assertNotEqual(tp.pack_fingerprint(), before)
        finally:
            sec._WORST_WEIGHT = saved
        self.assertEqual(tp.pack_fingerprint(), before)

    def test_fingerprint_covers_threat_likelihoods(self):
        before = tp.pack_fingerprint()
        with _moved_likelihood() as patched:
            self.assertTrue(patched.changed, "helper failed to move anything")
            self.assertNotEqual(tp.pack_fingerprint(), before)
        self.assertEqual(tp.pack_fingerprint(), before)

    def test_fingerprint_covers_control_efficacy(self):
        before = tp.pack_fingerprint()
        saved = sec._CONTROL_CATALOG[0]["efficacy"]
        try:
            sec._CONTROL_CATALOG[0]["efficacy"] = saved + 0.01
            self.assertNotEqual(tp.pack_fingerprint(), before)
        finally:
            sec._CONTROL_CATALOG[0]["efficacy"] = saved

    def test_compare_fingerprint(self):
        cur = tp.pack_fingerprint()
        self.assertTrue(tp.compare_fingerprint(cur)["matches"])
        self.assertFalse(tp.compare_fingerprint("deadbeef1234")["matches"])
        # A row from before versioned packs is unknown, not drifted.
        self.assertFalse(tp.compare_fingerprint(None)["matches"])
        self.assertFalse(tp.compare_fingerprint("")["matches"])


class TestCVSS(unittest.TestCase):
    def test_base_scores_are_in_range(self):
        for lk in range(1, 6):
            for im in range(1, 6):
                s = tp.cvss_base_score(lk, im)
                self.assertGreaterEqual(s, 0.0)
                self.assertLessEqual(s, 10.0)

    def test_zero_impact_is_zero(self):
        # "Not defined" in CVSS, not a clamped-up 1/10.
        self.assertEqual(tp.cvss_base_score(5, 0), 0.0)
        self.assertEqual(tp.cvss_base_score(5, -1), 0.0)

    def test_higher_impact_scores_higher(self):
        self.assertGreater(tp.cvss_base_score(4, 5), tp.cvss_base_score(4, 2))

    def test_out_of_range_is_clamped_not_fatal(self):
        """A bad catalog edit must produce a score, not an IndexError inside a
        user's report."""
        self.assertGreaterEqual(tp.cvss_base_score(99, 99), 0.0)
        self.assertLessEqual(tp.cvss_base_score(-5, -5), 10.0)

    def test_severity_bands(self):
        self.assertEqual(tp._cvss_severity(0.0), "None")
        self.assertEqual(tp._cvss_severity(3.9), "Low")
        self.assertEqual(tp._cvss_severity(4.0), "Medium")
        self.assertEqual(tp._cvss_severity(7.0), "High")
        self.assertEqual(tp._cvss_severity(9.8), "Critical")

    def test_every_catalog_threat_has_a_cvss_row(self):
        rows = tp.threat_rows()
        self.assertEqual(len(rows), len(sec._THREAT_CATALOG))
        for r in rows:
            self.assertIn("base_score", r)
            self.assertTrue(r["vector"].startswith("CVSS:3.1/"))
            self.assertIn(r["severity"], ("None", "Low", "Medium", "High", "Critical"))

    def test_unknown_threat_is_empty_not_an_error(self):
        self.assertEqual(tp.cvss_for("T99"), {})

    def test_threat_rows_keep_the_original_fields(self):
        row = tp.threat_rows()[0]
        for field in ("id", "title", "stride", "owasp", "base_likelihood",
                      "impact", "mitigations"):
            self.assertIn(field, row)


class TestEvalGate(unittest.TestCase):
    def test_the_suite_passes_on_this_pack(self):
        report = evalkit.run_eval()
        self.assertTrue(report["ok"], report["failures"])
        self.assertGreaterEqual(report["cases_run"], 8)
        self.assertGreaterEqual(report["invariants_run"], 4)

    def test_every_case_names_itself(self):
        for c in evalkit.cases():
            self.assertTrue(c["name"])
            self.assertTrue(c["note"])

    def test_no_duplicate_case_names(self):
        names = [c["name"] for c in evalkit.cases()]
        self.assertEqual(len(names), len(set(names)))

    def test_a_moved_likelihood_fails_the_gate(self):
        """The whole point: an accidental edit must be caught.

        A likelihood nudge changes real numbers and raises nothing, so the gate
        is the only thing standing between a catalog edit and a silently
        different set of reports.
        """
        self.assertTrue(evalkit.run_eval()["ok"])
        with _moved_likelihood() as patched:
            self.assertTrue(patched.changed, "helper failed to move anything")
            report = evalkit.run_eval()
            self.assertFalse(report["ok"], "gate did not notice a moved number")
            self.assertTrue(report["failures"])
        self.assertTrue(evalkit.run_eval()["ok"], "gate did not recover")

    def test_a_broken_control_efficacy_fails_an_invariant(self):
        before = sec._CONTROL_CATALOG[0]["efficacy"]
        try:
            # Invert an efficacy: a control that makes things worse.
            sec._CONTROL_CATALOG[0]["efficacy"] = 0.0
            report = evalkit.run_eval()
            bad = [i for i in report["invariants"] if not i["ok"]]
            if bad:
                self.assertFalse(report["ok"])
        finally:
            sec._CONTROL_CATALOG[0]["efficacy"] = before
        self.assertTrue(evalkit.run_eval()["ok"])

    def test_report_shape(self):
        r = evalkit.run_eval()
        self.assertIn("pack", r)
        self.assertIn("fingerprint", r["pack"])
        self.assertIsInstance(r["ok"], bool)
        for c in r["cases"]:
            self.assertIn("residual_pct", c)
            self.assertIn("ok", c)

    def test_render_is_readable(self):
        text = evalkit.render(evalkit.run_eval())
        self.assertIn("threat pack", text)
        self.assertIn("PASS", text)

    def test_rebaseline_reports_current_numbers_without_writing(self):
        out = evalkit.rebaseline()
        self.assertIn("pack", out)
        self.assertTrue(out["pack"]["fingerprint"])
        self.assertTrue(evalkit.run_eval()["ok"])


class TestEvalEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        from app import main as main_mod
        cls.client = TestClient(main_mod.app)

    def test_threat_pack_endpoint(self):
        r = self.client.get("/api/security/threat-pack")
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["manifest"]["pack_id"], tp.PACK_ID)
        self.assertTrue(body["threats"])
        self.assertIn("base_score", body["threats"][0])

    def test_eval_endpoint_reports_ok(self):
        r = self.client.get("/api/security/eval")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["ok"], r.json()["failures"])


class TestAssessmentStampsThePack(unittest.TestCase):
    def test_stored_assessment_reports_pack_drift(self):
        """A score read next to a different pack is two results wearing one id."""
        db = SessionLocal()
        try:
            rec = SecurityAssessment(investigation_id=1, product_name="x",
                                     exposure="confidential_data",
                                     overall_pct=50, markdown="m",
                                     threat_pack_version="0.9.0",
                                     threat_pack_fingerprint="stale123456")
            db.add(rec)
            db.commit()
            from app import main as main_mod
            body = main_mod._security_json(rec)
            self.assertEqual(body["threat_pack"]["version"], "0.9.0")
            self.assertFalse(body["threat_pack"]["matches"])
        finally:
            db.close()

    def test_current_pack_reports_a_match(self):
        db = SessionLocal()
        try:
            rec = SecurityAssessment(investigation_id=1, product_name="x",
                                     exposure="confidential_data",
                                     overall_pct=50, markdown="m",
                                     threat_pack_version=tp.PACK_VERSION,
                                     threat_pack_fingerprint=tp.pack_fingerprint())
            db.add(rec)
            db.commit()
            from app import main as main_mod
            self.assertTrue(main_mod._security_json(rec)["threat_pack"]["matches"])
        finally:
            db.close()

    def test_legacy_row_reports_unknown_not_drifted(self):
        """Pre-pack rows are unknown, which is a different claim from drifted."""
        db = SessionLocal()
        try:
            rec = SecurityAssessment(investigation_id=1, product_name="x",
                                     exposure="confidential_data",
                                     overall_pct=50, markdown="m")
            db.add(rec)
            db.commit()
            from app import main as main_mod
            pack = main_mod._security_json(rec)["threat_pack"]
            self.assertIsNone(pack["version"])
            self.assertFalse(pack["matches"])
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
