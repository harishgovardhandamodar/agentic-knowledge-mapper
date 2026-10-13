"""Adoption advice: does the organisation's nature change the answer?

The properties under test are the ones that would quietly produce a confident
wrong answer: a product residual quoted for the wrong organisation, an unstated
nature read as a clean bill of health, a prior analysis missed because the user
lower-cased or misspelled the vendor, and a condition presented as "secured".
"""
import json
import os
import tempfile
import unittest

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-adoption-"), "test.db"))

from app import adoption_advice as aa  # noqa: E402
from app import database as _db  # noqa: E402
from app.database import Base, SessionLocal, engine  # noqa: E402
from app.models import Investigation, SecurityAssessment  # noqa: E402

_db.init_db()


def _assessment(inv_id, product="Collibra AI Writing Assistant",
                residual=58.0, exposure="restricted_data",
                family=None, scoring=None, threats=None):
    return SecurityAssessment(
        investigation_id=inv_id, product_name=product,
        product_family=family, exposure=exposure, use_case="catch-up summaries",
        overall_pct=residual, inherent_pct=residual, residual_pct=residual,
        markdown="# report",
        posture="ELEVATED RISK — adopt only with guardrails and review",
        scoring_json=json.dumps(scoring or {"assessment_path": "standard"}),
        threats_json=json.dumps(threats or []),
        threat_pack_version="2.1.0", threat_pack_fingerprint="19a11481e69d")


class ProfileCase(unittest.TestCase):
    def test_swift_reads_as_financial_market_infrastructure(self):
        org = aa.profile_organisation(
            "adoption advice for collibra tools inside organisations like SWIFT")
        self.assertEqual(org["sector"], "financial_market_infrastructure")
        self.assertIn("swift", " ".join(org["signals"]).lower())

    def test_unstated_fields_stay_unknown_not_defaulted(self):
        org = aa.profile_organisation("we are thinking about adopting a tool")
        self.assertIsNone(org["sector"])
        self.assertIsNone(org["systemic"])
        self.assertIsNone(org["data_sensitivity"])
        self.assertEqual(org["regimes"], [])
        for field in ("sector", "systemic", "data_sensitivity"):
            self.assertIn(field, org["material_unknown"])

    def test_explicit_fields_override_the_text(self):
        org = aa.profile_organisation(
            "a bank in the EU", sector="retail", systemic=False,
            data_sensitivity="public")
        self.assertEqual(org["sector"], "retail")
        self.assertIs(org["systemic"], False)
        self.assertEqual(org["data_sensitivity"], "public")
        self.assertNotIn("sector", org["material_unknown"])

    def test_regimes_and_sensitivity_parse(self):
        org = aa.profile_organisation(
            "DORA and GDPR apply to our restricted customer data")
        self.assertIn("dora", org["regimes"])
        self.assertIn("gdpr", org["regimes"])
        self.assertEqual(org["data_sensitivity"], "restricted")
        self.assertTrue(org["pii"])

    def test_systemic_role_is_read(self):
        org = aa.profile_organisation(
            "a systemically important financial market infrastructure")
        self.assertIs(org["systemic"], True)

    def test_scrutiny_only_amplifies_and_is_clamped(self):
        org = aa.profile_organisation(
            "SWIFT, systemically important, DORA, MiFID, GDPR, restricted "
            "personal data, cross-border, third party",
            third_party_reliance=True)
        scr = aa.organisation_scrutiny(org)
        self.assertGreaterEqual(scr["multiplier"], 1.0)
        self.assertLessEqual(scr["multiplier"], 1.8)
        self.assertEqual(scr["band"], "high")
        kinds = {f["kind"] for f in scr["factors"]}
        self.assertIn("systemic", kinds)
        self.assertIn("regime", kinds)

    def test_an_unreadable_org_has_a_low_multiplier(self):
        scr = aa.organisation_scrutiny(aa.profile_organisation("a tool"))
        self.assertEqual(scr["multiplier"], 1.0)
        self.assertEqual(scr["band"], "low")


class InterestCase(unittest.TestCase):
    def test_security_risk_question_is_read(self):
        it = aa.profile_interest("specifically the security risk of adopting it")
        self.assertEqual(it["question"], "security_risk")

    def test_adoption_language_is_read(self):
        it = aa.profile_interest("we want to onboard and roll out the tool")
        self.assertEqual(it["question"], "adoption_fit")

    def test_misspelled_vendor_survives_as_a_candidate(self):
        it = aa.profile_interest(
            "adoption advice for colibra tools and features")
        self.assertIn("colibra", it["product_candidates"])

    def test_explicit_product_is_kept(self):
        it = aa.profile_interest("anything", product="Collibra")
        self.assertEqual(it["product"], "Collibra")
        self.assertIn("collibra", it["product_candidates"])


class DiscoveryCase(unittest.TestCase):
    def setUp(self):
        Base.metadata.create_all(bind=engine)
        self.db = SessionLocal()
        self.inv = Investigation(
            title="Collibra AI Writing Assistant on Restricted/Confidential Data",
            keywords="collibra, ai writing assistant, restricted data")
        self.db.add(self.inv)
        self.db.commit()
        self.db.refresh(self.inv)

    def tearDown(self):
        self.db.query(SecurityAssessment).filter(
            SecurityAssessment.investigation_id == self.inv.id).delete()
        self.db.query(Investigation).filter(
            Investigation.id == self.inv.id).delete()
        self.db.commit()
        self.db.close()

    def test_misspelled_vendor_finds_the_stored_analysis(self):
        self.db.add(_assessment(self.inv.id))
        self.db.commit()
        found = aa.find_prior_analyses(self.db, "colibra")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["product_name"], "Collibra AI Writing Assistant")
        self.assertEqual(found[0]["matched_on"], "product_name")
        self.assertEqual(
            found[0]["title"],
            "Collibra AI Writing Assistant on Restricted/Confidential Data")

    def test_match_by_investigation_title_alone(self):
        # The product name shares nothing with the request; only the analysis
        # title does. A user names the report, not the row.
        self.db.add(_assessment(self.inv.id, product="Widget", family="widget"))
        self.db.commit()
        found = aa.find_prior_analyses(self.db, "Collibra")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["matched_on"], "investigation_title")

    def test_no_match_is_empty_not_a_guess(self):
        self.db.add(_assessment(self.inv.id, product="Widget", family="widget"))
        self.db.commit()
        self.assertEqual(aa.find_prior_analyses(self.db, "unrelatedthing"), [])

    def test_blockers_are_surfaced_from_threats(self):
        self.db.add(_assessment(self.inv.id, threats=[
            {"id": "T12", "title": "Regulatory exposure",
             "residual_score": 86.0, "residual_severity": "high"}]))
        self.db.commit()
        found = aa.find_prior_analyses(self.db, "collibra")
        self.assertTrue(found[0]["blockers"])
        self.assertEqual(found[0]["blockers"][0]["id"], "T12")


class AdviceCase(unittest.TestCase):
    def setUp(self):
        Base.metadata.create_all(bind=engine)
        self.db = SessionLocal()
        self.inv = Investigation(title="adoption advice inv")
        self.db.add(self.inv)
        self.db.commit()
        self.db.refresh(self.inv)

    def tearDown(self):
        self.db.query(SecurityAssessment).filter(
            SecurityAssessment.investigation_id == self.inv.id).delete()
        self.db.query(Investigation).filter(
            Investigation.id == self.inv.id).delete()
        self.db.commit()
        self.db.close()

    def _prior(self, residual=58.0):
        rec = _assessment(self.inv.id, residual=residual)
        self.db.add(rec)
        self.db.commit()
        self.db.refresh(rec)
        return aa.find_prior_analyses(self.db, "collibra",
                                      investigation_id=self.inv.id)

    def test_no_product_is_insufficient_evidence(self):
        pack = aa.adoption_advice(self.db, query="tell me about governance")
        self.assertEqual(pack["verdict"]["key"], "insufficient_evidence")
        self.assertIsNone(pack["product"])
        self.assertIn("No product", pack["verdict"]["why"])

    def test_query_names_the_product_when_no_prior_exists(self):
        # "colibra tools" -- the token before a product noun is the product.
        pack = aa.adoption_advice(
            self.db, query="adoption advice for colibra tools inside a bank")
        self.assertEqual(pack["verdict"]["key"], "insufficient_evidence")
        self.assertEqual(pack["product"], "colibra")
        self.assertEqual(pack["product_from"], "query_candidate")
        self.assertIn("colibra", pack["verdict"]["why"])
        self.assertIn("read from the request", pack["verdict"]["why"])
        self.assertIn("was read from your request", pack["markdown"])

    def test_stray_significant_word_is_not_promoted_to_a_product(self):
        # A lone significant token ("governance") is not a product.
        pack = aa.adoption_advice(self.db, query="tell me about governance")
        self.assertIsNone(pack["product"])
        self.assertIsNone(pack["product_from"])

    def test_a_product_with_no_prior_is_insufficient_not_low(self):
        pack = aa.adoption_advice(self.db, query="adopt Collibra",
                                  product="Collibra")
        self.assertEqual(pack["verdict"]["key"], "insufficient_evidence")
        self.assertIn("Absence of evidence", pack["verdict"]["why"])

    def test_low_residual_for_an_ordinary_org_adopts(self):
        prior = self._prior(residual=10.0)
        pack = aa.adoption_advice(
            self.db, query="adopt Collibra writing assistant", product="Collibra",
            prior_analyses=prior,
            organisation={"sector": "retail", "systemic": False,
                          "data_sensitivity": "public"})
        self.assertEqual(pack["verdict"]["key"], "adopt")
        self.assertEqual(pack["product_risk_pct"], 10.0)

    def test_a_systemic_org_with_a_material_residual_does_not_adopt(self):
        prior = self._prior(residual=45.0)
        pack = aa.adoption_advice(
            self.db, query="adopt Collibra", product="Collibra",
            prior_analyses=prior,
            organisation={"sector": "financial_market_infrastructure",
                          "systemic": True, "regime": ["DORA"],
                          "data_sensitivity": "restricted"})
        self.assertEqual(pack["scrutiny"]["band"], "high")
        self.assertGreater(pack["adoption_pressure_pct"], pack["product_risk_pct"])
        self.assertEqual(pack["verdict"]["key"], "do_not_adopt")

    def test_a_bounded_pilot_is_the_middle_band(self):
        prior = self._prior(residual=30.0)
        pack = aa.adoption_advice(
            self.db, query="adopt Collibra", product="Collibra",
            prior_analyses=prior,
            organisation={"sector": "financial_market_infrastructure",
                          "systemic": True, "regime": ["DORA"],
                          "data_sensitivity": "restricted"})
        self.assertEqual(pack["verdict"]["key"], "pilot_only")

    def test_residual_blockers_force_do_not_adopt(self):
        rec = _assessment(self.inv.id, residual=40.0, threats=[
            {"id": "T12", "title": "Regulatory exposure",
             "residual_score": 88.0, "residual_severity": "high"}])
        self.db.add(rec)
        self.db.commit()
        prior = aa.find_prior_analyses(self.db, "collibra")
        pack = aa.adoption_advice(self.db, query="adopt Collibra",
                                  product="Collibra", prior_analyses=prior)
        self.assertTrue(pack["blockers"])
        self.assertEqual(pack["verdict"]["key"], "do_not_adopt")

    def test_unstated_org_nature_downgrades_a_clean_adopt_to_conditions(self):
        prior = self._prior(residual=5.0)
        pack = aa.adoption_advice(self.db, query="adopt Collibra",
                                  product="Collibra", prior_analyses=prior)
        self.assertEqual(pack["verdict"]["key"], "adopt_with_conditions")
        self.assertIn("unstated", pack["verdict"]["why"].lower())

    def test_every_condition_carries_a_residual_limitation(self):
        prior = self._prior()
        pack = aa.adoption_advice(
            self.db, query="adopt Collibra", product="Collibra",
            prior_analyses=prior,
            organisation={"sector": "financial_market_infrastructure",
                          "systemic": True, "data_sensitivity": "restricted",
                          "regime": ["DORA", "GDPR"],
                          "third_party_reliance": True, "cross_border": True})
        self.assertTrue(pack["conditions"])
        for c in pack["conditions"]:
            self.assertTrue(c["residual_limitation"], c["id"])
            self.assertTrue(c["why"], c["id"])

    def test_advice_never_claims_secured(self):
        prior = self._prior()
        pack = aa.adoption_advice(
            self.db, query="adopt Collibra", product="Collibra",
            prior_analyses=prior,
            organisation={"sector": "financial_market_infrastructure",
                          "systemic": True, "data_sensitivity": "restricted"})
        self.assertNotIn("secured", json.dumps(pack).lower())

    def test_markdown_references_the_prior_analysis_title(self):
        prior = self._prior()
        pack = aa.adoption_advice(self.db, query="adopt Collibra",
                                  product="Collibra", prior_analyses=prior)
        md = pack["markdown"]
        self.assertIn("# Adoption advice", md)
        self.assertIn("Collibra AI Writing Assistant", md)
        self.assertIn("Residual limitation", md)

    def test_fingerprint_is_stable_and_pinned_length(self):
        self.assertEqual(aa.adoption_advice_fingerprint(),
                         aa.adoption_advice_fingerprint())
        self.assertEqual(len(aa.adoption_advice_fingerprint()), 12)


class TestAdoptionAdviceEndpoints(AdviceCase):
    def setUp(self):
        super().setUp()
        from fastapi.testclient import TestClient  # noqa: E402

        from app.main import app as fastapi_app  # noqa: E402
        self.client = TestClient(fastapi_app)
        self.client.__enter__()
        self.headers = {"X-AKM-Actor": "tester"}

    def tearDown(self):
        try:
            self.client.__exit__(None, None, None)
        finally:
            super().tearDown()

    def test_post_returns_a_pack_with_a_verdict(self):
        r = self.client.post(
            "/api/adoption-advice",
            json={"query": "adoption advice for colibra inside a bank",
                  "investigation_id": self.inv.id},
            headers=self.headers)
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["method"], "adoption_advice_v1")
        self.assertIn(body["verdict"]["key"],
                      ("adopt", "adopt_with_conditions", "pilot_only",
                       "do_not_adopt", "insufficient_evidence"))
        self.assertIn("markdown", body)

    def test_get_cites_a_stored_analysis_for_the_family(self):
        self._prior()
        r = self.client.get(
            f"/api/investigations/{self.inv.id}/adoption-advice",
            params={"product": "colibra"})
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(len(body["prior_analyses"]), 1)
        self.assertEqual(body["product_risk_pct"], 58.0)


if __name__ == "__main__":
    unittest.main()
