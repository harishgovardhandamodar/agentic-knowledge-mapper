"""Portfolio layer: situation, unified register, leakage, advice.

The properties under test are the ones that would quietly produce a confident
wrong answer: a declared control counting as coverage, a risk row losing its
owner's decision on re-derivation, weight-level advice offered to an API-only
deployment, and two models with the same attack class collapsing into one row.
"""
import json
import os
import tempfile
import unittest

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-portfolio-"), "test.db"))

from app import database as _db  # noqa: E402
from app import leakage as lk  # noqa: E402
from app import model_eval as me  # noqa: E402
from app import model_kb as kb  # noqa: E402
from app import portfolio as pf  # noqa: E402
from app.database import Base, SessionLocal, engine  # noqa: E402
from app.models import (Investigation, Initiative, RiskEntry,  # noqa: E402
                        SecurityAssessment)

_db.init_db()


def _scoring(w1_pct=46.6):
    return json.dumps({
        "assessment_path": "model_engineering",
        "w1": {"overall_pct": w1_pct, "coverage_pct": 25.0,
               "model_adv_version": me.MODEL_ADV_VERSION,
               "model_adv_fingerprint": me.model_adv_fingerprint()},
        "w2": {"overall_pct": 60.0, "uncertainty_pct": 50.0,
               "adoption_version": me.ADOPTION_VERSION,
               "adoption_fingerprint": me.adoption_fingerprint()},
        "w3": {"residual_pct": 22.0,
               "mitigation_version": me.MITIGATION_VERSION,
               "mitigation_fingerprint": me.mitigation_fingerprint()},
    })


def _model_json(attacks, weights_source="open_weights", experiments=None,
                model_name="Acme TabPFN v2"):
    return json.dumps({
        "meta": {"model_name": model_name, "model_family": "tabular_fm",
                 "weights_source": weights_source,
                 "training_data_posture": "proprietary",
                 "deployment_pattern": "on_prem",
                 "workflows": ["adversarial_research", "adoption_risk"]},
        "attacks": attacks,
        "dimensions": [{"dimension": "memorization", "rating": "high"}],
        "mitigation": {"plan": [], "deferred": []},
        "experiments": experiments if experiments is not None else [],
    })

ATTACKS = [{"attack_id": "MA-01", "attack_class": "extraction",
            "applies_to": "model_specific", "confidence": 0.8}]

SITUATION = {
    "data": {"classification": "restricted", "pii_likelihood": True},
    "channel": "chat_ui",
    "actors": ["analyst"],
    "controls": {"dlp": "evidenced", "logging": "declared"},
    "blast_radius": {"tickets": True},
    "external": True,
    "obligations": ["GDPR Art.28"],
}


class PortfolioCase(unittest.TestCase):
    def setUp(self):
        Base.metadata.create_all(bind=engine)
        self.db = SessionLocal()
        self.inv = Investigation(title="portfolio inv")
        self.db.add(self.inv)
        self.db.commit()
        self.db.refresh(self.inv)

    def tearDown(self):
        self.db.query(Initiative).filter(
            Initiative.investigation_id == self.inv.id).delete()
        self.db.query(RiskEntry).filter(
            RiskEntry.investigation_id == self.inv.id).delete()
        self.db.query(SecurityAssessment).filter(
            SecurityAssessment.investigation_id == self.inv.id).delete()
        self.db.query(Investigation).filter(
            Investigation.id == self.inv.id).delete()
        self.db.commit()
        self.db.close()

    def _assessment(self, product="acme-tabpfn-v2", attacks=None,
                    situation=None, model_json=None, model_name=None,
                    requested_by=None, initiative_id=None):
        rec = SecurityAssessment(
            investigation_id=self.inv.id, product_name=product,
            requested_by=requested_by, initiative_id=initiative_id,
            exposure="restricted_data", use_case="churn scoring",
            focus_json=json.dumps(["fine-tune"]),
            overall_pct=46.6, inherent_pct=46.6, residual_pct=40.0,
            markdown="# report", threat_pack_version="2.1.0",
            threat_pack_fingerprint="19a11481e69d",
            scoring_json=_scoring(),
            model_json=model_json if model_json is not None
            else _model_json(attacks if attacks is not None else ATTACKS,
                             model_name=model_name or product),
            hypothesis_json=json.dumps({"claims": []}),
            situation_json=json.dumps(situation) if situation is not None
            else None)
        self.db.add(rec)
        self.db.commit()
        self.db.refresh(rec)
        kb.sync_model_kb(self.db, rec.id)
        return rec


class TestSituationProfile(PortfolioCase):
    def test_absent_fields_stay_unknown_rather_than_defaulting(self):
        sit = pf.normalize_situation({})
        self.assertIsNone(sit["data"]["classification"])
        self.assertEqual(sit["controls"]["dlp"], "unknown")
        self.assertEqual(sit["actors"], [])
        self.assertIn("controls.dlp", sit["unknown_fields"])

    def test_a_declared_control_does_not_reduce_risk(self):
        declared = pf.situation_multiplier(
            pf.normalize_situation({"data": {"classification": "internal"},
                                    "controls": {"logging": "declared"}}))
        unstated = pf.situation_multiplier(
            pf.normalize_situation({"data": {"classification": "internal"},
                                    "controls": {"logging": "unknown"}}))
        self.assertEqual(declared["multiplier"], unstated["multiplier"])
        self.assertIn("logging declared, not evidenced",
                      declared["unverified_controls"])

    def test_an_evidenced_control_does_reduce_risk(self):
        ev = pf.situation_multiplier(
            pf.normalize_situation({"data": {"classification": "internal"},
                                    "controls": {"logging": "evidenced"}}))
        un = pf.situation_multiplier(
            pf.normalize_situation({"data": {"classification": "internal"}}))
        self.assertLess(ev["multiplier"], un["multiplier"])

    def test_the_same_model_scores_differently_in_two_situations(self):
        research = pf.situation_multiplier(pf.normalize_situation(
            {"data": {"classification": "internal"}, "channel": "batch",
             "controls": {"logging": "evidenced", "dlp": "evidenced"}}))
        customer = pf.situation_multiplier(pf.normalize_situation(
            {"data": {"classification": "restricted", "pii_likelihood": True},
             "channel": "chat_ui", "external": True,
             "blast_radius": {"customer_channels": True, "tickets": True}}))
        self.assertGreater(customer["multiplier"], research["multiplier"])

    def test_an_unknown_channel_is_flagged_not_silently_accepted(self):
        self.assertFalse(pf.normalize_situation(
            {"channel": "carrier_pigeon"})["channel_valid"])


class TestLeakage(PortfolioCase):
    def test_only_pathways_the_situation_has_are_derived(self):
        sit = pf.normalize_situation({"channel": "batch",
                                      "data": {"classification": "internal"}})
        ids = {r["source_ref"] for r in pf.leakage_rows(sit, {})}
        self.assertNotIn("LP01", ids)   # no user-facing surface declared
        self.assertNotIn("LP02", ids)   # no retrieval declared

    def test_a_chat_surface_with_confidential_data_derives_the_paste_pathway(self):
        sit = pf.normalize_situation(SITUATION)
        rows = {r["source_ref"]: r for r in pf.leakage_rows(sit, {})}
        self.assertIn("LP01", rows)
        self.assertEqual(rows["LP01"]["layer"], "privacy")

    def test_severity_is_clamped_to_its_own_scale(self):
        sit = pf.normalize_situation({
            "data": {"classification": "restricted", "secrets_likelihood": True},
            "channel": "tool_calling_agent", "external": True,
            "blast_radius": {f: True for f in pf.BLAST_FIELDS}})
        for r in pf.leakage_rows(sit, {"weights_source": "open_weights"}):
            self.assertLessEqual(r["severity"], 100.0)
            self.assertGreaterEqual(r["severity"], 0.0)

    def test_evidencing_a_control_lowers_that_pathway(self):
        base = dict(SITUATION, controls={"dlp": "unknown", "classification_gate": "unknown",
                                         "output_review": "unknown"})
        un = {r["source_ref"]: r for r in pf.leakage_rows(pf.normalize_situation(base), {})}
        covered = dict(base, controls={"dlp": "evidenced"})
        ev = {r["source_ref"]: r for r in pf.leakage_rows(pf.normalize_situation(covered), {})}
        self.assertLess(ev["LP01"]["severity"], un["LP01"]["severity"])
        self.assertEqual(ev["LP01"]["control_coverage"]["evidenced"], ["C03"])

    def test_a_declared_control_counts_as_no_coverage(self):
        sit = pf.normalize_situation(dict(
            SITUATION, controls={"dlp": "declared", "classification_gate": "declared",
                                 "output_review": "declared"}))
        row = {r["source_ref"]: r for r in pf.leakage_rows(sit, {})}["LP01"]
        self.assertEqual(row["control_coverage"]["covered"], 0.0)
        self.assertEqual(sorted(row["control_coverage"]["declared_only"]),
                         ["C01", "C03", "C12"])

    def test_every_pathway_cites_the_catalog_that_produced_it(self):
        sit = pf.normalize_situation(SITUATION)
        for r in pf.leakage_rows(sit, {"weights_source": "open_weights"}):
            self.assertEqual(r["catalog_fingerprint"], lk.leakage_fingerprint())
            self.assertEqual(r["catalog_version"], lk.LEAKAGE_VERSION)

    def test_an_api_only_deployment_does_not_get_an_embeddings_side_channel(self):
        sit = pf.normalize_situation({"channel": "api"})
        ids = {r["source_ref"] for r in
               pf.leakage_rows(sit, {"weights_source": "api_only"})}
        self.assertNotIn("LP08", ids)


class TestUnifiedRegister(PortfolioCase):
    def test_model_privacy_and_product_rows_share_one_table(self):
        self._assessment(situation=SITUATION)
        reg = pf.derive_register(self.db, self.inv.id)
        self.assertEqual({r["layer"] for r in reg} - {"product"},
                         {"model", "privacy"})

    def test_two_models_with_the_same_attack_class_are_two_rows(self):
        # identical attack lists, different models: the register must still hold
        # two rows, because "extraction applies" is not one piece of news
        self._assessment(product="acme-tabpfn-v2")
        self._assessment(product="acme-tabpfn-v3")
        reg = pf.derive_register(self.db, self.inv.id)
        keys = [r["stable_key"] for r in reg]
        self.assertEqual(len(keys), len(set(keys)), "register keys must be unique")
        refs = {r["risk_id"] for r in reg if r["layer"] == "model"}
        self.assertIn("R-acme-tabpfn-v2-MA-01", refs)
        self.assertIn("R-acme-tabpfn-v3-MA-01", refs)

    def test_human_state_survives_re_derivation(self):
        self._assessment(situation=SITUATION)
        first = pf.derive_register(self.db, self.inv.id)
        target = next(r for r in first if r["layer"] == "model")
        pf.set_risk_state(self.db, target["entry_id"], status="accepted",
                          owner="risk-team", residual_note="accepted 2026-08",
                          accept=True, accepted_by="ciso",
                          acceptance_note="business need")
        again = pf.derive_register(self.db, self.inv.id)
        same = next(r for r in again if r["stable_key"] == target["stable_key"])
        self.assertEqual(same["status"], "accepted")
        self.assertEqual(same["owner"], "risk-team")
        self.assertEqual(same["accepted_by"], "ciso")
        self.assertEqual(same["residual_note"], "accepted 2026-08")
        self.assertEqual(len(again), len(first), "re-derivation must not add rows")

    def test_derived_fields_refresh_while_decisions_stay(self):
        self._assessment(situation=SITUATION)
        first = pf.derive_register(self.db, self.inv.id)
        t = next(r for r in first if r["layer"] == "model")
        pf.set_risk_state(self.db, t["entry_id"], owner="risk-team")
        pf.set_risk_state(self.db, t["entry_id"], mitigation_ids=["MM01", "MM05"])
        again = {r["stable_key"]: r for r in pf.derive_register(self.db, self.inv.id)}
        self.assertEqual(again[t["stable_key"]]["mitigation_ids"], ["MM01", "MM05"])
        self.assertEqual(again[t["stable_key"]]["owner"], "risk-team")

    def test_an_unowned_row_says_so_rather_than_defaulting(self):
        self._assessment(situation=SITUATION)
        reg = pf.derive_register(self.db, self.inv.id)
        self.assertTrue(any(r["owner_missing"] for r in reg))

    def test_an_unknown_status_is_rejected(self):
        self._assessment(situation=SITUATION)
        reg = pf.derive_register(self.db, self.inv.id)
        with self.assertRaises(ValueError):
            pf.set_risk_state(self.db, reg[0]["entry_id"], status="probably_fine")


class TestAdvisor(PortfolioCase):
    def test_weight_level_advice_is_withheld_from_an_api_only_deployment(self):
        self._assessment(situation=SITUATION)
        reg = pf.derive_register(self.db, self.inv.id)
        adv = pf.advise(self.db, self.inv.id, reg)
        model_risk = next(a for a in adv["advice"] if a["layer"] == "model")
        self.assertEqual(model_risk["controls_unavailable"], [])
        self.assertTrue(model_risk["controls"], "open weights can take MM advice")

    def test_api_only_drops_mm_controls_and_says_why(self):
        self._assessment(situation=SITUATION,
                         model_json=_model_json(ATTACKS,
                                                weights_source="api_only"))
        reg = pf.derive_register(self.db, self.inv.id)
        adv = pf.advise(self.db, self.inv.id, reg)
        model_risk = next(a for a in adv["advice"] if a["layer"] == "model")
        # serving-time controls (e.g. DP at inference) are still available; what
        # must not appear is anything that needs the weights
        self.assertTrue(model_risk["controls_unavailable"])
        self.assertTrue(all(c["requires"] == "training_access"
                            for c in model_risk["controls_unavailable"]))
        self.assertTrue(all(c["requires"] != "training_access"
                            for c in model_risk["controls"]))
        self.assertTrue(all("api_only" in c["reason_dropped"]
                            for c in model_risk["controls_unavailable"]))

    def test_a_partially_deployed_control_is_presented_as_a_quick_win(self):
        self._assessment(situation=SITUATION)
        self.db.add(Initiative(
            investigation_id=self.inv.id, title="init",
            control_inventory_json=json.dumps([
                {"control_id": "C04", "status": "partial"}])))
        self.db.commit()
        reg = pf.derive_register(self.db, self.inv.id)
        adv = pf.advise(self.db, self.inv.id, reg)
        lp04 = next(a for a in adv["advice"] if a["risk_id"] == "R-LP-acme-tabpfn-v2-LP04")
        self.assertTrue(lp04["quick_win"])
        first = next(c for c in lp04["controls"] if c["control_id"] == "C04")
        self.assertEqual(first["inventory_status"], "partial")
        self.assertIn("partially deployed", first["inventory_delta"])

    def test_every_advice_item_cites_the_risk_it_answers(self):
        self._assessment(situation=SITUATION)
        reg = pf.derive_register(self.db, self.inv.id)
        adv = pf.advise(self.db, self.inv.id, reg)
        ids = {r["risk_id"] for r in reg}
        for a in adv["advice"]:
            self.assertIn(a["risk_id"], ids)

    def test_advice_never_claims_secured(self):
        self._assessment(situation=SITUATION)
        reg = pf.derive_register(self.db, self.inv.id)
        adv = pf.advise(self.db, self.inv.id, reg)
        self.assertTrue(any("does not close it" in x for x in adv["limitations"]))
        blob = json.dumps(adv).lower()
        for banned in ("secured", "fully mitigated", "risk eliminated"):
            self.assertNotIn(banned, blob)

    def test_an_incomplete_situation_is_called_out_as_material(self):
        self._assessment(situation={"channel": "api"})
        reg = pf.derive_register(self.db, self.inv.id)
        adv = pf.advise(self.db, self.inv.id, reg)
        self.assertTrue(adv["situation"]["material_unknown"])
        self.assertTrue(any("starting point, not a sign-off" in x
                            for x in adv["limitations"]))

    def test_a_cascade_risk_is_advised_as_a_composition_not_a_base_model_problem(self):
        self._assessment(situation=SITUATION)
        reg = pf.derive_register(self.db, self.inv.id)
        adv = pf.advise(self.db, self.inv.id, reg)
        cas = next((a for a in adv["advice"] if a["scope"] == "cascade"), None)
        self.assertIsNotNone(cas)
        self.assertNotIn("MM01", [c["control_id"] for c in cas["controls"]])

    def test_playbooks_are_selected_by_situation_tags(self):
        sit = pf.normalize_situation(SITUATION)
        picked = lk.select_playbooks(sit["tags"])
        self.assertIn("PB01", [p["id"] for p in picked])


class TestPortfolioCascade(unittest.TestCase):
    def test_a_shared_mechanism_produces_a_transitive_edge(self):
        inits = [
            {"title": "Churn scoring", "models": ["acme-v2"],
             "business_use_case": "fine-tuned model on PII"},
            {"title": "Support assistant", "models": ["acme-v2"],
             "business_use_case": "agent with tool access to CRM"},
        ]
        edges = pf.portfolio_cascade({}, inits)
        self.assertTrue(edges)
        self.assertTrue(any(e["basis"] == "transitive" for e in edges))
        for e in edges:
            self.assertIn("via", e)

    def test_unrelated_initiatives_produce_no_edge(self):
        inits = [{"title": "A", "models": ["m1"], "business_use_case": "batch report"},
                 {"title": "B", "models": ["m2"], "business_use_case": "spreadsheet"}]
        self.assertEqual(pf.portfolio_cascade({}, inits), [])


class TestIntelAndMetrics(PortfolioCase):
    def test_a_stale_assessment_shows_up_in_the_feed(self):
        import datetime as dt
        rec = self._assessment(situation=SITUATION)
        rec.created_at = dt.datetime.utcnow() - dt.timedelta(days=200)
        self.db.commit()
        feed = pf.intel_feed(self.db, self.inv.id, stale_days=90)
        self.assertTrue(feed["stale_assessments"])
        self.assertFalse(feed["quiet"])

    def test_a_fresh_investigation_is_quiet_and_says_what_that_means(self):
        self._assessment(situation=SITUATION)
        feed = pf.intel_feed(self.db, self.inv.id, stale_days=90)
        self.assertTrue(feed["quiet"])
        self.assertIn("not that the landscape is unchanged", feed["note"])

    def test_an_empty_register_reports_none_rather_than_zero(self):
        m = pf.metrics([], {}, None)
        self.assertIsNone(m["pct_with_owner"])
        self.assertIsNone(m["pct_models_w2_known"])

    def test_metrics_report_unknowns_instead_of_a_composite_score(self):
        self._assessment(situation=SITUATION)
        reg = pf.derive_register(self.db, self.inv.id)
        m = pf.metrics(reg, kb.landscape(self.db, self.inv.id))
        self.assertEqual(m["register_total"], len(reg))
        self.assertNotIn("score", m)
        self.assertNotIn("grade", m)


class TestPortfolioEndpoints(PortfolioCase):
    """The API surface the Portfolio tab talks to.

    These tests pin the contract the UI depends on: stable keys survive the
    round trip, a recorded situation is what the register derives from (not
    the audit envelope around it), and acceptance cannot be recorded without
    naming who accepted and what they accepted.
    """

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

    def test_initiatives_are_listed_with_their_missing_fields(self):
        r = self.client.post(
            "/api/portfolio/initiatives",
            params={"investigation_id": self.inv.id},
            json={"title": "Churn assist", "business_use_case": "",
                  "owner": "", "data_classes": ["pii"],
                  "target_users": [], "systems": ["crm"],
                  "obligations": [], "control_inventory": [],
                  "status": "active", "review_cadence_days": 90},
            headers=self.headers)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["missing_fields"],
                         ["business_use_case", "owner"])
        g = self.client.get("/api/portfolio/initiatives",
                            params={"investigation_id": self.inv.id})
        self.assertEqual(g.status_code, 200, g.text)
        body = g.json()
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["undescribed"], 1)
        self.assertFalse(body["initiatives"][0]["described"])

    def test_recorded_situation_flows_into_register_leakage_and_advice(self):
        rec = self._assessment()
        posted = self.client.post(
            "/api/portfolio/situation",
            json={"investigation_id": self.inv.id,
                  "assessment_id": rec.id, "situation": SITUATION,
                  "actor": "tester", "rationale": "customer chat pilot"},
            headers=self.headers)
        self.assertEqual(posted.status_code, 200, posted.text)
        self.assertEqual(posted.json()["situation"]["channel"], "chat_ui")
        self.db.expire_all()

        reg = self.client.get("/api/portfolio/register",
                              params={"investigation_id": self.inv.id})
        self.assertEqual(reg.status_code, 200, reg.text)
        risks = reg.json()["risks"]
        keys = [x["stable_key"] for x in risks]
        self.assertEqual(len(keys), len(set(keys)))
        lp01 = next(x for x in risks if x["source_ref"] == "LP01")
        self.assertTrue(lp01["risk_id"].startswith("R-LP-acme-tabpfn-v2-LP01"))
        self.assertIn("C03", lp01["control_coverage"]["evidenced"])
        model = next(x for x in risks if x["layer"] == "model")
        self.assertIn("MM01", model["control_options"])
        self.assertTrue(model["why"])

        leak = self.client.get("/api/portfolio/leakage",
                               params={"investigation_id": self.inv.id})
        self.assertEqual(leak.status_code, 200, leak.text)
        payload = leak.json()
        self.assertEqual(payload["assessments_with_situation"], 1)
        self.assertEqual(payload["catalog_fingerprint"],
                         lk.leakage_fingerprint())
        self.assertIn("PB01", [x["id"] for x in payload["playbooks"]])

        adv = self.client.post(
            "/api/portfolio/advisor",
            json={"investigation_id": self.inv.id}, headers=self.headers)
        self.assertEqual(adv.status_code, 200, adv.text)
        pack = adv.json()
        item = next(x for x in pack["advice"] if x["layer"] == "model")
        self.assertTrue(item["title"])
        self.assertTrue(item["why"])
        self.assertIn("MM01", [x["control_id"] for x in item["controls"]])
        self.assertNotIn("secured", json.dumps(pack).lower())

        from app import dossier as dz  # noqa: E402
        stored = self.db.get(SecurityAssessment, rec.id)
        snap = dz._portfolio_snapshot(self.db, stored)
        self.assertEqual(snap["channel"], "chat_ui")
        self.assertEqual(snap["controls"]["dlp"], "evidenced")
        self.assertIn("controls.sso_roles", snap["unknown_fields"])

    def test_register_state_and_acceptance_rules(self):
        self._assessment(situation=SITUATION, requested_by="analyst")
        risks = self.client.get(
            "/api/portfolio/register",
            params={"investigation_id": self.inv.id}).json()["risks"]
        target = next(x for x in risks if x["layer"] == "model")
        moved = self.client.post(
            "/api/portfolio/register/state",
            json={"entry_id": target["entry_id"], "status": "mitigating",
                  "owner": "risk-team", "review_by": "2026-12-01",
                  "residual_note": "MM01 pilot running",
                  "rationale": "weekly review"},
            headers=self.headers)
        self.assertEqual(moved.status_code, 200, moved.text)
        self.assertEqual(moved.json()["owner"], "risk-team")
        again = {x["stable_key"]: x for x in self.client.get(
            "/api/portfolio/register",
            params={"investigation_id": self.inv.id}).json()["risks"]}
        self.assertEqual(again[target["stable_key"]]["status"], "mitigating")

        unnamed = self.client.post(
            "/api/portfolio/register/state",
            json={"entry_id": target["entry_id"], "accept": True},
            headers=self.headers)
        self.assertEqual(unnamed.status_code, 400)
        self_accepted = self.client.post(
            "/api/portfolio/register/state",
            json={"entry_id": target["entry_id"], "accept": True,
                  "accepted_by": "analyst",
                  "acceptance_note": "requester cannot accept their own risk"},
            headers=self.headers)
        self.assertEqual(self_accepted.status_code, 403)
        accepted = self.client.post(
            "/api/portfolio/register/state",
            json={"entry_id": target["entry_id"], "accept": True,
                  "accepted_by": "ciso",
                  "acceptance_note": "residual extraction accepted for pilot"},
            headers=self.headers)
        self.assertEqual(accepted.status_code, 200, accepted.text)
        self.assertEqual(accepted.json()["accepted_by"], "ciso")

    def test_intel_metrics_and_cascade_endpoints_use_stored_rows(self):
        self._assessment(situation=SITUATION)
        intel = self.client.get(
            "/api/portfolio/intel",
            params={"investigation_id": self.inv.id, "stale_days": 90})
        self.assertEqual(intel.status_code, 200, intel.text)
        self.assertTrue(intel.json()["quiet"])
        metrics = self.client.get(
            "/api/portfolio/metrics",
            params={"investigation_id": self.inv.id})
        self.assertEqual(metrics.status_code, 200, metrics.text)
        register = self.client.get(
            "/api/portfolio/register",
            params={"investigation_id": self.inv.id}).json()
        self.assertEqual(metrics.json()["register_total"],
                         register["total"])
        cascade = self.client.get(
            "/api/portfolio/cascade",
            params={"investigation_id": self.inv.id})
        self.assertEqual(cascade.status_code, 200, cascade.text)
        self.assertIn("edges", cascade.json())


    def test_initiative_aggregate_and_scoped_advice(self):
        created = self.client.post(
            "/api/portfolio/initiatives",
            params={"investigation_id": self.inv.id},
            json={"title": "Churn pilot", "business_use_case": "churn scoring",
                  "owner": "risk-team", "data_classes": ["pii"],
                  "target_users": ["analyst"], "systems": ["crm"],
                  "obligations": ["GDPR Art.28"],
                  "control_inventory": [{"control_id": "C04",
                                         "status": "partial"}],
                  "status": "active", "review_cadence_days": 90},
            headers=self.headers)
        self.assertEqual(created.status_code, 200, created.text)
        initiative_id = created.json()["id"]
        self._assessment(situation=SITUATION, initiative_id=initiative_id)
        self._assessment(product="acme-tabpfn-v3", model_name="Acme TabPFN v3",
                         situation=SITUATION)

        listed = self.client.get(
            "/api/portfolio/initiatives",
            params={"investigation_id": self.inv.id}).json()["initiatives"]
        aggregate = next(x for x in listed
                         if x["id"] == initiative_id)["aggregate"]
        self.assertEqual(aggregate["assessments"], 1)
        self.assertEqual(aggregate["assessments_with_situation"], 1)
        self.assertGreater(aggregate["risks"], 0)
        self.assertEqual(aggregate["open_risks"], aggregate["risks"])

        scoped = self.client.post(
            "/api/portfolio/advisor",
            json={"investigation_id": self.inv.id,
                  "initiative_id": initiative_id},
            headers=self.headers)
        self.assertEqual(scoped.status_code, 200, scoped.text)
        pack = scoped.json()
        self.assertEqual(pack["initiative_id"], initiative_id)
        self.assertTrue(pack["advice"])
        self.assertTrue(all("acme-tabpfn-v2" in x["risk_id"]
                            for x in pack["advice"]))
        lp04 = next(x for x in pack["advice"]
                    if x["risk_id"].endswith("LP04"))
        c04 = next(x for x in lp04["controls"]
                   if x["control_id"] == "C04")
        self.assertEqual(c04["inventory_status"], "partial")
        self.assertTrue(any("Scoped to initiative" in x
                            for x in pack["limitations"]))

        missing = self.client.post(
            "/api/portfolio/advisor",
            json={"investigation_id": self.inv.id, "initiative_id": 999999},
            headers=self.headers)
        self.assertEqual(missing.status_code, 404)


class TestMitigationAdvisorRole(PortfolioCase):
    """The mitigation-advisor as an A2A role, not just an endpoint.

    The role exists so the pipeline, a peer agent and the UI all read the
    same pack. These tests pin the bus contract: the card is discoverable,
    the intent is wired, the pack is deterministic across hops, and a bad
    payload is rejected on the record rather than answered with a guess.
    """

    def _dispatch(self, **payload):
        from app import agents
        env = agents.new_envelope("security-orchestrator",
                                  "mitigation-advisor",
                                  "advise_portfolio_risks",
                                  {"investigation_id": self.inv.id, **payload})
        return agents.dispatch(env, self.db)

    def test_card_and_handler_are_registered(self):
        from app import agents
        names = {c["name"] for c in agents.get_agent_cards()}
        self.assertIn("mitigation-advisor", names)
        card = next(c for c in agents.get_agent_cards()
                    if c["name"] == "mitigation-advisor")
        self.assertIn("advise_portfolio_risks", card["skills"])
        self.assertIn("mitigation-advisor", agents._HANDLERS)
        self.assertIn("advise_portfolio_risks",
                      agents._HANDLERS["mitigation-advisor"])

    def test_the_bus_returns_the_same_pack_as_the_api(self):
        self._assessment(situation=SITUATION)
        res = self._dispatch()
        pack = res["payload"]
        self.assertEqual(pack["method"], pf.PORTFOLIO_METHOD)
        self.assertEqual(pack["version"], pf.PORTFOLIO_VERSION)
        self.assertTrue(pack["advice"])
        self.assertTrue(pack["limitations"])
        self.assertIn("akm-leakage-pathways", pack["catalogs"])
        again = self._dispatch()
        self.assertEqual(again["payload"]["advice"], pack["advice"])

    def test_the_role_scopes_to_an_initiative_like_the_api(self):
        created = Initiative(
            investigation_id=self.inv.id, title="scoped pilot",
            control_inventory_json=json.dumps(
                [{"control_id": "C04", "status": "partial"}]))
        self.db.add(created)
        self.db.commit()
        self._assessment(situation=SITUATION, initiative_id=created.id)
        self._assessment(product="other", model_name="Other",
                         situation=SITUATION)
        pack = self._dispatch(initiative_id=created.id)["payload"]
        self.assertEqual(pack["initiative_id"], created.id)
        self.assertTrue(pack["advice"])
        self.assertTrue(all("acme-tabpfn-v2" in a["risk_id"]
                            for a in pack["advice"]))

    def test_a_bad_payload_is_rejected_not_guessed(self):
        from app import agents
        with self.assertRaises(ValueError):
            agents.dispatch(agents.new_envelope(
                "security-orchestrator", "mitigation-advisor",
                "advise_portfolio_risks", {}), self.db)
        with self.assertRaises(ValueError):
            self._dispatch(initiative_id=999999)


if __name__ == "__main__":
    unittest.main()