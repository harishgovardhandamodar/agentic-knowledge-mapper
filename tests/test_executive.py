"""Executive dashboard: availability, distribution, robustness.

Every number here is a count a reader can recompute from the rows it names.
The properties pinned are the ones that would quietly mislead a CISO: an
unknown reading as covered, a pending artifact counting as evidence, a
self-approval passing hygiene, or a composite score hiding its denominator.
"""
import datetime as dt
import json
import os
import tempfile
import unittest

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-exec-"), "test.db"))

from app import database as _db  # noqa: E402
from app import executive as ex  # noqa: E402
from app import model_eval as me  # noqa: E402
from app import model_kb as kb  # noqa: E402
from app.database import Base, SessionLocal, engine  # noqa: E402
from app.models import (AgentRun, Artifact, CveFinding,  # noqa: E402
                        DashboardSnapshot, Investigation,
                        Initiative, Job, RiskEntry, SecurityAssessment)


_db.init_db()

SITUATION = {
    "data": {"classification": "restricted", "pii_likelihood": True},
    "channel": "chat_ui",
    "actors": ["analyst"],
    "controls": {"dlp": "evidenced", "logging": "declared"},
    "blast_radius": {"tickets": True},
    "external": True,
}

THREATS = [{"id": "T01", "title": "Prompt paste of secrets",
            "residual_score": 72.0, "residual_likelihood": 0.8,
            "residual_severity": "high"}]

ATTACKS = [{"attack_id": "MA-01", "attack_class": "extraction",
            "applies_to": "model_specific", "confidence": 0.8}]


def _scoring():
    return json.dumps({
        "assessment_path": "model_engineering",
        "w1": {"overall_pct": 46.6, "coverage_pct": 25.0,
               "model_adv_version": me.MODEL_ADV_VERSION,
               "model_adv_fingerprint": me.model_adv_fingerprint()},
        "w2": {"overall_pct": 60.0, "uncertainty_pct": 50.0,
               "adoption_version": me.ADOPTION_VERSION,
               "adoption_fingerprint": me.adoption_fingerprint()},
        "w3": {"residual_pct": 22.0,
               "mitigation_version": me.MITIGATION_VERSION,
               "mitigation_fingerprint": me.mitigation_fingerprint()},
    })


def _model_json(name="Acme TabPFN v2"):
    return json.dumps({
        "meta": {"model_name": name, "model_family": "tabular_fm",
                 "weights_source": "open_weights",
                 "training_data_posture": "proprietary",
                 "deployment_pattern": "on_prem",
                 "workflows": ["adversarial_research", "adoption_risk"]},
        "attacks": ATTACKS,
        "dimensions": [{"dimension": "memorization", "rating": "high"}],
        "mitigation": {"plan": [], "deferred": []},
        "experiments": [],
    })


class ExecCase(unittest.TestCase):
    def setUp(self):
        Base.metadata.create_all(bind=engine)
        self.db = SessionLocal()
        self.inv = Investigation(title="exec inv")
        self.db.add(self.inv)
        self.db.commit()
        self.db.refresh(self.inv)

    def tearDown(self):
        run_ids = [r.id for r in self.db.query(AgentRun).filter(
            AgentRun.investigation_id == self.inv.id).all()]
        if run_ids:
            self.db.query(Job).filter(Job.run_id.in_(run_ids)).delete(
                synchronize_session=False)
        for model in (AgentRun, Artifact, CveFinding, RiskEntry,
                      Initiative, SecurityAssessment, DashboardSnapshot):
            self.db.query(model).filter(
                model.investigation_id == self.inv.id).delete()
        self.db.query(Investigation).filter(
            Investigation.id == self.inv.id).delete()
        self.db.commit()
        self.db.close()

    def _model_assessment(self, name="Acme TabPFN v2", situation=None,
                          initiative_id=None, requested_by="analyst",
                          created=None):
        rec = SecurityAssessment(
            investigation_id=self.inv.id, product_name=name,
            requested_by=requested_by, initiative_id=initiative_id,
            exposure="restricted_data", use_case="churn scoring",
            focus_json=json.dumps(["fine-tune"]),
            overall_pct=46.6, inherent_pct=46.6, residual_pct=40.0,
            markdown="# report", threat_pack_version="2.1.0",
            threat_pack_fingerprint="19a11481e69d",
            scoring_json=_scoring(), model_json=_model_json(name),
            hypothesis_json=json.dumps({"claims": []}),
            situation_json=json.dumps(situation) if situation else None)
        self.db.add(rec)
        self.db.commit()
        if created:
            rec.created_at = created
            self.db.commit()
        self.db.refresh(rec)
        kb.sync_model_kb(self.db, rec.id)
        return rec

    def _product_assessment(self, product="churn-app", threats=None,
                            pack_version="2.1.0"):
        rec = SecurityAssessment(
            investigation_id=self.inv.id, product_name=product,
            requested_by="analyst", exposure="confidential_data",
            use_case="churn scoring", focus_json=json.dumps([]),
            overall_pct=55.0, inherent_pct=68.0, residual_pct=55.0,
            markdown="# report", threat_pack_version=pack_version,
            threat_pack_fingerprint="fp" if pack_version else None,
            scoring_json=json.dumps({}), model_json=None,
            hypothesis_json=json.dumps({"claims": []}),
            threats_json=json.dumps(threats if threats is not None
                                    else THREATS))
        self.db.add(rec)
        self.db.commit()
        self.db.refresh(rec)
        return rec

    def _initiative(self, title="Churn pilot", **over):
        kw = {"investigation_id": self.inv.id, "title": title,
              "business_use_case": "churn scoring", "owner": "risk-team",
              "data_classes_json": json.dumps(["pii"]),
              "obligations_json": json.dumps(["GDPR"]),
              "control_inventory_json": json.dumps([]),
              "status": "active"}
        kw.update(over)
        ini = Initiative(**kw)
        self.db.add(ini)
        self.db.commit()
        self.db.refresh(ini)
        return ini

    def _artifact(self, title="vendor doc", review="accepted", days_ago=5,
                  artifact_type="paper"):
        a = Artifact(
            investigation_id=self.inv.id, title=title,
            artifact_type=artifact_type, review=review,
            created_at=dt.datetime.utcnow() - dt.timedelta(days=days_ago))
        self.db.add(a)
        self.db.commit()
        self.db.refresh(a)
        return a


class TestScope(ExecCase):
    def test_unknown_investigation_initiative_and_layer_are_rejected(self):
        with self.assertRaises(LookupError):
            ex.resolve_scope(self.db, 999999)
        ini = self._initiative()
        with self.assertRaises(LookupError):
            ex.resolve_scope(self.db, self.inv.id, initiative_id=999999)
        with self.assertRaises(ValueError):
            ex.resolve_scope(self.db, self.inv.id, layer="nope")
        scope = ex.resolve_scope(self.db, self.inv.id, initiative_id=ini.id)
        self.assertEqual(scope["initiative_title"], "Churn pilot")
        self.assertTrue(scope["accepted_only"])


class TestAvailability(ExecCase):
    def test_an_unassessed_initiative_is_listed_not_averaged_away(self):
        self._initiative(title="Covered", business_use_case="x", owner="o")
        self._initiative(title="Bare", business_use_case="", owner="")
        rec = self._model_assessment()
        rec.initiative_id = self.db.query(Initiative).filter(
            Initiative.title == "Covered").one().id
        self.db.commit()
        avail = ex.availability(self.db, self.inv.id)
        self.assertEqual(avail["initiative_coverage"], {"pct": 50.0, "n": 1,
                                                        "of": 2})
        self.assertEqual([u["title"] for u in avail["uncovered_initiatives"]],
                         ["Bare"])
        self.assertTrue(any(u["link"]["initiative_id"] is not None
                            for u in avail["uncovered_initiatives"]))

    def test_model_coverage_comes_from_stored_metadata(self):
        self._model_assessment()
        avail = ex.availability(self.db, self.inv.id)
        self.assertEqual(avail["model_coverage"]["of"], 1)
        self.assertEqual(avail["model_coverage"]["pct"], 100.0)
        self.assertEqual(avail["uncovered_models"], [])

    def test_a_product_without_a_catalog_assessment_is_uncovered(self):
        self._product_assessment(pack_version=None)
        avail = ex.availability(self.db, self.inv.id)
        self.assertEqual(avail["product_coverage"], {"pct": 0.0, "n": 0,
                                                     "of": 1})
        self.assertEqual(avail["uncovered_products"], ["churn-app"])

    def test_completeness_counts_owner_and_review_together(self):
        self._model_assessment(situation=SITUATION)
        rows = ex.scoped_register(self.db, self.inv.id,
                                  ex.resolve_scope(self.db, self.inv.id))
        open_rows = [r for r in rows if r["status"] == "open"]
        self.assertTrue(open_rows)
        avail = ex.availability(self.db, self.inv.id)
        self.assertEqual(avail["register_completeness"]["of"], len(open_rows))
        self.assertEqual(avail["register_completeness"]["n"], 0)

    def test_pending_evidence_moves_freshness_only_when_toggled(self):
        rec = self._model_assessment(situation=SITUATION)
        pending = self._artifact(title="unreviewed vendor note",
                                 review="pending", days_ago=2)
        rows = ex.scoped_register(self.db, self.inv.id,
                                  ex.resolve_scope(self.db, self.inv.id))
        for r in rows:
            e = self.db.query(RiskEntry).filter(
                RiskEntry.stable_key == r["stable_key"]).one_or_none()
            if e is None:
                e = RiskEntry(investigation_id=self.inv.id,
                              stable_key=r["stable_key"],
                              risk_id=r["risk_id"], layer=r["layer"],
                              title=r["title"], status="open")
                self.db.add(e)
            e.evidence_ids_json = json.dumps([pending.id])
        self.db.commit()
        on = ex.availability(self.db, self.inv.id,
                             ex.resolve_scope(self.db, self.inv.id,
                                              accepted_only=True))
        off = ex.availability(self.db, self.inv.id,
                              ex.resolve_scope(self.db, self.inv.id,
                                               accepted_only=False))
        self.assertEqual(on["evidence_freshness"]["samples"], 0)
        self.assertGreater(off["evidence_freshness"]["samples"], 0)
        self.assertTrue(off["evidence_freshness"]["open_high_without_evidence"]
                        < on["evidence_freshness"]["open_high_without_evidence"])

    def test_a_newer_accepted_artifact_makes_the_assessment_stale(self):
        rec = self._model_assessment(
            created=dt.datetime.utcnow() - dt.timedelta(days=60))
        self._artifact(title="newer accepted paper", review="accepted",
                       days_ago=5)
        avail = ex.availability(self.db, self.inv.id)
        self.assertEqual(len(avail["stale_assessments"]), 1)
        self.assertEqual(avail["stale_assessments"][0]["assessment_id"],
                         rec.id)

    def test_empty_denominators_read_unknown_not_zero(self):
        avail = ex.availability(self.db, self.inv.id)
        self.assertIsNone(avail["initiative_coverage"]["pct"])
        self.assertIsNone(avail["model_coverage"]["pct"])
        self.assertIsNone(avail["register_completeness"]["pct"])
        self.assertTrue(all(L["state"] == "unknown"
                            for L in avail["lights"][:3]))

    def test_provider_posture_coverage_tracks_fresh_pdp(self):
        import app.provider_posture as pp_mod  # noqa: E402
        rec = self._model_assessment(situation=SITUATION)
        rec.pdp_json = json.dumps({"findings": pp_mod.blank_findings()})
        self.db.commit()
        avail = ex.availability(self.db, self.inv.id)
        self.assertEqual(avail["pdp_coverage"]["of"], 1)
        self.assertEqual(avail["pdp_coverage"]["pct"], 100.0)
        self.assertEqual(avail["uncovered_providers"], [])

    def test_safety_coverage_counts_accepted_safety_sources(self):
        self._model_assessment(name="Acme Lab")
        avail = ex.availability(self.db, self.inv.id)
        self.assertEqual(avail["safety_coverage"]["of"], 1)
        self.assertEqual(avail["safety_coverage"]["pct"], 0.0)
        self._artifact(title="Acme Lab system card red team evals",
                       review="accepted",
                       artifact_type="paper")
        avail = ex.availability(self.db, self.inv.id)
        self.assertEqual(avail["safety_coverage"]["pct"], 100.0)
        self.assertEqual(avail["uncovered_safety_providers"], [])
        self.assertTrue(any(L["area"] == "safety sources"
                            for L in avail["lights"]))


class TestDistribution(ExecCase):
    def test_layers_scopes_and_statuses_stay_separate(self):
        self._model_assessment(situation=SITUATION)
        self._product_assessment()
        dist = ex.distribution(self.db, self.inv.id)
        self.assertIn("model", dist["by_layer"])
        self.assertIn("product", dist["by_layer"])
        self.assertIn("privacy", dist["by_layer"])
        self.assertNotIn("score", dist.keys())
        self.assertNotIn("grade", dist.keys())
        self.assertNotIn("composite", json.dumps(dist))
        self.assertIn("by_provider", dist)
        providers = {p["name"] for p in dist["top_providers"]}
        self.assertIn("churn-app", providers)

    def test_insight_cards_carry_numbers_and_links(self):
        self._model_assessment(situation=SITUATION)
        dist = ex.distribution(self.db, self.inv.id)
        self.assertTrue(dist["insight_cards"])
        for card in dist["insight_cards"]:
            self.assertTrue(card["text"])
            self.assertIn("view", card["link"])

    def test_volume_counts_runs_by_status(self):
        self.db.add(AgentRun(investigation_id=self.inv.id, status="done",
                             trigger="manual"))
        self.db.add(AgentRun(investigation_id=self.inv.id,
                             status="awaiting_approval", trigger="manual"))
        self.db.commit()
        dist = ex.distribution(self.db, self.inv.id)
        self.assertEqual(dist["assessment_volume"]["by_status"]["done"], 1)
        self.assertEqual(
            dist["assessment_volume"]["awaiting_approval"], 1)


class TestRobustness(ExecCase):
    def test_mapping_rate_counts_catalog_options(self):
        self._model_assessment(situation=SITUATION)
        rob = ex.robustness(self.db, self.inv.id)
        self.assertIsNotNone(rob["mitigation_mapping_rate"]["pct"])
        self.assertGreater(rob["mitigation_mapping_rate"]["of"], 0)

    def test_acceptance_without_a_review_date_is_undisciplined(self):
        self._model_assessment(situation=SITUATION)
        import app.portfolio as pf_mod  # noqa: E402
        rows = pf_mod.derive_register(self.db, self.inv.id)
        target = next(r for r in rows if r["layer"] == "model")
        pf_mod.set_risk_state(self.db, target["entry_id"], accept=True,
                              accepted_by="ciso",
                              acceptance_note="pilot residual")
        rob = ex.robustness(self.db, self.inv.id)
        self.assertEqual(rob["acceptance_discipline"],
                         {"pct": 0.0, "n": 0, "of": 1})

    def test_self_approval_is_a_violation_unknown_requester_is_not(self):
        run = AgentRun(investigation_id=self.inv.id, status="done",
                       trigger="manual")
        self.db.add(run)
        self.db.commit()
        self.db.add(Job(
            run_id=run.id, kind="security_assessment",
            key="sec-1", status="done",
            payload_json=json.dumps({"params": {"requested_by": "alice",
                                                "approved_by": "alice"}})))
        self.db.add(Job(
            run_id=run.id, kind="security_assessment",
            key="sec-2", status="done",
            payload_json=json.dumps({"params": {"approved_by": "bob"}})))
        self.db.commit()
        rob = ex.robustness(self.db, self.inv.id)
        self.assertEqual(len(
            rob["approval_hygiene"]["self_approval_violations"]), 1)
        self.assertEqual(rob["approval_hygiene"]["unverifiable_approvals"], 1)

    def test_awaiting_runs_list_age_and_sla(self):
        self.db.add(AgentRun(
            investigation_id=self.inv.id, status="awaiting_approval",
            trigger="manual",
            started_at=dt.datetime.utcnow() - dt.timedelta(days=10)))
        self.db.commit()
        rob = ex.robustness(self.db, self.inv.id)
        self.assertEqual(
            rob["approval_hygiene"]["awaiting_over_sla"], 1)

    def test_limitations_are_always_present(self):
        rob = ex.robustness(self.db, self.inv.id)
        self.assertGreaterEqual(len(rob["limitations"]), 3)
        blob = " ".join(rob["limitations"]).lower()
        self.assertIn("production", blob)


class TestAttention(ExecCase):
    def test_unowned_high_outranks_an_uncovered_initiative(self):
        self._model_assessment(situation=SITUATION)
        self._initiative(title="Bare", business_use_case="", owner="")
        attn = ex.attention(self.db, self.inv.id)
        kinds = [i["kind"] for i in attn["items"]]
        self.assertIn("unowned_open_high", kinds)
        self.assertIn("uncovered_initiative", kinds)
        scores = {i["kind"]: i["rank_score"] for i in attn["items"]}
        self.assertGreater(scores["unowned_open_high"],
                           scores["uncovered_initiative"])
        for item in attn["items"]:
            self.assertTrue(item["rank_why"])
            self.assertIn("view", item["link"])

    def test_an_open_cve_and_stale_assessment_appear_with_links(self):
        rec = self._model_assessment(
            created=dt.datetime.utcnow() - dt.timedelta(days=60))
        self._artifact(title="newer paper", review="accepted", days_ago=2)
        self.db.add(CveFinding(
            investigation_id=self.inv.id, cve_id="CVE-2026-0001",
            title="Vendor library RCE", status="Analyzed"))
        self.db.commit()
        kinds = {i["kind"] for i in ex.attention(self.db, self.inv.id)["items"]}
        self.assertIn("open_cve", kinds)
        self.assertIn("stale_assessment", kinds)

    def test_an_empty_portfolio_says_so(self):
        attn = ex.attention(self.db, self.inv.id)
        self.assertEqual(attn["items"], [])
        self.assertIn("nothing triggered", attn["note"])


class TestSnapshotsAndBrief(ExecCase):
    def test_snapshot_is_idempotent_per_day(self):
        self._model_assessment(situation=SITUATION)
        first = ex.write_snapshot(self.db, self.inv.id)
        second = ex.write_snapshot(self.db, self.inv.id)
        self.assertTrue(first["written"])
        self.assertFalse(second["written"])
        series = ex.snapshots(self.db, self.inv.id, days=90)
        self.assertEqual(len(series), 1)
        self.assertIn("open_high", series[0])

    def test_brief_names_coverage_concentration_and_limits(self):
        self._model_assessment(situation=SITUATION)
        md = ex.brief_markdown(self.db, self.inv.id)
        for section in ("Coverage at a glance", "Where risk concentrates",
                        "How well risks are handled", "Attention queue",
                        "Limitations"):
            self.assertIn(section, md)


class TestDashboardEndpoints(ExecCase):
    """The API surface the Dashboard tab talks to."""

    def setUp(self):
        super().setUp()
        from fastapi.testclient import TestClient  # noqa: E402
        from app.main import app as fastapi_app  # noqa: E402
        self.client = TestClient(fastapi_app)
        self.client.__enter__()

    def tearDown(self):
        try:
            self.client.__exit__(None, None, None)
        finally:
            super().tearDown()

    def _q(self, inv_id=None):
        return {"investigation_id": inv_id or self.inv.id}

    def test_all_sections_return_the_same_method_shape(self):
        self._model_assessment(situation=SITUATION)
        for section in ("summary", "availability", "distribution",
                        "robustness", "attention"):
            r = self.client.get(f"/api/dashboard/{section}",
                                params=self._q())
            self.assertEqual(r.status_code, 200, (section, r.text))
            body = r.json()
            self.assertEqual(body["method"], ex.EXECUTIVE_METHOD)
            self.assertEqual(body["version"], ex.EXECUTIVE_VERSION)
            self.assertIn("scope", body)

    def test_summary_answers_the_ciso_questions(self):
        self._model_assessment(situation=SITUATION)
        s = self.client.get("/api/dashboard/summary",
                            params=self._q()).json()
        for key in ("lights", "open_high", "open_critical",
                    "pending_approvals", "stale_count", "unowned_high",
                    "by_layer_open_high"):
            self.assertIn(key, s)

    def test_unknown_scope_is_rejected(self):
        self.assertEqual(self.client.get(
            "/api/dashboard/summary",
            params={"investigation_id": 999999}).status_code, 404)
        self.assertEqual(self.client.get(
            "/api/dashboard/summary",
            params={**self._q(), "layer": "nope"}).status_code, 422)

    def test_snapshot_trend_and_brief_endpoints(self):
        self._model_assessment(situation=SITUATION)
        empty = self.client.get("/api/dashboard/trends",
                                params=self._q()).json()
        self.assertEqual(empty["total"], 0)
        first = self.client.post("/api/dashboard/snapshot",
                                 params=self._q()).json()
        self.assertTrue(first["written"])
        again = self.client.post("/api/dashboard/snapshot",
                                 params=self._q()).json()
        self.assertFalse(again["written"])
        series = self.client.get("/api/dashboard/trends",
                                 params=self._q()).json()
        self.assertEqual(series["total"], 1)
        md = self.client.get("/api/dashboard/brief.md", params=self._q())
        self.assertEqual(md.status_code, 200)
        self.assertIn("Leadership brief", md.text)
        self.assertIn("Limitations", md.text)
        pdf = self.client.get("/api/dashboard/brief.pdf", params=self._q())
        self.assertEqual(pdf.status_code, 200)
        self.assertIn("application/pdf", pdf.headers["content-type"])
        self.assertTrue(pdf.content.startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()
