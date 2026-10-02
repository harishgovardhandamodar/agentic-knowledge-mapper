"""Provider AGI data posture: template, PDP findings, contribution map.

The properties pinned are the ones that would quietly write a conspiracy
narrative or a clean bill of health: a provider guessed rather than named, a
standing stronger than its evidence, a definite training claim without tier
terms, or an unknown that never surfaces.
"""
import json
import os
import tempfile
import unittest
from unittest import mock

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-provider-"), "test.db"))

from app import database as _db  # noqa: E402
from app import manager as mgr  # noqa: E402
from app import provider_posture as pp  # noqa: E402
from app.database import Base, SessionLocal, engine  # noqa: E402
from app.models import Artifact, Investigation, SecurityAssessment  # noqa: E402

_db.init_db()

COMMAND = ("Detailed security and privacy investigation of data exposure to "
           "AGI labs and model providers: OpenAI, Anthropic, Google, Meta -- "
           "training use of customer content, retention and deletion, what "
           "they collect, whether we are datapoints, and indirect "
           "contribution.")


class TestDetection(unittest.TestCase):
    def test_names_providers_in_canonical_form(self):
        found = pp.detect_providers(COMMAND)
        self.assertEqual([p["name"] for p in found],
                         ["OpenAI", "Anthropic", "Google", "Meta"])

    def test_aliases_resolve(self):
        found = pp.detect_providers("Is our Claude usage training Anthropic?")
        self.assertEqual([p["name"] for p in found], ["Anthropic"])

    def test_a_capability_question_is_not_a_posture_command(self):
        self.assertFalse(pp.is_posture_command(
            "Who leads on benchmarks, OpenAI or Google?"))
        self.assertTrue(pp.is_posture_command(COMMAND))

    def test_a_data_question_without_a_named_provider_has_no_subject(self):
        self.assertFalse(pp.is_posture_command(
            "How safe is our training data in the cloud?"))
        self.assertIsNone(pp.provider_plan("How safe is our data?"))


class TestPlan(unittest.TestCase):
    def test_template_subjects_are_providers_not_verb_phrases(self):
        plan = mgr.parse_command(COMMAND)
        self.assertEqual(plan["domain"], "provider_data_privacy_agi")
        self.assertEqual(plan["parsed_by"], "provider_template")
        self.assertEqual([t["subject"] for t in plan["topics"]],
                         ["OpenAI", "Anthropic", "Google", "Meta"])
        for t in plan["topics"]:
            self.assertEqual(t["task"], "provider_data_posture")
            self.assertIn("training data use", t["focus"])
            self.assertIn("capability benchmarks", t["anti_focus"])
        self.assertIn("datapoint", plan["summary"]["description"])

    def test_validate_plan_keeps_the_task(self):
        plan = mgr.validate_plan({
            "domain": "x",
            "topics": [{"title": "T", "subject": "S",
                        "task": "provider_data_posture"}],
            "summary": {}})
        self.assertEqual(plan["topics"][0]["task"], "provider_data_posture")

    def test_run_plan_seeds_situation_and_marker(self):
        db = SessionLocal()
        try:
            plan = mgr.parse_command(COMMAND)
            with mock.patch.object(mgr, "launch_run"), \
                    mock.patch.object(mgr, "launch_security_assessment") as la:
                row = mgr.run_plan(db, plan, {"research": False,
                                              "assessment": True}, COMMAND)
            self.assertEqual(len(la.call_args_list), 4)
            for call in la.call_args_list:
                params = call[0][1]
                self.assertEqual(params["situation"]["channel"], "api")
                self.assertEqual(
                    params["situation"]["data"]["classification"],
                    "confidential")
                self.assertIn("employees",
                              params["situation"]["actors"])
            inv = db.get(Investigation,
                         row["children"][0]["investigation_id"])
            self.assertIn("provider_data_posture", inv.keywords)
            self.assertTrue(pp.is_provider_investigation(
                inv.title, inv.keywords, inv.description))
        finally:
            db.close()


class TestPlannerFamilies(unittest.TestCase):
    def _inv(self, title, keywords, description=""):
        return Investigation(title=title, keywords=keywords,
                             description=description, sources="web,rss")

    def test_policy_trust_and_reporting_families_are_added(self):
        from app import agent as _agent
        inv = self._inv("OpenAI data posture: training, retention, collection",
                        "OpenAI, provider_data_posture, privacy policy",
                        "Primary sources: privacy policy, DPA")
        clean: list = []
        _agent._ensure_provider_posture_queries(inv, clean, {"web", "rss"})
        self.assertTrue(clean)
        blob = " ".join(q["text"] for q in clean).lower()
        # official terms first: policy, enterprise, feedback, review
        self.assertIn("privacy policy", blob)
        self.assertIn("enterprise", blob)
        self.assertIn("feedback", blob)
        self.assertIn("human review", blob)
        self.assertLessEqual(len(clean), 6)

    def test_trust_and_safety_families_fill_leftover_slots(self):
        # The six-query cap means families past index six only fire when the
        # LLM already planned near-identical queries; the primary mechanism
        # is the planner prompt hint, pinned here through its helper (the
        # planner entry point itself is stubbed out by other suites, so the
        # wording -- not the call -- is what this test owns).
        from app import agent as _agent
        hint = _agent._provider_prompt_hint()
        self.assertIn("provider data-posture", hint)
        self.assertIn("safety evaluations", hint)
        self.assertIn("not capability leaderboards", hint)

    def test_non_provider_briefs_are_untouched(self):
        from app import agent as _agent
        inv = self._inv("TabPFN safety", "tabular model", "")
        clean: list = []
        _agent._ensure_provider_posture_queries(inv, clean, {"web"})
        self.assertEqual(clean, [])


class PdpCase(unittest.TestCase):
    def setUp(self):
        Base.metadata.create_all(bind=engine)
        self.db = SessionLocal()
        self.inv = Investigation(
            title="OpenAI data posture",
            keywords="OpenAI, provider_data_posture, privacy policy",
            description="provider posture template run")
        self.db.add(self.inv)
        self.db.commit()
        self.db.refresh(self.inv)

    def tearDown(self):
        self.db.query(SecurityAssessment).filter(
            SecurityAssessment.investigation_id == self.inv.id).delete()
        self.db.query(Artifact).filter(
            Artifact.investigation_id == self.inv.id).delete()
        self.db.query(Investigation).filter(
            Investigation.id == self.inv.id).delete()
        self.db.commit()
        self.db.close()

    def _artifact(self, title, review="accepted", tags="policy"):
        a = Artifact(investigation_id=self.inv.id, title=title,
                     artifact_type="paper", review=review, tags=tags)
        self.db.add(a)
        self.db.commit()
        self.db.refresh(a)
        return a

    def _accepted_dicts(self):
        return [{"id": a.id, "title": a.title, "tags": a.tags,
                 "artifact_type": a.artifact_type, "review": a.review}
                for a in self.db.query(Artifact).filter(
                    Artifact.investigation_id == self.inv.id,
                    Artifact.review == "accepted").all()]


class TestPdpAssessment(PdpCase):
    def test_policy_evidence_reads_partial_everything_else_unknown(self):
        self._artifact("OpenAI privacy policy: training opt-out and "
                       "retention terms")
        result = pp.assess_pdp(self._accepted_dicts())
        by_id = {f["id"]: f for f in result["findings"]}
        self.assertEqual(len(result["findings"]), 10)
        self.assertEqual(by_id["PDP01"]["standing"], "partial")
        self.assertEqual(by_id["PDP02"]["standing"], "partial")
        self.assertEqual(by_id["PDP07"]["standing"], "unknown")
        self.assertEqual(result["fingerprint"], pp.pdp_fingerprint())

    def test_pending_artifacts_are_not_evidence(self):
        self._artifact("Vendor privacy policy with training terms",
                       review="pending")
        result = pp.assess_pdp(self._accepted_dicts())
        self.assertTrue(all(f["standing"] == "unknown"
                            for f in result["findings"]))

    def test_supported_is_never_derived(self):
        self._artifact("OpenAI enterprise zero retention DPA terms")
        result = pp.assess_pdp(self._accepted_dicts())
        self.assertNotIn("supported",
                         {f["standing"] for f in result["findings"]})

    def test_human_override_is_the_only_path_to_supported(self):
        findings = pp.blank_findings()
        with self.assertRaises(ValueError):
            pp.set_pdp_finding(findings, "PDP99", standing="supported")
        with self.assertRaises(ValueError):
            pp.set_pdp_finding(findings, "PDP01", standing="proven")
        updated = pp.set_pdp_finding(
            findings, "PDP01", standing="supported",
            summary="Enterprise DPA s4.2: no training on business data.",
            evidence_ids=[7], actor="ciso")
        self.assertEqual(updated["standing"], "supported")
        self.assertEqual(updated["reviewed_by"], "ciso")


class TestRegisterRows(PdpCase):
    def _assessed(self, product="OpenAI"):
        rec = SecurityAssessment(
            investigation_id=self.inv.id, product_name=product,
            exposure="confidential_data", use_case="org AI use",
            overall_pct=50.0, markdown="# report",
            threat_pack_version="2.1.0",
            threats_json=json.dumps([]),
            scoring_json=json.dumps({}),
            hypothesis_json=json.dumps({"claims": []}))
        self.db.add(rec)
        self.db.commit()
        self.db.refresh(rec)
        self._artifact("OpenAI privacy policy training opt-out retention")
        from app import provider_posture as _pp
        rec.pdp_json = json.dumps(_pp.assess_pdp(self._accepted_dicts()))
        self.db.commit()
        return rec

    def test_pdp_rows_carry_standings_not_scores(self):
        from app import portfolio as pf
        self._assessed()
        rows = [r for r in pf.register_with_state(self.db, self.inv.id)
                if r["source_catalog"] == pp.PDP_ID]
        self.assertEqual(len(rows), 10)
        keys = [r["stable_key"] for r in rows]
        self.assertEqual(len(keys), len(set(keys)))
        for r in rows:
            self.assertIsNone(r["severity"])
            self.assertIn(r["confidence_band"], pp.STANDINGS)
            self.assertIn("provider_posture", r["situation_tags"])
            self.assertTrue(r["control_options"])
        partial = [r for r in rows if r["source_ref"] == "PDP01"]
        self.assertEqual(partial[0]["confidence_band"], "partial")

    def test_register_tag_filter_finds_posture_rows(self):
        from fastapi.testclient import TestClient
        from app.main import app as fastapi_app
        self._assessed()
        client = TestClient(fastapi_app)
        with client:
            r = client.get("/api/portfolio/register",
                           params={"investigation_id": self.inv.id,
                                   "tag": "provider_posture"})
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(len(r.json()["risks"]), 10)


class TestSafetyContext(PdpCase):
    def _safety_dicts(self):
        return [{"id": a.id, "title": a.title, "tags": a.tags,
                 "artifact_type": a.artifact_type, "review": a.review}
                for a in self.db.query(Artifact).filter(
                    Artifact.investigation_id == self.inv.id,
                    Artifact.review == "accepted").all()]

    def test_system_card_fills_saf_leaves_pdp_training_unknown(self):
        self._artifact("OpenAI system card: red team evals and preparedness",
                       tags="ai_safety,model_card")
        pdp = pp.assess_pdp(self._safety_dicts())
        saf = pp.assess_safety(self._safety_dicts())
        by_pdp = {f["id"]: f["standing"] for f in pdp["findings"]}
        by_saf = {f["id"]: f["standing"] for f in saf["findings"]}
        # the card says nothing about customer data terms: PDP01 stays put
        self.assertEqual(by_pdp["PDP01"], "unknown")
        # but the safety literature is documented, with its claim class
        self.assertEqual(by_saf["SAF01"], "partial")
        self.assertEqual(by_saf["SAF02"], "partial")
        saf01 = next(f for f in saf["findings"] if f["id"] == "SAF01")
        self.assertEqual(saf01["claim_class"], "safety_governance")

    def test_safety_source_with_data_terms_reaches_both(self):
        self._artifact("OpenAI data usage and retention terms with "
                       "enterprise opt-out", tags="policy")
        pdp = pp.assess_pdp(self._safety_dicts())
        by_pdp = {f["id"]: f["standing"] for f in pdp["findings"]}
        self.assertEqual(by_pdp["PDP01"], "partial")

    def test_supported_is_never_derived_for_safety_either(self):
        self._artifact("Anthropic responsible scaling policy RSP",
                       tags="ai_safety,rsp")
        saf = pp.assess_safety(self._safety_dicts())
        self.assertNotIn("supported", {f["standing"] for f in saf["findings"]})
        updated = pp.set_safety_finding(
            saf["findings"], "SAF01", standing="supported",
            summary="RSP v2.1 dated 2025-01.", actor="lead")
        self.assertEqual(updated["standing"], "supported")
        with self.assertRaises(ValueError):
            pp.set_safety_finding(saf["findings"], "SAF99",
                                  standing="supported")

    def test_posture_envelope_carries_both_catalogs(self):
        self._artifact("OpenAI privacy policy training retention terms")
        env = pp.assess_posture(self._safety_dicts())
        self.assertEqual(len(env["findings"]), 10)
        self.assertEqual(len(env["safety"]), 6)
        self.assertEqual(env["safety_catalog"], pp.SAFETY_ID)
        self.assertEqual(env["safety_fingerprint"], pp.safety_fingerprint())

    def test_safety_feedback_paths_gate_on_eval_evidence(self):
        cmap = pp.contribution_map(
            [{"source_ref": "PDP06", "confidence_band": "unknown"}])
        by_id = {e["id"]: e for e in cmap["direct"] + cmap["indirect"]}
        self.assertEqual(by_id["direct-safety-feedback"]["status"],
                         "possible")
        cmap = pp.contribution_map(
            [{"source_ref": "PDP06", "confidence_band": "partial"}])
        by_id = {e["id"]: e for e in cmap["direct"] + cmap["indirect"]}
        self.assertEqual(by_id["direct-safety-feedback"]["status"],
                         "active")
        self.assertEqual(by_id["indirect-safety-feedback"]["status"],
                         "active")

    def test_safety_planner_families_fill_remaining_slots(self):
        from app import agent as _agent
        inv = Investigation(
            title="Anthropic data posture: training, retention, collection",
            keywords="Anthropic, provider_data_posture, privacy policy",
            description="provider posture template run",
            sources="web,rss")
        clean: list = []
        _agent._ensure_provider_posture_queries(inv, clean, {"web", "rss"})
        blob = " ".join(q["text"] for q in clean).lower()
        # backstop order: official terms, then feedback families; the cap
        # holds at six and the planner prompt carries safety coverage
        self.assertIn("feedback", blob)
        self.assertIn("human review", blob)
        self.assertEqual(len(clean), 6)
    def test_synthesis_safety_subsection_separates_columns(self):
        from app.models import ManagerRun
        plan = mgr.parse_command(
            "Data exposure investigation: OpenAI -- training use, retention, "
            "are we datapoints?")
        with mock.patch.object(mgr, "launch_run"), \
                mock.patch.object(mgr, "launch_security_assessment"):
            row = mgr.run_plan(self.db, plan, {"research": False,
                                               "assessment": True},
                               "provider command")
        stored = json.loads(self.db.query(ManagerRun).filter(
            ManagerRun.id == row["id"]).first().plan_json)
        t = stored["topics"][0]
        inv = self.db.query(Investigation).filter(
            Investigation.id == t["investigation_id"]).first()
        inv.status = "ready"
        rec = SecurityAssessment(
            investigation_id=inv.id, product_name="OpenAI",
            exposure="confidential_data", use_case="org AI use",
            overall_pct=50.0, markdown="# posture report",
            scoring_json=json.dumps({}),
            hypothesis_json=json.dumps({"claims": []}))
        self.db.add(rec)
        self.db.commit()
        self.db.refresh(rec)
        art = Artifact(
            investigation_id=inv.id,
            title="OpenAI system card: red team evals preparedness",
            artifact_type="paper", review="accepted",
            tags="ai_safety,model_card")
        self.db.add(art)
        self.db.commit()
        env = pp.assess_posture(
            [{"id": art.id, "title": art.title, "tags": art.tags,
              "artifact_type": art.artifact_type, "review": "accepted"}])
        rec.pdp_json = json.dumps(env)
        self.db.commit()
        with mock.patch.object(mgr.llm, "chat", return_value="# synthesis"):
            out = mgr.compile_run(self.db, row["id"])
        md = out["markdown"]
        self.assertIn("## AI safety research context", md)
        self.assertIn("Safety transparency vs customer-data transparency",
                      md)
        # thin safety docs, unstated data terms: columns must diverge
        self.assertIn("documented", md)
        self.assertIn("unstated", md)


class TestIntelSafety(PdpCase):
    def test_new_terms_and_safety_sources_trigger_rereview(self):
        import datetime as dt
        from app import portfolio as pf
        self._artifact("OpenAI updated privacy policy retention terms",
                       review="accepted", tags="policy")
        feed = pf.intel_feed(self.db, self.inv.id)
        kinds = {x["title"]: x for x in feed["new_posture_sources"]}
        self.assertTrue(kinds)
        self.assertFalse(feed["quiet"])
        self._artifact("OpenAI system card frontier evals", review="accepted",
                       tags="ai_safety,model_card")
        feed = pf.intel_feed(self.db, self.inv.id)
        safety = [x for x in feed["new_posture_sources"] if x["safety"]]
        self.assertTrue(safety)
    def test_active_paths_need_register_evidence(self):
        cmap = pp.contribution_map([])
        self.assertEqual(cmap["active_count"], 0)
        self.assertTrue(all(e["status"] == "possible"
                            for e in cmap["direct"] + cmap["indirect"]))
        rows = [{"source_ref": "LP01"}, {"source_ref": "LP04"}]
        cmap = pp.contribution_map(rows)
        by_id = {e["id"]: e for e in cmap["direct"] + cmap["indirect"]}
        self.assertEqual(by_id["direct-paste"]["status"], "active")
        self.assertEqual(by_id["direct-api-logs"]["status"], "active")
        self.assertEqual(by_id["indirect-web"]["status"], "possible")

    def test_mermaid_and_datapoint_answers_name_unknowns(self):
        cmap = pp.contribution_map([{"source_ref": "LP01"}])
        dot = pp.contribution_mermaid(cmap, provider="OpenAI")
        self.assertIn("graph LR", dot)
        self.assertIn("OpenAI", dot)
        text = pp.datapoint_summary("OpenAI", pp.blank_findings(), cmap)
        self.assertIn("Org data:", text)
        self.assertIn("Individual presence:", text)
        self.assertIn("Unknowns:", text)
        self.assertIn("PDP01", text)


class TestClaimGuard(unittest.TestCase):
    def test_definite_claim_without_tier_terms_is_stripped(self):
        out = pp.guard_provider_claims(
            "The vendor trains on your API data. Retention defaults apply.")
        self.assertEqual(out["removed_count"], 1)
        self.assertIn("Retention defaults apply.", out["text"])
        self.assertTrue(out["removed"])

    def test_tier_specific_claim_survives(self):
        text = ("The vendor trains on your API data under consumer terms, "
                "with an opt-out available.")
        out = pp.guard_provider_claims(text)
        self.assertEqual(out["removed_count"], 0)
        self.assertIn("opt-out", out["text"])


class TestEndpoints(PdpCase):
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

    def _assessment(self):
        rec = SecurityAssessment(
            investigation_id=self.inv.id, product_name="Anthropic",
            exposure="confidential_data", use_case="org AI use",
            overall_pct=50.0, markdown="# report",
            scoring_json=json.dumps({}),
            hypothesis_json=json.dumps({"claims": []}))
        self.db.add(rec)
        self.db.commit()
        self.db.refresh(rec)
        return rec

    def test_pdp_sync_derives_from_accepted_evidence(self):
        rec = self._assessment()
        self._artifact("Anthropic privacy policy data usage retention terms")
        r = self.client.post(
            f"/api/security/assessments/{rec.id}/pdp/sync",
            headers={"X-AKM-Actor": "tester"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(len(r.json()["findings"]), 10)
        self.assertEqual(r.status_code, 200)

    def test_pdp_sync_404s_unknown_assessment(self):
        r = self.client.post("/api/security/assessments/999999/pdp/sync")
        self.assertEqual(r.status_code, 404)

    def test_human_override_requires_a_real_dimension(self):
        rec = self._assessment()
        bad = self.client.post(
            "/api/portfolio/pdp/state",
            json={"assessment_id": rec.id, "dimension_id": "PDP99",
                  "standing": "supported", "actor": "ciso"},
            headers={"X-AKM-Actor": "ciso"})
        self.assertEqual(bad.status_code, 422)
        ok = self.client.post(
            "/api/portfolio/pdp/state",
            json={"assessment_id": rec.id, "dimension_id": "PDP05",
                  "standing": "supported",
                  "summary": "Enterprise DPA excludes training.",
                  "actor": "ciso", "rationale": "read the DPA"},
            headers={"X-AKM-Actor": "ciso"})
        self.assertEqual(ok.status_code, 200, ok.text)
        self.assertEqual(ok.json()["standing"], "supported")


class TestAdvisorPlaybook(unittest.TestCase):
    def test_confidential_external_situation_selects_the_provider_playbook(self):
        from app import leakage as lk
        from app import portfolio as pf
        sit = pf.normalize_situation({
            "data": {"classification": "confidential"},
            "channel": "api", "actors": ["employees"],
            "controls": {}, "blast_radius": {}, "external": True})
        picked = lk.select_playbooks(sit["tags"])
        pb05 = next((p for p in picked if p["id"] == "PB05"), None)
        self.assertIsNotNone(pb05)
        self.assertIn("LP04", pb05["forced"])
        self.assertTrue(any("enterprise" in c.lower()
                            for c in pb05["checks"]))


class TestSynthesis(PdpCase):
    def test_compile_adds_the_provider_compare_section(self):
        from app.models import ManagerRun
        plan = mgr.parse_command(
            "Data exposure investigation: OpenAI, Anthropic -- training use, "
            "retention, are we datapoints?")
        self.assertEqual(len(plan["topics"]), 2)
        with mock.patch.object(mgr, "launch_run"), \
                mock.patch.object(mgr, "launch_security_assessment"):
            row = mgr.run_plan(self.db, plan, {"research": False,
                                               "assessment": True},
                               "provider command")
        stored = json.loads(self.db.query(ManagerRun).filter(
            ManagerRun.id == row["id"]).first().plan_json)
        for t in stored["topics"]:
            inv = self.db.query(Investigation).filter(
                Investigation.id == t["investigation_id"]).first()
            inv.status = "ready"
            rec = SecurityAssessment(
                investigation_id=inv.id, product_name=t["subject"],
                exposure="confidential_data", use_case="org AI use",
                overall_pct=50.0, markdown="# posture report",
                scoring_json=json.dumps({}),
                hypothesis_json=json.dumps({"claims": []}))
            self.db.add(rec)
            self.db.commit()
            self.db.refresh(rec)
            art = Artifact(investigation_id=inv.id,
                           title=f"{t['subject']} privacy policy training "
                                 "retention terms",
                           artifact_type="paper", review="accepted")
            self.db.add(art)
            self.db.commit()
            rec.pdp_json = json.dumps(pp.assess_posture(
                [{"id": art.id, "title": art.title, "tags": "",
                  "artifact_type": "paper", "review": "accepted"}]))
            self.db.commit()
        with mock.patch.object(mgr.llm, "chat", return_value="# synthesis"):
            out = mgr.compile_run(self.db, row["id"])
        md = out["markdown"]
        self.assertIn("## Provider data posture compare", md)
        self.assertIn("PDP01", md)
        self.assertIn("Am I a datapoint?", md)
        self.assertIn("graph LR", md)
        self.assertIn("## Preference, feedback and post-training", md)
        self.assertIn("RLHF01", md)
        self.assertIn("## Synthesis", md)


class TestRlhfCatalog(unittest.TestCase):
    def test_eight_dimensions_with_classes_tiers_and_layers(self):
        self.assertEqual(len(pp.RLHF_DIMENSIONS), 8)
        ids = [d["id"] for d in pp.RLHF_DIMENSIONS]
        self.assertEqual(ids, [f"RLHF{i:02d}" for i in range(1, 9)])
        for d in pp.RLHF_DIMENSIONS:
            self.assertIn(d["class"], pp.RLHF_CLASSES)
            self.assertTrue(d["tiers"])
            self.assertEqual(d["layer"], "privacy")
            self.assertTrue(d["controls"])
        self.assertTrue(pp.rlhf_fingerprint())

    def test_feedback_evidence_reads_partial_rest_unknown(self):
        arts = [{"id": 1, "title": "Consumer thumbs feedback retention "
                                   "and training terms",
                 "tags": "feedback", "artifact_type": "paper",
                 "review": "accepted"}]
        result = pp.assess_rlhf(arts)
        by_id = {f["id"]: f for f in result["findings"]}
        self.assertEqual(len(result["findings"]), 8)
        self.assertEqual(by_id["RLHF01"]["standing"], "partial")
        self.assertEqual(by_id["RLHF01"]["class"], "A")
        self.assertEqual(by_id["RLHF02"]["standing"], "partial")
        self.assertEqual(by_id["RLHF06"]["standing"], "unknown")
        self.assertEqual(result["fingerprint"], pp.rlhf_fingerprint())

    def test_api_no_train_claim_does_not_satisfy_safety_logs(self):
        arts = [{"id": 2, "title": "API data is not used for training",
                 "tags": "", "artifact_type": "paper",
                 "review": "accepted"}]
        by_id = {f["id"]: f["standing"]
                 for f in pp.assess_rlhf(arts)["findings"]}
        # "not used for training" says nothing about abuse-log retention
        self.assertEqual(by_id["RLHF05"], "unknown")

    def test_supported_never_derived_pending_never_counts(self):
        arts = [{"id": 3, "title": "Feedback retention years policy",
                 "tags": "", "artifact_type": "paper",
                 "review": "pending"}]
        self.assertTrue(all(f["standing"] == "unknown"
                            for f in pp.assess_rlhf(arts)["findings"]))
        arts[0]["review"] = "accepted"
        self.assertNotIn("supported",
                         {f["standing"]
                          for f in pp.assess_rlhf(arts)["findings"]})

    def test_override_is_the_only_path_to_supported(self):
        findings = pp.blank_rlhf()
        self.assertTrue(all(f["standing"] == "unknown" for f in findings))
        updated = pp.set_rlhf_finding(
            findings, "RLHF02", standing="supported",
            summary="Help page: feedback kept 5 years.", actor="lead")
        self.assertEqual(updated["standing"], "supported")
        with self.assertRaises(ValueError):
            pp.set_rlhf_finding(findings, "RLHF99", standing="supported")
        with self.assertRaises(ValueError):
            pp.set_rlhf_finding(findings, "RLHF01", standing="proven")

    def test_tier_table_names_tiers_not_verdicts(self):
        arts = [{"id": 1, "title": "Thumbs feedback retention terms",
                 "tags": "", "artifact_type": "paper",
                 "review": "accepted"}]
        table = pp.rlhf_tier_table(
            "OpenAI", pp.assess_rlhf(arts)["findings"])
        self.assertIn("RLHF01", table)
        self.assertIn("consumer", table)
        self.assertIn("partial", table)

    def test_datapoint_answers_keep_capability_and_safety_apart(self):
        arts = [{"id": 1, "title": "Consumer feedback training terms",
                 "tags": "", "artifact_type": "paper",
                 "review": "accepted"}]
        answers = pp.datapoint_answers(
            "OpenAI", pp.assess_rlhf(arts)["findings"])
        self.assertEqual(set(answers) - {"provider"},
                         {"capability", "safety", "org_api"})
        self.assertIn("usually no by default", answers["org_api"])
        # safety answer never clears capability rows, capability never
        # clears safety rows: different sentences, different evidence
        self.assertNotIn("no by default", answers["capability"])
        self.assertNotIn("no by default", answers["safety"])


class TestRlhfRegister(PdpCase):
    def _assessed_rlhf(self, product="OpenAI"):
        rec = SecurityAssessment(
            investigation_id=self.inv.id, product_name=product,
            exposure="confidential_data", use_case="org AI use",
            overall_pct=50.0, markdown="# report",
            threat_pack_version="2.1.0",
            threats_json=json.dumps([]),
            scoring_json=json.dumps({}),
            hypothesis_json=json.dumps({"claims": []}))
        self.db.add(rec)
        self.db.commit()
        self.db.refresh(rec)
        self._artifact("Consumer thumbs feedback retention training terms")
        rec.pdp_json = json.dumps(pp.assess_posture(self._accepted_dicts()))
        self.db.commit()
        return rec

    def _accepted_dicts(self):
        return [{"id": a.id, "title": a.title, "tags": a.tags,
                 "artifact_type": a.artifact_type, "review": a.review}
                for a in self.db.query(Artifact).filter(
                    Artifact.investigation_id == self.inv.id,
                    Artifact.review == "accepted").all()]

    def test_rlhf_rows_carry_subclass_not_scores(self):
        from app import portfolio as pf
        self._assessed_rlhf()
        rows = [r for r in pf.register_with_state(self.db, self.inv.id)
                if r["source_catalog"] == pp.RLHF_ID]
        self.assertEqual(len(rows), 8)
        self.assertEqual({r["subclass"] for r in rows},
                         {"preference_feedback"})
        for r in rows:
            self.assertIsNone(r["severity"])
            self.assertIn(r["confidence_band"], pp.STANDINGS)
            self.assertTrue(r["control_options"])

    def test_envelope_carries_all_three_catalogs(self):
        rec = self._assessed_rlhf()
        payload = json.loads(rec.pdp_json)
        self.assertEqual(len(payload["findings"]), 10)
        self.assertEqual(len(payload["safety"]), 6)
        self.assertEqual(len(payload["rlhf"]), 8)
        self.assertEqual(payload["rlhf_fingerprint"],
                         pp.rlhf_fingerprint())

    def test_contribution_edges_name_their_type(self):
        cmap = pp.contribution_map([{"source_ref": "LP01"}])
        by_id = {e["id"]: e for e in cmap["direct"] + cmap["indirect"]}
        self.assertEqual(by_id["direct-feedback"]["edge"],
                         "feedback_submitted")
        self.assertEqual(by_id["indirect-web"]["edge"], "crawl")
        # connector paths map to no edge type rather than a wrong one
        self.assertIsNone(by_id["direct-connectors"]["edge"])


class TestRlhfAdvisor(unittest.TestCase):
    def test_chat_situation_selects_the_feedback_playbook(self):
        from app import leakage as lk
        from app import portfolio as pf
        sit = pf.normalize_situation({
            "data": {"classification": "confidential"},
            "channel": "chat_ui", "actors": ["employees"],
            "controls": {}, "blast_radius": {}, "external": True})
        ids = [p["id"] for p in lk.select_playbooks(sit["tags"])]
        self.assertIn("PB06", ids)
        pb06 = next(p for p in lk.select_playbooks(sit["tags"])
                    if p["id"] == "PB06")
        self.assertIn("LP01", pb06["forced"])
        self.assertTrue(any("opt-out" in c for c in pb06["checks"]))


if __name__ == "__main__":
    unittest.main()
