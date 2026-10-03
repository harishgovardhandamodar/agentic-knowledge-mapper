"""The assurance engine: declared vs verified residual and its gates.

Run with:  python3 -m pytest tests/test_assurance.py -q

Every test pins one rule the gates exist to enforce. The shape of the engine
matters here: evidence speaks to a threat by *naming it in the artifact text*
or a mapped known-exploit id, and a control is verified only when an accepted
primary artifact names the control id. A structured field nobody reads would
make the gate look satisfied while the content said nothing.

The common thread: the *verified* number is the honest one, so an unanswered
architecture question, a pending artifact or a self-attested claim must never
reduce it.
"""
import os
import tempfile
import unittest

# Pinned before the app import: app.database reads the URL at import time, and
# a test run must never touch the developer's working database.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(
        tempfile.mkdtemp(prefix="akm-assurance-"), "test.db"))

from app import assurance as A
from app import security as SEC

FULL_CHECKLIST = {spec["key"]: {"status": "known", "value": "yes"}
                  for spec in A.ARCHITECTURE_ITEMS}

#: A real catalogue control, so in_catalog is True and the status is decided by
#: the evidence rather than by an unknown id.
CONTROL_ID = sorted(SEC._CONTROL_BY_ID)[0]


def _artifact(atype="contract", *, review="accepted", relevance=0.9,
              title="vendor security overview", text="retention 90 days, "
              "reviewed by an auditor", url="https://example.invalid/doc",
              **extra):
    """An artifact dict in the shape the engine reads.

    ``text`` is where threat and control ids must appear: the engine matches on
    searchable content, so a structured ``threat_ids`` field is not evidence.
    """
    a = {
        "id": f"a-{atype}-{review}-{title[:12]}",
        "artifact_type": atype,
        "review": review,
        "relevance": relevance,
        "title": title,
        "description": text,
        "url": url,
        "source": url,
        "origin": atype,
        "drift": False,
    }
    a.update(extra)
    return a


def _threat(tid, score=90.0, **extra):
    t = {"id": tid, "title": f"threat {tid}", "residual_score": score,
         "coverage": 80.0}
    t.update(extra)
    return t


class TestSourceClassification(unittest.TestCase):
    def test_vendor_web_page_is_self_attested(self):
        self.assertEqual(A.source_class(_artifact("vendor_web")), "self_attested")

    def test_a_note_with_no_url_and_no_primary_kind_is_self_attested(self):
        self.assertEqual(A.source_class(_artifact("note", url="")), "self_attested")

    def test_self_origin_wins_even_for_a_primary_kind(self):
        self.assertEqual(
            A.source_class(_artifact("contract", origin="self")), "self_attested")

    def test_a_contract_is_its_own_class_not_generic_vendor_docs(self):
        self.assertEqual(A.source_class(_artifact("contract")), "contract")

    def test_dpa_text_is_recognised_as_a_contract(self):
        a = _artifact("vendor_documents",
                      title="data processing agreement",
                      text="this data processing agreement binds the vendor")
        self.assertEqual(A.source_class(a), "contract")

    def test_audit_and_penetration_test_are_primary_kinds(self):
        for kind in ("audit", "penetration_test", "red_team", "log_sample"):
            self.assertIn(kind, A._PRIMARY_TYPES)
            self.assertEqual(A.source_class(_artifact(kind)), "vendor_docs")

    def test_provenance_records_review_relevance_and_usability(self):
        prov = A.artifact_provenance(_artifact("contract", review="pending"))
        self.assertEqual(prov["review"], "pending")
        self.assertEqual(prov["source_class"], "contract")
        self.assertTrue(prov["is_primary"])
        # Pending is primary but not usable: the distinction that stops a
        # pending PDF from reducing residual.
        self.assertFalse(prov["usable_for_reduction"])

    def test_accepted_primary_evidence_is_usable(self):
        prov = A.artifact_provenance(_artifact("contract"))
        self.assertTrue(prov["usable_for_reduction"])

    def test_self_attested_provenance_is_never_usable(self):
        prov = A.artifact_provenance(_artifact("vendor_web"))
        self.assertFalse(prov["usable_for_reduction"])


class TestPendingEvidence(unittest.TestCase):
    def test_pending_artifacts_are_counted_but_carry_no_weight(self):
        w = A.pending_evidence_weight([_artifact(review="accepted"),
                                        _artifact(review="pending", title="p")])
        self.assertEqual(w["accepted"], 1)
        self.assertEqual(w["pending"], 1)
        self.assertLess(w["pending_weight"], 1.0)
        self.assertEqual(w["usable_for_reduction"], w["accepted"])

    def test_rejected_artifacts_are_neither_pending_nor_usable(self):
        w = A.pending_evidence_weight([_artifact(review="rejected")])
        self.assertEqual(w["pending"], 0)
        self.assertEqual(w["rejected"], 1)
        self.assertEqual(w["usable_for_reduction"], 0)

    def test_review_queue_recommends_an_action_per_item(self):
        q = A.review_queue([_artifact(review="pending")], timeout_days=0)
        self.assertEqual(q["pending"], 1)
        item = q["items"][0]
        self.assertTrue(item["recommended_action"])
        self.assertIn("reason", item)

    def test_low_relevance_pending_item_is_recommended_against(self):
        q = A.review_queue([_artifact(review="pending", relevance=0.1)],
                           timeout_days=0)
        self.assertEqual(q["items"][0]["recommended_action"], "reject")

    def test_recent_item_is_not_yet_overdue(self):
        q = A.review_queue([_artifact(review="pending")], timeout_days=90)
        self.assertEqual(q["overdue"], 0)


class TestControlAttestation(unittest.TestCase):
    def test_declared_only_control_is_not_verified(self):
        att = A.control_attestation([CONTROL_ID], [])
        self.assertEqual(att[CONTROL_ID]["status"], "declared")
        self.assertEqual(A.verified_control_ids(att), [])

    def test_accepted_primary_evidence_naming_the_control_verifies_it(self):
        art = _artifact("contract", title="security addendum",
                        text=f"{CONTROL_ID} is covered by the addendum")
        att = A.control_attestation([CONTROL_ID], [art])
        self.assertEqual(att[CONTROL_ID]["status"], "evidenced")
        self.assertEqual(A.verified_control_ids(att), [CONTROL_ID])

    def test_pending_evidence_does_not_verify_a_control(self):
        art = _artifact("contract", review="pending", title="draft addendum",
                        text=f"{CONTROL_ID} is claimed in the draft")
        att = A.control_attestation([CONTROL_ID], [art])
        self.assertEqual(att[CONTROL_ID]["status"], "declared")

    def test_self_attested_claim_does_not_verify_a_control(self):
        art = _artifact("vendor_web", title="our security page",
                        text=f"{CONTROL_ID} is implemented")
        att = A.control_attestation([CONTROL_ID], [art])
        self.assertNotEqual(att[CONTROL_ID]["status"], "evidenced")

    def test_out_of_catalogue_id_is_unknown_never_declared(self):
        att = A.control_attestation(["NOT-A-CONTROL"], [])
        self.assertEqual(att["NOT-A-CONTROL"]["status"], "unknown")


class TestArchitectureGate(unittest.TestCase):
    def test_absent_checklist_is_unknown_not_a_pass(self):
        gate = A.architecture_gate(None, "restricted_data")
        self.assertTrue(gate["open_items"])
        self.assertTrue(all(i["status"] != "known" for i in gate["items"]))

    def test_restricted_tier_with_an_open_item_blocks(self):
        gate = A.architecture_gate({"logging": {"status": "unknown"}},
                                   "restricted_data")
        self.assertTrue(gate["gate_blocked_applied"])

    def test_confidential_tier_also_blocks(self):
        gate = A.architecture_gate({"logging": {"status": "unknown"}},
                                   "confidential_data")
        self.assertTrue(gate["gate_blocked_applied"])

    def test_public_tier_reports_gaps_without_blocking(self):
        gate = A.architecture_gate({"logging": {"status": "unknown"}}, "public")
        self.assertTrue(gate["open_items"])
        self.assertFalse(gate["gate_blocked_applied"])

    def test_complete_checklist_does_not_block(self):
        gate = A.architecture_gate(FULL_CHECKLIST, "restricted_data")
        self.assertFalse(gate["gate_blocked_applied"])
        self.assertEqual(gate["open_items"], [])

    def test_blocking_names_the_threats_it_determines(self):
        gate = A.architecture_gate(None, "restricted_data")
        self.assertTrue(set(gate["blocked_threats"]) & set(A.GATE_BLOCKED_THREATS))
        self.assertTrue(gate["findings"])
        self.assertEqual(gate["findings"][0]["severity"], "blocking")


class TestEvidenceGate(unittest.TestCase):
    def test_no_evidence_gates_the_threat(self):
        gate = A.evidence_gate([_threat("T02")], [])
        self.assertEqual(gate["gated_threats"], ["T02"])
        self.assertTrue(gate["applied"])

    def test_enough_accepted_primary_evidence_releases_the_gate(self):
        arts = [_artifact("contract", title=f"contract {i}",
                          text=f"T02 evidence number {i}")
                for i in range(A.MIN_ACCEPTED_PER_TOP_THREAT)]
        gate = A.evidence_gate([_threat("T02")], arts)
        self.assertEqual(gate["gated_threats"], [])
        self.assertEqual(gate["per_threat"][0]["accepted_evidence"],
                         A.MIN_ACCEPTED_PER_TOP_THREAT)

    def test_pending_evidence_does_not_release_the_gate(self):
        arts = [_artifact("contract", review="pending", title=f"pending {i}",
                          text=f"T02 evidence number {i}") for i in range(5)]
        self.assertTrue(A.evidence_gate([_threat("T02")], arts)["gated_threats"])

    def test_low_relevance_evidence_does_not_release_the_gate(self):
        arts = [_artifact("contract", relevance=0.2, title=f"weak {i}",
                          text=f"T02 evidence number {i}") for i in range(5)]
        self.assertTrue(A.evidence_gate([_threat("T02")], arts)["gated_threats"])

    def test_drifted_evidence_does_not_release_the_gate(self):
        arts = [_artifact("contract", drift=True, title=f"drifted {i}",
                          text=f"T02 evidence number {i}") for i in range(5)]
        self.assertTrue(A.evidence_gate([_threat("T02")], arts)["gated_threats"])

    def test_self_attested_evidence_does_not_release_the_gate(self):
        arts = [_artifact("vendor_web", title=f"marketing {i}",
                          text=f"T02 we are safe number {i}") for i in range(5)]
        self.assertTrue(A.evidence_gate([_threat("T02")], arts)["gated_threats"])

    def test_evidence_about_another_threat_does_not_release_this_one(self):
        arts = [_artifact("contract", title=f"about T07 {i}",
                          text=f"T07 is addressed in appendix {i}")
                for i in range(5)]
        self.assertTrue(A.evidence_gate([_threat("T02")], arts)["gated_threats"])

    def test_only_the_top_threats_are_gated(self):
        rows = [_threat("T02"), _threat("T07")] + [
            _threat(f"T{20 + i}") for i in range(A.TOP_THREAT_GATE_N)]
        gate = A.evidence_gate(rows, [])
        self.assertLessEqual(len(gate["gated_threats"]), A.TOP_THREAT_GATE_N)


FORENSICS_CORPUS = " ".join(t for el in A.FORENSICS_ELEMENTS
                            for t in el["terms"])


class TestForensics(unittest.TestCase):
    def test_nothing_evidenced_is_not_reconstructable(self):
        f = A.forensics_readiness([], {}, FULL_CHECKLIST)
        self.assertFalse(f["reconstructable"])
        self.assertEqual(f["score"], 0.0)
        self.assertEqual(f["band"], "not_demonstrated")

    def test_forensics_gates_the_reconstruction_sensitive_threats(self):
        f = A.forensics_readiness([], {}, FULL_CHECKLIST)
        self.assertTrue(set(f["gated_threats"]) & {"T01", "T02", "T06", "T08"})

    def test_a_full_log_sample_reconstructs(self):
        art = _artifact("log_sample", title="sample log extract",
                        text=FORENSICS_CORPUS)
        f = A.forensics_readiness([art], {}, FULL_CHECKLIST)
        self.assertTrue(f["reconstructable"])
        self.assertEqual(f["score"], f["max_score"])

    def test_a_pending_log_sample_does_not_count(self):
        art = _artifact("log_sample", review="pending",
                        title="draft log extract", text=FORENSICS_CORPUS)
        self.assertFalse(A.forensics_readiness([art], {}, {})["reconstructable"])

    def test_a_partial_sample_does_not_claim_reconstructability(self):
        art = _artifact("log_sample", title="sample log extract",
                        text="user_identity and timestamp only")
        self.assertFalse(A.forensics_readiness([art], {}, FULL_CHECKLIST)
                         ["reconstructable"])


class TestBlastRadius(unittest.TestCase):
    FULL = {"restricted_assets": 4, "confidential_assets": 9,
            "privileged_users": 180, "avg_context_kb": 8.0,
            "max_context_kb": 32.0}

    def test_no_inventory_is_unquantified_never_zero(self):
        r = A.blast_radius(25.0, None, "restricted_data")
        self.assertFalse(r["quantified"])
        self.assertIsNone(r["records_at_risk"])
        self.assertIn("not quantified", r["summary"])

    def test_inventory_quantifies_exposure(self):
        r = A.blast_radius(25.0, self.FULL, "restricted_data")
        self.assertTrue(r["quantified"])
        self.assertEqual(r["inventory"]["records_in_scope"], 13)
        self.assertEqual(r["records_at_risk"], 13 * 180)
        self.assertGreater(r["max_payload_mb"], 0)

    def test_restricted_tier_blocks_a_decision_without_quantification(self):
        self.assertTrue(A.blast_radius(25.0, {}, "restricted_data")
                        ["blocks_decision"])
        self.assertFalse(A.blast_radius(25.0, {}, "public")["blocks_decision"])

    def test_missing_inputs_are_named(self):
        r = A.blast_radius(25.0, {"restricted_assets": 4}, "restricted_data")
        self.assertIn("privileged_users", r["missing_inputs"])


class TestInjectionCap(unittest.TestCase):
    def test_t05_coverage_is_capped_without_adversarial_evidence(self):
        cap = A.injection_cap([_threat("T05", coverage=90.0)], [])
        self.assertTrue(cap["active"])
        self.assertEqual(cap["cap"], 0.35)
        self.assertEqual(cap["applied_to"], ["T05"])

    def test_the_cap_lowers_coverage_and_raises_residual(self):
        threat = _threat("T05", coverage=90.0)
        before = threat["coverage"]
        A.injection_cap([threat], [])
        self.assertEqual(threat["coverage"], 35.0)
        self.assertLess(threat["coverage"], before)

    def test_accepted_adversarial_evidence_lifts_the_cap(self):
        art = _artifact("red_team", title="injection suite result",
                        text="KE-01 prompt injection suite, 240 cases, results "
                             "recorded and accepted")
        cap = A.injection_cap([_threat("T05", coverage=90.0)], [art])
        self.assertFalse(cap["active"])

    def test_other_threats_are_untouched(self):
        threat = _threat("T02", coverage=90.0)
        A.injection_cap([threat], [])
        self.assertEqual(threat["coverage"], 90.0)


class TestChains(unittest.TestCase):
    def test_full_metadata_context_fires_the_ke_chain(self):
        chains = A.detect_chains([_threat("T01"), _threat("T05")], [])
        self.assertTrue(chains)
        self.assertEqual(chains[0]["path"], ["KE-01", "KE-06"])

    def test_chain_needs_both_halves_in_scope(self):
        self.assertEqual(A.detect_chains([_threat("T01")], []), [])

    def test_chain_carries_one_mitigation_set_not_two(self):
        chain = A.detect_chains([_threat("T01"), _threat("T05")], [])[0]
        self.assertTrue(chain["mitigations"])
        self.assertIn("composite_residual", chain)

    def test_explicit_full_metadata_context_fires_without_both_threats(self):
        chains = A.detect_chains([_threat("T05")], [],
                                 full_metadata_context=True)
        self.assertTrue(chains)


class TestDecisionFrame(unittest.TestCase):
    CLEAN = dict(gate={"gate_blocked_applied": False, "open_items": [],
                       "items": []},
                 ev_gate={"gated_threats": []},
                 forensics={"reconstructable": True, "band": "reconstructable"},
                 radius={"quantified": True, "blocks_decision": False},
                 evidence_confidence=0.9)

    def _frame(self, **kw):
        args = dict(verified_residual_pct=20.0, declared_residual_pct=15.0,
                   exposure="restricted_data", **self.CLEAN)
        args.update(kw)
        return A.decision_frame(**args)

    def test_clean_low_residual_is_accepted(self):
        self.assertEqual(self._frame()["decision"], A.DECISION_ACCEPT)

    def test_blocked_architecture_rejects(self):
        d = self._frame(gate={"gate_blocked_applied": True,
                              "open_items": ["no-logging"], "items": []})
        self.assertEqual(d["decision"], A.DECISION_REJECT)

    def test_unquantified_restricted_tier_does_not_accept(self):
        d = self._frame(radius={"quantified": False, "blocks_decision": True,
                                "missing_inputs": ["privileged_users"]})
        self.assertNotEqual(d["decision"], A.DECISION_ACCEPT)
        self.assertTrue(d["actions_0_30_days"])

    def test_high_verified_residual_asks_for_guardrails_not_silence(self):
        # 50+ is not an automatic reject: a high verified residual with clean
        # gates is a business decision, and the frame says so rather than
        # pretending the arithmetic settles it.
        self.assertEqual(self._frame(verified_residual_pct=70.0)["decision"],
                         A.DECISION_GUARDRAILS)

    def test_unquantified_restricted_tier_rejects(self):
        self.assertEqual(
            self._frame(radius={"quantified": False, "blocks_decision": True,
                                "missing_inputs": ["privileged_users"]})
            ["decision"], A.DECISION_REJECT)

    def test_unreconstructable_forensics_on_a_restricted_tier_asks_for_guardrails(self):
        d = self._frame(forensics={"reconstructable": False, "score": 21.0,
                                   "band": "partial", "max_score": 100,
                                   "not_found": ["prompt_hash"]})
        self.assertEqual(d["decision"], A.DECISION_GUARDRAILS)

    def test_low_evidence_confidence_is_not_a_silent_accept(self):
        self.assertNotEqual(self._frame(evidence_confidence=0.1)["decision"],
                            A.DECISION_ACCEPT)

    def test_every_decision_carries_reasons_and_a_headline(self):
        for kw in ({}, {"verified_residual_pct": 70.0},
                   {"gate": {"gate_blocked_applied": True, "open_items": ["x"],
                             "items": []}}):
            d = self._frame(**kw)
            self.assertTrue(d["headline"])
            self.assertTrue(d["reasons"])

    def test_decision_compares_verified_against_declared(self):
        d = self._frame(verified_residual_pct=30.0, declared_residual_pct=10.0)
        self.assertIn("declared", json_text(d))


def json_text(obj) -> str:
    import json
    return json.dumps(obj, default=str)


class TestAssess(unittest.TestCase):
    THREATS = [{"id": t, "title": f"threat {t}", "inherent_score": 90.0,
                "likelihood": 5, "impact": 5, "cvss": 9.0}
               for t in ("T01", "T02", "T05", "T06", "T07", "T11")]

    def _assess(self, **kw):
        args = dict(exposure="restricted_data",
                    inherent_threats=[dict(t) for t in self.THREATS])
        args.update(kw)
        return A.assess(**args)

    def test_both_layers_are_reported_and_verified_is_the_headline(self):
        out = self._assess(declared_controls=[CONTROL_ID])
        self.assertIn("declared", out)
        self.assertIn("verified", out)
        self.assertEqual(out["headline_layer"], "verified")

    def test_verified_residual_is_never_better_than_declared(self):
        # The verified layer uses a subset of controls, so it can only be
        # worse or equal. A run where it is better is a bug.
        out = self._assess(declared_controls=[CONTROL_ID])
        self.assertGreaterEqual(out["verified"]["residual_pct"],
                                out["declared"]["residual_pct"])

    def test_no_architecture_data_never_produces_an_accept(self):
        out = self._assess(declared_controls=[CONTROL_ID])
        self.assertNotEqual(out["decision"]["decision"], A.DECISION_ACCEPT)

    def test_gates_open_are_named_when_nothing_was_supplied(self):
        out = self._assess()
        self.assertTrue(out["gates_open"])

    def test_complete_inputs_close_every_gate(self):
        # Every gate needs its own evidence kind: contracts for the evidence
        # threshold, a log sample for forensics, a red-team result for the
        # injection cap, and the checklist plus inventory for the rest.
        threat_ids = " ".join(f"T{t}" for t in ("T01", "T02", "T05", "T06",
                                               "T07", "T11"))
        arts = [_artifact("contract", title=f"contract {i}",
                          text=f"{threat_ids} number {i} {CONTROL_ID}")
                for i in range(A.MIN_ACCEPTED_PER_TOP_THREAT)]
        arts.append(_artifact(
            "log_sample", title="interaction log extract",
            text=FORENSICS_CORPUS))
        arts.append(_artifact("red_team", title="injection suite",
                              text="KE-01 prompt injection results recorded"))
        out = self._assess(declared_controls=[CONTROL_ID],
                           architecture_checklist=FULL_CHECKLIST,
                           exposure_inventory=TestBlastRadius.FULL,
                           artifacts=arts)
        self.assertEqual(out["gates_open"], [])
        # Gates closed is necessary but not sufficient: the decision still
        # depends on the verified residual and its evidence confidence, which
        # is what stops "everything is answered" being read as "it's safe".
        self.assertIn(out["decision"]["decision"],
                      (A.DECISION_ACCEPT, A.DECISION_GUARDRAILS))
        self.assertNotEqual(out["decision"]["decision"], A.DECISION_REJECT)

    def test_evidence_confidence_is_a_share_between_zero_and_one(self):
        conf = self._assess(declared_controls=[CONTROL_ID])["evidence_confidence"]
        self.assertGreaterEqual(conf, 0.0)
        self.assertLessEqual(conf, 1.0)

    def test_pending_evidence_is_reported_as_pending(self):
        out = self._assess(artifacts=[_artifact("contract", review="pending")])
        self.assertEqual(out["pending_evidence"]["pending"], 1)

    def test_forensics_and_radius_always_travel_with_the_result(self):
        out = self._assess(declared_controls=[CONTROL_ID])
        self.assertIn("forensics", out)
        self.assertIn("blast_radius", out)

    def test_control_attestation_is_always_present(self):
        out = self._assess(declared_controls=[CONTROL_ID])
        self.assertEqual(out["control_attestation"][CONTROL_ID]["status"],
                         "declared")


class TestQuestionnaire(unittest.TestCase):
    def test_open_items_become_questions_naming_their_threats(self):
        gate = A.architecture_gate({"logging": {"status": "unknown"}},
                                   "restricted_data")
        q = A.vendor_questionnaire(gate)
        self.assertTrue(q["items"])
        self.assertTrue(all(item["blocks"] for item in q["items"]))
        self.assertTrue(all(item["question"] for item in q["items"]))
        self.assertTrue(q["markdown"])

    def test_answered_items_are_not_asked_again(self):
        gate = A.architecture_gate(FULL_CHECKLIST, "restricted_data")
        self.assertEqual(A.vendor_questionnaire(gate)["items"], [])

    def test_a_partial_answer_still_asks_for_the_rest(self):
        partial = dict(FULL_CHECKLIST)
        partial[A.ARCHITECTURE_ITEMS[0]["key"]] = {"status": "unknown",
                                                   "value": ""}
        gate = A.architecture_gate(partial, "restricted_data")
        self.assertEqual(len(A.vendor_questionnaire(gate)["items"]), 1)


class TestPackAndRegister(unittest.TestCase):
    def test_canonical_key_is_stable_for_one_family(self):
        self.assertEqual(A.canonical_register_key("Acme  Support", "own", "T02"),
                         A.canonical_register_key("acme support", "own", "t02"))

    def test_different_families_get_different_keys(self):
        self.assertNotEqual(A.canonical_register_key("acme", "own", "T02"),
                            A.canonical_register_key("other", "own", "T02"))

    def test_different_layers_get_different_keys(self):
        self.assertNotEqual(A.canonical_register_key("acme", "own", "T02"),
                            A.canonical_register_key("acme", "model", "T02"))

    def test_unnamed_family_is_explicit_not_collapsed_into_one(self):
        self.assertTrue(A.canonical_register_key(None, "own", "T02")
                        .startswith("unassigned"))

    def test_pack_supersession_reports_without_rescoring(self):
        sup = A.pack_supersession("1999.1", "deadbeef")
        self.assertTrue(sup["stale"])
        self.assertIn("current_version", sup)


if __name__ == "__main__":
    unittest.main()