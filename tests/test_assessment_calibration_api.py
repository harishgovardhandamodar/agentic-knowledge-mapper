"""The stored-row read path must surface floor and provenance, not just the score.

Separate from `test_score_calibration_contract` because this one goes through
`_security_json` on a real persisted row: the guarantee is only useful if it
survives storage and the API envelope.
"""
import json

import pytest
from fastapi.testclient import TestClient

from app import security as sec
from app.database import SessionLocal, init_db
from app.main import app
from app.models import Investigation, SecurityAssessment


@pytest.fixture(scope="module")
def client():
    init_db()
    return TestClient(app)


@pytest.fixture()
def stored(client):
    inherent = [
        {"id": t[0], "title": t[1], "stride": t[2], "owasp": t[3],
         "likelihood": float(sec._scale_likelihood(t[4], 1.0)),
         "impact": float(t[5]), "description": t[6], "mitigations": list(t[7])}
        for t in sec._THREAT_CATALOG
    ]
    res = sec.score_assessment(
        "confidential_data", inherent,
        active_controls=[c["id"] for c in sec._CONTROL_CATALOG])

    db = SessionLocal()
    inv = Investigation(title="calibration-read", keywords="k")
    db.add(inv)
    db.commit()
    db.refresh(inv)
    rec = SecurityAssessment(
        investigation_id=inv.id, run_id=1, product_name="Calibration target",
        exposure="confidential_data", overall_pct=res["residual_pct"],
        inherent_pct=res["inherent_pct"], residual_pct=res["residual_pct"],
        markdown="# stub", scoring_json=json.dumps(res),
        controls_json=json.dumps({"active_controls": res["active_controls"]}))
    db.add(rec)
    db.commit()
    db.refresh(rec)
    aid, inv_id = rec.id, inv.id
    db.close()
    yield aid
    db = SessionLocal()
    try:
        db.query(SecurityAssessment).filter(
            SecurityAssessment.id == aid).delete()
        db.query(Investigation).filter(
            Investigation.id == inv_id).delete()
        db.commit()
    finally:
        db.close()


class TestAssessmentReadSurfacesCalibration:
    def test_top_level_floor_flag_is_present(self, client, stored):
        d = client.get(f"/api/security/assessments/{stored}").json()
        assert d["floor_capped"] is True
        assert d["floor"]["controls_beyond_floor"] > 0
        assert d["floor"]["controls_effective"] > 0

    def test_efficacy_provenance_is_visible_on_the_read(self, client, stored):
        d = client.get(f"/api/security/assessments/{stored}").json()
        ev = d["efficacy_evidence"]
        assert ev["n_controls"] > 0
        assert ev["all_validated"] is False
        assert len(ev["unvalidated_controls"]) == ev["n_controls"]

    def test_analysis_carries_the_band_and_its_variance_budget(self, client, stored):
        a = client.get(f"/api/security/assessments/{stored}/analysis").json()
        band = a["uncertainty"]
        assert band["mean_pct"] == 24.2
        assert band["lower_pct"] <= band["mean_pct"] <= band["upper_pct"]
        assert band["floor_capped"] is True

        vb = band["variance_budget"]
        assert vb["total_variance"] > 0
        assert "threat_catalogue_completeness" in vb["unquantified"]
        assert "residual_floor" in vb["unquantified"]

    def test_band_is_wider_because_efficacies_are_unvalidated(self, client, stored):
        band = client.get(
            f"/api/security/assessments/{stored}/analysis").json()["uncertainty"]
        # The unvalidated-prior band must not be the narrow "measured" band.
        assert (band["upper_pct"] - band["lower_pct"]) > 4.0

    def test_legacy_row_without_the_new_blocks_still_reads(self, client):
        db = SessionLocal()
        inv = Investigation(title="legacy-read", keywords="k")
        db.add(inv)
        db.commit()
        db.refresh(inv)
        rec = SecurityAssessment(
            investigation_id=inv.id, run_id=1, product_name="Legacy",
            exposure="confidential_data", overall_pct=10.0,
            scoring_json=json.dumps({"assessment_path": "standard",
                                     "residual_pct": 10.0,
                                     "threats": [], "inherent_pct": 20.0}),
            markdown="# legacy")
        db.add(rec)
        db.commit()
        db.refresh(rec)
        aid, inv_id = rec.id, inv.id
        db.close()

        d = client.get(f"/api/security/assessments/{aid}")
        assert d.status_code == 200
        body = d.json()
        # Absent, not False: a row that predates the block must not be read as
        # "we checked and the score did not saturate".
        assert body["floor_capped"] is None
        assert body["floor"] is None
        assert body["efficacy_evidence"] is None

        db = SessionLocal()
        try:
            db.query(SecurityAssessment).filter(
                SecurityAssessment.id == aid).delete()
            db.query(Investigation).filter(
                Investigation.id == inv_id).delete()
            db.commit()
        finally:
            db.close()


class TestScenarioAndProbeEndpoints:
    def test_scenarios_derive_from_stored_rows(self, client, stored):
        d = client.get(f"/api/security/assessments/{stored}/scenarios")
        assert d.status_code == 200
        body = d.json()
        assert body["stats"]["rows_considered"] > 0
        assert body["method"]["id"] == "SCENARIO-SYNTHESIS"
        for sc in body["scenarios"]:
            assert sc["why"], "every scenario must explain itself"

    def test_attack_tree_is_a_graph(self, client, stored):
        d = client.get(f"/api/security/assessments/{stored}/attack-tree")
        assert d.status_code == 200
        body = d.json()
        assert "nodes" in body and "edges" in body
        assert body["note"], "the tree must say it is derived, not observed"
        by_id = {n["id"]: n for n in body["nodes"]}
        for e in body["edges"]:
            assert e["from"] in by_id and e["to"] in by_id
            assert (by_id[e["from"]]["coverage"]
                    > by_id[e["to"]]["coverage"])

    def test_probe_library_withholds_payloads(self, client):
        d = client.get("/api/probes")
        assert d.status_code == 200
        ids = [p["id"] for p in d.json()["probes"]]
        assert "verbatim_extraction" in ids
        assert "Repeat this passage exactly" not in d.text

    def test_probe_run_requires_confirmation(self, client, stored):
        d = client.post(
            f"/api/security/assessments/{stored}/probes/run",
            json={"probe_id": "verbatim_extraction",
                  "endpoint": "https://a.test/v1"})
        assert d.status_code == 200
        assert d.json()["status"] == "skipped"

    def test_probe_run_refuses_an_off_allow_list_target(self, client, stored):
        d = client.post(
            f"/api/security/assessments/{stored}/probes/run",
            json={"probe_id": "verbatim_extraction",
                  "endpoint": "https://evil.test/v1", "confirm": True})
        assert d.status_code == 200
        assert d.json()["status"] == "skipped"
        assert "allow-list" in (d.json()["reason"] or "")

    def test_report_now_carries_scenarios(self, client, stored):
        d = client.get(f"/api/security/assessments/{stored}/report")
        assert d.status_code == 200
        keys = [s["key"] for s in d.json()["sections"]]
        assert "scenarios" in keys
