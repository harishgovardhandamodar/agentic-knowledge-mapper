"""Reviewer identity and the tidy dataset export.

Two guarantees under test. First: two reviewers judging the same artifact must
not destroy each other's work, and their disagreement must be measurable
rather than resolved by last-write-wins. Second: one investigation must export
as documented, versioned tables whose fingerprint is stable, so a paper can
cite the dataset by hash.
"""
import json

import pytest
from fastapi.testclient import TestClient

from app import security as sec
from app.database import SessionLocal, init_db
from app.main import app
from app.models import Artifact, ArtifactReview, Investigation, SecurityAssessment


@pytest.fixture(scope="module")
def client():
    init_db()
    return TestClient(app)


def _scored():
    inherent = [
        {"id": t[0], "title": t[1], "stride": t[2], "owasp": t[3],
         "likelihood": float(sec._scale_likelihood(t[4], 1.0)),
         "impact": float(t[5]), "description": t[6], "mitigations": list(t[7])}
        for t in sec._THREAT_CATALOG
    ]
    return sec.score_assessment("confidential_data", inherent,
                                active_controls=["C01", "C02"])


@pytest.fixture()
def setup(client):
    db = SessionLocal()
    inv = Investigation(title="review-group", keywords="k")
    db.add(inv)
    db.commit()
    db.refresh(inv)
    res = _scored()
    rec = SecurityAssessment(
        investigation_id=inv.id, run_id=1, product_name="Group target",
        exposure="confidential_data", overall_pct=res["residual_pct"],
        inherent_pct=res["inherent_pct"], residual_pct=res["residual_pct"],
        markdown="# stub", scoring_json=json.dumps(res),
        threats_json=json.dumps(res["threats"]),
        controls_json=json.dumps({"active_controls": ["C01", "C02"]}),
        assurance_json=json.dumps({"assessed": True, "threats": []}))
    db.add(rec)
    db.commit()
    db.refresh(rec)
    art = Artifact(investigation_id=inv.id, title="Vendor DPA",
                   artifact_type="dpa", url="https://vendor.test/dpa",
                   content="zero retention agreed", review="pending",
                   relevance=0.9, assessment_id=rec.id)
    db.add(art)
    db.commit()
    db.refresh(art)
    ids = {"inv": inv.id, "rec": rec.id, "art": art.id}
    db.close()
    yield ids
    db = SessionLocal()
    try:
        db.query(ArtifactReview).filter(
            ArtifactReview.artifact_id == ids["art"]).delete()
        db.query(Artifact).filter(Artifact.id == ids["art"]).delete()
        db.query(SecurityAssessment).filter(
            SecurityAssessment.id == ids["rec"]).delete()
        db.query(Investigation).filter(
            Investigation.id == ids["inv"]).delete()
        db.commit()
    finally:
        db.close()


class TestReviewerIdentity:
    def test_two_reviewers_both_survive(self, client, setup):
        for who, verdict in (("ana", "accepted"), ("ben", "rejected")):
            r = client.post(
                f"/api/security/assessments/{setup['rec']}"
                f"/evidence/{setup['art']}/review",
                json={"review": verdict, "reviewer": who})
            assert r.status_code == 200
        db = SessionLocal()
        rows = db.query(ArtifactReview).filter(
            ArtifactReview.artifact_id == setup["art"]).all()
        by_who = {r.reviewer: r.verdict for r in rows}
        db.close()
        # Neither judgment destroyed the other.
        assert by_who == {"ana": "accepted", "ben": "rejected"}

    def test_row_keeps_latest_for_legacy_readers(self, client, setup):
        client.post(
            f"/api/security/assessments/{setup['rec']}"
            f"/evidence/{setup['art']}/review",
            json={"review": "accepted", "reviewer": "ana"})
        client.post(
            f"/api/security/assessments/{setup['rec']}"
            f"/evidence/{setup['art']}/review",
            json={"review": "rejected", "reviewer": "ben"})
        db = SessionLocal()
        row = db.query(Artifact).filter(Artifact.id == setup["art"]).one()
        db.close()
        assert row.review == "rejected"

    def test_re_review_updates_in_place(self, client, setup):
        client.post(
            f"/api/security/assessments/{setup['rec']}"
            f"/evidence/{setup['art']}/review",
            json={"review": "accepted", "reviewer": "ana"})
        client.post(
            f"/api/security/assessments/{setup['rec']}"
            f"/evidence/{setup['art']}/review",
            json={"review": "rejected", "reviewer": "ana",
                  "note": "second look"})
        db = SessionLocal()
        rows = db.query(ArtifactReview).filter(
            ArtifactReview.artifact_id == setup["art"],
            ArtifactReview.reviewer == "ana").all()
        db.close()
        # One row per (artifact, reviewer): "who currently believes what" is
# always answerable.
        assert len(rows) == 1
        assert rows[0].verdict == "rejected"


class TestDisagreement:
    def test_conflict_is_named_with_both_verdicts(self, client, setup):
        client.post(
            f"/api/security/assessments/{setup['rec']}"
            f"/evidence/{setup['art']}/review",
            json={"review": "accepted", "reviewer": "ana"})
        client.post(
            f"/api/security/assessments/{setup['rec']}"
            f"/evidence/{setup['art']}/review",
            json={"review": "rejected", "reviewer": "ben"})
        d = client.get(
            f"/api/security/assessments/{setup['rec']}/reviews/disagreements")
        assert d.status_code == 200
        body = d.json()
        assert body["stats"]["n_conflicts"] == 1
        assert body["conflicts"][0]["votes"] == {"ana": "accepted",
                                                 "ben": "rejected"}

    def test_unmeasured_agreement_is_not_perfect_agreement(self, client, setup):
        client.post(
            f"/api/security/assessments/{setup['rec']}"
            f"/evidence/{setup['art']}/review",
            json={"review": "accepted", "reviewer": "ana"})
        d = client.get(
            f"/api/security/assessments/{setup['rec']}/reviews/disagreements")
        stats = d.json()["stats"]
        assert stats["n_conflicts"] == 0
        assert stats["kappa"] is None
        assert "unmeasured" in stats["note"]


class TestDataset:
    def test_tables_and_counts(self, client, setup):
        client.post(
            f"/api/security/assessments/{setup['rec']}"
            f"/evidence/{setup['art']}/review",
            json={"review": "accepted", "reviewer": "ana"})
        d = client.get(f"/api/investigations/{setup['inv']}/dataset")
        assert d.status_code == 200
        body = d.json()
        assert body["dataset_version"] == "1"
        assert body["counts"] == {"assessments": 1, "threats": 12,
                                  "controls": 2, "artifacts": 1, "reviews": 1,
                                  "judgments": 0}
        assert set(body["tables"]) == {"assessments", "threats", "controls",
                                       "artifacts", "reviews", "judgments"}

    def test_scores_travel_with_pack_and_calibration(self, client, setup):
        row = client.get(
            f"/api/investigations/{setup['inv']}/dataset").json()[
                "tables"]["assessments"][0]
        assert row["residual_pct"] is not None
        assert "floor_capped" in row
        assert "n_unvalidated_controls" in row

    def test_threat_rows_carry_floor_flags(self, client, setup):
        threats = client.get(
            f"/api/investigations/{setup['inv']}/dataset").json()[
                "tables"]["threats"]
        assert len(threats) == 12
        assert all("floor_capped" in t for t in threats)
        assert all(t["assessment_id"] == setup["rec"] for t in threats)

    def test_artifact_content_is_a_digest_not_text(self, client, setup):
        art = client.get(
            f"/api/investigations/{setup['inv']}/dataset").json()[
                "tables"]["artifacts"][0]
        assert art["content_digest"] is not None
        assert len(art["content_digest"]) == 16
        assert "content" not in art

    def test_fingerprint_is_stable(self, client, setup):
        a = client.get(f"/api/investigations/{setup['inv']}/dataset").json()
        b = client.get(f"/api/investigations/{setup['inv']}/dataset").json()
        assert a["manifest"]["fingerprint"] == b["manifest"]["fingerprint"]

    def test_missing_investigation_is_404(self, client):
        assert client.get("/api/investigations/999999/dataset").status_code == 404


class TestGapLifecycleApi:
    def test_ruled_out_without_evidence_is_refused(self, client, setup):
        r = client.post(
            f"/api/investigations/{setup['inv']}/research-gaps/status",
            json={"question": "Is X true?", "status": "ruled_out"})
        assert r.status_code == 422

    def test_gap_lifecycle_round_trip(self, client, setup):
        q = "Is X true?"
        r = client.post(
            f"/api/investigations/{setup['inv']}/research-gaps/status",
            json={"question": q, "status": "investigating",
                  "decided_by": "ana"})
        assert r.status_code == 200
        assert r.json()["status"] == "investigating"
        r = client.post(
            f"/api/investigations/{setup['inv']}/research-gaps/status",
            json={"question": q, "status": "ruled_out",
                  "evidence": "ran 30 probes, zero hits", "decided_by": "ana"})
        assert r.status_code == 200
        d = client.get(
            f"/api/investigations/{setup['inv']}/research-gaps/ruled-out")
        assert d.status_code == 200
        assert d.json()["count"] >= 1
        assert any(x["question"] == q for x in d.json()["ruled_out"])

    def test_unknown_status_is_refused(self, client, setup):
        r = client.post(
            f"/api/investigations/{setup['inv']}/research-gaps/status",
            json={"question": "Is X true?", "status": "bogus"})
        assert r.status_code == 422


class TestJudgmentsApi:
    def test_rescore_attributes_authorship(self, client, setup):
        r = client.post(
            f"/api/security/assessments/{setup['rec']}/rescore",
            json={"applicability": {"T01": 0.8}, "author": "ana",
                  "rationale": "chat surface present", "persist": False})
        assert r.status_code == 200
        body = r.json()
        assert any(j["author"] == "ana" and j["subject"] == "T01"
                   for j in body.get("judgments", []))

    def test_unattributed_rescore_uses_the_session_actor(self, client, setup):
        # No explicit author: the request actor (session key) is recorded
        # instead. That distinguishes two anonymous callers from each other,
        # which a shared "unknown" could not.
        r = client.post(
            f"/api/security/assessments/{setup['rec']}/rescore",
            json={"applicability": {"T01": 0.8}, "persist": False})
        assert r.status_code == 200
        judgments = r.json().get("judgments", [])
        assert judgments, "applicability without author must still be recorded"
        assert all(j["author"] for j in judgments)
        assert all(j["author"] != "ana" for j in judgments)
