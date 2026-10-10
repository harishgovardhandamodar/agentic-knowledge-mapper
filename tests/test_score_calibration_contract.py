"""The API must carry the epistemic guarantees, not just the score.

`security.score_assessment` is the only place the floor and provenance facts
are computed; these tests assert they survive the trip to a consumer, so a
regression that drops them cannot reach a reader through the API unnoticed.
"""
import json

import pytest

from app import security as sec


@pytest.fixture()
def scored():
    inherent = [
        {"id": t[0], "title": t[1], "stride": t[2], "owasp": t[3],
         "likelihood": float(sec._scale_likelihood(t[4], 1.0)),
         "impact": float(t[5]), "description": t[6], "mitigations": list(t[7])}
        for t in sec._THREAT_CATALOG
    ]
    return sec.score_assessment(
        "confidential_data", inherent,
        active_controls=[c["id"] for c in sec._CONTROL_CATALOG])


class TestScoringContract:
    def test_top_level_floor_flag_matches_the_block(self, scored):
        assert scored["floor_capped"] == scored["floor"]["floor_capped"]

    def test_residual_is_never_reported_without_the_floor_block(self, scored):
        # The pairing is the guarantee: a consumer reading only `residual_pct`
        # from the same dict must still be able to find out it saturates.
        assert "residual_pct" in scored
        assert "floor" in scored

    def test_breakdown_method_states_the_score_is_ordinal(self, scored):
        assert "ordinal" in scored["breakdown"]["method"]

    def test_efficacy_evidence_sits_next_to_the_score(self, scored):
        assert scored["efficacy_evidence"]["n_controls"] == len(
            sec._CONTROL_CATALOG)

    def test_control_catalog_exposes_provenance_per_row(self):
        for row in sec.control_catalog():
            assert "evidence" in row
            assert "efficacy_is_prior" in row

    def test_legacy_shaped_input_degrades_without_raising(self):
        # A caller that does not pass applicability still gets a full result.
        res = sec.score_assessment(
            "confidential_data",
            [{"id": "T01", "likelihood": 3, "impact": 4}])
        assert "floor" in res
        assert "efficacy_evidence" in res

    def test_scoring_is_still_deterministic_with_the_new_fields(self):
        inherent = [{"id": t[0],
                     "likelihood": float(sec._scale_likelihood(t[4], 1.0)),
                     "impact": float(t[5])} for t in sec._THREAT_CATALOG]
        a = sec.score_assessment("confidential_data", inherent,
                                 active_controls=["C01", "C02"])
        b = sec.score_assessment("confidential_data", inherent,
                                 active_controls=["C01", "C02"])
        assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)

    def test_residual_value_itself_is_unchanged_by_the_diagnostics(self):
        # The whole point of Tier 1 was to stop the system overclaiming without
        # changing what it computes. Guard that against a future "improvement".
        inherent = [{"id": t[0],
                     "likelihood": float(sec._scale_likelihood(t[4], 1.0)),
                     "impact": float(t[5])} for t in sec._THREAT_CATALOG]
        all_cids = [c["id"] for c in sec._CONTROL_CATALOG]
        res = sec.score_assessment("confidential_data", inherent,
                                   active_controls=all_cids)
        assert res["residual_pct"] == 24.2
        assert res["inherent_pct"] == 68.8
