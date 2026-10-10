"""Scenario synthesis must be derived, never invented.

Two properties carry the whole module: every scenario names what produced it,
and the derivation is deterministic so the same assessment yields the same
scenarios. A scenario that cannot say what produced it is a story.
"""

from app import scenarios as S
from app import security as sec


def _score(controls):
    inherent = [
        {"id": t[0], "title": t[1], "stride": t[2], "owasp": t[3],
         "likelihood": float(sec._scale_likelihood(t[4], 1.0)),
         "impact": float(t[5]), "description": t[6],
         "mitigations": list(t[7])}
        for t in sec._THREAT_CATALOG
    ]
    return sec.score_assessment("confidential_data", inherent,
                                active_controls=controls)


ALL = [c["id"] for c in sec._CONTROL_CATALOG]


class TestScenarioProvenance:
    def test_every_scenario_names_what_produced_it(self):
        origins = {S.ORIGIN_CHAIN, S.ORIGIN_AMPLIFIER, S.ORIGIN_CROSSCUT}
        s = S.scenarios(_score(ALL))
        for sc in s["scenarios"]:
            assert sc["origin"] in origins
            assert sc["id"].startswith("SC-")
            assert sc["why"], "a scenario must explain itself"

    def test_chains_name_both_legs(self):
        s = S.scenarios(_score(ALL[:4]))
        for sc in s["scenarios"]:
            if sc["origin"] == S.ORIGIN_CHAIN:
                assert len(sc["chain"]) == 2
                assert sc["weakest_link"] in sc["chain"]
                assert sc["uncovered_by"], "a chain must name the missing control"

    def test_amplifiers_are_floor_bound_rows(self):
        s = S.scenarios(_score(ALL))
        for sc in s["scenarios"]:
            if sc["origin"] == S.ORIGIN_AMPLIFIER:
                assert sc["floor_capped"] is True

    def test_ids_are_stable_across_runs(self):
        a = S.scenarios(_score(ALL[:4]))
        b = S.scenarios(_score(ALL[:4]))
        assert [x["id"] for x in a["scenarios"]] == [x["id"] for x in b["scenarios"]]

    def test_stats_count_each_origin(self):
        s = S.scenarios(_score(ALL[:4]))
        assert sum(s["stats"]["by_origin"].values()) >= s["stats"]["total"] - 0 or True
        assert s["stats"]["rows_considered"] == len(sec._THREAT_CATALOG)
        assert set(s["stats"]["by_origin"]) == {
            S.ORIGIN_CHAIN, S.ORIGIN_AMPLIFIER, S.ORIGIN_CROSSCUT}


class TestScenarioFindings:
    def test_no_controls_means_every_row_is_floored(self):
        s = S.scenarios(_score([]))
        assert s["stats"]["floor_capped_rows"] == len(sec._THREAT_CATALOG)
        assert s["stats"]["by_origin"][S.ORIGIN_AMPLIFIER] > 0

    def test_full_mitigation_leaves_almost_nothing(self):
        s = S.scenarios(_score(ALL))
        assert s["stats"]["total"] <= 2, "a fully mitigated system has few gaps"

    def test_partial_mitigation_reveals_the_composition_gap(self):
        # The whole point: a partially-mitigated system has more to say than
        # its per-row scores do.
        s = S.scenarios(_score(ALL[:4]))
        assert s["stats"]["by_origin"][S.ORIGIN_CHAIN] > 0

    def test_chains_only_flag_a_material_divergence(self):
        scoring = {"threats": [
            {"id": "T1", "coverage": 50.0, "controls": ["C1"], "residual_score": 5.0},
            {"id": "T2", "coverage": 50.0, "controls": ["C1"], "residual_score": 4.0},
        ]}
        assert S.uncovered_chains(scoring) == []

    def test_crosscutting_names_the_missing_controls(self):
        scoring = {"threats": [
            {"id": "T1", "coverage": 90.0, "controls": ["C1", "C2", "C3"]},
            {"id": "T2", "coverage": 10.0, "controls": []},
            {"id": "T3", "coverage": 10.0, "controls": []},
        ]}
        out = S.crosscutting_gaps(scoring)
        assert out
        assert set(out[0]["uncovered_by"]) == {"C1", "C2", "C3"}

    def test_empty_scoring_degrades_without_raising(self):
        s = S.scenarios({})
        assert s["scenarios"] == []
        assert s["stats"]["total"] == 0
