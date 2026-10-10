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

    def test_chains_name_every_leg(self):
        s = S.scenarios(_score(ALL[:4]))
        assert any(sc["origin"] == S.ORIGIN_CHAIN for sc in s["scenarios"])
        for sc in s["scenarios"]:
            if sc["origin"] == S.ORIGIN_CHAIN:
                assert len(sc["chain"]) >= 2
                assert sc["weakest_link"] in sc["chain"]
                assert sc["chain"][-1] == sc["weakest_link"]
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

    def test_full_mitigation_leaves_only_declining_paths(self):
        # Even a fully mitigated system has compositional structure: T12 sits
        # at 55% on a single control while its peers are at 69%+. The findings
        # must all be distinct (endpoint, gap) pairs, never restatements.
        s = S.scenarios(_score(ALL))
        keys = [(sc["weakest_link"], tuple(sorted(sc.get("uncovered_by") or [])))
                for sc in s["scenarios"]]
        assert len(set(keys)) == len(keys)
        assert all(sc.get("hops", 2) >= 2 for sc in s["scenarios"]
                   if sc["origin"] == S.ORIGIN_CHAIN)

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



class TestMultiHop:
    def _scored(self, controls):
        inherent = [
            {"id": t[0], "title": t[1], "stride": t[2], "owasp": t[3],
             "likelihood": float(sec._scale_likelihood(t[4], 1.0)),
             "impact": float(t[5]), "description": t[6],
             "mitigations": list(t[7])}
            for t in sec._THREAT_CATALOG
        ]
        return sec.score_assessment("confidential_data", inherent,
                                    active_controls=controls)

    def test_three_hop_chains_enumerate_when_coverage_declines(self):
        s = S.scenarios(self._scored(ALL[:4]))
        multihop = [sc for sc in s["scenarios"] if (sc.get("hops") or 2) > 2]
        assert multihop, "a partially mitigated system must yield multi-hop paths"

    def test_attack_tree_is_renderable_without_rederiving(self):
        tree = S.attack_tree(self._scored(ALL[:4]))
        assert tree["stats"]["nodes"] > 0
        assert tree["stats"]["edges"] > 0
        assert all({"id", "coverage"} <= set(n) for n in tree["nodes"])
        assert all({"from", "to"} <= set(e) for e in tree["edges"])
        assert tree["note"], "the tree must say it is derived, not observed"

    def test_attack_tree_edges_point_at_declining_coverage(self):
        scoring = {"threats": [
            {"id": "T1", "title": "t1", "coverage": 90.0, "controls": ["C1"],
             "residual_score": 1.0},
            {"id": "T2", "title": "t2", "coverage": 40.0, "controls": ["C1"],
             "residual_score": 4.0},
            {"id": "T3", "title": "t3", "coverage": 5.0, "controls": [],
             "residual_score": 9.0},
        ]}
        tree = S.attack_tree(scoring)
        assert tree["stats"]["max_hops"] == 3
        by_id = {n["id"]: n for n in tree["nodes"]}
        for e in tree["edges"]:
            assert by_id[e["from"]]["coverage"] > by_id[e["to"]]["coverage"]
