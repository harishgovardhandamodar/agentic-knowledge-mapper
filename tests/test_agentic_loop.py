"""Items 3-8: the agentic loop, measured trends, powered plans, authorship.

Each test pins a guarantee that did not exist before: scenarios become probe
plans, trends refuse to claim direction inside noise, plans carry their trial
counts, judgments carry authors, gaps carry lifecycles, and paths run past
three hops.
"""
import pytest

from app import benchmarks as B
from app import leadership as L
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


class TestScenarioProbeWiring:
    def test_every_testable_scenario_gets_real_probes(self):
        plans = S.scenarios_probe_plan(_score(ALL[:4]))
        assert plans["plans"], "a gappy posture must yield testable scenarios"
        for p in plans["plans"]:
            assert p["probes"], "a plan with no probes is not a plan"
            assert p["attribute_to"], "an outcome with nowhere to go is lost"

    def test_probes_come_from_the_harness(self):
        from app import probes as P
        plans = S.scenarios_probe_plan(_score(ALL[:4]))
        for p in plans["plans"]:
            for probe in p["probes"]:
                assert probe["probe_id"] in P.PROBES

    def test_untestable_scenarios_are_counted_not_hidden(self):
        scored = _score(ALL[:4])
        plans = S.scenarios_probe_plan(scored, limit=40)
        total = len(S.scenarios(scored)["scenarios"])
        assert (len(plans["plans"]) + plans["untestable_scenarios"] == total)

    def test_plan_names_its_scenario(self):
        scored = _score(ALL[:4])
        plans = S.scenarios_probe_plan(scored, limit=40)
        ids = {s["id"] for s in S.scenarios(scored)["scenarios"]}
        for p in plans["plans"]:
            assert p["scenario_id"] in ids


class TestCompareVerdict:
    def test_separated_intervals_are_distinguishable(self):
        v = B.compare_verdict({"lower_pct": 20, "upper_pct": 28},
                              {"lower_pct": 40, "upper_pct": 50})
        assert v["verdict"] == "distinguishable"
        assert v["direction"] == "up"

    def test_overlapping_intervals_are_indistinguishable(self):
        v = B.compare_verdict({"lower_pct": 20, "upper_pct": 28},
                              {"lower_pct": 24, "upper_pct": 32})
        assert v["verdict"] == "indistinguishable"
        assert v["overlap_pct_points"] > 0

    def test_missing_band_is_unmeasured_not_equal(self):
        v = B.compare_verdict({"lower_pct": 20, "upper_pct": 28}, None)
        assert v["verdict"] == "unmeasured"
        assert "cannot be decided" in v["reason"]

    def test_malformed_band_is_unmeasured(self):
        assert B.compare_verdict({}, {})["verdict"] == "unmeasured"


class TestTrendSignificance:
    def test_clear_move_claims_direction(self):
        s = L._bootstrap_delta_ci([70, 72, 71, 69, 70], [40, 42, 41, 39, 40])
        assert s["verdict"] == "improving"
        assert s["upper"] < 0

    def test_noise_refuses_direction(self):
        s = L._bootstrap_delta_ci([50, 52], [51, 49])
        assert s["verdict"] == "indistinguishable_from_flat"

    def test_single_observation_is_not_a_trend(self):
        s = L._bootstrap_delta_ci([60], [55])
        assert s["verdict"] == "insufficient_history"
        assert s["lower"] is None

    def test_empty_side_is_not_a_trend(self):
        assert L._bootstrap_delta_ci([], [55])["verdict"] == "insufficient_history"

    def test_deterministic(self):
        a = L._bootstrap_delta_ci([70, 72, 71], [40, 42, 41])
        b = L._bootstrap_delta_ci([70, 72, 71], [40, 42, 41])
        assert a == b


class TestPoweredPlans:
    def test_every_planned_experiment_carries_trials(self):
        from app import model_eval as M
        p = M.plan_experiments(
            {"name": "x"},
            [{"attack_class": "extraction", "confidence": 0.8}],
            [{"dimension": "robustness", "rating": "unknown"}], [], [])
        assert p["experiments"], "an open question must yield a probe"
        for e in p["experiments"]:
            assert e["n_trials"] >= 1
            assert e["trials_for_80_power"] >= e["n_trials"]

    def test_probe_registry_names_threats_and_trials(self):
        from app import probes as P
        reg = P.probe_registry()
        assert len(reg["probes"]) == len(P.PROBES)
        for r in reg["probes"]:
            assert r["default_trials"] >= 1
            assert isinstance(r["exercises_threats"], list)


class TestJudgmentAuthorship:
    def test_rescore_attributes_applicability(self):
        r = sec.score_assessment(
            "confidential_data",
            [{"id": "T01", "likelihood": 4, "impact": 5}],
            applicability={"T01": 0.8}, applicability_author="ana",
            applicability_rationale="chat surface present")
        assert r["judgments"] == [{
            "kind": "applicability", "subject": "T01", "value": 0.8,
            "author": "ana", "rationale": "chat surface present",
            "recorded_at": r["judgments"][0]["recorded_at"]}]

    def test_unattributed_weights_stay_anonymous(self):
        r = sec.score_assessment(
            "confidential_data",
            [{"id": "T01", "likelihood": 4, "impact": 5}],
            applicability={"T01": 0.8})
        assert r["judgments"][0]["author"] == "unknown"

    def test_no_applicability_means_no_judgments(self):
        r = sec.score_assessment(
            "confidential_data", [{"id": "T01", "likelihood": 4, "impact": 5}])
        assert r["judgments"] == []


class TestGapLifecycle:
    def test_ruled_out_requires_evidence(self):
        from app import explainer as E
        # Validation precedes any database touch, so None db still refuses.
        with pytest.raises(ValueError, match="requires evidence"):
            E.set_gap_status(None, 0, "Is X true?", "ruled_out")

    def test_statuses_are_a_closed_vocabulary(self):
        from app import explainer as E
        assert set(E.GAP_STATUSES) == {"open", "investigating", "answered",
                                       "ruled_out", "verified"}
        with pytest.raises(ValueError, match="unknown gap status"):
            E.set_gap_status(None, 0, "q?", "bogus")


class TestLongerPaths:
    def test_paths_run_past_three_hops(self):
        chains = S.uncovered_chains(_score(ALL[:4]), max_chain=5)
        assert any((c.get("hops") or 0) > 3 for c in chains)

    def test_findings_stay_distinct_across_lengths(self):
        chains = S.uncovered_chains(_score(ALL[:4]), max_chain=5)
        keys = [(c.get("endpoint") or c.get("weakest_link"),
                 tuple(sorted(c.get("uncovered_by") or []))) for c in chains]
        assert len(set(keys)) == len(keys)

    def test_all_lengths_represented(self):
        from collections import Counter
        chains = S.uncovered_chains(_score(ALL[:4]), max_chain=5)
        lengths = Counter(c.get("hops", 2) for c in chains)
        assert 2 in lengths
        assert max(lengths) >= 4
