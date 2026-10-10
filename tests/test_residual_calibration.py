"""Floor saturation, efficacy provenance, and the variance budget.

These test the epistemic guarantees rather than the arithmetic: that the score
declares when it has stopped being able to move, that no efficacy is displayed
without its provenance, and that the credible band names what it does not cover.
"""
import pytest

from app import security as sec
from app import uncertainty as unc


def _inherent():
    """The shipped catalogue at full exposure weight."""
    return [
        {"id": t[0], "likelihood": sec._scale_likelihood(t[4], 1.0), "impact": t[5]}
        for t in sec._THREAT_CATALOG
    ]


def _score(n_controls=0, **kw):
    cids = [c["id"] for c in sec._CONTROL_CATALOG][:n_controls]
    return sec.score_assessment("confidential_data", _inherent(),
                                active_controls=cids, **kw)


# --------------------------------------------------------------- floor ---


class TestFloorDiagnostics:
    def test_no_controls_is_wholly_floor_capped(self):
        res = _score(0)
        assert res["floor_capped"] is True
        assert res["floor"]["floor_capped_count"] == len(_inherent())

    def test_floor_capped_recedes_as_coverage_grows(self):
        counts = [_score(n)["floor"]["floor_capped_count"] for n in (0, 3, 6, 12, 15)]
        assert counts == sorted(counts, reverse=True)
        assert counts[-1] < counts[0]

    def test_residual_saturates_and_says_so(self):
        # The empirical finding: the headline barely moves once coverage passes
        # the floor, and the block must name the controls responsible.
        wide = _score(12)["residual_pct"]
        wider = _score(15)["residual_pct"]
        assert abs(wide - wider) < 1.0, "expected saturation at high coverage"
        floor = _score(15)["floor"]
        assert floor["controls_beyond_floor"] > 0
        assert floor["controls_effective"] > 0
        assert (floor["controls_beyond_floor"] + floor["controls_effective"]
                == len(sec._CONTROL_CATALOG))

    def test_every_control_is_either_effective_or_beyond_floor(self):
        floor = _score(15)["floor"]
        assert sorted(floor["controls_beyond_floor_ids"]
                      + floor["controls_effective_ids"]) == sorted(
            c["id"] for c in sec._CONTROL_CATALOG)

    def test_orphaned_controls_are_reported_separately(self):
        # A control that touches no included threat changes nothing at all; it
        # is named apart from the floored ones so "inert" and "saturated" are
        # never conflated.
        res = sec.score_assessment(
            "confidential_data",
            [{"id": "T01", "likelihood": 3, "impact": 4}],
            active_controls=[c["id"] for c in sec._CONTROL_CATALOG])
        assert res["floor"]["controls_orphaned"]

    def test_floor_is_reported_at_the_top_level_not_only_in_breakdown(self):
        res = _score(3)
        assert res["floor_capped"] is True
        assert "floor" in res
        assert res["breakdown"]["min_residual_floor"] == sec._MIN_RESIDUAL_LIKELIHOOD

    def test_floor_bound_predicate_matches_the_formula(self):
        assert sec._is_floor_bound(0.0) is True
        assert sec._is_floor_bound(0.64) is True
        assert sec._is_floor_bound(0.70) is False
        assert sec._is_floor_bound(1.0) is False

    def test_note_states_the_score_is_ordinal(self):
        assert "ordinal" in _score(0)["floor"]["note"]


# ---------------------------------------------------------- provenance ---


class TestEfficacyProvenance:
    def test_every_catalogue_control_declares_its_basis(self):
        for row in sec.control_catalog():
            assert row["evidence"]["basis"] in sec.EFFICACY_BASIS
            assert row["evidence"]["source"]
            assert "concentration" in row["evidence"]

    def test_catalogue_efficacies_are_flagged_as_priors_by_default(self):
        assert all(row["efficacy_is_prior"] for row in sec.control_catalog())

    def test_unknown_control_degrades_to_an_unvalidated_prior(self):
        rec = sec.control_evidence("C99")
        assert rec["n_observations"] == 0
        assert rec["validated"] is False
        assert rec["declared"] is None

    def test_summary_counts_unvalidated_controls(self):
        res = _score(4)
        ev = res["efficacy_evidence"]
        assert ev["n_controls"] == 4
        assert ev["all_validated"] is False
        assert len(ev["unvalidated_controls"]) == 4

    def test_recording_an_observation_marks_the_control_measured(self):
        try:
            sec.record_efficacy_observation("C01", 0.9, source="probe", note="n=40")
            rec = sec.control_evidence("C01")
            assert rec["basis"] == "measured"
            assert rec["validated"] is True
            assert rec["posterior_mean"] > rec["declared"]  # pulled toward 0.9
            # The prior is retained, not discarded.
            assert rec["posterior_mean"] < 0.9
        finally:
            sec.EFFICACY_OBSERVATIONS.pop("C01", None)

    def test_rejects_impossible_efficacy(self):
        for bad in (1.5, -0.1, "high"):
            with pytest.raises(ValueError):
                sec.record_efficacy_observation("C02", bad, source="x")

    def test_efficacy_interval_is_wide_for_an_unvalidated_prior(self):
        iv = unc.efficacy_interval("C01")
        assert iv["basis"] == "expert_elicited"
        assert (iv["upper"] - iv["lower"]) > 0.4, "an unmeasured prior is not tight"


# --------------------------------------------------------- propagation ---


class TestUncertaintyPropagation:
    def test_explicit_concentration_is_accepted_alongside_status_names(self):
        by_status = unc.residual_interval(0.6, [(0.8, unc.DIRECT)])
        by_conc = unc.residual_interval(0.6, [(0.8, 4.0)])
        assert (by_conc["upper"] - by_conc["lower"]) > (
            by_status["upper"] - by_status["lower"])

    def test_unvalidated_control_widens_the_assessment_band(self):
        res = _score(6)
        default = unc.assessment_interval(res)
        # Pretend every control was validated with strong direct evidence; the
        # band must narrow, which is what an observation should buy.
        optimistic = unc.assessment_interval(
            res, evidence_by_control={cid: unc.DIRECT
                                      for cid in res["active_controls"]})
        assert (optimistic["upper_pct"] - optimistic["lower_pct"]) < (
            default["upper_pct"] - default["lower_pct"])

    def test_control_concentration_tracks_recorded_provenance(self):
        assert unc.control_concentration("C01") == \
            sec.UNVALIDATED_EFFICACY_CONCENTRATION
        try:
            sec.record_efficacy_observation("C03", 0.8, source="probe")
            assert unc.control_concentration("C03") > \
                sec.UNVALIDATED_EFFICACY_CONCENTRATION
        finally:
            sec.EFFICACY_OBSERVATIONS.pop("C03", None)


# ------------------------------------------------------ variance budget ---


class TestVarianceBudget:
    def test_budget_splits_into_bounded_shares(self):
        vb = unc.variance_budget(_score(6), draws=400)
        # Each share is a variance ratio, so each is in 0..1. They need not sum
        # to 1: the residual floor is a variance-reducing clip, so a negative
        # interaction term is the expected reading near saturation.
        for key in ("share_inherent", "share_efficacy", "share_interaction"):
            assert -1.0 <= vb[key] <= 1.0
        assert vb["total_variance"] > 0
        assert "interaction_note" in vb

    def test_efficacy_uncertainty_is_actually_reported(self):
        vb = unc.variance_budget(_score(6), draws=400)
        assert vb["total_variance"] > 0
        assert vb["share_efficacy"] > 0

    def test_names_the_inputs_the_band_does_not_cover(self):
        vb = unc.variance_budget(_score(3), draws=200)
        for key in ("threat_impact_values", "likelihood_judgement",
                    "applicability_weights", "residual_floor",
                    "aggregation_weights", "threat_catalogue_completeness"):
            assert key in vb["unquantified"]
            assert vb["unquantified"][key]

    def test_budget_is_deterministic(self):
        a = unc.variance_budget(_score(3), draws=200)
        b = unc.variance_budget(_score(3), draws=200)
        assert a["total_variance"] == b["total_variance"]

    def test_band_carries_its_budget_so_they_cannot_be_shown_apart(self):
        band = unc.assessment_interval(_score(3), draws=200)
        assert "variance_budget" in band
        assert band["floor_capped"] is True
        assert band["efficacy_evidence"]["n_controls"] == 3

    def test_frozen_inputs_collapse_their_variance(self):
        # Sanity on the decomposition itself: a one-control threat with no
        # efficacy spread must attribute its variance to the inherent draw.
        res = sec.score_assessment(
            "confidential_data",
            [{"id": "T01", "likelihood": 3, "impact": 4}],
            active_controls=[])
        vb = unc.variance_budget(res, draws=400)
        assert vb["share_efficacy"] == 0.0
        assert vb["share_inherent"] > 0.0
