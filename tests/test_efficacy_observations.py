"""Observed attack outcomes must move efficacy, and only when truly observed.

The distinction under test: a vendor document *asserts* a control exists, an
adversarial test *observes* whether it held. Only the second may change a
control's provenance, and only as a Bernoulli trial — never as a chosen number.
"""
import pytest

from app import security as sec


@pytest.fixture(autouse=True)
def _clean_registry():
    before = {k: list(v) for k, v in sec.EFFICACY_OBSERVATIONS.items()}
    yield
    sec.EFFICACY_OBSERVATIONS.clear()
    sec.EFFICACY_OBSERVATIONS.update(before)


class TestEfficacyTrials:
    def test_a_single_held_trial_moves_the_mean_only_slightly(self):
        before = sec.control_evidence("C01")
        after = sec.record_efficacy_trial("C01", held=True, source="probe")
        # One trial cannot support a tight claim about a 0.70 prior.
        assert after["posterior_mean"] > before["posterior_mean"]
        assert after["posterior_mean"] < 0.85
        assert after["concentration"] > before["concentration"]
        assert after["n_held"] == 1
        assert after["n_breached"] == 0

    def test_repeated_held_trials_converge_toward_one(self):
        for i in range(12):
            sec.record_efficacy_trial("C02", held=True, source=f"probe-{i}")
        rec = sec.control_evidence("C02")
        assert rec["posterior_mean"] > 0.88
        assert rec["basis"] == "measured"
        assert rec["validated"] is True

    def test_breached_trials_pull_the_mean_down(self):
        for i in range(3):
            sec.record_efficacy_trial("C03", held=False, source=f"probe-{i}")
        rec = sec.control_evidence("C03")
        assert rec["posterior_mean"] < sec.control_evidence("C03")["declared"]
        assert rec["n_breached"] == 3

    def test_mixed_trials_land_between(self):
        for i in range(4):
            sec.record_efficacy_trial("C04", held=True, source=f"h{i}")
        for i in range(2):
            sec.record_efficacy_trial("C04", held=False, source=f"b{i}")
        rec = sec.control_evidence("C04")
        assert 0.6 < rec["posterior_mean"] < 0.85

    def test_an_unvalidated_control_stays_unvalidated_with_no_trials(self):
        assert sec.control_evidence("C05")["validated"] is False
        assert sec.control_evidence("C05")["basis"] == "expert_elicited"

    def test_summary_counts_trials_across_the_control_set(self):
        sec.record_efficacy_trial("C01", held=True, source="p")
        sec.record_efficacy_trial("C01", held=False, source="p")
        summary = sec.efficacy_evidence_summary(["C01", "C02"])
        assert summary["n_held_trials"] == 1
        assert summary["n_breached_trials"] == 1


class TestOutcomeExtraction:
    @pytest.mark.parametrize("text", [
        "the egress allowlist blocked the exfiltration attempt",
        "the classification gate prevented the paste",
        "audit found the injection was contained",
        "no exfiltration was observed in 40 probes",
    ])
    def test_reads_a_held_outcome(self, text):
        assert sec.efficacy_outcome_from_text(text) == "held"

    @pytest.mark.parametrize("text", [
        "the attacker bypassed the classification gate",
        "credentials exfiltrated from the sandbox",
        "the prompt injection succeeded in reaching the tool",
    ])
    def test_reads_a_breached_outcome(self, text):
        assert sec.efficacy_outcome_from_text(text) == "breached"

    @pytest.mark.parametrize("text", [
        "the vendor maintains an egress allowlist",
        "we reviewed the DPA and the control is in place",
        "",
    ])
    def test_presence_is_not_an_outcome(self, text):
        # The distinction that matters: asserting a control exists is not
        # evidence that it ever blocked anything.
        assert sec.efficacy_outcome_from_text(text) is None

    def test_a_contradictory_artifact_records_nothing(self):
        # Resolving this ambiguity by guessing is how a measurement becomes a
        # fiction, so the extractor refuses.
        assert sec.efficacy_outcome_from_text(
            "the allowlist blocked the attack, but the attacker got through") is None

    def test_empty_input_is_safe(self):
        assert sec.efficacy_outcome_from_text(None) is None


class TestObservationValidation:
    def test_rejects_an_out_of_range_float(self):
        for bad in (1.5, -0.1):
            with pytest.raises(ValueError):
                sec.record_efficacy_observation("C01", bad, source="x")

    def test_rejects_a_non_numeric_float(self):
        with pytest.raises(ValueError):
            sec.record_efficacy_observation("C01", "high", source="x")

    def test_float_observations_still_work_for_imported_data(self):
        rec = sec.record_efficacy_observation("C06", 0.9, source="import")
        assert rec["n_observations"] == 1
        assert rec["posterior_mean"] > rec["declared"]

    def test_unknown_control_is_a_safe_prior(self):
        rec = sec.control_evidence("NOPE")
        assert rec["declared"] is None
        assert rec["validated"] is False
        assert rec["concentration"] == sec.UNVALIDATED_EFFICACY_CONCENTRATION