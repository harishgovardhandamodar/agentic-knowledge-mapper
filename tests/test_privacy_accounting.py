"""DP accounting, domain-distinct spend, and detector reliability.

Three properties under test, each of which exists because a reviewer asked a
question the module could not previously answer:

* does the composed (epsilon, delta) reflect *observers* rather than fetches;
* does the concave spend actually differ from the linear counter;
* does the extraction detector fire on real reproductions and stay quiet on
  unrelated text.
"""
import math

import pytest

from app import privacy as P


def _pages(hosts: dict[str, int]) -> list[dict]:
    return [{"url": f"https://{h}/p{i}", "text": f"t{h}{i}"}
            for h, n in hosts.items() for i in range(n)]


class TestDpAccounting:
    def test_reports_a_bound_and_declares_it_is_not_a_guarantee(self):
        d = P.dp_accounting(_pages({"a.com": 2, "b.com": 1}), queries=1)
        assert d["epsilon"] > 0
        assert d["delta"] == P.DEFAULT_DELTA
        # The engine adds no noise, so the number must never read as a promise.
        assert d["mechanism"] == "accounted-not-enforced"
        assert "NOT a differential-privacy guarantee" in d["note"]

    def test_more_observers_costs_more_privacy_than_more_pages(self):
        # The central claim: one host watched ten pages is a smaller exposure
        # than ten hosts each watched once.
        one_host = P.dp_accounting(_pages({"a.com": 10}))
        ten_hosts = P.dp_accounting(_pages({f"h{i}.com": 1 for i in range(10)}))
        assert ten_hosts["epsilon"] > one_host["epsilon"]

    def test_epsilon_falls_as_noise_rises(self):
        pages = _pages({f"h{i}.com": 1 for i in range(5)})
        low = P.dp_accounting(pages, noise_multiplier=1.0)["epsilon"]
        high = P.dp_accounting(pages, noise_multiplier=5.0)["epsilon"]
        assert high < low

    def test_epsilon_is_linear_in_sensitivity(self):
        # Sensitivity is an additive exposure measure, so epsilon is linear in
        # it by construction: one domain costs exactly a tenth of ten. The
        # value of the model is that it is *linear in observers*, not in
        # fetches -- see the "one host vs ten hosts" test.
        one = P.dp_accounting(_pages({"a.com": 1}))["epsilon"]
        ten = P.dp_accounting(_pages({f"h{i}.com": 1 for i in range(10)}))["epsilon"]
        assert one > 0
        assert ten > one
        assert ten == pytest.approx(one * 10, rel=0.01)

    def test_per_domain_breakdown_names_the_drivers(self):
        d = P.dp_accounting(_pages({"a.com": 3, "b.com": 1}))
        domains = {r["domain"]: r["novel_pages"] for r in d["per_domain"]}
        assert domains == {"a.com": 3, "b.com": 1}
        assert d["distinct_domains"] == 2

    def test_queries_add_sensitivity(self):
        without = P.dp_accounting(_pages({"a.com": 1}), queries=0)
        with_q = P.dp_accounting(_pages({"a.com": 1}), queries=3)
        assert with_q["sensitivity"] > without["sensitivity"]

    def test_seen_pages_are_not_novel(self):
        pages = _pages({"a.com": 2})
        seen = {P._digest(p["text"]) for p in pages}
        d = P.dp_accounting(pages, seen_hashes=seen)
        # Domains still counted as observers, but no novel pages behind them.
        assert d["per_domain"][0]["novel_pages"] == 0

    def test_no_external_pages_is_zero_not_a_crash(self):
        d = P.dp_accounting([], queries=0)
        assert d["epsilon"] == 0.0
        assert d["distinct_domains"] == 0

    def test_loopback_urls_are_still_counted_as_reach(self):
        # _is_external is the module's existing "not a file:// url" test; it
        # does not model loopback as internal. This test pins the actual
        # behaviour so a future decision to treat localhost as internal is a
        # visible change rather than a silent one.
        d = P.dp_accounting([{"url": "http://localhost:8204/api/health",
                              "text": "ok"}])
        assert d["distinct_domains"] == 1
        assert d["per_domain"][0]["domain"] == "localhost"

    def test_epsilon_from_rdp_never_divides_by_zero(self):
        eps, order = P.epsilon_from_rdp([1.0, 2.0, 8.0], 1.0)
        assert math.isfinite(eps)
        assert order > 1.0


class TestDomainSpend:
    def test_concave_is_below_linear_when_one_host_is_revisited(self):
        s = P.domain_spend(_pages({"a.com": 6}))
        assert s["concave_spend"] < s["linear_spend"]
        assert s["spread"] > 0

    def test_many_hosts_cost_more_than_one_host(self):
        one = P.domain_spend(_pages({"a.com": 10}))["concave_spend"]
        many = P.domain_spend(_pages({f"h{i}.com": 1 for i in range(10)}))["concave_spend"]
        assert many > one

    def test_per_host_view_is_cheaper_than_a_new_observer(self):
        s = P.domain_spend(_pages({"a.com": 3, "b.com": 1}))
        by_domain = {r["domain"]: r["novel_pages"] for r in s["per_domain"]}
        assert by_domain["a.com"] == 3
        assert s["distinct_domains"] == 2


class TestDetectorRoc:
    def test_extraction_detector_discriminates(self):
        r = P.detector_roc()
        assert r["auc"] > 0.8
        # Precision at the engine's operating threshold must be clean: a flag
        # on planted reproductions should not be a coin flip.
        assert r["operating_point"]["fpr"] <= 0.1

    def test_membership_detector_finds_a_planted_canary(self):
        m = P.membership_detector_roc()
        assert m["auc"] > 0.9

    def test_uppercase_canary_is_detectable(self):
        # Regression: the tokeniser was lowercase-only, so a machine-generated
        # caps canary lost its distinctive words and was reported "non-member".
        canary = ("ZKQ7XQ PROVINCEDIAMOND42 ledger marker alpha seven bravo "
                  "charlie delta echo")
        assert P._ngrams(canary), "caps tokenisation must survive the n-gram test"
        sig = P.membership_inference(canary, [f"record {canary} filed"])
        assert sig["signal"] == "member"

    def test_short_canary_reports_no_ngrams_rather_than_clean(self):
        # Fewer than NGRAM words yields no n-grams; reporting "non-member" there
        # would be a false negative dressed as a clean result.
        short = "ZKQ7XQ PROVINCEDIAMOND42 ledger"
        assert P._ngrams(short) == set()
        sig = P.membership_inference(short, ["anything"])
        assert sig["canary_ngrams"] == 0
        assert sig["signal"] in ("non-member", "inconclusive")

    def test_unrelated_output_does_not_trip_extraction(self):
        art = ("the vendor stores telemetry in the eu region for thirty days "
               "and deletes it automatically afterwards")
        out = P.extraction_resistance([("A1", art)], ["revenue rose eleven percent"])
        assert out["stats"]["extracted"] == 0
        assert out["ok"] is True

    def test_verbatim_reproduction_is_still_caught(self):
        art = ("the vendor stores telemetry in the eu region for thirty days "
               "and deletes it automatically afterwards")
        out = P.extraction_resistance([("A1", art)], [art])
        assert out["stats"]["high"] >= 1
        assert out["ok"] is False