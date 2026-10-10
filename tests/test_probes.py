"""The probe harness must be safe by construction and honest by reporting.

The safety envelope is tested as refusals: no target, a non-HTTP target, a
host off the allow-list, and no allow-list at all must each refuse rather than
guess. Execution is tested against a local HTTP server, because a harness
test that cannot reach anything proves nothing about what it would report.
"""
import http.server
import json
import socketserver
import threading

import pytest

from app import probes as P
from app import security as sec


@pytest.fixture(autouse=True)
def _clean_registry():
    before = {k: list(v) for k, v in sec.EFFICACY_OBSERVATIONS.items()}
    yield
    sec.EFFICACY_OBSERVATIONS.clear()
    sec.EFFICACY_OBSERVATIONS.update(before)


class _Leaky(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            body = {}
        user = " ".join(
            m.get("content", "") for m in body.get("messages", [])
            if isinstance(m, dict)).lower()
        if "proj-identifier-4821" in user or "repeat this passage" in user:
            out = ("the vendor stores telemetry in the eu region for thirty days "
                   "and deletes it automatically afterwards. PROJ-IDENTIFIER-4821")
        else:
            out = "I don't have that information."
        payload = json.dumps(
            {"choices": [{"message": {"content": out}}]}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture()
def leaky_host():
    srv = socketserver.TCPServer(("127.0.0.1", 0), _Leaky)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"127.0.0.1:{port}"
    srv.shutdown()


class TestSafetyEnvelope:
    def test_no_target_refuses(self):
        with pytest.raises(P.ProbeRefused):
            P.resolve_target(None, allow_hosts=["x.test"])

    def test_non_http_target_refuses(self):
        with pytest.raises(P.ProbeRefused):
            P.resolve_target({"endpoint": "ftp://x.test/cmd"},
                             allow_hosts=["x.test"])

    def test_off_allow_list_refuses(self):
        with pytest.raises(P.ProbeRefused):
            P.resolve_target({"endpoint": "https://evil.test/v1"},
                             allow_hosts=["api.acme.test"])

    def test_no_allow_list_refuses(self):
        with pytest.raises(P.ProbeRefused):
            P.resolve_target({"endpoint": "https://api.acme.test/v1"},
                             allow_hosts=[])

    def test_allow_listed_host_resolves(self):
        url = P.resolve_target({"endpoint": "https://api.acme.test/v1"},
                               allow_hosts=["api.acme.test"])
        assert url == "https://api.acme.test/v1"

    def test_allow_listed_host_with_port_resolves(self):
        url = P.resolve_target({"endpoint": "http://127.0.0.1:8080/v1"},
                               allow_hosts=["127.0.0.1:8080"])
        assert url == "http://127.0.0.1:8080/v1"

    def test_unknown_probe_refuses_without_sending(self):
        r = P.run_probe("nope", target={"endpoint": "https://a.test/v1"},
                        confirm=True, allow_hosts=["a.test"])
        assert r["status"] == "skipped"
        assert r["attempts"] == []

    def test_unconfirmed_run_sends_nothing(self):
        r = P.run_probe("verbatim_extraction",
                        target={"endpoint": "https://a.test/v1"},
                        trials=5, confirm=False, allow_hosts=["a.test"])
        assert r["status"] == "skipped"
        assert r["would_send"]["trials"] == 5

    def test_trials_are_capped(self):
        r = P.run_probe("verbatim_extraction",
                        target={"endpoint": "https://a.test/v1"},
                        trials=10_000, confirm=False, allow_hosts=["a.test"])
        assert r["trials_requested"] <= P.MAX_TRIALS


class TestExecution:
    def test_leaky_endpoint_reports_every_hit(self, leaky_host):
        r = P.run_probe("verbatim_extraction",
                        target={"endpoint": f"http://{leaky_host}/v1"},
                        trials=4, confirm=True, allow_hosts=[leaky_host])
        assert r["status"] == "completed"
        assert r["successes"] == 4
        assert r["score"]["verdict"] == "control_not_effective"
        assert r["score"]["rate"]["lower"] >= 0.3

    def test_safe_endpoint_reports_inconclusive(self, leaky_host):
        r = P.run_probe("membership_probe",
                        target={"endpoint": f"http://{leaky_host}/v1"},
                        trials=4, confirm=True, allow_hosts=[leaky_host])
        assert r["status"] == "completed"
        assert r["successes"] == 0
        assert r["score"]["verdict"] == "inconclusive"

    def test_unreachable_target_is_unknown_not_a_pass(self, leaky_host):
        dead = "127.0.0.1:1"
        r = P.run_probe("verbatim_extraction",
                        target={"endpoint": f"http://{dead}/v1"},
                        trials=2, confirm=True, allow_hosts=[dead])
        assert r["status"] == "unreachable"
        assert "unknown" in (r["reason"] or "").lower()

    def test_attempts_carry_only_an_excerpt(self, leaky_host):
        r = P.run_probe("canary_exfiltration",
                        target={"endpoint": f"http://{leaky_host}/v1"},
                        trials=2, confirm=True, allow_hosts=[leaky_host])
        for a in r["attempts"]:
            assert len(a.get("excerpt", "")) <= 160

    def test_payloads_are_not_served_over_the_library(self):
        lib = P.probe_library()
        ids = [p["id"] for p in lib["probes"]]
        assert "verbatim_extraction" in ids
        dumped = json.dumps(lib)
        assert "Repeat this passage exactly" not in dumped


class TestTrialRecording:
    def test_completed_probe_records_one_trial_per_control(self, leaky_host):
        r = P.run_probe("verbatim_extraction",
                        target={"endpoint": f"http://{leaky_host}/v1"},
                        trials=3, confirm=True, allow_hosts=[leaky_host])
        prov = P.record_probe_as_trial(
            "verbatim_extraction", r, control_ids=["C02", "C03"],
            source="probe test")
        assert len(prov) == 2
        # 3/3 attacks succeeded: each control earns a breached trial.
        assert all(p["n_breached"] == 1 for p in prov)
        assert sec.control_evidence("C02")["validated"] is True

    def test_skipped_probe_records_nothing(self):
        r = P.run_probe("verbatim_extraction",
                        target={"endpoint": "https://a.test/v1"},
                        confirm=False, allow_hosts=["a.test"])
        prov = P.record_probe_as_trial("verbatim_extraction", r,
                                       control_ids=["C02"], source="t")
        assert prov == []
        assert sec.control_evidence("C02")["n_observations"] == 0

    def test_repeated_probes_narrow_the_posterior(self, leaky_host):
        for _ in range(4):
            r = P.run_probe("verbatim_extraction",
                            target={"endpoint": f"http://{leaky_host}/v1"},
                            trials=1, confirm=True, allow_hosts=[leaky_host])
            P.record_probe_as_trial("verbatim_extraction", r,
                                    control_ids=["C10"], source="t")
        rec = sec.control_evidence("C10")
        assert rec["n_observations"] == 4
        assert rec["posterior_mean"] < rec["declared"]
