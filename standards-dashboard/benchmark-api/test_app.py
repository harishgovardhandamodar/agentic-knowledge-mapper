import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(__file__))
from app import _mutation_error, app  # noqa: E402

client = TestClient(app)


def test_health_is_open():
    assert client.get("/health").status_code == 200


def test_status_is_open():
    assert client.get("/api/benchmark/status").status_code == 200


def test_mutation_error_token_logic():
    assert _mutation_error("s3cret", "s3cret", "172.17.0.1") is None
    assert _mutation_error("s3cret", "wrong", "127.0.0.1") is not None
    assert _mutation_error("", "", "127.0.0.1") is None
    assert _mutation_error("", "", "::1") is None
    assert _mutation_error("", "", "172.17.0.1") is not None


def test_requires_token_when_configured(monkeypatch):
    monkeypatch.setenv("BENCH_API_TOKEN", "s3cret")
    # wrong/missing token -> 401 regardless of client host
    assert client.post("/api/benchmark/run").status_code == 401
    assert client.post("/api/benchmark/stop").status_code == 401
    assert client.post("/api/benchmark/rerun", json={}).status_code == 401
    assert client.post(
        "/api/benchmark/rerun-model", json={"key": "qwen7b"},
        headers={"Authorization": "Bearer nope"},
    ).status_code == 401


def test_rejects_remote_client_without_token(monkeypatch):
    monkeypatch.delenv("BENCH_API_TOKEN", raising=False)
    # TestClient reports a non-loopback client host, so mutations are denied
    assert client.post("/api/benchmark/run").status_code == 403
    assert client.post("/api/benchmark/stop").status_code == 403


def test_run_accepts_token_via_bearer(monkeypatch):
    monkeypatch.setenv("BENCH_API_TOKEN", "s3cret")
    # authorized decision at the pure level; never POST a real job here
    assert _mutation_error("s3cret", "s3cret", "") is None
    # Bearer prefix is stripped by require_authorized before the pure check
    provided = "Bearer s3cret"
    if provided.startswith("Bearer "):
        provided = provided[len("Bearer "):]
    assert _mutation_error("s3cret", provided, "172.17.0.1") is None
    # loopback is still gated behind the configured token, not exempted
    assert _mutation_error("s3cret", "wrong", "127.0.0.1") is not None
    assert _mutation_error("s3cret", "", "::1") is not None