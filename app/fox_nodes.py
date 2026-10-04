"""Fox-services infrastructure nodes as seen from the leadership board.

The nodes are the hosts the assessment pipeline and its LLM gateway depend on.
Their *declared* posture -- trust boundary, hardware -- is configuration, not
discovery: this app cannot reach inside a peer to ask it for a CPU model. The
live part is status: each node's service endpoint is probed with a short
timeout, and a down node is data, never an error.

A node whose host is not configured reports ``unprobed`` rather than guessing:
a board that quietly reports a host it never checked is worse than one that
says "no probe endpoint configured".
"""

import json
import os
import time
from urllib.parse import urlparse

import httpx

from . import openshell as osh

#: Where a node sits relative to the data-governance perimeter. This is the
#: same boundary the security posture reports: processing is permitted inside
#: it under guardrails; the outside is untrusted.
TRUST_INSIDE = "inside the data-governance perimeter"
TRUST_LOCAL = "outside the perimeter — local / developer"


def _env_specs() -> dict:
    """Operator-declared specs keyed by node id, from FOX_NODES_SPECS JSON."""
    try:
        raw = json.loads(os.environ.get("FOX_NODES_SPECS", "") or "{}")
        return raw if isinstance(raw, dict) else {}
    except Exception:
        return {}


def _fallback_gateway_host() -> tuple[str | None, int | None]:
    """Derive the local fallback gateway target from LLM_FALLBACK_URL, if any."""
    fb = os.environ.get("LLM_FALLBACK_URL", "").strip().rstrip("/")
    if not fb:
        return None, None
    try:
        u = urlparse(fb)
        host = u.hostname or None
        port = u.port
        return host, port
    except Exception:
        return None, None


_fb_host, _fb_port = _fallback_gateway_host()

FOX_NODES: list[dict] = [
    {
        "id": "axiom",
        "name": "axiom",
        "role": "LLM gateway + OpenShell broker — primary inference host",
        "host": os.environ.get("FOX_NODE_AXIOM_HOST", "192.168.1.173"),
        "port": int(os.environ.get("FOX_NODE_AXIOM_PORT", "8210")),
        "probe": "broker",
        "trust_boundary": TRUST_INSIDE,
        "max_data_tier": "confidential_data",
        "cpu": "AMD 7800X3D",
        "gpu": "2x RTX 5080",
        "ram": "64 GB",
        "storage": "2 TB",
        "note": ("Runs the fox-services broker and the LLM gateway; agent tool "
                 "calls and inference go through it. Hardware declared by the "
                 "operator."),
    },
    {
        "id": "axiom-dgx",
        "name": "axiom-dgx",
        "role": "Declared GPU inference node",
        "host": os.environ.get("FOX_NODE_AXIOM_DGX_HOST"),
        "port": int(os.environ.get("FOX_NODE_AXIOM_DGX_PORT", "8210")),
        "probe": "http",
        "trust_boundary": TRUST_INSIDE,
        "max_data_tier": "confidential_data",
        "cpu": "NVIDIA GB10",
        "gpu": "NVIDIA GB10",
        "ram": "128 GB",
        "storage": "4 TB",
        "note": ("Declared in the fox-services pool with operator-declared "
                 "hardware. No probe endpoint is configured, so status stays "
                 "unprobed until FOX_NODE_AXIOM_DGX_HOST is set."),
    },
    {
        "id": "harishs-macbook-pro",
        "name": "Harishs-MacBook-Pro",
        "role": "Developer workstation — local fallback gateway",
        "host": os.environ.get("FOX_NODE_MAC_HOST") or _fb_host,
        "port": int(os.environ.get("FOX_NODE_MAC_PORT") or _fb_port or 8210),
        "probe": "gateway",
        "trust_boundary": TRUST_LOCAL,
        "max_data_tier": "public",
        "cpu": None,
        "gpu": None,
        "ram": None,
        "storage": None,
        "note": ("Local gateway for offline development, outside the managed "
                 "perimeter, so it may only carry public/synthetic data. "
                 "Probe target derives from LLM_FALLBACK_URL when set."),
    },
]

for _node in FOX_NODES:
    _node.update(_env_specs().get(_node["id"], {}))


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _probe_http(host: str | None, port: int | None,
                path: str, timeout: float) -> dict:
    """A plain HTTP probe. A missing host is unprobed, not down."""
    if not host:
        return {"reachable": None, "state": "unprobed",
                "error": "no probe endpoint configured"}
    try:
        t0 = time.time()
        r = httpx.get(f"http://{host}:{port}{path}", timeout=timeout)
        return {"reachable": True, "state": "up",
                "status_code": r.status_code,
                "latency_ms": int((time.time() - t0) * 1000)}
    except Exception as exc:
        return {"reachable": False, "state": "down",
                "error": f"{type(exc).__name__}"}


def _gateway_models(host: str | None, port: int | None,
                    timeout: float) -> dict:
    """Probe an OpenAI-compatible /v1/models endpoint for served model names."""
    if not host:
        return {"reachable": None, "state": "unprobed", "models": [],
                "error": "no probe endpoint configured"}
    try:
        t0 = time.time()
        r = httpx.get(f"http://{host}:{port}/v1/models", timeout=timeout)
        latency_ms = int((time.time() - t0) * 1000)
        models: list[str] = []
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, dict):
                models = [str(m.get("id") or m.get("name") or "")
                          for m in (data.get("data") or [])
                          if isinstance(m, dict)]
                models = [m for m in models if m]
        return {"reachable": True, "state": "up", "models": models,
                "latency_ms": latency_ms}
    except Exception as exc:
        return {"reachable": False, "state": "down", "models": [],
                "error": f"{type(exc).__name__}"}


def _probe_broker(host: str | None, port: int | None,
                  timeout: float) -> dict:
    """Broker node: authoritative broker + gateway posture via the configured
    broker URL (which resolves correctly both inside docker and in dev), plus
    the models the gateway is actually serving."""
    st = osh.broker_status(timeout)
    gw = st.get("gateway") or {}
    out: dict = {
        "reachable": bool(st.get("reachable")),
        "state": "up" if st.get("reachable") else "down",
        "gateway": {"reachable": bool(gw.get("reachable"))},
        "sandboxes": st.get("sandboxes") or [],
    }
    if not st.get("reachable"):
        out["error"] = st.get("error") or "broker unreachable"
    models = _gateway_models(host, port, timeout)
    out["models"] = models.get("models") if models.get("reachable") else []
    out["gateway_latency_ms"] = models.get("latency_ms")
    return out


def _probe_node(node: dict, timeout: float) -> dict:
    probe = node.get("probe")
    host, port = node.get("host"), node.get("port")
    if probe == "broker":
        return _probe_broker(host, port, timeout)
    if probe == "gateway":
        return _gateway_models(host, port, timeout)
    return _probe_http(host, port, "/", timeout)


def infrastructure(timeout: float = 4.0) -> dict:
    """All fox-services nodes with declared posture and live status."""
    nodes = [dict(n) for n in FOX_NODES]
    for n in nodes:
        n["status"] = _probe_node(n, timeout)
    return {
        "nodes": nodes,
        "generated": _now_iso(),
        "note": ("Declared posture (trust boundary, hardware) comes from "
                 "configuration; status is probed live. A node whose host is "
                 "not configured reports unprobed rather than guessing."),
    }