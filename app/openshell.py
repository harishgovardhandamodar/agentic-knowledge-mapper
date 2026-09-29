"""OpenShell protection for the security agent's untrusted work.

NVIDIA OpenShell is the safe runtime for AI agents: tool execution happens
inside kernel-confined sandboxes governed by a declarative YAML policy
(filesystem / network egress / process rules, formally verified before they
widen), and agents never hold real credentials -- the gateway brokers them
only into requests bound for approved endpoints.

This module is the AKM side of that protection:

* :func:`fetch_url` -- fetch a product/doc page the way
  :func:`security.fetch_page_summary` needs it, inside a managed sandbox
  when one is reachable, else direct. Same return shape plus a ``sandbox``
  flag, and it never raises (the caller treats an unreachable page the
  same either way).
* :func:`generate_policy_yaml` -- deterministic OpenShell policy for the
  assessed product, derived from the exposure tier and the hosts the
  assessment actually fetched. Hand-emitted: this repo has no YAML
  dependency, and the schema is fixed, so a template beats a parser.
* :func:`assessment_openshell_block` -- the posture record stored with the
  assessment (sandbox usage, policy, active OpenShell controls).

The sandbox itself is brokered by fox-services (``/api/openshell/*``), which
owns the gateway relationship; AKM never shells out to the ``openshell``
CLI. When the broker or the gateway is down every call degrades to direct
fetch -- the assessment records ``sandbox_used: false`` instead of failing,
so protection is reported, never assumed.
"""
from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import urlsplit

import requests

ENABLED = os.environ.get("OPENSHELL_ENABLED", "1") == "1"
BROKER_URL = os.environ.get("OPENSHELL_BROKER_URL",
                            "http://host.docker.internal:8210").rstrip("/")
BROKER_TIMEOUT_S = float(os.environ.get("OPENSHELL_TIMEOUT_S", "25"))
FETCH_TIMEOUT_S = 8

POLICY_VERSION = "1"
OPENSHELL_CONTROLS = ("C13", "C14", "C15")

_CURL_UA = "PostAGI-SecurityAgent/1.0"
_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,253}[a-z0-9])?$")


class OpenshellUnavailable(Exception):
    """The fox-services OpenShell broker (or the gateway behind it) is down."""

    def __init__(self, detail: str):
        super().__init__(detail)
        self.detail = detail


def broker_status(timeout: float | None = None) -> dict[str, Any]:
    """Broker + gateway posture. Never raises -- unreachable is data."""
    try:
        r = requests.get(f"{BROKER_URL}/api/openshell/status",
                         timeout=timeout or BROKER_TIMEOUT_S)
        r.raise_for_status()
        body = r.json()
        if not isinstance(body, dict):
            raise ValueError("not a status object")
        return {"reachable": True, **body}
    except Exception as e:
        return {"reachable": False, "gateway": {"reachable": False},
                "sandboxes": [], "error": f"{type(e).__name__}: {e}"}


def broker_exec(command: list[str], sandbox: str | None = None,
                workdir: str | None = None, timeout_s: float | None = None,
                timeout: float | None = None) -> dict[str, Any]:
    """Run ``command`` in a managed sandbox via the broker.

    Returns ``{"ok", "exit_code", "stdout", "stderr", "sandbox"}``.
    Raises :class:`OpenshellUnavailable` on any transport, gateway or
    command failure -- callers that can proceed without a sandbox catch it.
    """
    payload: dict[str, Any] = {"command": list(command)}
    if sandbox:
        payload["sandbox"] = sandbox
    if workdir:
        payload["workdir"] = workdir
    if timeout_s:
        payload["timeout_s"] = timeout_s
    try:
        r = requests.post(f"{BROKER_URL}/api/openshell/exec", json=payload,
                          timeout=timeout or BROKER_TIMEOUT_S)
    except Exception as e:
        raise OpenshellUnavailable(f"broker unreachable: {e}")
    if r.status_code == 503:
        try:
            body = r.json()
            detail = (body.get("detail") or body.get("error")
                      if isinstance(body, dict) else None)
        except Exception:
            detail = None
        raise OpenshellUnavailable(str(detail or "gateway unavailable"))
    try:
        r.raise_for_status()
        body = r.json()
    except Exception as e:
        raise OpenshellUnavailable(f"broker exec failed: {e}")
    if not isinstance(body, dict) or not body.get("ok", True) or body.get("exit_code", 0) != 0:
        raise OpenshellUnavailable(
            f"sandbox command failed: {(body.get('stderr') or '')[:200] if isinstance(body, dict) else body}")
    return {"ok": True, "exit_code": int(body.get("exit_code", 0)),
            "stdout": body.get("stdout", ""), "stderr": body.get("stderr", ""),
            "sandbox": body.get("sandbox")}


def _http_url(url: Any) -> str | None:
    if not url or not str(url).strip():
        return None
    try:
        parts = urlsplit(str(url).strip())
    except Exception:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    return str(url).strip()


def fetch_url(url: str, timeout: int = FETCH_TIMEOUT_S) -> dict[str, Any]:
    """Fetch a page body, sandboxed when possible.

    Returns ``{"ok", "status_code", "ctype", "body"}`` with ``ok`` False on
    any failure. The sandbox path shells the fetch out to ``curl`` inside
    the managed sandbox; a missing curl, a dead broker, or a dead gateway
    all land here as ``ok: False`` so the caller falls back to direct.
    """
    clean = _http_url(url)
    if not clean:
        return {"ok": False, "status_code": 0, "ctype": "", "body": ""}
    if ENABLED:
        try:
            res = broker_exec(["curl", "-sSL", "--max-time", str(timeout),
                               "-A", _CURL_UA, "--compressed",
                               "-D", "-", clean],
                              timeout_s=timeout + 5)
            header, _, body = res["stdout"].partition("\r\n\r\n")
            if not body:
                header, _, body = res["stdout"].partition("\n\n")
            m = re.search(r"HTTP/\S+\s+(\d{3})", header)
            code = int(m.group(1)) if m else 0
            cm = re.search(r"(?im)^content-type:\s*([^\r\n]+)", header)
            ctype = (cm.group(1).split(";")[0].strip() if cm else "")
            if code == 200 and body:
                return {"ok": True, "status_code": code,
                        "ctype": ctype, "body": body}
        except OpenshellUnavailable:
            pass
        except Exception:
            pass
    return {"ok": False, "status_code": 0, "ctype": "", "body": ""}


def _yq_str(s: Any) -> str:
    """Double-quoted YAML scalar (valid for any unicode, no yaml dep)."""
    t = str(s or "").replace("\\", "\\\\").replace('"', '\\"')
    t = t.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return f'"{t}"'


def generate_policy_yaml(product_name: str, exposure: str,
                         page_urls: list[str]) -> str:
    """Deterministic OpenShell sandbox policy for the assessed product.

    Egress allows exactly the hosts the assessment fetched (GET only) --
    everything else stays denied -- and the exposure tier decides whether
    widening the policy needs a human (restricted/confidential) or not.
    Same inputs always produce the same bytes.
    """
    hosts: list[str] = []
    seen: set[str] = set()
    for u in page_urls or []:
        try:
            parts = urlsplit(str(u).strip())
            h = (parts.hostname or "").lower()
        except Exception:
            continue
        if parts.scheme not in ("http", "https"):
            continue
        if h and _HOST_RE.match(h) and h not in seen:
            seen.add(h)
            hosts.append(h)
    hosts.sort()
    exposure = (exposure or "confidential_data").strip()
    review = exposure in ("restricted_data", "confidential_data")
    lines = [
        "# OpenShell sandbox policy generated by AKM -- apply with:",
        "#   openshell policy set --file openshell-policy.yaml",
        "# Widening egress or filesystem access should be proved first:",
        "#   openshell policy prove --file openshell-policy.yaml",
        'policy_version: "1"',
        f"product: {_yq_str(product_name or 'Target product')}",
        f"exposure: {_yq_str(exposure)}",
        "filesystem:",
        '  read: ["/workspace", "/tmp"]',
        '  deny: ["~/.aws", "~/.config", "~/.ssh", "/etc/shadow", "/root"]',
        "network:",
        "  default: deny",
    ]
    if hosts:
        lines.append("  allow:")
        for h in hosts:
            lines.append(f"    - host: {_yq_str(h)}")
            lines.append("      methods: [GET]")
            lines.append("      reason: fetched during assessment")
    else:
        lines.append("  allow: []  # no hosts fetched -- add explicit research hosts")
    lines += [
        "process:",
        "  deny: [ssh, scp, nc, ncat]",
        "credentials:",
        "  broker: true  # agents never hold secrets; the gateway injects them per approved endpoint",
        "review:",
        f"  required: {'true' if review else 'false'}"
        + ("  # restricted/confidential: a human approves any widening"
           if review else "  # lower tiers may widen with `openshell policy prove`"),
    ]
    return "\n".join(lines) + "\n"


def assessment_openshell_block(pages: list[dict[str, Any]], product_name: str,
                               exposure: str,
                               active_controls: list[str]) -> dict[str, Any]:
    """Posture record stored with the assessment (in ``controls_json``)."""
    pages = pages or []
    used = [p for p in pages if p.get("sandbox")]
    return {"sandbox_used": bool(used),
            "sandbox_pages": len(used),
            "policy_yaml": generate_policy_yaml(
                product_name, exposure,
                [p.get("url", "") for p in pages if p.get("excerpt")]),
            "policy_version": POLICY_VERSION,
            "controls": [c for c in (active_controls or [])
                         if c in OPENSHELL_CONTROLS]}
