"""Client for the fox-services LLM gateway (OpenAI-compatible /v1/chat/completions).

Identified by header X-Service-Name for attribution. Works both from inside
docker (host.docker.internal) and local dev (localhost) via fallback.
"""
import json
import os
import re
import time

import httpx

SERVICE_NAME = "agentic-knowledge-mapper"

BASE_URL = os.environ.get("LLM_BASE_URL", "http://192.168.1.173:8210/v1").rstrip("/")
# Optional second backend (e.g. local gateway as fallback when primary is a
# mesh peer's Ollama). Tried in order after BASE_URL.
FALLBACK_URL = os.environ.get("LLM_FALLBACK_URL", "").rstrip("/")
MODEL = os.environ.get("LLM_MODEL", "qwen3.8:27b")
# Model name on the fallback backend (names can differ per host,
# e.g. qwen3.8:latest on axiom vs qwen3.8:27b locally). Defaults to MODEL.
FALLBACK_MODEL = os.environ.get("LLM_FALLBACK_MODEL", MODEL)
TIMEOUT_S = float(os.environ.get("LLM_TIMEOUT_S", "180"))


def _bases() -> list:
    chain = [BASE_URL]
    if FALLBACK_URL and FALLBACK_URL not in chain:
        chain.append(FALLBACK_URL)
    # docker <-> local-dev swap as last resort
    for b in list(chain):
        alt = (b.replace("host.docker.internal", "localhost")
               if "host.docker.internal" in b else
               b.replace("localhost", "host.docker.internal").replace(
                   "127.0.0.1", "host.docker.internal")
               if ("localhost" in b or "127.0.0.1" in b) else b)
        if alt != b and alt not in chain:
            chain.append(alt)
    return chain


class LLMError(Exception):
    pass


FOX_TELEMETRY_URL = os.environ.get("FOX_TELEMETRY_URL", "").rstrip("/")


def _telemetry_base() -> str:
    """Where digest-only proof reports go. Prefers an explicit telemetry URL,
    otherwise derives the gateway root from the fallback ``.../v1`` base."""
    if FOX_TELEMETRY_URL:
        return FOX_TELEMETRY_URL
    if FALLBACK_URL.endswith("/v1"):
        return FALLBACK_URL[: -len("/v1")]
    return ""


def _report_proof(payload: dict) -> None:
    """Fire-and-forget proof linkage for calls that bypass the gateway.

    Only digests and metadata cross this boundary; prompts and completions do
    not. A failed report is dropped: telemetry must never break inference.
    """
    base = _telemetry_base()
    if not base:
        return
    import json as _json
    import threading as _threading
    import urllib.request as _urllib

    data = _json.dumps(payload).encode("utf-8")

    def _send() -> None:
        try:
            req = _urllib.Request(base + "/api/usage/report", data=data,
                                  headers={"Content-Type": "application/json"},
                                  method="POST")
            with _urllib.urlopen(req, timeout=3) as res:
                res.read()
        except Exception:
            pass

    _threading.Thread(target=_send, daemon=True).start()


def _post(base: str, payload: dict, extra_headers: dict | None = None) -> tuple[dict, dict]:
    url = base + "/chat/completions"
    try:
        with httpx.Client(timeout=TIMEOUT_S) as client:
            resp = client.post(url, json=payload,
                               headers={"X-Service-Name": SERVICE_NAME, **(extra_headers or {})})
            resp.raise_for_status()
            return resp.json(), dict(resp.headers)
    except Exception as e:
        raise LLMError(f"{url}: {e}")


def _prompt_text(messages: list) -> str:
    """Flatten a message list into the text that will be hashed for the audit
    record. Best effort: malformed entries are skipped, not fatal."""
    parts = []
    for m in messages or []:
        if isinstance(m, dict):
            c = m.get("content")
            if isinstance(c, str):
                parts.append(c)
            elif isinstance(c, list):
                parts.extend(str(p.get("text", "")) for p in c
                             if isinstance(p, dict))
    return "\n".join(parts)


def _used_model(data: dict, requested: str) -> str:
    """Which model actually served the call. The gateway may answer on a
    fallback base under a different name, and the audit record must name the
    real one."""
    try:
        return data.get("model") or requested
    except AttributeError:
        return requested


def chat(messages: list, model: str = MODEL, temperature: float = 0.2,
         max_tokens: int = 2048) -> str:
    """Plain chat completion, returns assistant text. Walks the base chain,
    using FALLBACK_MODEL on non-primary bases when the caller asked for MODEL
    (peer/local model names can differ)."""
    _t0 = time.time()
    errors = []
    bases = _bases()
    prompt_text = _prompt_text(messages)
    ledger_headers = {}
    try:
        from . import ledger as _ledger_ctx
        run_id = _ledger_ctx.current_run()
        if run_id:
            ledger_headers = {
                "X-Ledger-Run": run_id,
                "X-Ledger-Prompt-Sha256": _ledger_ctx.text_digest(prompt_text),
            }
    except Exception:
        ledger_headers = {}
    for i, base in enumerate(bases):
        m = model if (i == 0 or model != MODEL) else FALLBACK_MODEL
        payload = {"model": m, "messages": messages,
                   "temperature": temperature, "max_tokens": max_tokens}
        try:
            data, raw_headers = _post(base, payload, ledger_headers)
            response_headers = {str(k).lower(): v for k, v in (raw_headers or {}).items()}
            break
        except LLMError as e:
            errors.append(str(e))
    else:
        raise LLMError("; ".join(errors))
    try:
        text = data["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError) as e:
        raise LLMError(f"unexpected gateway response: {e}")

    # Audit checkpoint. This is the single choke point for every model call in
    # the app, so it is where the timeline gets its "a model said this" rows.
    # No-ops unless a ledger run is open (see ledger.record_llm_call).
    try:
        from . import ledger
        usage = data.get("usage") or {}
        used_model = _used_model(data, model)
        latency_ms = int((time.time() - _t0) * 1000)
        tokens_in = int(usage.get("prompt_tokens") or 0)
        tokens_out = int(usage.get("completion_tokens") or 0)
        gateway = {
            "request_id": (response_headers.get("x-fox-request-id")
                           or response_headers.get("x-request-id") or ""),
            "proof": response_headers.get("x-fox-proof") or "",
            "provider_request_id": str(data.get("id") or ""),
        }
        ledger.record_llm_call(
            used_model, prompt_text, text,
            latency_ms=latency_ms, tokens_in=tokens_in, tokens_out=tokens_out,
            gateway=gateway)
        if not gateway["request_id"]:
            # Direct backends bypass Fox-services telemetry, so link this call
            # with a digest-only report. The gateway path already logged itself.
            _report_proof({
                "service": SERVICE_NAME,
                "model": used_model,
                "prompt_tokens": tokens_in,
                "completion_tokens": tokens_out,
                "duration_ms": latency_ms,
                "status": "complete",
                "request_id": (gateway["provider_request_id"]
                               or f"direct-{int(_t0 * 1000)}"),
                "prompt_sha256": ledger.text_digest(prompt_text),
                "output_sha256": ledger.text_digest(text),
                "client_prompt_sha256": ledger.text_digest(prompt_text),
                "ledger_run_id": ledger.current_run() or "",
            })
    except Exception:
        pass  # auditing must never break the call it is recording
    return text


def _parse_json_lenient(text: str):
    """Parse model output as JSON, tolerating the ways models actually break it.

    Small models in particular emit pretty-printed JSON with literal newlines
    inside strings, trailing commas, and prose around the payload. Strict
    parsing turns any of that into a total failure -- and for a 15KB deep-dive
    answer, *some* deviation is the norm, not the exception. Each repair is
    tried in order of fidelity: the first parse that succeeds wins, so clean
    output takes exactly the same path as before.
    """
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", (text or "").strip(),
                     flags=re.IGNORECASE)
    attempts = []
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as e:
        attempts.append(f"strict: {e}")
    try:
        # Literal control characters (real newlines/tabs) inside strings: the
        # single most common model-JSON defect. Still exact otherwise.
        return json.loads(cleaned, strict=False)
    except json.JSONDecodeError as e:
        attempts.append(f"lenient-controls: {e}")
    # Find the first balanced {...} or [...] span instead of the greedy
    # first-brace-to-last-brace regex, which breaks when trailing prose
    # contains braces of its own. When several spans parse (e.g. citation
    # markers like "[1], [2]" in leading prose), the longest one wins: the
    # real payload dwarfs any accidental fragment.
    decoder = json.JSONDecoder(strict=False)
    best = None
    for i, ch in enumerate(cleaned):
        if ch not in "{[":
            continue
        try:
            obj, end = decoder.raw_decode(cleaned[i:])
        except json.JSONDecodeError as e:
            attempts.append(f"span@{i}: {e}")
            continue
        if best is None or end > best[1]:
            best = (obj, end)
    if best is not None:
        return best[0]
    # Last resort: drop trailing commas before } and ], then re-try the span.
    repaired = re.sub(r",\s*([}\]])", r"\1", cleaned)
    if repaired != cleaned:
        best = None
        for i, ch in enumerate(repaired):
            if ch not in "{[":
                continue
            try:
                obj, end = decoder.raw_decode(repaired[i:])
            except json.JSONDecodeError:
                continue
            if best is None or end > best[1]:
                best = (obj, end)
        if best is not None:
            return best[0]
        attempts.append("trailing-comma repair failed")
    raise LLMError(f"LLM did not return JSON ({'; '.join(attempts[:3])}): "
                   f"{(text or '')[:300]}")


def chat_json(messages: list, model: str = MODEL, temperature: float = 0.2,
              max_tokens: int = 2048) -> dict | list:
    """Chat completion parsed as JSON (tolerates code fences / prose / the
    usual model formatting defects -- see _parse_json_lenient)."""
    text = chat(messages, model=model, temperature=temperature, max_tokens=max_tokens)
    return _parse_json_lenient(text)


def health() -> dict:
    """Gateway reachability + model inventory (best effort)."""
    out = {"base_url": BASE_URL, "fallback_url": FALLBACK_URL or None,
           "model": MODEL, "fallback_model": FALLBACK_MODEL,
           "reachable": False, "models": []}
    for base in _bases():
        try:
            with httpx.Client(timeout=10) as client:
                r = client.get(base + "/models", headers={"X-Service-Name": SERVICE_NAME})
                if r.status_code == 200:
                    ids = [m.get("id") for m in r.json().get("data", [])]
                    out.update(reachable=True, via=base, models=ids[:30],
                               model_available=(MODEL in ids))
                    return out
        except Exception:
            continue
    return out
