"""Client for the fox-services LLM gateway (OpenAI-compatible /v1/chat/completions).

Identified by header X-Service-Name for attribution. Works both from inside
docker (host.docker.internal) and local dev (localhost) via fallback.
"""
import json
import os
import re

import httpx

SERVICE_NAME = "agentic-knowledge-mapper"

BASE_URL = os.environ.get("LLM_BASE_URL", "http://host.docker.internal:8210/v1").rstrip("/")
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


def _post(base: str, payload: dict) -> dict:
    url = base + "/chat/completions"
    try:
        with httpx.Client(timeout=TIMEOUT_S) as client:
            resp = client.post(url, json=payload,
                               headers={"X-Service-Name": SERVICE_NAME})
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        raise LLMError(f"{url}: {e}")


def chat(messages: list, model: str = MODEL, temperature: float = 0.2,
         max_tokens: int = 2048) -> str:
    """Plain chat completion, returns assistant text. Walks the base chain,
    using FALLBACK_MODEL on non-primary bases when the caller asked for MODEL
    (peer/local model names can differ)."""
    errors = []
    bases = _bases()
    for i, base in enumerate(bases):
        m = model if (i == 0 or model != MODEL) else FALLBACK_MODEL
        payload = {"model": m, "messages": messages,
                   "temperature": temperature, "max_tokens": max_tokens}
        try:
            data = _post(base, payload)
            break
        except LLMError as e:
            errors.append(str(e))
    else:
        raise LLMError("; ".join(errors))
    try:
        return data["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError) as e:
        raise LLMError(f"unexpected gateway response: {e}")


def chat_json(messages: list, model: str = MODEL, temperature: float = 0.2,
              max_tokens: int = 2048) -> dict | list:
    """Chat completion parsed as JSON (tolerates code fences / prose)."""
    text = chat(messages, model=model, temperature=temperature, max_tokens=max_tokens)
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.IGNORECASE)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        m = re.search(r"(\{.*\}|\[.*\])", cleaned, flags=re.DOTALL)
        if m:
            return json.loads(m.group(1))
        raise LLMError(f"LLM did not return JSON: {text[:300]}")


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
