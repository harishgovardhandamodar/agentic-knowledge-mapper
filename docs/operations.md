# Operations

Deploy, configure, schedule, and recover the Mapper.

Related: [architecture](architecture.md) · [data-model](data-model.md)

## Deployment

```mermaid
flowchart TB
    GH["repo checkout"] --> IMG["docker build\npython:3.12-slim + requirements\n+ chromium + vendored mermaid.js"]
    IMG --> RUN["docker compose up -d\n:8204 → dashboard"]
    RUN --> VOL[("named volume akm_data\n/app/data → akm.db\n+ mermaid_png/ picture cache")]
    RUN --> GW["env: LLM_BASE_URL (+ fallback)\nmesh peer or host gateway"]
    RUN --> SCH["APScheduler in-process\n1-min timetable tick\n10-min watch tick"]
```

```bash
docker compose up -d --build
# GUI at http://localhost:8204 (container: agentic-knowledge-mapper)
```

Local dev:

```bash
pip install -r requirements.txt
LLM_BASE_URL=http://localhost:8210/v1 python -m uvicorn app.main:app --port 8204 --reload
```

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `LLM_BASE_URL` | `http://host.docker.internal:8210/v1` (compose: axiom LAN `192.168.1.173:8210/v1`; the tailnet name is unusable while the peer firewall blackholes it) | primary OpenAI-compatible backend |
| `LLM_FALLBACK_URL` | `http://host.docker.internal:8210/v1` | second backend |
| `LLM_MODEL` / `LLM_FALLBACK_MODEL` | `qwen3.8:latest` / `qwen3.8:27b` | model names per backend |
| `LLM_TIMEOUT_S` | `180` | per-request timeout |
| `LLM_CONNECT_TIMEOUT_S` | `5` | connect-only timeout; a blackholed primary base fails over to the next in seconds instead of burning the full `LLM_TIMEOUT_S` |
| `AKM_CHROMIUM_BIN` | auto-detected (`chromium`, `chromium-browser`, `google-chrome`) | browser used to draw mermaid figures for PDF/bundle export; empty means no binary and exports fall back to source text |
| `AKM_MERMAID_JS` | `static/vendor/mermaid.min.js` | figure renderer; falls back to the pinned CDN when the vendored file is absent |
| `AKM_MERMAID_CACHE` | `data/mermaid_png/` (inside the `akm_data` volume) | rendered pictures, keyed by source hash; survives rebuilds, so repeat exports skip the browser |
| `AKM_PATTERNS_DIR` | `<repo>/../AI-Agents-Patterns` | sibling checkout served same-origin at `/patterns/` for the AI Agents tab; when absent the tab reports the reason instead of a broken frame |
| `AI_AGENTS_PATTERNS_DIR` | `../AI-Agents-Patterns` (compose only) | host path bind-mounted read-only to `/patterns-kb` for the mapper container; override when the checkout lives elsewhere |

`GET /api/health` reports gateway reachability and the model inventory
(`model_available` flag) — the header shows a green/amber/red dot. It also
carries the preferred/fallback signal the UI branches on: `preferred_url`
(always Axiom, first in the chain), `served_by`, `preferred_reachable`,
`fallback_active`, and a ready-to-show `notice`. When `fallback_active` is
true the Fluid UI shows an amber banner naming both the serving and the
preferred gateway, so a call served by a fallback is never mistaken for the
preferred one. The banner clears on its own once Axiom answers again.

## LLM failover (UML sequence)

```mermaid
sequenceDiagram
    autonumber
    participant C as llm.chat()
    participant P as primary base
    participant F as fallback base
    participant A as localhost/host swaps
    C->>P: POST /chat/completions
    alt ok
        P-->>C: content
    else LLMError
        C->>F: retry (fallback model name)
        alt ok
            F-->>C: content
        else LLMError
            C->>A: last-resort host swaps
            A-->>C: content or raise LLMError
        end
    end
```

`chat_json()` strips code fences and extracts the first `{…}`/`[…]` block;
callers treat failure as "LLM unavailable" and use deterministic fallbacks.

## Scheduler ticks

```mermaid
flowchart TB
    T1(["every 1 min\n_tick"]) --> D1{"enabled + next_run_at\ndue + not busy?"}
    D1 -- yes --> L["launch_run(trigger=schedule)\nslip next_run_at (no backlog)"]
    D1 -- no --> SKIP1(["skip"])
    T2(["every 10 min\n_tick_watched"]) --> D2{"watched + done\n+ no running expl.\n+ no re-answer today?"}
    D2 -- yes --> R["clone question (meta.watch_of)\nlaunch_explanation → drift verdict"]
    D2 -- no --> SKIP2(["skip"])
```

Per-investigation timetables are edited in the sidebar
(`PUT …/schedule {enabled, cron, max_items, max_rounds}`); cron validated with
`croniter`. Missed windows are skipped, never backfilled.

## Data & recovery

- SQLite WAL + `busy_timeout=5000`; background threads use their own
  `SessionLocal` sessions — never share sessions across threads.
- On boot, runs stuck `running` are marked `error` ("interrupted by server
  restart") so the 429 guard never deadlocks; the scheduler then resumes.
- Schema upgrades are additive (`ensure_columns`); the DB file persists in the
  `akm_data` volume across rebuilds. Back up `data/akm.db` (or the volume)
  to preserve investigations. The `data/mermaid_png/` picture cache beside it
  is disposable: deleting it only makes the next PDF/bundle export re-render
  its figures.
- Search providers are keyless and best-effort (RSS/arXiv/DuckDuckGo HTML);
  rate-limits surface as fewer candidates, never as run failures.
