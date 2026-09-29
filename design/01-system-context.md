# 01 — System context, containers, deployment

How the system fits together: what is inside the trust boundary, what is
outside it, and what runs where.

Related: [uml.md](02-uml.md) · [interaction.md](interaction.md) ·
[privacy.md](privacy.md) · [../docs/architecture.md](../docs/architecture.md)

## System context (C4 level 1)

```mermaid
flowchart LR
    R["Researcher<br/>browser, no install"]
    AKM["Agentic Knowledge Mapper<br/>:8204"]
    GW["fox-services LLM gateway<br/>:8210"]
    INF["Inference<br/>DGX Spark · RTX 5080 mesh"]
    WEB["Open web<br/>RSS · arXiv · DuckDuckGo"]
    SD["AI Standards dashboard<br/>:5173"]
    OS["OpenShell sandbox broker<br/>:8210 /api/openshell/*"]
    NVD["NVD · CIRCL<br/>CVE enrichment"]
    R -->|"HTTP + X-AKM-Session"| AKM
    AKM -->|"OpenAI-compatible /v1/chat/completions"| GW
    GW -->|"HTTP"| INF
    AKM -->|"keyless fetch"| WEB
    AKM -->|"HTTP, read-only data.json"| SD
    AKM -.->|"sandboxed fetch when reachable"| OS
    AKM -.->|"best-effort enrichment"| NVD
    GW -.->|"brokers sandboxed exec"| OS

```

The person uses a browser. The app is the only service that stores anything.
Everything else is a dependency the app can work without:

| Dependency | If it is down | Why it is safe to lose |
|---|---|---|
| LLM gateway / mesh | Agents fall back to deterministic behaviour (keyword pre-rank, template prose, split-topic fallback) | Every model call is wrapped; no run depends on a model answering |
| Open web | Fewer candidates; runs still complete | Search providers are keyless and best-effort |
| OpenShell broker | Fetches go direct, and each page records `sandbox: false` | The report states the protection instead of assuming it |
| Standards dashboard | Standards sub-tab returns 503 with the reason; the rest of the app is untouched | One cache-backed route |
| NVD / CIRCL | CVE row stored as `unknown` | An id with no metadata beats no id |

## Containers (C4 level 2)

```mermaid
flowchart TB
    subgraph BROWSER["Browser — no build step, no framework"]
        SPA["static/index.html<br/>single-file vanilla JS SPA<br/>vis-network · mermaid@10 lazy"]
    end
    subgraph APP["FastAPI app :8204 — container agentic-knowledge-mapper"]
        API["main.py<br/>93 REST paths · request schemas"]
        LED["ledger_api.py + ledger.py<br/>hash chain · mandates · proofs"]
        AG["agent.py<br/>collection loop"]
        EX["explainer.py<br/>Q&A pipeline"]
        SA["security_agent.py<br/>assessment worker"]
        A2A["agents.py<br/>A2A envelope bus · 5 agent cards"]
        EN["security.py<br/>threat pack · scoring · report"]
        MGR["manager.py<br/>parse · fan-out · synthesis"]
        STD["standards_matrix.py<br/>score matrix · findings"]
        SCH["scheduler.py<br/>cron · watch re-answers"]
        JQ["jobqueue.py<br/>persisted · idempotent · leased"]
        SUP["cve.py · drift.py · yield_.py · recommend.py<br/>evalkit.py · grounding.py · writeguard.py"]
        SRCH["search.py<br/>RSS · arXiv · DuckDuckGo"]
        LLM["llm.py<br/>single model choke point"]
        OBS["obs.py<br/>trace id · structured logs"]
    end
    DB[("SQLite WAL<br/>data/akm.db<br/>17 tables")]
    SPA --> API
    API --> LED
    API --> AG & EX & SA & MGR & STD & SCH & JQ
    AG --> SRCH
    AG & EX & SA & A2A & MGR --> LLM
    SA --> A2A --> EN
    AG & EX & SUP & SCH --> LLM
    API & AG & EX & SA & MGR & STD & SCH & JQ & LED --> DB
    LED -.->|"hash + redact every event"| LLM
    OBS -.->|"one id per user action"| API & AG & EX & SA & A2A

```

### Who owns what

| Module | Responsibility | Notable failure behaviour |
|---|---|---|
| `main.py` | Routes, request schemas, JSON shaping | 404/503 carry the reason, never a silent empty list |
| `agent.py` | plan → search → analyze → map → refine | 429 guard when a run is already going |
| `explainer.py` | research → compose → ground → critique → save | Bounded phases; corpus cache makes repeats free |
| `security_agent.py` | Assessment orchestration + approval gate | Parks on `awaiting_approval` rather than proceeding |
| `agents.py` | A2A `a2a/1.0` envelopes, 5 agent cards | Every hop appended to the trace and the chain |
| `security.py` | Threat pack 2.1.0, deterministic scoring, report | Pure function; pinned by `evalkit.py` |
| `manager.py` | Command parse, fan-out, synthesis | No background watcher — statuses derive live |
| `standards_matrix.py` | 34 frameworks × 10 pillars, relevance ranking | Cached; `no-store` per assessment |
| `scheduler.py` | 1-min cron tick, 10-min watch tick | Missed windows are skipped, never backfilled |
| `jobqueue.py` | Row-before-thread, idempotency key, lease | Lease expiry recovers dead workers, not slow ones |
| `ledger.py` / `ledger_api.py` | Chains, mandates, approvals, proofs, export | **Fail-open**: an outage degrades to unaudited, never 500 |
| `llm.py` | The one place a model is called | Failover chain, then deterministic fallback by callers |
| `writeguard.py` | Write-verify-repair over composed prose | Can only remove text, never add it |
| `grounding.py` | One shared verbatim-quote gate | Invalid citations are dropped and counted |
| `obs.py` | Trace id, structured logging | Never raises into a request |

## Deployment (C4 level 3)

```mermaid
flowchart TB
    subgraph HOST["Operator machine — DGX Spark, aarch64"]
        subgraph COMPOSE["docker compose (this repo)"]
            MAPPER["agentic-knowledge-mapper<br/>python:3.12-slim · :8204"]
            STD["ai-standards-dashboard<br/>nginx static build · :5173"]
            VOL[("named volume akm_data<br/>/app/data → data/akm.db")]
        end
        subgraph SIBLING["fox-services (sibling checkout)"]
            FOX["fox-services · :8210<br/>OpenAI-compatible gateway<br/>mesh discovery · proofs · OpenShell broker"]
        end
    end
    subgraph PEER["Mesh peer — axiom-1, 2× RTX 5080"]
        OLL["Ollama :11434/v1<br/>qwen3.8:27b and friends"]
    end
    subgraph WAN["Internet — keyless, best-effort"]
        FEEDS["RSS · arXiv · DuckDuckGo · NVD · CIRCL"]
    end
    BROWSER["Researcher's browser"]
    BROWSER -->|":8204"| MAPPER
    MAPPER --> VOL
    MAPPER -.->|":5173 data.json"| STD
    MAPPER -->|"100.101.3.115:11434/v1 (primary)"| OLL
    MAPPER -->|"host.docker.internal:8210/v1 (fallback)"| FOX
    MAPPER -.->|"host.docker.internal:8210<br/>OpenShell broker"| FOX
    MAPPER --> FEEDS
    FOX -->|"mesh HTTP"| OLL

```

`docker compose up -d --build` brings up two services here: the mapper and the
vendored standards dashboard. `fox-services` is started from its own checkout
first, because the mapper treats it as a dependency, not as part of itself.

## Runtime topology — who talks to whom, and when

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser
    participant A as app :8204
    participant S as scheduler
    participant J as job worker
    participant G as gateway :8210
    Note over S: every 1 min<br/>S->>A: read due investigations (own session)<br/>S->>J: launch_run(trigger=schedule) when not busy<br/>Note over J: every 1 s poll, lease claimed<br/>J->>A: claim(kind, lease) → job row<br/>J->>G: model call via llm.py<br/>Note over G: never called by the browser —<br/>only the app holds a gateway address<br/>G-->>J: content + routing + proof headers<br/>J->>A: events, artifacts, status<br/>Note over B: on every request<br/>B->>A: X-AKM-Session, X-AKM-Actor<br/>A->>A: resolve session, bind trace id<br/>A-->>B: response (ledger failure never becomes a 500)

```

## Failure domains

```mermaid
flowchart TB
    subgraph FD1["1. One model call fails"]
        A1["llm.chat tries primary → fallback → host swaps"]
        A2["caller catches, uses deterministic path"]
        A3["run continues; the model absence is on the record"]
    end
    subgraph FD2["2. A whole service is down"]
        B1["ledger / gateway outage"]
        B2["product calls proceed unaudited (fail-open)"]
        B3["DLQ table + GET /api/ledger/audit-drops shows the holes"]
    end
    subgraph FD3["3. The process restarts"]
        C1["runs stuck 'running' → 'interrupted by server restart'"]
        C2["jobs with expired leases are re-claimed"]
        C3["watched explanations re-answered on the next tick"]
    end
    subgraph FD4["4. The database is locked"]
        D1["WAL + busy_timeout=5000"]
        D2["each thread owns its own SessionLocal"]
        D3["additive migrations; the file persists in the volume"]
    end

```

## Configuration surface

Everything the app reads from the environment, in one place. See
[../docs/operations.md](../docs/operations.md) for how to set them.

| Variable | Default | Effect |
|---|---|---|
| `LLM_BASE_URL` | compose: mesh peer `http://100.101.3.115:11434/v1` | primary OpenAI-compatible backend |
| `LLM_FALLBACK_URL` | `http://host.docker.internal:8210/v1` | second backend, tried on error |
| `LLM_MODEL` / `LLM_FALLBACK_MODEL` | `qwen3.8:27b` | the model actually asked for, per backend |
| `LLM_TIMEOUT_S` | `180` | per-request timeout |
| `FOX_TELEMETRY_URL` | *(unset)* | digest-only gateway proof linkage on direct backends |
| `LEDGER_CAPTURE_PAYLOADS` | `0` | `1` stores prompts and args verbatim; off means hashed + redacted |
| `AKM_SESSION_IDLE_S` | `1800` | a browser sitting closes after this idle |
| `AKM_LOG_FORMAT` | `text` | `json` for one object per line |
| `AKM_LOG_LEVEL` | `info` | `debug`/`info`/`warn`/`error` |
| `AKM_IMAGE_PROBE` | `1` | section-image vocabulary relevance gate |
| `AKM_WRITEGUARD` / `_REPAIRS` / `_JUDGE` | `1` | write-verify-repair, repairs, drift judge |
| `OPENSHELL_ENABLED` | `1` | `0` forces direct fetches |
| `OPENSHELL_BROKER_URL` | `http://host.docker.internal:8210` | OpenShell broker |
| `OPENSHELL_TIMEOUT_S` | `25` | sandbox exec timeout |
| `STANDARDS_BASE_URL` | `http://standards` | in-compose dashboard host |
| `STANDARDS_TIMEOUT_S` / `STANDARDS_CACHE_TTL_S` | `10` / `900` | score-matrix fetch budget and cache |

## Related

- Component and class detail: [uml.md](02-uml.md)
- Storage detail: [data-model.md](data-model.md)
- What crosses a boundary, and what must not: [privacy.md](privacy.md)
