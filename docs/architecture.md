# Architecture

How the Agentic Knowledge Mapper fits together: system context, containers,
components, and the data flow between them.

Related: [agent-loop](agent-loop.md) · [explainer](explainer.md) ·
[security-agent](security-agent.md) · [data-model](data-model.md) ·
[frontend](frontend.md) · [operations](operations.md)

## System context

```mermaid
flowchart LR
    U["Researcher\n(browser)"] --> AKM["Agentic Knowledge Mapper\n:8204"]
    AKM --> GW["fox-services LLM gateway\n:v1/chat/completions"]
    GW --> L1["Local Ollama"]
    GW --> L2["Mesh peers\n(axiom-1 …)"]
    AKM --> WEB["Open web\nRSS · arXiv API · DuckDuckGo"]
```

The Mapper is a self-hosted research assistant. The user defines
**investigations** (a brief: title + keywords + free-text description); agents
collect and map knowledge into per-investigation graphs, and an explainer
answers questions with grounded, illustrated explanations. All LLM reasoning
goes through the fox-services gateway — no external API keys, with automatic
failover across local and mesh models.

## Containers

```mermaid
flowchart TB
    subgraph Browser["Browser (vanilla JS SPA)"]
        UI["static/index.html\nsingle-file GUI"]
    end
    subgraph App["FastAPI :8204 (Docker: agentic-knowledge-mapper)"]
        API["main.py\n~90 REST endpoints"]
        AG["agent.py\ncollection loop"]
        EX["explainer.py\nQ&A pipeline"]
        SEC["security_agent.py\n+ agents.py (A2A)\n+ security.py (engine)"]
        SCH["scheduler.py\ncron ticks"]
        SRCH["search.py\nRSS · arXiv · web"]
        LLM["llm.py\ngateway client"]
    end
    DB[("SQLite WAL\ndata/akm.db")]
    UI --> API
    API --> AG & EX & SEC & SCH
    AG --> SRCH
    AG & EX & SEC --> LLM
    API & AG & EX & SEC & SCH --> DB
```

| Container / module | Responsibility |
|---|---|
| `static/index.html` | All GUI: sidebar, 6 tabs, overlays, polling, mermaid rendering |
| `app/main.py` | FastAPI routes, request schemas, JSON serializers |
| `app/agent.py` | Collection loop: plan → search → analyze → map → refine (background thread) |
| `app/explainer.py` | Question answering: graph-first research → compose → ground → critique → diagram |
| `app/security_agent.py` + `app/agents.py` + `app/security.py` | Security assessments via the A2A envelope protocol |
| `app/scheduler.py` | Cron timetables for investigations + watch/drift re-answers |
| `app/search.py` | Keyless providers: RSS feeds, arXiv API, DuckDuckGo HTML |
| `app/llm.py` | OpenAI-compatible gateway client with base-chain failover + `chat_json` |
| `app/models.py` / `database.py` | SQLAlchemy models, WAL engine, column migrations |

## Component dependencies (UML)

```mermaid
classDiagram
    class FastAPI {
        +investigations CRUD
        +runs & events
        +artifacts & graph
        +explainer
        +security
    }
    class CollectionAgent {
        +run_investigation_agent()
        +launch_run()
    }
    class Explainer {
        +run_explainer()
        +launch_explanation()
    }
    class SecurityAgent {
        +run_security_assessment()
        +launch_security_assessment()
    }
    class A2A {
        +dispatch()
        +run_security_a2a_workflow()
    }
    class Scheduler {
        +_tick()
        +_tick_watched()
    }
    class SearchProviders {
        +search_rss()
        +search_arxiv()
        +search_web()
    }
    class LLMClient {
        +chat()
        +chat_json()
        +health()
    }
    class Store {
        +SessionLocal
        +init_db()
    }
    FastAPI --> CollectionAgent : launches
    FastAPI --> Explainer : launches
    FastAPI --> SecurityAgent : launches
    FastAPI --> Scheduler : starts on boot
    FastAPI --> Store : get_db
    CollectionAgent --> SearchProviders : queries
    CollectionAgent --> LLMClient : plan/analyze
    CollectionAgent --> Store : persists
    Explainer --> LLMClient : research/compose/critique
    Explainer --> Store : corpus + graph save
    SecurityAgent --> A2A : envelope workflow
    A2A --> LLMClient : exec paragraph
    A2A --> Store : agentic in-app search
    Scheduler --> CollectionAgent : cron launches
    Scheduler --> Explainer : watch re-answers
```

## Runtime data flow (a collection run)

```mermaid
sequenceDiagram
    autonumber
    actor R as Researcher
    participant UI as Browser GUI
    participant API as FastAPI
    participant AGT as Collection agent (thread)
    participant LLM as LLM gateway
    participant WEB as RSS/arXiv/DDG
    participant DB as SQLite
    R->>UI: Save brief, Run agent
    UI->>API: POST /investigations/{id}/run
    API->>AGT: launch_run() → thread
    API-->>UI: {status: started}
    loop poll every 2s
        UI->>API: GET /runs/{id}/events?after_id=
        API-->>UI: AgentEvents (plan/search/analyze/map/summary)
    end
    AGT->>LLM: plan queries (JSON)
    AGT->>WEB: fan-out search (ThreadPool ≤8)
    AGT->>LLM: analyze batches (relevance/tags/relations)
    AGT->>DB: persist artifacts + relationships
    AGT->>DB: run.status=done + stats
    UI->>API: GET /investigations/{id}/graph
    API-->>UI: nodes + edges → vis-network
```

## Key design decisions

- **Investigations scope everything.** Artifacts, relationships, runs, explanations,
  corpus pages, and security assessments all carry `investigation_id`. Deleting
  an investigation cascades. See [data-model](data-model.md).
- **Agents run in background threads with own sessions**, never on request
  threads. Progress is an append-only `AgentEvent` log the GUI polls —
  no websockets, no blocking calls. See [agent-loop](agent-loop.md).
- **LLM is an unreliable dependency, treated as one.** Every LLM call is wrapped
  in try/except with deterministic fallbacks (keyword pre-rank, template
  paragraphs); the gateway client walks a base chain (primary → fallback →
  localhost/host swaps). See [operations](operations.md).
- **Graph-first answering.** The explainer prefers the already-collected
  knowledge graph and cached corpus before hitting the web, and records which
  path it took in the trace. See [explainer](explainer.md).
- **Security is a separate agent family** speaking an envelope protocol (A2A),
  searching the app's own graph for evidence. See [security-agent](security-agent.md).
