# Agentic Knowledge Mapper

You define an **investigation** (keywords + free-text brief of what to
collect) and agents plan searches, analyze candidates, and map them into a
per-investigation **knowledge graph**. An **explainer** answers questions with
grounded, illustrated explanations, and an **AI Security agent** assesses
products used with sensitive data. All LLM reasoning goes through the
**fox-services gateway** (OpenAI-compatible `/v1/chat/completions`, local
Ollama or mesh peers — no external API keys).

## Documentation (design, with diagrams)

| Doc | Contents |
|---|---|
| [docs/architecture.md](docs/architecture.md) | System context, containers, UML component/class diagrams, runtime flows |
| [docs/agent-loop.md](docs/agent-loop.md) | Collection loop state machine, activity flow, stage protocol, guards |
| [docs/explainer.md](docs/explainer.md) | Q&A pipeline, graph-first routing, grounding, threads/quiz/watch |
| [docs/security-agent.md](docs/security-agent.md) | A2A envelope protocol, threat model, report structure |
| [docs/data-model.md](docs/data-model.md) | ER diagram, tables, review lifecycle, migrations |
| [docs/frontend.md](docs/frontend.md) | View map, tab flows, GUI conventions |
| [docs/operations.md](docs/operations.md) | Deploy, config, LLM failover, scheduler, recovery |

All diagrams are Mermaid (rendered by GitHub and by most markdown viewers).

## Agent loop

```
brief (keywords + description)
  → PLAN      LLM drafts ≤6 targeted queries, picking rss/arxiv/web per query
  → SEARCH    RSS feeds · arXiv API · DuckDuckGo HTML (dedupe by URL/title)
  → ANALYZE   LLM batches: relevance 0..1, keep/drop, tags, sentiment,
              projection, relates_to[] against already-collected artifacts
  → MAP       persist top artifacts + agent relationships (+ tag-overlap fallback)
  → REFINE    if yield is low, planner drafts follow-up queries (≤ max_rounds)
```

Progress streams as `AgentEvent`s; the GUI polls `GET /api/runs/{id}/events`.
Details: [agent-loop](docs/agent-loop.md).

## Architecture

```
┌──────────────┐     ┌──────────────────┐     ┌──────────────┐
│   Frontend   │────▶│   FastAPI (Python)│────▶│   SQLite DB  │
│  (vanilla JS)│◀────│   uvicorn :8204  │◀────│ (data/akm.db)│
└──────────────┘     └──────────────────┘     └──────────────┘
                        │ agents: collection · explainer · security (A2A)
                        │ LLM via fox-services gateway
                        ▼ (/v1/chat/completions)
                 ┌────────────────┐
                 │ local Ollama / │
                 │   mesh peers   │
                 └────────────────┘
```

Components, UML diagrams, and data flows: [architecture](docs/architecture.md).

## GUI

- **Investigations** — create/select; per-item artifact/relationship/run counts; brief editor; cron timetables; prefs.
- **Knowledge graph** — vis-network, node size = relevance, category/similarity clustering, compare-highlight.
- **Review queue** — pending/accepted/rejected with relevance ring + agent reason.
- **Timeline** — run history, manual adds, baseline→target compare.
- **Explainer** — modes (explain/deep-dive/compare/tutor/critique/tldr/glossary/api-ref), evidence drawer, trace, roadmap, quizzes, threads, bookmarks, drift watch.
- **AI Security** — product + exposure form; score, executive summary, threat register, known exploits grounded in the investigation graph, A2A trail, diagrams, Markdown/PDF export.
- **Agent console** — live stage-colored event log, search plan, run stats.

GUI map and flows: [frontend](docs/frontend.md).

## API (selection)

| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | Health + LLM gateway status |
| GET/POST | `/api/investigations` | List / create |
| GET/PUT/DELETE | `/api/investigations/{id}` | Detail (with recent runs) / update brief / delete |
| POST | `/api/investigations/{id}/run` | Start agent run `{max_items, max_rounds}` |
| GET | `/api/runs?investigation_id=` | Run history |
| GET | `/api/runs/{id}` | Run + full event log |
| GET | `/api/runs/{id}/events?after_id=` | Poll new events |
| GET | `/api/investigations/{id}/graph` | Nodes + edges |
| GET | `/api/investigations/{id}/graph/clusters?mode=` | category \| similarity centroids |
| GET | `/api/investigations/{id}/artifacts?review=&search=` | Review queue |
| GET/POST | `/api/investigations/{id}/explain`, `/api/investigations/{id}/explanations` | Ask / history |
| GET | `/api/explanations/{id}`, `…/thread`, `…/suggestions` | Detail / thread / follow-up ideas |
| POST | `/api/explanations/{id}/followup`, `…/quiz`, `…/bookmark`, `…/watch`, `…/feedback`, `…/save_to_graph`, `…/investigate_gaps` | Threads, quiz, curation, watch, gap runs |
| POST | `/api/investigations/{id}/security/assess` | Start security assessment run |
| GET | `/api/investigations/{id}/security/assessments` | Assessment history |
| GET | `/api/security/assessments/{id}`, `…/markdown`, `…/pdf` | Report / exports |
| GET | `/api/agents/cards`, `/.well-known/agents` | A2A agent registry |
| PATCH/DELETE | `/api/artifacts/{id}` | Review state / delete |
| POST | `/api/relationships` | Manual edge |

## Running

```bash
docker compose up -d --build
# GUI at http://localhost:8204
```

Requires **fox-services** reachable (compose default: mesh peer Ollama,
fallback `http://host.docker.internal:8210/v1`).
Config via env: `LLM_BASE_URL`, `LLM_FALLBACK_URL`, `LLM_MODEL`,
`LLM_FALLBACK_MODEL`, `LLM_TIMEOUT_S` (default 180). Local dev:

```bash
pip install -r requirements.txt
LLM_BASE_URL=http://localhost:8210/v1 python -m uvicorn app.main:app --port 8204 --reload
```

Operations (deploy, scheduler, failover, recovery): [operations](docs/operations.md).

## Structure

```
agentic-knowledge-mapper/
├── app/
│   ├── main.py           # FastAPI routes
│   ├── agent.py          # plan→search→analyze→map loop (background thread)
│   ├── explainer.py      # Q&A pipeline: research→compose→ground→critique→diagram
│   ├── security_agent.py # security runs (background thread, trigger=security)
│   ├── agents.py         # A2A envelope protocol: collector→intel→writer
│   ├── security.py       # threat catalog, diagrams, Markdown/PDF report engine
│   ├── scheduler.py      # cron timetables + watch/drift re-answers
│   ├── search.py         # RSS / arXiv / DuckDuckGo providers
│   ├── llm.py            # fox-services gateway client (OpenAI-compat + fallback)
│   ├── models.py         # Investigation, Artifact, Relationship, AgentRun,
│   │                     #   AgentEvent, Explanation, CorpusPage, SecurityAssessment
│   └── database.py       # SQLite WAL engine + migrations
├── docs/                 # design documentation with Mermaid diagrams
├── static/index.html     # GUI (all CSS/JS inline)
├── docker-compose.yml    # port 8204
├── Dockerfile
└── requirements.txt
```
