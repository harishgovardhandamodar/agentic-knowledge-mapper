# Agentic Knowledge Mapper

A parallel project to **post-AGI-society**: instead of a fixed topic with a fixed
pipeline, you define an **investigation** (keywords + free-text brief of what to
collect) and an **agent** plans searches, analyzes candidates, and maps them into
a per-investigation **knowledge graph**. All LLM reasoning goes through the
**fox-services gateway** (OpenAI-compatible `/v1/chat/completions`, local Ollama
or mesh peers — no external API keys).

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

## Architecture

```
┌──────────────┐     ┌──────────────────┐     ┌──────────────┐
│   Frontend   │────▶│   FastAPI (Python)│────▶│   SQLite DB  │
│  (vanilla JS)│◀────│   uvicorn :8204  │◀────│ (data/akm.db)│
└──────────────┘     └──────────────────┘     └──────────────┘
                             │ LLM via fox-services :8210
                             ▼ (/v1/chat/completions)
                      ┌────────────────┐
                      │ local Ollama / │
                      │   mesh peers   │
                      └────────────────┘
```

## GUI

- **Investigations** — create/select; per-item artifact/relationship/run counts.
- **Collection brief** — title, keywords, description, source toggles (RSS/arXiv/Web), save, run.
- **Knowledge graph** — vis-network, node size = relevance, category/similarity clustering toggle, physics toggle.
- **Review queue** — pending/accepted/rejected with relevance ring + agent reason; accept/reject/delete.
- **Agent console** — live stage-colored event log, search plan, run stats.

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
| PATCH/DELETE | `/api/artifacts/{id}` | Review state / delete |
| POST | `/api/relationships` | Manual edge |

## Running

```bash
docker compose up -d --build
# GUI at http://localhost:8204
```

Requires **fox-services** reachable (default `http://host.docker.internal:8210/v1`).
Config via env: `LLM_BASE_URL`, `LLM_MODEL` (default `qwen3.8:27b`),
`LLM_TIMEOUT_S` (default 180). Local dev:

```bash
pip install -r requirements.txt
LLM_BASE_URL=http://localhost:8210/v1 python -m uvicorn app.main:app --port 8204 --reload
```

## Structure

```
agentic-knowledge-mapper/
├── app/
│   ├── main.py       # FastAPI routes
│   ├── agent.py      # plan→search→analyze→map loop (background thread)
│   ├── search.py     # RSS / arXiv / DuckDuckGo providers
│   ├── llm.py        # fox-services gateway client (OpenAI-compat + fallback)
│   ├── models.py     # Investigation, Artifact, Relationship, AgentRun, AgentEvent
│   └── database.py   # SQLite WAL engine
├── static/index.html # GUI (all CSS/JS inline)
├── docker-compose.yml  # port 8204
├── Dockerfile
└── requirements.txt
```
