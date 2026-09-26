# Collection agent loop

`app/agent.py` — the plan → search → analyze → map → refine loop that turns an
investigation brief into a knowledge graph. Runs in a background thread with
its own DB session; progress streams as `AgentEvent` rows.

Related: [architecture](architecture.md) · [data-model](data-model.md) ·
[frontend](frontend.md) · [operations](operations.md)

## State machine (UML)

```mermaid
stateDiagram-v2
    [*] --> planning : launch_run()
    planning --> searching : plan saved (≤6 queries)
    planning --> failed : planner LLM error
    searching --> analyzing : candidates found
    searching --> done : no candidates
    analyzing --> mapping : kept = top by relevance
    analyzing --> done : nothing worth keeping
    mapping --> refining : yield < max_items and rounds left
    mapping --> done : caps reached
    refining --> searching : follow-up queries (≤3)
    refining --> done : no follow-ups
    done --> [*] : stats + summary event
    failed --> [*] : error + summary event
```

## Activity flow

```mermaid
flowchart TB
    S(["launch_run(inv, max_items, max_rounds)"]) --> R["create AgentRun(status=running)\ninv.status=running"]
    R --> P["PLAN: llm.chat_json\n≤6 queries × sources\n(rss/arxiv/web ∩ enabled)"]
    P --> SEEN["seen = existing urls+titles\n(dedupe)"]
    SEEN --> LOOP{"round ≤ max_rounds\nand kept < max_items?"}
    LOOP -- no --> DONE
    LOOP -- yes --> F["SEARCH: ThreadPool fan-out\n(min 8, tasks = queries × sources)"]
    F --> PRE{"found > 3×max_items?"}
    PRE -- yes --> PR["cheap keyword pre-rank\n(title×2 + desc×1)"]
    PRE -- no --> AN
    PR --> AN["ANALYZE: batches of 5\nrelevance 0..1, keep/drop,\ntags, sentiment, projection,\nrelates_to[existing ids]"]
    AN --> KEEP{"any kept\n(keep flag or rel ≥ 0.4)?"}
    KEEP -- no --> DONE
    KEEP -- yes --> MAP["MAP: persist artifacts\n(origin=agent, review=pending)\n+ relationships (≤60)\n+ tag-overlap fallback edges"]
    MAP --> CAP{"kept ≥ max_items\nor rounds exhausted?"}
    CAP -- yes --> DONE
    CAP -- no --> FUP["planner: ≤3 follow-up\nqueries on gaps"]
    FUP --> F2{"follow-ups?"}
    F2 -- yes --> F
    F2 -- no --> DONE
    DONE(["run.status=done/error\ninv.status=ready\nsummary event"])
```

## Stage protocol (what the GUI shows)

Each stage emits `AgentEvent(run_id, stage, message, data)`:

| Stage | Emitted when | `data` payload |
|---|---|---|
| `plan` | queries planned (or refinement) | `{queries: [{text, sources}]}` + rationale |
| `search` | round starts / finishes / pre-ranked | `{count, sample: [titles]}` |
| `analyze` | each 5-item batch judged | progress `analyzed/total` |
| `map` | artifacts + edges persisted | `{kept: [titles]}` |
| `summary` | run done / failed / interrupted | stats or error |

The console polls `GET /api/runs/{id}/events?after_id=` every 2 s and renders
stage-colored entries — see [frontend](frontend.md#agent-console).

## Analysis verdict (LLM contract)

`_analyze_batch` sends ≤5 candidates plus up to 40 already-collected artifacts
as `relates_to` reference, and expects a JSON list:

```json
[{
  "index": 0,
  "relevance": 0.85,
  "keep": true,
  "reason": "directly measures scaling-law claim",
  "artifact_type": "paper",
  "tags": ["scaling-laws", "eval"],
  "sentiment": 0.1,
  "summary": "one–two sentences",
  "projection": {"type": "accelerationist", "confidence": 0.7,
                 "timeframe": "2027-2030", "summary": "..."} | null,
  "relates_to": [{"id": 12, "relationship_type": "supports",
                  "description": "..."}]
}]
```

Kept rule: `keep == true` **or** `relevance ≥ 0.4`, and `relevance > 0`.
Relationship types are restricted to
`references | supports | contradicts | builds_upon | responds_to | similar_to`
(else coerced to `similar_to`); edges to unknown ids or self-edges are dropped.

## Concurrency & guards

```mermaid
sequenceDiagram
    autonumber
    participant UI as GUI
    participant API as POST /run
    participant DB as SQLite
    participant TH as Agent thread
    UI->>API: start run
    API->>DB: any run status=running?
    alt busy
        DB-->>API: yes → 429
    else free
        API->>TH: launch_run (daemon thread)
        TH->>DB: own SessionLocal session
        TH->>TH: plan → search → analyze → map
        TH->>DB: AgentEvents + final stats
    end
```

- One running run per investigation for manual runs (`429` guard); the
  scheduler additionally skips (never queues) when busy.
- Search fan-out uses `ThreadPoolExecutor(max_workers=min(8, tasks))`.
- Crash recovery on boot: runs stuck `running` are marked `error`
  ("interrupted by server restart") so the guard never deadlocks.
- Entry points: `launch_run(inv, …)` (manual/scheduled) and
  `launch_run_with_goal(inv, goal, …)` (explainer-gap auto-investigation,
  trigger `explainer_gap`).
