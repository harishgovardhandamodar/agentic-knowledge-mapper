# Fox Security Research Core — Switchable Core

Optimized core that pairs with the Risk Console GUI, covering collection,
assessment, model/provider/RLHF risk, landscape, scoring, and risk management
via MCP tools, A2A, and a structured swarm (not unbounded chat).

Related: [01-system-context.md](01-system-context.md) ·
[02-uml.md](02-uml.md) · [risk-console.md](risk-console.md) ·
[risk-management.md](risk-management.md) · [risk-scoring.md](risk-scoring.md)

## Design thesis

| Principle | Choice |
|---|---|
| GUI is a projection | Risk Console + Classic only call APIs; no agent logic in browser |
| Swarm is role-stable | Few long-lived types; many short-lived tasks — not N personalities |
| A2A = coordination | Typed envelopes, `task_id` = ledger run id |
| MCP = capabilities | Tools: search, fetch, graph, register, score, index, ledger |
| Deterministic core | Scoring, pack math, FTS, priority = code; LLM only plans/judges/drafts |
| One risk spine | Unified register + `risk_scoring` feeds Console, briefs, agents |

```text
Risk Console / Classic GUI
        │ REST
API façade (auth as today)
  ├─ Job queue (risk_* / sec_*) ── Swarm runtime (A2A bus) ── MCP tools ── SQLite/ledger
  └─ Read models (search, dashboard)
```

## Four swarms (12 cards, ~15 skills, 8–9 MCP servers)

**Knowledge:** collector-orchestrator, research-collector (graph+web/arxiv via MCP), explainer, drift-judge

**Assessment:** security-orchestrator, model-eval-orchestrator, control-analyst / model-mitigation-analyst, threat-intel / model-adv-intel (RM*), provider-posture, report-writer

**Risk:** risk-orchestrator (`risk_sync`·`review`·`decide`·`enrich`), risk-intake, risk-triage (calls `mcp-score`, no LLM numbers), risk-treatment (wraps mitigation-advisor + experiments), risk-monitor (stale/SLA/intel), risk-governance (acceptance drafts), risk-reporter (digests/briefs)

**Portfolio:** manager-orchestrator, synthesizer

Shared: research-collector, profiler, mcp-search.

## MCP tool surface

| MCP | Tools | Used by |
|---|---|---|
| mcp-search | web_search, arxiv, rss, fetch_page (OpenShell, via fox-services) | collector, enrich |
| mcp-graph | query_artifacts, upsert_node, upsert_edge, subgraph | collector, landscape, Console graph |
| mcp-register | upsert_risk, list_risks, link_treatment, get_risk | risk swarm |
| mcp-score | score_risk, score_portfolio, fingerprint | triage, dashboard |
| mcp-assess | get_assessment, list_findings | intake, reporter |
| mcp-index | search, suggest, reindex_doc | Console search |
| mcp-ledger | append_event, request_approval, verify | all orchestrators |
| mcp-catalog | threat_pack, model_adversarial, mm_controls, playbooks | analysts |
| mcp-brief | render_brief, dossier_slice | risk-reporter, exports |

All tools idempotent, JSON, never silently accept risk or change pack constants. Fetch always via fox-services broker (OpenShell), only local model `qwen3.8:27b` via `http://host.docker.internal:8210/v1`.

## A2A patterns

`collect_research | map_attacks | rate_adoption | ingest_findings | score_priority | propose_treatment | detect_stale | draft_brief | draft_acceptance | profile_provider | sync_kb`

- **Pipeline:** plan → collect → analyze → score → report (assessment)
- **Fan-out/fan-in:** Manager topics, parallel provider posture
- **Reactive:** assessment.done → risk_sync; CVE → risk_review
- **Human gate:** treatment/acceptance → approval MCP → resume

Job queue leases, one `risk_sync` per assessment id, shared collector cache.

## Deterministic core (not agents)

`risk_scoring`, `threatpack`/`model_eval`, `jobqueue`, `ledger`, `search_index` (FTS5 → ES), `kb_sync`, `writeguard` — agents call via MCP, never reimplement.

## Switchable core

`app/fox_security_research_core.py` (or `app/swarm.py` + `app/mcp/*`) is the switchable core. Classic `security_agent` remains the default engine; the Fox core is selected via:

- Env `FOX_CORE_ENABLED=1` (default on) + header `X-Fox-Core: fox` or query `?core=fox`
- Console toggle **Fox Research Core ↔ Classic Core** next to Risk Console / Classic pills — same data, different orchestration (swarm + MCP vs direct A2A)
- Ledger records `core: fox` vs `classic` per run, so the audit can prove which path was used

```text
          ┌─ Knowledge swarm
GUI ─ API ─┼─ Assessment swarm ── A2A ── MCP tools ── deterministic core ── SQLite
          ├─ Risk swarm
          └─ Portfolio swarm
```

Scale-up: split MCP servers into processes; keep orchestrators in-app first.
