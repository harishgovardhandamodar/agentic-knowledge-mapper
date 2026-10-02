# Architecture

How the Agentic Knowledge Mapper fits together: system context, containers,
components, and the data flow between them.

Related: [agent-loop](agent-loop.md) · [explainer](explainer.md) ·
[security-agent](security-agent.md) · [data-model](data-model.md) ·
[frontend](frontend.md) · [operations](operations.md)

## System context

```mermaid
flowchart LR
    U["Researcher<br/>(browser)"] --> AKM["Agentic Knowledge Mapper<br/>:8204"]
    AKM --> GW["fox-services LLM gateway<br/>/v1/chat/completions"]
    GW --> L1["Local Ollama"]
    GW --> L2["Mesh peers<br/>(axiom-1 …)"]
    AKM --> WEB["Open web<br/>RSS · arXiv API · DuckDuckGo"]
    AKM --> OS["OpenShell broker<br/>:8210 (sandboxed fetch)"]
    AKM --> STD["AI Standards dashboard<br/>:5173 (read-only taxonomy)"]
```

The Mapper is a self-hosted research assistant. The user defines
**investigations** (a brief: title + keywords + free-text description); agents
collect and map knowledge into per-investigation graphs, and an explainer
answers questions with grounded, illustrated explanations. All LLM reasoning
goes through the fox-services gateway — no external API keys, with automatic
failover across local and mesh models.

The two dashed-service integrations are optional by design: the OpenShell
broker degrades to a direct fetch (recording `sandbox: false` rather than
failing), and the standards dashboard is a read-only consumer source that
returns 503 with a reason when unreachable. Neither is on the critical path of
collecting or answering.

## Seven applications, one subject

![fox-services gateway, the LLM dependency](screenshots/06-fox-services.png)

The word "mapper" undersells what is deployed. Seven applications are involved,
and they are not layers of one thing — they are peers with different jobs:

| App | Port | Route | Role | Talks to |
|---|---|---|---|
| **Agentic Knowledge Mapper** | 8204 | `/` (`static/index.html`) | investigations, graph, explainer, security | fox-services, standards dashboard, OpenShell, web |
| **Risk Console** | 8204 | `/console` (`static/console/index.html`) | risk-first alternative GUI, same REST | same backend as Mapper (no fork) |
| **Leadership Dashboard** | 8204 | `#dashboard` (pane) | availability / distribution / robustness | executive, scheduler |
| **fox-services** | 8210 | `/v1/chat/completions` | LLM gateway (OpenAI-compatible) | local Ollama, mesh peers, OpenShell broker |
| **AI Standards dashboard** | 5173 | `/` | browsable standards taxonomy | its own `data.json` |
| **OpenShell broker** | 8210 (in fox-services) | `/broker/fetch` | sandboxed fetch, egress policy | Mapper's fetch requests |

The mapper is the only one that holds research data. Everything else is either
a dependency it calls or a dataset it reads. Risk Console and Leadership
Dashboard are **presentation layers** over the same FastAPI — no new scoring,
no forked business logic: every number is a read from stored rows.

Do not confuse containers with **app tabs** in the mapper's own UI. AI
Standards is a separate container that the Mapper *iframes*; the other six
tabs — Mapper, AI Security, **Leadership Dashboard**, **Risk Console** (also at
`/console`), Agentic Manager, and Design & Architecture — are pane switches
inside `static/index.html` (Risk Console also served as a standalone shell at
`/console` for the toggle). Design & Architecture additionally has no service of
its own: it reads `design/` through `app/design_docs.py`.

![The standalone standards dashboard](screenshots/24-standards-dashboard.png)

## Containers

```mermaid
flowchart TB
    subgraph Browser["Browser (vanilla JS SPA)"]
        UI["static/index.html\nsingle-file GUI (Mapper + Security + Dashboard)"]
        RC["static/console/index.html\nRisk Console shell<br/>persona presets · Risk Cards · Report Reader"]
    end
    subgraph App["FastAPI :8204 (Docker: agentic-knowledge-mapper)"]
        API["main.py<br/>~110 REST paths"]
        AG["agent.py<br/>collection loop"]
        EX["explainer.py<br/>Q&A pipeline"]
        SEC["security_agent.py<br/>+ agents.py (A2A)<br/>+ security.py (engine)"]
        DOS["dossier.py<br/>report assembly"]
        MMP["mermaid_png.py<br/>figure renderer"]
        BRW["headless Chromium<br/>+ vendored mermaid.js"]
        MGR["manager.py<br/>fan-out + synthesis"]
        JOB["jobqueue.py<br/>durable queue (security runs)"]
        SCH["scheduler.py<br/>cron ticks + dashboard snapshots"]
        SRCH["search.py<br/>RSS · arXiv · web"]
        KBS["kb_search.py<br/>FTS5 → LIKE fallback"]
        CON["console.py<br/>BFF aggregators (console/home)"]
        PORT["portfolio.py<br/>unified register · leakage LP01-08"]
        EXEC["executive.py<br/>availability · distribution · robustness"]
        PP["provider_posture.py<br/>PDP01-10 · SAF01-06 · RLHF01-08"]
        MEM["memorization.py<br/>RM01-06 · preference memorization"]
        LEAK["leakage.py<br/>pathways + PB01-07"]
        LLM["llm.py<br/>gateway client"]
        LED["ledger.py<br/>hash-chained audit"]
    end
    DB[("SQLite WAL<br/>data/akm.db · 20+ tables<br/>initiatives · risks · snapshots")]
    UI & RC --> API
    API --> AG & EX & SEC & MGR & SCH & CON & KBS
    SEC --> JOB
    JOB --> SEC
    AG --> SRCH
    AG & EX & SEC --> LLM
    AG & EX & SEC & MGR & LED & PORT & EXEC & PP & MEM --> DB
    SEC --> LED
    API --> DOS
    DOS --> MMP
    MMP --> BRW
    MMP --> VOLC[("picture cache<br/>data/mermaid_png")]

```

| Container / module | Responsibility |
|---|---|
| `static/index.html` | Classic GUI: 7 apps (Mapper 9 views, Security 9 sub-tabs, Leadership Dashboard, Risk Console shell, Manager, Standards, Design & Architecture), sidebar, overlays, polling, mermaid + vis-network |
| `static/console/index.html` | Risk Console shell: persona presets, 10 areas, Risk Cards, Report Reader, charts (Chart.js), graphs (lite/risk/pathway), search suggest, saved views, master–detail, drawers |
| `app/design_docs.py` | Fixed index over `design/`; serves a design document by id for the Design & Architecture tab |
| `app/main.py` | FastAPI routes (~110 paths), request schemas, JSON serializers, `/console` + `/api/console/*` + `/api/search` |
| `app/agent.py` | Collection loop: plan → search → analyze → map → refine (background thread); provider posture + RLHF + memorization query packs |
| `app/explainer.py` | Question answering: graph-first research → compose → ground → critique → diagram; investigation_summary now carries `manager_synthesis` |
| `app/security_agent.py` + `app/agents.py` + `app/security.py` + `app/threatpack.py` | Security assessments via A2A envelope protocol, scored against versioned pack; agents now include `model-adv-intel` RM01-06, hypothesis `H-RM01/05`, mitigation `MM16` |
| `app/dossier.py` | Report assembly: executive summary + 7 sections + model synthesis RM01-06 + W3 from stored rows, Markdown/HTML, Markdown+images bundle |
| `app/mermaid_png.py` | Figure renderer: batch-draws mermaid sources to PNG via headless Chromium, cached by source hash |
| `app/model_eval.py` | Model-engineering core: family/modality enums, attack taxonomy (`memorization`/`alignment_data_leakage` + subtypes `preference_memorization` etc., `method_general` 0.25), `adversarial_coverage_v1` + `adoption_risk_v1` (`preference_data_exposure` signal), method versions 2.0.0/1.1.0, fingerprints (no LLM, evalkit-pinned) |
| Chromium + vendored `mermaid.min.js` | Baked into the image so PDF/bundle exports draw real pictures with no network |
| `app/manager.py` | Command parsing (provider template per lab, `provider_data_privacy_agi`), fan-out over topics, summary compilation with provider compare + RLHF tier tables + datapoint answers + synthesis safety subsection |
| `app/portfolio.py` | Unified register (`product`/`model`/`privacy`/`supply_chain` + `rm` subclass `preference_feedback`/`rlhf_memorization`), initiatives (`Initiative`), situation profiles, leakage `LP01-08` + `PB01-07`, cascade, mitigation advisor (org-controllable), intel + metrics |
| `app/leakage.py` | Leakage pathways, process patterns `PR01-05`, playbooks `PB01-07` (incl. RLHF), fingerprints |
| `app/provider_posture.py` | `provider_data_posture_v1` PDP01-10 + `provider_safety_context_v1` SAF01-06 (firewalled) + `akm-rlhf-feedback-retention` RLHF01-08, contribution map direct vs indirect (+ safety-feedback gated on PDP06), claim guard |
| `app/memorization.py` | `akm-rlhf-memorization` RM01-06 (data_class `preference_pair`/`sft_demo`/…, pipeline stages `sft`/`reward_model`/`rl_finetune`), query pack, `PB07` mapping, hypothesis drafts `H-RM01/05`, write-guard |
| `app/executive.py` | Leadership dashboard: availability (initiative/model/product/PDP/safety), distribution (`by_provider`, top RM*), robustness (mapping/validation/acceptance/inventory lift, approval hygiene, pack hygiene with safety), attention queue, snapshots/trends, briefs |
| `app/console.py` | BFF aggregators `GET /api/console/home|risks|brief` (persona-aware, read-only, no new scoring) |
| `app/kb_search.py` | FTS5 → LIKE fallback KB search over risks/artifacts/assets/decisions, `GET /api/search` + `suggest`, field filters, prefix `memoriz*`, highlights, facets, persona `accepted_only` |
| `app/standards_matrix.py` | Relevance-ranked standards score matrix served to the security pane |
| `app/cve.py` | CVE collection and enrichment (NVD → CIRCL → recorded unknown) |
| `app/recommend.py` | Coverage gaps, control leverage, stale brief, per-query-shape yields |
| `app/drift.py` | Deterministic prefilter + LLM judge for watch re-answers |
| `app/writeguard.py` | audit → repair → strip → drift gate on the way out of the explainer; provider/memorization phrases tier-gated |
| `app/grounding.py` | Verbatim citation checks (stdlib only) |
| `app/jobqueue.py` | Row-before-thread queue for security runs: leases, backoff, orphan recovery |
| `app/approvals.py` | Requester ≠ approver, fails closed |
| `app/openshell.py` | Sandboxed fetch, egress policy generation, posture reporting |
| `app/ledger.py` + `app/ledger_api.py` + `app/ledger_models.py` | Hash-chained audit ledger, mandates, sessions, proofs, approvals, exports |
| `app/evalkit.py` | Pinned scoring cases (8+5+15+4+8+4+10+5, now 50 cases/21 invariants) and invariants, CI gate on threat/model/portfolio/provider packs + RM01-06 |
| `app/scheduler.py` | Cron timetables for investigations + watch/drift re-answers + hourly `dashboard_snapshots` |
| `app/search.py` | Keyless providers: RSS feeds, arXiv API, DuckDuckGo HTML (unchanged; KB search is `kb_search.py`) |
| `app/llm.py` | OpenAI-compatible gateway client with base-chain failover + `chat_json` |
| `app/obs.py` | Traces and contextvars, re-bound at job claim |
| `app/models.py` / `database.py` | SQLAlchemy models (20+ tables: `initiatives`, `risk_entries`, `dashboard_snapshots`, `security_assessments.situation_json`/`initiative_id`/`requested_by`/`pdp_json`), WAL engine, column migrations |

## Component dependencies (UML)

```mermaid
classDiagram
    class RiskConsole {
        +persona presets
        +Risk Cards + Report Reader
        +charts + graphs + search
    }
    class Executive {
        +availability / distribution / robustness
        +snapshots + briefs
    }
    class Portfolio {
        +unified register
        +leakage + cascade + advisor
    }
    class ProviderPosture {
        +PDP/SAF/RLHF assess
        +contribution map + guard
    }
    class Memorization {
        +RM01-06 + subtypes
        +rm_rows + write-guard
    }
    class KBSearch {
        +search() + suggest()
    }
    class ConsoleBFF {
        +home() + risks() + brief()
    }
    class FastAPI {
        +investigations CRUD
        +runs & events
        +artifacts & graph
        +explainer
        +security
        +console + search
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
        +resume_security_assessment()
    }
    class A2A {
        +dispatch()
        +new_envelope()
    }
    class JobQueue {
        +enqueue()
        +claim()
        +recover_orphans()
    }
    class Ledger {
        +append()
        +verify_chain()
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
    FastAPI --> SecurityAgent : launches via queue
    FastAPI --> Scheduler : starts on boot
    FastAPI --> Store : get_db
    FastAPI --> RiskConsole : serves /console
    FastAPI --> ConsoleBFF : /api/console/*
    FastAPI --> KBSearch : /api/search
    RiskConsole --> ConsoleBFF : reads
    RiskConsole --> KBSearch : suggest
    ConsoleBFF --> Portfolio : composes
    ConsoleBFF --> Executive : composes
    Portfolio --> ProviderPosture : PDP/RLHF/SAF
    Portfolio --> Memorization : RM rows
    SecurityAgent --> JobQueue : enqueue + claim
    CollectionAgent --> SearchProviders : queries
    CollectionAgent --> LLMClient : plan/analyze
    CollectionAgent --> Store : persists
    Explainer --> LLMClient : research/compose/critique
    Explainer --> Store : corpus + graph save
    SecurityAgent --> A2A : envelope workflow
    SecurityAgent --> Ledger : one chain per A2A task id
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

## Report exports (dossier → Markdown / PDF / bundle)

The Summary tab's Full report section previews the dossier and exports it in
three formats. All of them read the same `investigation_dossier()` payload,
so preview, Markdown, PDF and bundle can never disagree about what was
investigated or how a score was reached.

```mermaid
flowchart LR
    UI2["Browser<br/>Preview / Print"] --> API2["main.py<br/>/dossier · /markdown · /pdf · /bundle"]
    API2 --> DOS2["dossier.py<br/>exec summary + §§1–8"]
    DOS2 --> MD["dossier.md<br/>prose + mermaid fences"]
    MD --> PDF["security.py build_pdf<br/>A4 + vectors + PNGs"]
    MD --> ZIP["dossier_bundle()<br/>md + images/*.png"]
    DOS2 --> MMP2["mermaid_png.py<br/>collect → render → cache"]
    MMP2 --> CHR["headless Chromium<br/>vendored mermaid.js"]
    MMP2 --> CAC[("data/mermaid_png<br/>sha1(source).png")]
```

- **Markdown** is the prose plus the mermaid fences verbatim — it renders
  natively on GitHub and keeps every figure re-renderable elsewhere.
- **PDF** draws the three canonical figures (`dataflow`, `workflow`,
  `threat_paths`) as ReportLab vectors and every other mermaid fence as a
  rendered PNG picture. A fence with no picture keeps its source text: a
  missing picture never breaks the export.
- **Bundle** (`.zip`) is the Markdown with a picture link above each fence
  plus the pictures under `images/` — figures show in viewers with no
  diagram plugin, and the fences stay for GitHub and reproducibility.
- **Pictures are content-addressed.** Rendered PNGs persist in the
  `akm_data` volume keyed by source hash, so repeat exports never relaunch
  the browser; a changed diagram re-renders, an unchanged one does not.

## Key design decisions

- **Investigations scope everything.** Artifacts, relationships, runs, explanations,
  corpus pages, security assessments, CVE findings, yields, and manager runs
  all carry `investigation_id`. Deleting an investigation cascades — except
  through the `ledger_*` tables, which attach by id and never cascade, because
  an audit record that dies with its subject is not an audit record. See
  [data-model](data-model.md).
- **A long security run is a row before it is a thread.** Security work goes
  through `app/jobqueue.py` with a lease, a heartbeat, exponential backoff, and
  orphan recovery on boot; a run row alone was not a durable record of a job.
  Collection and explainer runs still use a guarded daemon thread each
  (one running run per investigation, crash recovery on boot) — the queue is
  where it is needed, not everywhere.
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
- **Exports are assembled, not generated.** Dossier prose, PDF vectors, and
  rendered figures all read stored rows and cached pictures — no LLM, no
  recomputation — so re-exporting the same investigation byte-agrees on the
  numbers. See [frontend](frontend.md).
- **Model assessments are a separate mode, not a product flavor.**
  `assessment_mode=model_engineering` runs W1 adversarial research plus W2
  adoption risk (plus W3 mitigation planning when requested) through their
  own A2A agents, scores, catalogs and report template. Scores may be null
  (no evidence) and stay null through display. Families are data in
  `app/model_eval.py`, never new code paths.
- **Mitigations are recommended, never implemented.** The MM01–MM15 catalog
  carries efficacy priors and burden ratings; the analyst ranks by driver
  pressure minus burden, residuals stay indicative, and inapplicable controls
  are deferred with reasons rather than silently dropped.
- **History is immutable.** Re-scores write new rows (`supersedes_id`);
  old packs render with superseded badges plus changelog excerpts, never
  re-arithmetic. Fingerprint moves without version bumps fail CI.
- **Research is collected once per subject.** The collector caches by
  (investigation, subject, questions) with a corpus-drift guard, so
  parallel model jobs share literature instead of triplicating fan-out.
- **The LLM is optional in the loop, not in the product.** Research, scoring,
  and diagram generation all have deterministic paths; the pack's own evalkit
  pins the expected scores so a silent model change fails CI instead of
  quietly re-scoring every assessment in the database. See
  [threatpack](threatpack.md).

## Where the boundaries are

Four boundaries in this system are worth stating explicitly, because most of
what could leak crosses one of them. The full diagram, including the data
flows, is in [../design/privacy.md](../design/privacy.md).

1. **Browser → Mapper** — prompts and briefs. Hashed or redacted before
   storage; raw payloads only when `LEDGER_CAPTURE_PAYLOADS=1`.
2. **Mapper → fox-services** — prompt text and completions. This is the one
   boundary where research content actually moves.
3. **Mapper → Open web** — outbound fetches. Attempts go through the OpenShell
   broker; on failure they fall back to direct and record `sandbox: false`.
4. **Mapper → SQLite** — persistence. Wallet for the audit chain, git-ignored
   for everything else.

What is **not** implemented, and is not implied by any diagram here: user
authentication, encryption at rest, TLS, and a data-retention schedule. The
`ledger_approvals` table enforces requester ≠ approver, which is an integrity
control, not an access control — there are no accounts behind it.
