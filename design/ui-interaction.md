# 07 — UI interaction

How a person actually moves through the app: five top-level apps, their views,
the overlays that sit on top, and what each control does to the system behind
it.

The UI is a single page (`static/index.html`, ~5.9k lines, no framework, no
build step). Every screen below is a `switchApp` / `switchView` target, and
every control is one function that either calls an API route or changes
browser-local state.

Related: [interaction.md](interaction.md) (what the API does) ·
[../docs/frontend.md](../docs/frontend.md) · [state.md](state.md)

## The five apps

```mermaid
flowchart TB
    R["Researcher"] --> A{"App switcher"}
    A -->|1| MAP["Mapper<br/>collect · map · review · explain"]
    A -->|2| SEC["AI Security<br/>assess · score · control"]
    A -->|3| MGR["Agentic Manager<br/>command · fan-out · summary"]
    A -->|4| STD["AI Standards<br/>frameworks · coverage"]
    A -->|5| DSG["Design & Architecture<br/>diagrams · data model · privacy"]
    MAP --> M8
    SEC --> S2
    MGR --> M3
    STD --> SD1
    DSG --> D2

    M8["8 Mapper views"]
    M8 --> m1["Knowledge graph"]
    M8 --> m2["Review<br/>pending count badge"]
    M8 --> m3["Artifacts<br/>collected, filterable"]
    M8 --> m4["Known issues<br/>CVE count badge"]
    M8 --> m5["Timeline<br/>one chain per run"]
    M8 --> m6["Explainer"]
    M8 --> m7["Agent console<br/>live stage log"]
    M8 --> m8b["Audit ledger<br/>violation badge"]

    S2["Security: 2 panes"]
    S2 --> s2a["Assessment"]
    S2 --> s2b["Standards coverage"]

    M3["Manager: 3 cards"]
    M3 --> m3a["Command box"]
    M3 --> m3b["Plan preview"]
    M3 --> m3c["Runs + timeline"]

    SD1["Standalone dashboard in an iframe<br/>(its own service on :5173)"]

    D2["Design set: 10 documents"]
    D2 --> d2a["Rail<br/>grouped, in reading order,<br/>with diagram counts"]
    D2 --> d2b["Rendered document<br/>Markdown + live Mermaid"]
    D2 --> d2c["Outline<br/>h2/h3 anchors, scroll spy"]
    D2 --> d2d["Source toggle<br/>the raw Markdown"]

```

The Standards tab is the odd one out and deliberately so: it is a **different
service** in an `<iframe>`, not another view. The same data is also available
as a scored matrix inside Security → Standards coverage, computed by the
mapper itself — the iframe shows the dashboard's own view, the sub-tab shows
the assessment-specific score.

The Design tab is different in kind again: it has no service and no data model.
It reads the `design/` directory in this repository over
`GET /api/design/docs` and renders it, so the diagrams on screen are the ones
in the repository rather than screenshots of them. The selected document lives
in the fragment (`#design/privacy`), which makes every document linkable.

## Mapper: the loop a person is actually in

```mermaid
flowchart LR
    BRIEF["Write the brief<br/>keywords, description,<br/>sources, domains"] --> RUN["Run agent"]
    RUN -.->|"polls every 2 s"| CONS["Agent console:<br/>plan → search → analyze → map → summary"]
    CONS --> GRAPH["Knowledge graph<br/>nodes + edges, click a node"]
    GRAPH --> REV["Review queue<br/>accept / reject / relevance reason"]
    GRAPH --> ASK["Explainer<br/>ask about the graph"]
    ASK --> ANS["Grounded answer<br/>with claims, sources,<br/>diagram, critique"]
    REV --> MORE["collect more"]
    ASK --> GAPS["Research gaps<br/>find the open questions"]
    GAPS --> RUN2["gap-driven run<br/>(the loop closes itself)"]
    RUN2 --> GRAPH
    GRAPH -.->|"#:explainer question="| ASK
    GRAPH -.->|"#:inv links"| SEC
    M4["Known issues<br/>CVE enrichment"] --> GRAPH

```

The `#` deep links are worth calling out: `#explainer` and `#:inv` let any
screen open another one with context, which is how a finding gets from the
security report into the research graph without re-typing the question.

## Security: assessment, then the nine sub-tabs

```mermaid
flowchart TB
    FORM["Product + exposure tier + focus<br/>+ per-control overrides"] --> GATE{"Require approval?"}
    GATE -- no --> GO["Assess → job queue → A2A workflow"]
    GATE -- yes --> PARK["Run parks at 'awaiting_approval'"]
    PARK --> DEC{"Another human decides?"}
    DEC -- deny --> DEN["Denied; the request and the decision<br/>are both on the chain"]
    DEC -- grant --> GO
    GO --> RES["Result lands on the overview"]
    RES --> RPT["The assessment's nine sub-tabs"]
    RPT --> t1["1 Overview<br/>aggregates, posture, distribution"]
    RPT --> t2["2 Threats<br/>T01–T12, scored"]
    RPT --> t3["3 Controls<br/>C01–C15, applicability, plan"]
    RPT --> t4["4 Investigation<br/>the analysis the controls were judged against"]
    RPT --> t5["5 Evidence<br/>per-claim sources, matched_on"]
    RPT --> t6["6 Known issues<br/>CVEs found in the evidence"]
    RPT --> t7["7 Agents<br/>the five A2A cards and what each returned"]
    RPT --> t8["8 Audit chain<br/>the one chain behind this run"]
    RPT --> t9["9 Report<br/>the markdown, §§1–12"]
    RPT --> t10["Standards coverage<br/>ranked frameworks, matched tokens"]

```

The audit sub-tab is the interesting one: the A2A task id *is* the ledger run
id, which is how a report and its evidence chain stay bound to each other. The
same chain, scoped to one run, is reachable from the Mapper's Audit ledger tab.

## Manager: understand before you launch

```mermaid
sequenceDiagram
    autonumber
    actor R as Researcher
    participant UI as Manager tab
    participant API as /api/manager
    R->>UI: paste a command
    UI->>API: POST /api/manager/parse
    API-->>UI: plan {domain, exposure, topics[], summary} + which path served it
    Note over UI: Understand has NO side effects —<br/>you can parse as often as you like<br/>R->>UI: uncheck a topic · set per-topic exposure · toggle launchers<br/>UI->>API: POST /api/manager/run<br/>API-->>UI: {run_id, children[]}
    loop poll
        UI->>API: GET /api/manager/runs
        API-->>UI: statuses derived live from the child runs
    end
    R->>UI: Compile summary
    UI->>API: POST /api/manager/runs/{id}/compile
    alt a child is still running
        API-->>UI: 409
    else all terminal
        API-->>UI: 200 (idempotent)
    end
    UI->>API: GET /api/manager/runs/{id}/timeline
    API-->>UI: 6-step strip + per-lane actions
    UI->>API: GET /api/manager/links
    API-->>UI: topics nested under the summary in the sidebar

```

The split between *parse* and *run* is the UX decision worth stealing: the
expensive, irreversible part (creating a dozen investigations) is gated behind
a preview of exactly what will be created, with per-topic control.

## What each control does, in one table

| Control | Screen | Calls | Effect on the system |
|---|---|---|---|
| Run agent | Mapper sidebar | `POST /investigations/{id}/run` | `AgentRun` row + worker thread; 429 if one is already going |
| Executive summary | Mapper sidebar | `GET /investigations/{id}/summary` | Overview overlay: aggregates, top threats, findings |
| Find open gaps | Mapper sidebar | `GET /investigations/{id}/recommendations` | Lists the least-covered questions; each can launch a gap run |
| Investigate gaps | Explainer | `POST /explanations/{id}/investigate_gaps` | Closes the loop: an answer that finds its own research |
| Save schedule | Mapper sidebar | `PUT /investigations/{id}/schedule` | Cron + items + rounds; the 10-min tick starts launching runs |
| Accept / reject | Review queue | `POST /artifacts/{id}/review` | `review` flips; rejection is reversible |
| Detect drift | Artifacts | `POST /investigations/{id}/detect-drift` | Flags off-brief artifacts; nothing is deleted |
| Collect issues | Known issues | `POST /investigations/{id}/cves` | Enriches CVEs from artifacts + reports, idempotently |
| Assess | Security | `POST /investigations/{id}/security/assess` | Job + A2A run, or a parked run awaiting approval |
| Approve / deny | Security | `POST /api/security/runs/{id}/approval` | The decision lands on the chain and re-queues the job |
| Compile summary | Manager | `POST /api/manager/runs/{id}/compile` | Synthesis artifact on the summary investigation |
| Verify chain | Audit ledger | `GET /ledger/runs/{id}/verify` | Recomputes every hash; reports `break_at` if tampered |
| Export | Audit ledger | `GET /ledger/runs/{id}/export` | A bundle that verifies offline, with no database attached |

## Overlays: what floats above everything

```mermaid
flowchart TB
    subgraph OVS["Overlays (one panel, swapped contents)"]
        O1["Executive summary<br/>aggregates · top threats · findings"]
        O2["Artifact detail<br/>relevance, reason, tags, content"]
        O3["CVE detail<br/>severity, cvss, impact, graph node"]
        O4["Explanation detail<br/>full answer, claims, quiz"]
        O5["Agent timeline<br/>one chain, per stage"]
        O6["Audit detail<br/>event JSON, proofs, contamination"]
        O7["Roadmap / help"]
    end
    ANY["any view"] --> OVS
    O1 --> CLOSE["closeOverlay()"]
    O2 --> CLOSE
    O6 --> CLOSE
    NOTE1["One overlay element, not seven. Deep links (#:inv, #explainer)<br/>open a view *with* an overlay already up, which is how a CVE<br/>in the security report lands on the graph with its node selected."]

    OVS ~~~ NOTE1
    classDef note fill:#fbfcfd,stroke:#c8d0da,stroke-dasharray:4 3,font-style:italic,color:#57606a
    class NOTE1 note
```

## Badges: the app telling you it wants attention

```mermaid
flowchart LR
    subgraph BADGES["Counts that mean 'you have something to do'"]
        B1["pendingCount → Review"]
        B2["cveCount → Known issues"]
        B3["auditBadge → Audit ledger<br/>violations in recent runs"]
        B4["secStdCount → Standards coverage"]
        B5["mgrRunsCount → Manager runs"]
        B6["SEC_SUBTABS[].n → per-sub-tab counts<br/>(e.g. pending approvals)"]
    end
    BADGES --> UI["Rendered on the tab itself, so the count is visible before you click"]
    NOTE1["A badge is a count, never a spinner. Nothing in this UI<br/>blocks on a background job; you can leave and come back."]

    BADGES ~~~ NOTE1
    classDef note fill:#fbfcfd,stroke:#c8d0da,stroke-dasharray:4 3,font-style:italic,color:#57606a
    class NOTE1 note
```

## The design rules the UI follows

```mermaid
flowchart TB
    R1["No framework, no build step<br/>one HTML file the container can serve"] --> ALL
    R2["Never block on a background job<br/>poll, show progress, let the person leave"] --> ALL
    R3["Every destructive-ish action is reversible or explicit<br/>(reject can be reset; delete is its own button)"] --> ALL
    R4["Show the reason, not just the verdict<br/>(relevance_reason, drift pill, verdict on every audit event)"] --> ALL
    R5["Counts, not spinners — and no claim the model made<br/>that the API cannot back"] --> ALL
    ALL["The UI states exactly what happened,<br/>including when a fallback served the answer"]

```

That last rule is the one that shows up most in the design: the UI says "Ledge"
or "deterministic fallback" when that is what happened. The person reading the
screen is being told the truth about the machine that produced it.

## Related

- What those calls do server-side: [interaction.md](interaction.md)
- The state each control moves: [state.md](state.md)
- [../docs/frontend.md](../docs/frontend.md) for the view-by-view inventory
