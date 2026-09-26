# Frontend guide

`static/index.html` — a single-file vanilla-JS SPA (vis-network for the graph,
lazy-loaded mermaid for diagrams, no build step). Layout: header, sidebar,
main tab area.

Related: [architecture](architecture.md) · [agent-loop](agent-loop.md) ·
[explainer](explainer.md) · [security-agent](security-agent.md)

## View map

```mermaid
flowchart TB
    SB["Sidebar\n• investigations list\n• new investigation form\n• collection brief (title/keywords/desc/sources)\n• schedule (cron/items/rounds)\n• prefs (domains, auto-save)"]
    SB --> TABS
    subgraph TABS["Main tabs (switchView)"]
        G["Knowledge graph\nvis-network · cluster bar\n(category/similarity)\nnode overlay on click"]
        R["Review\npending/accepted/rejected/all\nrelevance ring + reason"]
        TL["Timeline\nrun list + manual adds\nbaseline→target compare\n+ highlight in graph"]
        E["Explainer\nask row (mode/depth/audience)\narticle + evidence drawer\ntrace · roadmap · quiz\nthreads · bookmarks · watch"]
        S["AI Security\nproduct/exposure form\nscore + exec summary\nexploits · evidence · A2A trail\ndiagrams · md/PDF export"]
        C["Agent console\nrun controls\nsearch plan\nlive event log"]
    end
```

## Key flows

**Select investigation → work it.** `selectInvestigation(id)` loads brief,
graph, review queue, timeline, explanations, prefs. All tab loaders are scoped
by the global `currentInv`.

```mermaid
flowchart LR
    A["selectInvestigation(id)"] --> B["loadGraph + loadArtifacts\n+ loadTimeline + loadExplanations\n+ schedule/prefs UI"]
    B --> C["switchView(graph)"]
```

**Run the collection agent.** `startRun()` saves the brief, `POST …/run`,
then `watchRun()` polls `GET /runs/{id}/events?after_id=` every 2 s and
appends stage-colored entries; on `done` it refreshes graph, review count,
timeline, and investigations.

**Ask the explainer.** `askExplainer()` posts question + mode/depth/audience,
then polls the explanation until `done`; renders the article, evidence drawer,
trace panel, mermaid diagrams (lazy-loaded `mermaid@10` once, `run({nodes})`),
suggestions, quiz, and follow-up composer.

**Security assessment.** `runSecurityAssessment()` posts product + exposure,
polls the run's events into a compact stage log, then loads the finished
`SecurityAssessment` by `stats.assessment_id` and renders score, executive
paragraph, threat register, exploits/evidence tables, A2A trail with queries,
mermaid diagrams, full markdown, and md/PDF/history actions.

## Conventions

- `escHtml()` for all interpolated strings; `mdInline`/`mdBlock` for light
  markdown; `showNotif()` for toasts; `debounce()` on search input.
- Dark/light theme via CSS variables + `localStorage`.
- Node click → detail overlay (`openDetailOverlay`): description, source link,
  relationships, similar artifacts with shared tags.
- Compare mode: `compareRuns()` diffs two runs (`new_node_ids/new_edge_ids`),
  `highlightInGraph()` spotlights them; banner clears.
