# Explainer pipeline

`app/explainer.py` (~1300 lines) — turns a question into a researched,
illustrated, grounded answer with citations, threads, quizzes, and drift
watching. `run_explainer(exp_id)` runs in a background thread; the GUI polls
`Explanation.status` plus a `phase` field in `meta`
(`researching → composing → critique → saving → done`).

Related: [architecture](architecture.md) · [data-model](data-model.md) ·
[frontend](frontend.md)

## Pipeline flowchart

```mermaid
flowchart TB
    Q(["ask: question + mode/depth/audience\n+ max_pages + max_hops"]) --> CTX["collect context\n• graph artifacts (~8, Jaccard-ranked)\n• corpus cache (CorpusPage rows)\n• source affinity (learned)\n• preferred domains + expand terms"]
    CTX --> GAP{"gap check:\ncan the graph answer it?"}
    GAP -- "coverage full" --> GONLY["answer from graph (+corpus)\nweb_skipped = true"]
    GAP -- "partial / missing" --> RES["RESEARCH: web search +\nfetch pages (≤ max_pages)\ncorpus-cache first"]
    GONLY --> COMP
    RES --> COMP["COMPOSE: mode/depth/audience rules\n+ section plan (deep)\n≤12 pages context"]
    COMP --> GRD["VERIFY grounding:\nquotes valid? citations resolve?"]
    GRD --> EV{"eval: needs_more\nand hops left?"}
    EV -- yes --> RES2["hop: research missing_topics\n(40% page budget)"]
    RES2 --> COMP
    EV -- no --> CR["CRITIQUE pass\n(adversarial claims review)"]
    CR --> DIA["diagram: mermaid\n(validated, else dropped)"]
    DIA --> SAVE{"root + auto-save on?"}
    SAVE -- yes --> G["save to graph:\nconcepts + relations\n(tagged explanation:)"]
    SAVE -- no --> CORP
    G --> CORP["save fetched pages\nto corpus cache"]
    CORP --> W{"watch re-answer?"}
    W -- yes --> DR["drift verdict vs original"]
    W -- no --> DONE
    DR --> DONE(["status=done\nanswer + trace + quiz-able"])
```

## Inputs

| Dimension | Values | Effect (`DEPTH_PLAN`) |
|---|---|---|
| `mode` | `explain`, `deep_dive`, `compare`, `tutor`, `critique`, `tldr`, `glossary`, `api_ref` | section rules + tone |
| `depth` | `shallow` (3 pp / 3 § / 2k tok), `balanced` (6 / 5 / 4k), `deep` (8 / 7 / 6k + section plan) | research budget |
| `audience` | `beginner`, `intermediate`, `advanced` | jargon/analogy policy |
| `max_hops` | 0 (default; 1 when `depth=deep`) | research–compose loops |

## Grounding & trust

- **Quote validation** (`_quote_valid`): every quoted claim must appear in a
  cited page; violations are recorded in `answer.grounding` and the trace.
- **Source affinity** (`_source_affinity`): thumbs up/down feedback on claims
  (`POST /explanations/{id}/feedback`) re-ranks domains for future research.
- **Corpus memory** (`CorpusPage`, unique per investigation+URL): every fetched
  page is cached with text/images/date, so repeat questions cost no fetches.
- **Provenance trace** (`Explanation.trace` JSON): queries, hits, fetched pages
  with keep/drop, timings, coverage/gaps, hops, critique count, diagram type.

## Threads, quiz, roadmap, watch

```mermaid
flowchart LR
    ROOT["root explanation\n(parent_id = null)"] --> F1["follow-up\n(scope: whole/section/claim)"]
    ROOT --> F2["follow-up …"]
    F1 --> F1a["…"]
    ROOT -.-> W["watch: scheduler re-answers daily\n→ drift verdict stored in meta"]
    ROOT --> QUIZ["quiz: SRS flashcards\ngenerated from answer"]
    ALL["all explanations"] --> ROAD["roadmap: open gaps aggregated"]
```

- Follow-ups reuse the parent's excerpt as a synthetic cited source
  (`explanation://{id}`); `thread_id` groups the conversation.
- `POST …/investigate_gaps` launches the collection agent on the open gaps
  (`launch_run_with_goal`, trigger `explainer_gap`) — the loop closes itself.
- Watched roots are re-answered daily by the scheduler; the new child carries
  `meta.watch_of` and a `drift` verdict vs. the original.

## Suggestions, gaps, investigation summary

- `GET …/explanations/{id}/suggestions` ("Next questions"): trace items and
  graph artifacts ranked by overlap against the question+answer intent, most
  plausible first. Trace items clear a low bar (0.2); graph artifacts need
  0.45 plus corpus-distinctive mass (half their matched terms rare in the
  investigation), near-dupes collapse, and thin strips refill from the
  answer's own section headings. Never invented.
- `GET …/investigations/{id}/research-gaps`: open questions ranked by
  supporting-artifact coverage (novel first) plus tag-novel areas;
  `POST …/research-gaps/run` launches a paper-first goal run on the
  least-covered ones.
- `GET …/investigations/{id}/summary`: executive summary (model prose with
  a 45s bound, deterministic factual brief on failure), top artifacts by
  relevance, top threats and recent explanations, novel areas. Shown in the
  brief panel's Executive summary overlay.

## Answer JSON (stored in `Explanation.answer`)

```json
{
  "summary": "…",
  "sections": [{"heading": "…", "body_md": "…", "claims": [
    {"text": "…", "sources": [{"url": "…", "quote": "…"}]}]}],
  "key_points": ["…"],
  "sources": [{"url": "…", "title": "…", "published": "…"}],
  "diagram": {"mermaid": "flowchart …", "diagram_type": "…"},
  "critique": ["…"],
  "grounding": {"…": "…"},
  "quiz": null,
  "as_of": "2026-…"
}
```
