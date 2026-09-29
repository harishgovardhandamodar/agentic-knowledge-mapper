# 05 — Activity (UML activity)

The decisions an agent makes while it works: what it tries, what it gives up
on, and what it falls back to. These are the flows where the interesting
behaviour lives, because every one of them has a branch for "the model said no
useful thing" and a branch for "the model is not there".

Related: [interaction.md](interaction.md) (call order) · [state.md](state.md)
(object lifetimes) · [../docs/agent-loop.md](../docs/agent-loop.md)

## Collection: plan → search → analyze → map → refine

```mermaid
flowchart TB
    S(["launch_run(inv, max_items, max_rounds)"]) --> R["AgentRun(status=running)<br/>inv.status=running<br/>run.start on the chain"]
    R --> Y["rank planned query shapes by<br/>observed yield (cumulative)"]
    Y --> P["PLAN: llm.chat_json<br/>≤6 queries × sources<br/>(rss / arxiv / web ∩ enabled)"]
    P --> PFALL{"planner LLM failed?"}
    PFALL -- yes --> PD["deterministic plan:<br/>keywords + title, ≤3 queries"]
    PFALL -- no --> SEEN
    PD --> SEEN["seen = existing urls + titles<br/>(dedupe across runs)"]
    SEEN --> LOOP{"round ≤ max_rounds<br/>and kept < max_items?"}
    LOOP -- no --> DONE
    LOOP -- yes --> F["SEARCH: ThreadPool fan-out<br/>(min(8, queries × sources))"]
    F --> FALL{"providers unavailable?"}
    FALL -- yes --> FEMPTY["fewer candidates —<br/>never a run failure"]
    FALL -- no --> PRE
    FEMPTY --> PRE
    PRE{"found > 3 × max_items?"}
    PRE -- yes --> PR["cheap keyword pre-rank<br/>(title×2 + desc×1)"]
    PRE -- no --> AN
    PR --> AN["ANALYZE: batches of 5<br/>relevance 0..1, keep/drop, tags,<br/>sentiment, projection, relates_to[]"]
    AN --> AFALL{"analyze LLM failed?"}
    AFALL -- yes --> ADEF["deterministic verdicts:<br/>relevance from token overlap,<br/>keep at ≥0.4"]
    AFALL -- no --> KEEP
    ADEF --> KEEP{"anything kept?"}
    KEEP -- no --> DONE
    KEEP -- yes --> MAP["MAP: persist artifacts<br/>(origin=agent, review=pending)<br/>+ relationships ≤60<br/>+ tag-overlap fallback edges"]
    MAP --> CVE["collect CVEs mentioned<br/>by this run (idempotent)"]
    CVE --> QY["query_shape_yields +=<br/>found / kept / llm_calls"]
    QY --> CAP{"kept ≥ max_items<br/>or rounds exhausted?"}
    CAP -- yes --> DONE
    CAP -- no --> FUP["planner: ≤3 follow-up queries<br/>aimed at what is missing"]
    FUP --> F2{"any follow-ups?"}
    F2 -- yes --> F
    F2 -- no --> DONE
    DONE(["run.status=done | error<br/>inv.status=ready<br/>run.end + summary event"])

```

## Explainer: can the graph answer it, and does the prose hold up

```mermaid
flowchart TB
    Q(["ask: question + mode/depth/audience"]) --> CTX["collect context<br/>• graph artifacts (Jaccard-ranked)<br/>• corpus cache (CorpusPage rows)<br/>• source affinity from feedback<br/>• preferred domains + expand terms"]
    CTX --> GAP{"gap check:<br/>can the graph answer it?"}
    GAP -- "coverage full" --> GONLY["answer from graph (+corpus)<br/>web_skipped = true"]
    GAP -- "partial / missing" --> RES["RESEARCH: search + fetch ≤ max_pages<br/>corpus-cache first"]
    GONLY --> COMP
    RES --> COMP["COMPOSE: mode/depth/audience rules<br/>+ section plan (deep)"]
    COMP --> WG["write-verify-repair<br/>(writeguard.py)"]
    subgraph GUARD["Guard: can only remove text, never add it"]
        G1["audit every section:<br/>a sentence with a NUMBER, DATE, VERSION,<br/>ID, % or MONEY claim must be<br/>sourced — framing prose always passes"]
        G1 --> G2{"unsupported sentences?"}
        G2 -- yes --> G3["one rewrite per affected section,<br/>then re-audit"]
        G3 --> G4{"rewrite held?"}
        G4 -- no --> G5["strip the offending sentences —<br/>deleting text cannot invent a falsehood"]
        G4 -- yes --> G6["keep the rewrite"]
        G2 -- no --> G6
        G5 --> G7["drift gate: a section sharing no<br/>vocabulary with the brief or its<br/>own planned sub-question is a candidate;<br/>one batched judge confirms"]
    end
    WG --> GUARD
    GUARD --> GRD["grounding: every quote must appear<br/>verbatim (12+ chars) in its cited source<br/>else the citation is dropped and counted"]
    GRD --> EV{"eval says needs_more<br/>and hops left?"}
    EV -- yes --> RES2["hop: research missing_topics<br/>(40% of the page budget)"]
    RES2 --> COMP
    EV -- no --> CR["CRITIQUE: adversarial review of the claims<br/>SUPPORTED / UNCERTAIN"]
    CR --> DIA["diagram: mermaid, validated or dropped<br/>image kept only if it shares vocabulary"]
    DIA --> SAVE{"root + auto_save on?"}
    SAVE -- yes --> G["save to graph:<br/>concepts + relations, tagged"]
    SAVE -- no --> CORP
    G --> CORP["save fetched pages to the corpus cache"]
    CORP --> W{"watched?"}
    W -- yes --> DR["drift verdict vs the original answer"]
    W -- no --> DONE
    DR --> DONE(["status=done<br/>answer + trace + quiz-able"])

```

## The write-verify-repair guard, in full

```mermaid
flowchart TB
    A["composed answer"] --> B["split each section into units:<br/>a list item is ONE unit even when it wraps;<br/>a paragraph splits into sentences"]
    B --> C["for each sentence ≥24 chars"]
    C --> D{"carries a checkable specific?<br/>CVE/GHSA id · date · version · % · money · year · quantity"}
    D -- no --> D1["framing, transition or definition<br/>→ passes untouched"]
    D -- yes --> E{"the value appears verbatim<br/>in a source?"}
    E -- yes --> E1["supported"]
    E -- no --> F{"shares ≥2 content tokens<br/>with some source?"}
    F -- yes --> E1
    F -- no --> G["unsupported: no_evidence_for"]
    G --> H{"repairs enabled<br/>and under the cap?"}
    H -- yes --> I["one rewrite using only sourced facts"]
    I --> J{"re-audit found fewer<br/>unsupported sentences?"}
    J -- yes --> K["keep the rewrite"]
    J -- no --> L["discard it — keep the original wording"]
    H -- no --> M["strip the sentences, rebuild the body<br/>from the surviving units with their original spacing"]
    M --> N["re-audit: unsupported_remaining<br/>should be zero — a non-zero value is<br/>surfaced, not assumed clean"]
    K --> N
    L --> M
    N --> O["drop sections whose body is now empty"]
    O --> P["drift gate, capped at 34% of sections:<br/>if almost everything looks off-brief,<br/>the judge or the question is wrong — keep and report"]

```

## Security assessment: applicability, scoring, and the report

```mermaid
flowchart TB
    S(["product + exposure + focus"]) --> PLAN["control-analyst proposes<br/>a control plan and applicability 0..1 per threat"]
    PLAN --> J{"model reachable?"}
    J -- no --> HEUR["heuristic applicability:<br/>keyword table, finance-domain bridges<br/>(payment, customer, ledger, PCI …)"]
    J -- yes --> LLM["LLM proposes applicability per threat"]
    LLM --> INT["threat-intel re-judges against the<br/>collected evidence, same deterministic heuristic"]
    HEUR --> REJ
    INT --> REJ{"evidence confirms relevance?"}
    REJ -- yes --> UP["lift toward 1.0"]
    REJ -- no --> HOLD["hold the 0.45 floor —<br/>evidence and focus can confirm relevance,<br/>never acquit below what was proposed"]
    UP --> AGG
    HOLD --> AGG{"applicability ≥ 0.3?"}
    AGG -- no --> EXCL["reported, but excluded from the aggregates"]
    AGG -- yes --> W["weight the aggregate by relevance,<br/>renormalized: a uniform map still<br/>scores exactly as unweighted"]
    EXCL --> SCORE
    W --> SCORE["score_assessment()<br/>likelihood × impact per threat,<br/>scaled by exposure tier<br/>worst 0.55 + breadth 0.45, top 5"]
    SCORE --> RES{"residual ≥ 0.35 × inherent?"}
    RES -- yes --> FLOOR["residual floor applies"]
    RES -- no --> NORM
    FLOOR --> NORM["posture string, distribution, perspectives"]
    NORM --> OS["OpenShell: every page records sandbox: true/false;<br/>policy YAML = exactly the hosts fetched;<br/>restricted tiers need human review to widen"]
    OS --> REP["build_report: §§1-12 with mermaid<br/>workflow · dataflow · threat paths · heat map"]
    REP --> EVAL["evalkit gate: does the pack still produce<br/>the pinned aggregates? a moved number fails CI"]

```

## Manager: understand → serve → synthesise

```mermaid
flowchart TB
    C(["command"]) --> P["parse_command"]
    P --> M{"model reachable and plan valid?"}
    M -- yes --> LLM["LLM split: {domain, exposure, topics[], summary}"]
    M -- no --> DET["deterministic splitter:<br/>slashes, semicolons, lines, numbered items;<br/>'especially X' scopes the topics"]
    LLM --> CONF["preview: topics, per-topic launchers, exposure"]
    DET --> CONF
    CONF --> U{"topics unchecked,<br/>exposure set, launchers adjusted"}
    U --> FAN["create ≤6 investigations (duplicates dropped)<br/>+ a summary shell; ManagerRun row"]
    FAN --> LA["per topic: launch_run(focus terms)<br/>+ launch_security_assessment(same focus)"]
    LA --> TRACK["statuses derived live from the<br/>agent/security tables — no watcher,<br/>so a restart strands nothing"]
    TRACK --> C2{"user asks to compile?"}
    C2 -- no --> TRACK
    C2 -- yes --> ALD{"every child terminal?"}
    ALD -- no --> R409["409 — nothing to synthesise yet"]
    ALD -- yes --> SYN["LLM synthesis of the finished assessments<br/>(truncated briefs)"]
    SYN --> ART["manager-synthesis artifact on the summary investigation"]
    ART --> DET2["deterministic tables: top risks,<br/>overlaps, lapses — plus the model prose"]
    DET2 --> NEST["GET /manager/links nests the topics<br/>under the summary in the mapper sidebar"]

```

## Drift: cheap first, expensive second, silent never

```mermaid
flowchart TB
    A["artifact candidates"] --> P1["pass 1 — deterministic prefilter<br/>(shared vocabulary with the brief<br/>or the already-collected corpus)"]
    P1 --> P2["candidates only"]
    P2 --> P3{"pass 2 — LLM judge,<br/>batched, over candidates"}
    P3 -- "off-brief" --> FLAG["flag: kept, dimmed in the graph,<br/>'drift' pill in the review queue — never deleted"]
    P3 -- "on-brief" --> CLEAR["cleared"]
    P3 -- "judge unreachable / bad shape" --> EV["record drift.judge_failed as an event;<br/>fail open, but visibly — a silent empty set<br/>would look identical to 'no drift'"]
    EV --> CLEAR
    FLAG --> USE["the flag survives into the graph,<br/>the collection view and the timeline"]

```

## Recommendations: computed from numbers already paid for

```mermaid
flowchart TB
    A(["GET /investigations/{id}/recommendations"]) --> COV["coverage_gaps:<br/>which dimensions of the brief have nothing at all"]
    A --> LEV["control_leverage:<br/>which single control would most reduce residual<br/>(arithmetic over two calls to a pure function)"]
    A --> STALE["stale_brief:<br/>has the corpus moved on from the brief?"]
    A --> YLD["query yields:<br/>which query shapes keep paying and which have gone dead"]
    COV --> DG["digest: all of the above, ranked"]
    LEV --> DG
    STALE --> DG
    YLD --> DG
    DG --> EV["each item names the evidence it came from,<br/>so 'you have 0 coverage of X' is distinguishable<br/>from something invented"]
    NOTE1["no model call, pull-only, on demand"]

    A ~~~ NOTE1
    classDef note fill:#fbfcfd,stroke:#c8d0da,stroke-dasharray:4 3,font-style:italic,color:#57606a
    class NOTE1 note
```

## Ask: five things the app refuses to do silently

```mermaid
flowchart TB
    subgraph NEVER["Never, by construction"]
        N1["never cite a source the run did not fetch<br/>— grounding drops it and counts it"]
        N2["never store a prompt verbatim unless<br/>LEDGER_CAPTURE_PAYLOADS=1 was set"]
        N3["never let an approval be self-approved<br/>— and never wave it through on a missing identity"]
        N4["never let an audit failure become a product 500<br/>— the drop is recorded, the request continues"]
        N5["never gate a re-queued parked job out by key uniqueness<br/>— uniqueness is over live jobs only"]
    end
    subgraph FALLBACK["When a dependency is missing"]
        F1["model → deterministic plan, verdicts, template prose"]
        F2["broker → direct fetch, recorded as sandbox: false"]
        F3["NVD → CIRCL → honest 'unknown' CVE row"]
        F4["standards dashboard → 503 with the reason"]
        F5["drift judge → flag nothing, but record that it could not run"]
        F6["rewrite that did not help → keep the original wording"]
    end

```

## Related

- [interaction.md](interaction.md) — the same flows as call sequences
- [state.md](state.md) — how runs, jobs and approvals move through states
- [controls.md](controls.md) — the control behind each "never"
