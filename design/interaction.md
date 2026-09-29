# 04 — Interaction (UML sequence)

What calls what, in what order, on every flow a person can trigger. Each
diagram is one flow; the participant list is the set of processes that can
change state or leave a record.

Related: [activity.md](activity.md) (the decisions inside) · [state.md](state.md)
(the life of each object) · [../docs/agent-loop.md](../docs/agent-loop.md)

## Every request: the wrapper that never fails closed

This runs in front of *every* product request, so it is the first thing to
understand about the whole system.

```mermaid
sequenceDiagram
    actor U as Browser
    participant API as FastAPI
    participant SESS as open_session dependency
    participant OBS as obs.py
    participant L as ledger.py
    participant H as handler
    U->>API: GET /api/… + X-AKM-Session, X-AKM-Actor
    API->>SESS: run the dependency
    SESS->>OBS: trace = X-AKM-Trace-Id or new_trace(session_key)
    OBS-->>SESS: bound in a contextvar
    alt session key present
        SESS->>L: resolve_session(client_key)
        L-->>SESS: ses-… (or a new row)
    else anonymous
        SESS-->>SESS: no session, request proceeds
    end
    SESS->>H: yield the session id
    H-->>U: 200
    Note over SESS,L: if the ledger is down, the request proceeds unaudited —<br/>an audit outage never becomes a product 500

```

## Collection run (manual, scheduled, or gap-driven)

```mermaid
sequenceDiagram
    actor R as Researcher
    participant UI as GUI
    participant API as main.py
    participant Q as job queue / thread
    participant AGT as agent.py
    participant Y as yield_.py
    participant SRCH as search.py
    participant LLM as llm.py
    participant L as ledger.py
    participant DB as SQLite
    R->>UI: Run agent
    UI->>API: POST /investigations/{id}/run {max_items, max_rounds}
    API->>DB: any run status=running for this investigation?
    alt busy
        API-->>UI: 429
    else free
        API->>DB: AgentRun(status=running, trigger=manual|schedule|explainer_gap)
        API->>L: run.start (mandate hashed at creation)
        API->>Q: launch_run → thread with its own SessionLocal
        API-->>UI: {status: started, run_id}
        loop poll every 2 s
            UI->>API: GET /runs/{id}/events?after_id=
            API-->>UI: new AgentEvents (plan/search/analyze/map/summary)
        end
        Q->>Y: rank_queries(planned shapes, observed yield)
        Y-->>Q: known-good shapes first, dead shapes last
        Q->>LLM: plan ≤6 queries × sources
        LLM-->>Q: JSON plan
        Q->>SRCH: fan-out (ThreadPool ≤8): rss | arxiv | web
        SRCH-->>Q: candidates, deduped by url + title
        opt more than 3× max_items
            Q->>Q: cheap keyword pre-rank<br/>(title×2 + desc×1)
        end
        loop batches of 5
            Q->>LLM: analyze(relevance, keep, tags, sentiment, projection, relates_to)
            LLM-->>Q: verdicts
            Q->>L: llm.call (prompt_hash only)
        end
        Q->>DB: keep top artifacts (review=pending, origin=agent) + edges
        Q->>DB: query_shape_yields += found/kept/llm_calls
        Q->>L: agent.step, run.end, stats
        Q->>DB: run.status=done, investigation.status=ready
        UI->>API: GET /investigations/{id}/graph
        API-->>UI: nodes + edges → vis-network
        opt CVE sweep
            Q->>DB: collect CVEs mentioned by this run's artifacts (idempotent)
        end
    end

```

## Explainer: a question becomes a grounded, illustrated answer

```mermaid
sequenceDiagram
    actor R as Researcher
    participant UI as GUI
    participant API as main.py
    participant EX as explainer.py
    participant GRD as grounding.py
    participant WG as writeguard.py
    participant SRCH as search.py
    participant LLM as llm.py
    participant DB as SQLite
    R->>UI: Ask (question, mode, depth, audience)
    UI->>API: POST /investigations/{id}/explain
    API->>DB: Explanation(status=running, meta.phase=researching)
    API->>EX: launch_explanation → thread
    API-->>UI: {id}
    loop poll while status=running
        UI->>API: GET /explanations/{id}
        API-->>UI: status + meta.phase
    end
    EX->>DB: graph artifacts (Jaccard-ranked) + corpus cache hits
    alt the graph already answers it
        EX->>EX: coverage full<br/>→ web_skipped = true
    else partial or missing
        EX->>SRCH: search + fetch ≤ max_pages
        EX->>DB: CorpusPage rows (unique per investigation+url)
    end
    EX->>LLM: compose (mode/depth/audience rules, section plan)
    LLM-->>EX: sections + claims + citations
    EX->>WG: audit_answer(question, answer, pages, brief, section_plan)
    WG->>WG: audit → repair (≤2)<br/>→ strip → drift gate
    WG-->>EX: report — answer["sections"] may shrink, never grow
    EX->>GRD: verify_grounding(claims, sources)
    GRD-->>EX: surviving citations + grounding_violations count
    alt needs_more and hops left
        EX->>SRCH: hop research (40% page budget)
        EX->>LLM: recompose
    end
    EX->>LLM: critique pass (adversarial claim review)
    LLM-->>EX: SUPPORTED / UNCERTAIN verdicts
    EX->>EX: diagram: mermaid,<br/>validated or dropped
    opt root + auto_save_explanations
        EX->>DB: save concepts + relationships to the graph
    end
    EX->>DB: answer, trace, quiz, status=done
    UI->>API: GET /explanations/{id}/suggestions
    API-->>UI: next questions, ranked against the question+answer intent

```

## Security assessment: A2A workflow plus an approval gate

```mermaid
sequenceDiagram
    actor R as Researcher
    participant UI as Security tab
    participant API as main.py
    participant SA as security_agent.py
    participant JQ as jobqueue.py
    participant AP as approvals.py
    participant ORC as orchestrator
    participant CA as control-analyst
    participant COL as research-collector
    participant INT as threat-intel
    participant WRI as report-writer
    participant SEC as security.py
    participant OS as openshell.py
    participant L as ledger.py
    participant DB as SQLite
    R->>UI: product + exposure + workflow (+ require approval)
    UI->>API: POST /investigations/{id}/security/assess
    API->>DB: SecurityAssessment shell + AgentRun(trigger=security)
    API->>JQ: enqueue(kind=security, key=sec:{run_id})
    JQ-->>API: existing job if the key is live (idempotent double-submit)
    API-->>UI: {run_id}
    JQ->>JQ: claim(kind, lease) → running + lease_expires_at
    alt require_approval
        JQ->>AP: same_actor(approver, requester)?
        AP-->>JQ: 403 if identical, empty identity fails closed
        JQ->>L: approval.request (hold verdict)
        JQ->>DB: run parked awaiting_approval
        R->>UI: POST /api/security/runs/{run_id}/approval {approved_by, approved_control_plan}
        API->>AP: requester ≠ approver, both recorded
        API->>L: approval decision lands on the chain
        API->>JQ: re-queue the same job under the same key
    end
    JQ->>SA: run_security_assessment(run_id, params)
    SA->>L: run.start (mandate hashed)
    SA->>ORC: plan_assessment (a2a/1.0 envelope)
    ORC->>CA: analyse_controls + judge_applicability
    CA-->>ORC: control plan + applicability 0..1 per threat
    ORC->>COL: collect_research
    loop per doc URL
        COL->>OS: fetch_url (sandboxed when the broker answers)
        OS-->>COL: page + sandbox: true/false
    end
    COL->>DB: multi-query search over the investigation's own graph
    COL-->>ORC: ranked evidence, each with matched_on + claim_hash
    ORC->>INT: map_attacks
    INT-->>ORC: KE-01…KE-08 × T01…T12, plus local refs
    ORC->>WRI: write_section
    WRI->>LLM as llm: grounded executive paragraph (deterministic fallback)
    WRI->>WRI: post-hoc verbatim check on the paragraph it just wrote
    WRI-->>ORC: §6 markdown + exec bullets
    ORC->>SEC: score_assessment(threats, controls, exposure, applicability)
    SEC-->>ORC: inherent, residual, posture, distribution (pure function)
    ORC->>SEC: build_report + diagrams
    SA->>DB: SecurityAssessment row (markdown, JSON blobs, pack fingerprint)
    SA->>L: run.end + stats.assessment_id
    SA->>JQ: complete(job)
    UI->>API: GET /security/assessments/{id}
    API-->>UI: report + diagrams + A2A trail + 9 sub-tabs

```

## Agentic Manager: one command, N investigations, one summary

```mermaid
sequenceDiagram
    actor R as Researcher
    participant UI as Manager tab
    participant API as main.py
    participant MGR as manager.py
    participant LLM as llm.py
    participant AG as collection agent
    participant SA as security agent
    participant DB as SQLite
    R->>UI: "run security investigations on AI agents in finance, especially payments / DeFi / crypto"
    UI->>API: POST /api/manager/parse {command}
    API->>MGR: parse_command
    MGR->>LLM: split into {domain, exposure, topics[], summary}
    alt model unavailable or plan invalid
        MGR->>MGR: deterministic splitter<br/>(slashes, semicolons, lines,<br/>"especially X")
    end
    MGR-->>UI: plan + which path served it (no side effects)
    R->>UI: uncheck a topic, set per-topic exposure, adjust launchers
    UI->>API: POST /api/manager/run {plan, options}
    API->>MGR: start_run
    MGR->>DB: N investigations (≤6 topics, duplicates dropped) + summary shell
    MGR->>DB: ManagerRun(command, plan_json, status=running)
    loop per topic
        MGR->>AG: launch_run(inv) with focus terms
        MGR->>SA: launch_security_assessment(inv) with the same focus
    end
    MGR-->>UI: {run_id, children}
    loop poll while anything runs
        UI->>API: GET /api/manager/runs
        API-->>UI: statuses derived live from the agent/security tables
    end
    R->>UI: Compile summary
    UI->>API: POST /api/manager/runs/{id}/compile
    alt a child is still running
        API-->>UI: 409
    else all children terminal
        API->>MGR: LLM synthesis of the finished assessments (truncated briefs)
        MGR->>DB: manager-synthesis artifact on the summary investigation
        MGR->>DB: ManagerRun.status=compiled, synthesis_artifact_id
        API-->>UI: 200 (idempotent on repeat)
    end
    UI->>API: GET /api/manager/runs/{id}/timeline
    API-->>UI: 6-step strip + per-lane actions, ≤50 per lane
    UI->>API: GET /api/manager/links
    API-->>UI: topics nested under their summary in the mapper sidebar

```

## The job queue: row before thread, lease before retry

```mermaid
sequenceDiagram
    participant API as main.py
    participant JQ as jobqueue.py
    participant DB as SQLite
    participant W as worker thread
    API->>JQ: enqueue(kind, payload, key)
    JQ->>DB: INSERT jobs(status=pending) — the row exists before any thread
    alt key already live
        JQ-->>API: JobExists → re-attach to the existing job
    end
    loop every 1 s
        JQ->>DB: claim(kinds, lease) WHERE status IN (pending, retry) AND next_attempt_at ≤ now
        DB-->>JQ: job + lease_expires_at
    end
    W->>DB: heartbeat(job, lease) while working
    alt success
        W->>JQ: complete(job)
        JQ->>DB: status=done, finished_at
    else transient failure
        W->>JQ: fail(job, error, retry=true)
        JQ->>DB: status=retry, next_attempt_at += backoff
        Note over JQ: until attempts == max_attempts<br/>JQ->>DB: status=failed for a human
    end
    Note over W,DB: on boot, recover_orphans() re-queues only jobs whose<br/>lease has expired — a slow job is never duplicated

```

## Audit: verify a chain, a proof, and a claim

```mermaid
sequenceDiagram
    actor A as Auditor / Researcher
    participant UI as Audit ledger tab
    participant API as ledger_api.py
    participant L as ledger.py
    participant DB as SQLite
    A->>UI: pick a run
    UI->>API: GET /ledger/runs/{id}/timeline?limit=2000
    API->>DB: events (newest first, every actor)
    API-->>UI: chain with verdicts
    A->>API: GET /ledger/runs/{id}/verify
    API->>L: verify_chain(run_id)
    L->>DB: recompute sha256 over each canonical core
    L-->>API: {ok: true} or {ok: false, break_at: seq, reason}
    A->>API: GET /ledger/runs/{id}/proofs
    API->>L: verify_proof(each event)
    L-->>API: content hashes over prompt/output digests, claim hashes,<br/>input refs that must still resolve
    A->>API: GET /ledger/runs/{id}/claims
    API->>L: grounding status per claim (verbatim | corroboration | review)
    A->>API: GET /ledger/runs/{id}/contamination/{claim_hash}
    API->>L: contamination(run_id, ref, max_depth=12)
    L-->>API: every event, hop and answer that consumed the claim
    A->>API: GET /ledger/runs/{id}/export
    API-->>A: events + claims + approvals + an offline verification report
    A->>API: POST /ledger/verify-export (with no database attached)
    API-->>A: {verified: true} — the bundle stands on its own

```

## Human actions and sessions

```mermaid
sequenceDiagram
    actor R as Researcher
    participant UI as GUI
    participant API as main.py
    participant L as ledger.py
    participant DB as SQLite
    R->>UI: click (accept artifact, change pref, start assessment)
    UI->>API: request with X-AKM-Session + X-AKM-Actor
    API->>L: record_human(actor, action, detail)
    alt a run is open
        L->>DB: human event on that run's chain
    else only a session is open
        L->>DB: session action on the sitting's own run
    else nothing open
        L->>L: dropped rather than guessed at
    end
    Note over L: identity comes from the header, else the session key —<br/>a shared "user" default could not tell two people apart<br/>R->>UI: Timeline (ledger-wide)<br/>UI->>API: GET /ledger/timeline<br/>API-->>UI: every chain interleaved into one newest-first stream<br/>R->>UI: open a session<br/>UI->>API: GET /ledger/sessions/{id}/insights<br/>API-->>UI: violations, token use, activity, per-run health, failed runs

```

## Standards coverage, and the OpenShell-sandboxed fetch

```mermaid
sequenceDiagram
    participant UI as Security tab
    participant API as standards_matrix.py
    participant SD as standards dashboard :5173
    participant OS as openshell.py
    participant BR as fox-services broker
    participant W as target page
    UI->>API: GET /api/standards/score-matrix?assessment_id=
    API->>API: is a cached copy still fresh?<br/>(STANDARDS_CACHE_TTL_S)
    alt stale
        API->>SD: GET data.json over the compose network
        SD-->>API: 34 frameworks × 10 pillars
    end
    API->>API: relevance = token overlap<br/>of the assessment's threats, controls,<br/>cited standards and exploit classes<br/>against each framework
    API-->>UI: ranked rows + matched tokens (no-store: it is per assessment)
    Note over API,SD: 404 unknown assessment · 503 unreachable dashboard, with the reason<br/>UI->>OS: fetch_url(url)<br/>OS->>BR: POST /api/openshell/exec (curl inside the managed sandbox)
    alt broker answers
        BR-->>OS: stdout + sandbox: true
        OS-->>UI: page, recorded as sandboxed
    else broker or gateway down
        OS->>W: direct fetch
        W-->>OS: page
        OS-->>UI: page, recorded as sandbox: false
    end
    Note over UI: the report states the protection instead of assuming it

```

## CVE collection

```mermaid
sequenceDiagram
    participant A as agent.py end-of-run, or the GUI button
    participant API as main.py
    participant CVE as cve.py
    participant DB as SQLite
    participant NVD as NVD
    participant CIRCL as CIRCL
    A->>CVE: collect(investigation_id, texts from artifacts + reports)
    loop every CVE-YYYY-NNNNN found
        CVE->>DB: cve_findings row (status=unknown, severity=unknown)
        alt row already exists
            CVE->>CVE: skip — both paths are idempotent
        else new
            CVE->>NVD: enrich
            alt NVD answers
                NVD-->>CVE: published, cvss, severity, status
            else NVD fails
                CVE->>CIRCL: fallback
                CIRCL-->>CVE: partial metadata
            else both fail
                CVE-->>CVE: keep the honest "unknown" record
            end
            CVE->>DB: update the row
            CVE->>DB: lightweight Artifact(type=cve) as a graph node + edge to the mentioning artifact
        end
    end
    API-->>A: {collected: [...], skipped: n}

```

## Watch, drift, and the self-closing loop

```mermaid
sequenceDiagram
    participant S as scheduler (10-min tick)
    participant EX as explainer.py
    participant DR as drift.py
    participant AG as agent.py
    participant DB as SQLite
    S->>DB: watched, done, no running explanation, not re-answered today?
    alt yes
        S->>EX: launch_explanation(clone of the question, meta.watch_of=id)
        EX-->>DB: new explanation + drift verdict vs the original
    end
    S->>DB: due investigations, not busy
    S->>AG: launch_run(trigger=schedule)
    Note over S: missed windows are skipped, never backfilled<br/>R->>DR as user: POST /investigations/{id}/detect-drift<br/>DR->>DR: deterministic prefilter (title + tags + description tokens)<br/>DR->>DR: LLM judge over candidates only<br/>DR-->>R: flagged artifacts (kept, dimmed, never deleted)<br/>R->>EX as user: POST /explanations/{id}/investigate_gaps<br/>EX->>DB: the least-covered open questions<br/>EX->>AG: launch_run_with_goal(goal, trigger=explainer_gap)<br/>Note over EX,AG: the loop closes itself — the answer finds its own research

```

## Failure-path interaction: the LLM is an unreliable dependency

```mermaid
sequenceDiagram
    participant C as llm.chat()
    participant P as primary base
    participant F as fallback base
    participant H as host swaps
    participant Caller as the agent that asked
    C->>P: POST /chat/completions
    alt ok
        P-->>C: content + x-served-model, x-fox-proof
    else error
        C->>F: retry with the fallback model name
        alt ok
            F-->>C: content
        else error
            C->>H: last-resort localhost / host swaps
            H-->>C: content or raise
        end
    end
    alt every path failed
        H-->>Caller: LLMError
        Caller->>Caller: deterministic fallback<br/>(keyword pre-rank ·<br/>template prose · split topics)
    end
    Note over C,Caller: the audit record names the model that ACTUALLY served the call,<br/>plus tokens, latency and the gateway proof id

```

## Related

- Decisions inside the agents: [activity.md](activity.md)
- Run / job / approval lifecycles: [state.md](state.md)
- What each hop records, and what it must not: [privacy.md](privacy.md)
