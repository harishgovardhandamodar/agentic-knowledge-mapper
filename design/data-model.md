# 03 — Data model

Every table, how they relate, and what is stored where. All 17 tables live in
one SQLite file (`data/akm.db`, WAL mode; the `akm_data` Docker volume in the
container) and are created by `create_all()`, upgraded additively by
`ensure_columns()`.

Related: [../docs/data-model.md](../docs/data-model.md) · [uml.md](02-uml.md) ·
[privacy.md](privacy.md)

## The scoping rule

Everything is scoped by `investigation_id`, and deleting an investigation
cascades to everything it produced. That is the single most important
structural fact in the schema: it is what makes a privacy promise like "this
graph only ever contained what you collected for that brief" checkable rather
than aspirational.

```mermaid
erDiagram
    INVESTIGATION ||--o{ ARTIFACT : "scopes, cascades"
    INVESTIGATION ||--o{ RELATIONSHIP : "scopes, cascades"
    INVESTIGATION ||--o{ AGENT_RUN : "scopes, cascades"
    INVESTIGATION ||--o{ EXPLANATION : "scopes, cascades"
    INVESTIGATION ||--o{ CORPUS_PAGE : "scopes, cascades"
    INVESTIGATION ||--o{ SECURITY_ASSESSMENT : "scopes, cascades"
    INVESTIGATION ||--o{ CVE_FINDING : "scopes, cascades"
    INVESTIGATION ||--o{ QUERY_SHAPE_YIELD : "scopes, cascades"
    INVESTIGATION ||--o{ MANAGER_RUN : "summary target"
    AGENT_RUN ||--o{ AGENT_EVENT : "logs, cascades"
    AGENT_RUN ||--o{ ARTIFACT : "collected_by"
    AGENT_RUN ||--o{ RELATIONSHIP : "mapped_by"
    AGENT_RUN ||--o{ SECURITY_ASSESSMENT : "produced_by"
    AGENT_RUN ||--o{ JOB : "does"
    ARTIFACT ||--o{ RELATIONSHIP : "source_id, cascades"
    ARTIFACT ||--o{ RELATIONSHIP : "target_id, cascades"
    ARTIFACT ||--o| CVE_FINDING : "graph node for"
    EXPLANATION ||--o{ EXPLANATION : "parent/thread"
    INVESTIGATION {
        int id PK
        string title
        string keywords
        text description
        string sources
        string status "draft|running|ready"
        int hidden "0|1 — out of the list, not deleted"
        int schedule_enabled
        string schedule_cron
        int schedule_max_items
        int schedule_rounds
        datetime next_run_at
        string preferred_domains
        int auto_save_explanations
    }
    ARTIFACT {
        int id PK
        int investigation_id FK
        string title
        string artifact_type "news|paper|essay|research|tweet|interview|book|projection|cve"
        string url
        text description
        text content
        float relevance "0..1 agent score"
        string relevance_reason
        string review "pending|accepted|rejected"
        int drift "0|1 off-brief, kept but flagged"
        string origin "agent|manual"
        int run_id FK "null for manual"
    }
    RELATIONSHIP {
        int id PK
        int investigation_id FK
        int source_id FK
        int target_id FK
        string relationship_type "references|supports|contradicts|builds_upon|responds_to|similar_to"
        string origin "agent|manual"
        int run_id FK
    }
    CVE_FINDING {
        int id PK
        int investigation_id FK
        string cve_id "unique per investigation"
        string status "vendor standing, or unknown — never a guess"
        string severity "critical|high|medium|low|unknown"
        float cvss
        text impact "CIA triad when known"
        int artifact_id FK "the graph node"
    }
    AGENT_RUN {
        int id PK
        int investigation_id FK
        string status "running|done|error"
        string trigger "manual|schedule|explainer_gap|security"
        text plan "JSON"
        text stats "JSON"
        text error
        datetime started_at
        datetime finished_at
    }
    AGENT_EVENT {
        int id PK
        int run_id FK
        string stage "plan|search|analyze|map|summary"
        text message
        text data "JSON"
    }
    EXPLANATION {
        int id PK
        int investigation_id FK
        string question
        text answer "JSON: summary, sections, claims, sources, diagram, critique, grounding, write_audit"
        string status "running|done|error"
        text trace "JSON provenance"
        string mode
        string depth
        string audience
        int max_pages
        int hops
        text meta "JSON: phase, feedback, watch_of, drift"
        int parent_id FK "null for a root"
        int thread_id
        text quiz "JSON"
        int bookmarked
        int watched
    }
    CORPUS_PAGE {
        int id PK
        int investigation_id FK
        string url "unique per investigation"
        text text
        text images "JSON"
    }
    SECURITY_ASSESSMENT {
        int id PK
        int investigation_id FK
        int run_id FK
        string product_name
        string exposure
        text controls_json "JSON: active controls, control plan, OpenShell posture"
        float overall_pct
        float inherent_pct
        float residual_pct
        text markdown
        text diagrams_json
        text threats_json
        text evidence_json
        text a2a_trace_json
        string threat_pack_version
        string threat_pack_fingerprint
    }
    MANAGER_RUN {
        int id PK
        text command
        text plan_json "JSON: domain, exposure, topics, summary"
        string status "running|compiled"
        int summary_investigation_id FK
    }
    QUERY_SHAPE_YIELD {
        int id PK
        int investigation_id FK
        string shape "unique per investigation"
        string example
        int attempts
        int found
        int kept
        int llm_calls
    }
    JOB {
        int id PK
        string key "unique among live jobs only"
        string kind
        text payload_json
        string status "pending|retry|running|done|failed"
        int attempts
        int max_attempts
        text last_error
        int run_id FK
        datetime next_attempt_at
        datetime lease_expires_at "recovery is lease-based, so slow work is not duplicated"
    }

```

## The audit ledger — a second, separate graph

The ledger is deliberately *not* part of the investigation cascade. An audit
record outlives the thing it records, which is the entire point: a deleted
investigation must not delete the evidence that it was worked on.

```mermaid
erDiagram
    LEDGER_RUN ||--o{ LEDGER_EVENT : "chains, cascades"
    LEDGER_RUN ||--o{ LEDGER_CLAIM : "asserts, cascades"
    LEDGER_RUN ||--o{ LEDGER_APPROVAL : "gates, cascades"
    LEDGER_RUN ||--o| LEDGER_RUN : "session spine anchors"
    LEDGER_RUN {
        string id PK "caller-supplied, not autoincrement"
        string label
        string kind "task|session"
        string session_id FK "owning sitting"
        string client_key "browser's stable key"
        datetime last_seen_at
        string status "open|closed|aborted"
        text mandate_json "JSON policy in force"
        string mandate_hash "hashed at run creation"
        string genesis_hash
        string head_hash "cheap anchoring"
        int head_seq
    }
    LEDGER_EVENT {
        int id PK
        string run_id FK
        int seq "0-based, unique per run"
        string ts "ISO-8601 string — offset preserved, lexicographic = chronological"
        string actor_type "agent|llm|mcp|a2a|human|system"
        string actor
        string kind "llm.call|mcp.call|agent.hop|gate.check|run.start|…"
        string intent
        string verdict "pass|allow|warn|flag|hold|deny|block"
        string severity "info|warn|block"
        text data_json "canonical core — hashed"
        text input_refs "JSON list of sha256 — lineage edges"
        string prev_hash
        string hash "covers the core above"
        text proof_json "derived — NOT hashed, recomputed on verify"
        string trace "trace id — NOT hashed, an observation not a claim"
    }
    LEDGER_CLAIM {
        int id PK
        string run_id FK
        string claim_hash "sha256 of text + citations"
        int seq "emitting event"
        string actor
        text text
        text citations_json
        int n_sources
        string confidence "high|medium|low|none"
        string verdict "supported|unsupported|uncertain|unverified"
        string verifier "verbatim|corroboration|reviewer|human"
    }
    LEDGER_APPROVAL {
        int id PK
        string run_id FK
        int seq "approval.request event"
        string kind
        string subject_hash "the claim or event being approved"
        string requested_by
        string decision "grant|deny, null while pending"
        string decided_by "never the requester"
        datetime decided_at
        string event_hash "the decision is itself a chained event"
    }
    LEDGER_AUDIT_DROP {
        int id PK
        datetime ts
        string run_id "nullable — the chain write itself failed"
        string recorder "which helper failed"
        string actor
        text error
        text detail_json "redacted"
    }

```

Three deliberate design decisions are visible in that schema and are worth
stating, because each one looks like a mistake until you know why:

1. **`proof_json` and `trace` are outside the hashed core.** `proof_json` is
   derived state — verification recomputes it and reports drift rather than
   trusting the stored copy. `trace` says *when* and *under which request* a
   record was written, not what the record claims. Folding either into
   `data_json` would change every event hash and break verification of every
   run already on disk.
2. **`ts` is a string, not a datetime.** Audit needs the exact authored
   timestamp with its offset preserved, and lexicographic order must equal
   chronological order.
3. **`ledger_audit_drops` is not in the chain.** A row usually exists *because*
   the chain write failed. It is where an operator looks to answer "did we lose
   anything?" — `GET /api/ledger/audit-drops`.

## What is stored where — the data inventory

```mermaid
flowchart LR
    subgraph DISC["On-disk, git-ignored"]
        DB[("data/akm.db<br/>17 tables · WAL")]
        PDF["security PDF<br/>rendered on demand, not stored"]
    end
    subgraph HASH["Hashed, not stored"]
        PH["llm.call prompt_hash<br/>= sha256(prompt)"]
        CH["claim_hash<br/>= sha256(text + citations)"]
        EH["event hash chain<br/>prev_hash + core"]
        GH["gateway proof<br/>x-fox-proof / x-fox-request-id"]
    end
    subgraph PLAIN["Stored verbatim"]
        AR["artifact content, titles, urls, tags"]
        EX["explanation answer, trace, sections"]
        MA["assessment markdown + JSON blobs"]
        MC["corpus page text and images"]
    end
    DB --> HASH
    DB --> PLAIN
    DB -.->|"rebuildable"| PDF
    MA -->|"markdown →"| PDF

```

| Data | Stored as | Retention / control |
|---|---|---|
| Prompts sent to a model | `sha256` + `prompt_chars` in `llm.call.data_json` | `LEDGER_CAPTURE_PAYLOADS=1` stores them verbatim; off by default |
| Model completions | verbatim in `llm.call.data_json` | evidence that cannot be re-derived, so it is kept; credentials inside are redacted first |
| Credentials anywhere in a payload | `[redacted]` before storage | `ledger._redact` runs on the way in; numbers survive, because redacting a token count would destroy evidence while protecting nothing |
| Collected article text | `artifacts.content`, `corpus_pages.text` | the substance of the investigation; git-ignored, cascade-deleted with the investigation |
| Security report | `security_assessments.markdown` + JSON | no report files written to disk; PDF is rendered per request |
| Ledger events | full canonical core + hashes | append-only by convention; `verify_chain` detects tampering after the fact |
| Gateway proofs | request id, proof hash, token counts, served model | digests and metadata cross the service boundary; prompt/completion never do |

## Uniqueness and idempotency constraints

```mermaid
flowchart TB
    C1["uq_cve_finding<br/>investigation_id + cve_id<br/>re-collecting adds nothing new"]
    C2["uq_corpus_inv_url<br/>investigation_id + url<br/>a repeat question costs no fetch"]
    C3["uq_query_shape_yield<br/>investigation_id + shape<br/>yield is cumulative, one row per shape"]
    C4["uq_ledger_event_seq<br/>run_id + seq<br/>a chain has no gaps or duplicates"]
    C5["uq_jobs_live_key<br/>key, unique WHERE status IN pending/retry/running<br/>double-submit re-attaches; a parked job can be re-queued later"]
    C1 --> DB[("all enforced by SQLite")]
    C2 --> DB
    C3 --> DB
    C4 --> DB
    C5 --> DB

```

`uq_jobs_live_key` deserves a note: uniqueness is over *live* jobs, not over
the key itself. A key names a unit of work, and the same key legitimately
comes back later — a run parked at an approval gate is re-queued under its
original key once approved. A plain `UNIQUE(key)` would refuse that second
enqueue forever.

## Migrations

```mermaid
flowchart LR
    BOOT["app boots"] --> CA["create_all()<br/>creates any missing table"]
    CA --> EC["ensure_columns()<br/>per-column _MIGRATIONS list"]
    EC --> ADD["additive ALTER TABLE … ADD COLUMN<br/>existing akm.db upgrades in place"]
    ADD --> OK["no destructive step: nothing is ever dropped"]

```

`_MIGRATIONS` in `app/database.py` holds one `ALTER TABLE … ADD COLUMN` per
missing column. There is no destructive step, so a rebuild of the container
never loses the `akm_data` volume's contents.

## Related

- Field-by-field tables: [../docs/data-model.md](../docs/data-model.md)
- Who may see what: [privacy.md](privacy.md)
