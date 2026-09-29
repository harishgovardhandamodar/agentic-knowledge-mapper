# 08 — Privacy

What data exists, who can see it, where it can go, and what provably cannot
leave. This document is written to be checkable: every claim below names the
code that enforces it, and every gap is labelled as a gap.

Related: [controls.md](controls.md) · [../docs/privacy.md](../docs/privacy.md) ·
[../docs/ledger.md](../docs/ledger.md) · [01-system-context.md](01-system-context.md)

## The five trust boundaries

```mermaid
flowchart TB
    subgraph B0["TB0 · The person"]
        U["Browser<br/>holds the session key, the actor name,<br/>and every credential the app never sees"]
    end
    subgraph B1["TB1 · This app — Mapper, Security, Manager, Standards"]
        direction TB
        API["FastAPI :8204<br/>routes, mandates, redaction"]
        AG["Agents<br/>collect · analyse · compose"]
        subgraph B1a["TB1a · The ledger — append-only, separately governed"]
            L["hash-chained events<br/>claims · approvals · drops"]
        end
    end
    subgraph B2["TB2 · Local model gateway"]
        GW["fox-services :8210<br/>OpenAI-compatible, key-holding<br/>OpenShell broker · request proofs"]
        MESH["Ollama mesh<br/>DGX Spark · RTX 5080"]
    end
    subgraph B3["TB3 · The open internet"]
        WEB["RSS · arXiv · DuckDuckGo<br/>page fetches · NVD / CIRCL"]
    end
    subgraph B4["TB4 · Other local services"]
        STD["Standards dashboard :5173<br/>reads the db, serves a static page"]
    end

    U -->|"HTTPS-less HTTP on loopback,<br/>headers carry identity"| API
    API --> L
    AG --> L
    API -->|"prompt + completion, inside the LAN"| GW
    GW --> MESH
    AG -->|"search terms, page urls"| WEB
    WEB -->|"page text"| AG
    STD -->|"reads the same SQLite file"| API
    NOTE1["The only place anything leaves the machine.<br/>Requests carry queries and URLs, not the corpus and not credentials."]

    B3 ~~~ NOTE1
    classDef note fill:#fbfcfd,stroke:#c8d0da,stroke-dasharray:4 3,font-style:italic,color:#57606a
    class NOTE1 note
```

Four of the five boundaries are crossed by data the person already chose to
send (a question, a keyword, a URL). The fifth — TB1a — is crossed by data the
app generates about itself. That is the boundary that matters most here, and
it is the one the ledger exists to make auditable.

## Data-flow: what crosses each boundary, and in what form

```mermaid
flowchart LR
    Q["Question / brief"] -->|"verbatim, on loopback"| API
    API -->|"search terms"| WEB
    API -->|"prompt text"| GW
    GW -->|"completion text"| API
    WEB -->|"page text"| API
    API -->|"artifacts, corpus, explanation,<br/>assessment markdown"| DB[("akm.db")]
    API -->|"prompt_hash = sha256(prompt)<br/>completion verbatim<br/>tokens, latency, model, proof id"| L[("ledger")]
    API -->|"nothing"| EXT["Third-party LLM API<br/>— no client for one exists in this codebase"]
    DB -.->|"read by the dashboard"| STD["standards dashboard :5173"]
    L -->|"export bundle, verifiable offline"| HUMAN["Auditor downloads it"]

```

The single most important line in that diagram is the last one on the right: a
model request goes to the local gateway and nowhere else. There is no
cloud-provider client in the codebase — the only way an OpenAI-compatible
endpoint is reached is through `fox-services`.

## What is stored, hashed, or never kept

```mermaid
flowchart TB
    subgraph ALLOWED["Stored, deliberately — this is the product's substance"]
        A1["Artifact content, titles, urls, tags, sentiment"]
        A2["Explanation answers, sections, claims, trace"]
        A3["Security report markdown + JSON"]
        A4["Model completions (in the ledger)"]
    end
    subgraph HASHED["Stored as a digest only"]
        H1["Prompts → sha256 + prompt_chars"]
        H2["Claims → sha256(text + citations)"]
        H3["Event chain → prev_hash + hashed core"]
        H4["Gateway proofs → x-fox-proof, x-fox-request-id"]
    end
    subgraph NEVER["Never stored anywhere"]
        N1["Model API keys<br/>(held by the gateway, not the app)"]
        N2["Session cookies in the ledger<br/>(session_id is redacted like any credential)"]
        N3["Credentials inside any payload<br/>(redacted before the write)"]
        N4["Raw prompts,<br/>unless LEDGER_CAPTURE_PAYLOADS=1"]
    end
    ALLOWED --> DB[("akm.db · git-ignored · the akm_data volume")]
    HASHED --> DB
    NEVER -.-> X(["not on disk, not on the chain, not in a log"])

```

The distinction in the top box is the honest one: **completions are kept
because they cannot be re-derived.** A prompt can be regenerated from its
inputs; a completion is the evidence. The design accepts that cost and makes
it visible rather than pretending the ledger is free of content.

## Redaction, exactly

`ledger._redact` runs on the way into immutable storage, on every payload,
recursively through dicts and lists. Its rules are narrow on purpose:

| Rule | Behaviour | Why |
|---|---|---|
| `_SECRET_KEY` | `password`, `secret`, `api_key`/`apikey`, `authorization`, `credential`, `private_key`, `session_id`, `cookie`, `passphrase` → `[redacted]` **whatever the value is** | these names are never metrics |
| `_SECRET_IF_STRING` | `token`, `tokens`, `auth`, `bearer` → `[redacted]` **only when the value is a string, list or dict** | `tokens_in: 812` is a metric; `access_token: "…"` is a secret |
| `_SECRET_VALUE` | `sk-…`, `pk-…`, `ghp-`/`gho-`, `xox[baprs]-`, and any 40+ char opaque base64-ish run | catches credentials in free text and in headers |
| Hex-digest exclusion | a 40+ character `[A-Fa-f0-9]` run is **not** redacted | hashes are evidence — payload hashes, genesis values, claim addresses. Redacting them would gut exactly the records the function exists to preserve |
| Numbers survive | `relevance: 0.87`, `latency_ms: 2410` are never touched | an audit record is full of counts; redacting them would destroy evidence while protecting nothing |

The exclusion is the interesting part. A naive secret scrubber would eat every
hash on the chain and quietly destroy the audit trail it was protecting. This
one knows the difference between a credential and a content address.

## Prompt capture: off by default, and the reason

```mermaid
flowchart LR
    E{"LEDGER_CAPTURE_PAYLOADS"} -->|"unset / 0 / false"| OFF["prompts stored as<br/>sha256 + prompt_chars"]
    E -->|"1 / true / yes"| ON["prompts stored verbatim<br/>(still redacted)"]
    OFF --> V["what it enables:<br/>• prove which prompt produced an output<br/>• reproduce a call exactly<br/>what it costs:<br/>• the ledger is immutable — this is permanent"]
    ON --> V2["what it enables:<br/>• byte-exact reproduction of a run<br/>what it costs:<br/>• every prompt, including anything a user<br/>pasted, becomes permanent"]
    NOTE1["The default is off *because the ledger has no delete.<br/>A convenience flag must not be able to make a permanent record silently."]

    OFF ~~~ NOTE1
    classDef note fill:#fbfcfd,stroke:#c8d0da,stroke-dasharray:4 3,font-style:italic,color:#57606a
    class NOTE1 note
```

## Retention and deletion

```mermaid
flowchart TB
    subgraph CASCADE["Deleted with the investigation (the scoping rule)"]
        C1["artifacts · relationships · agent_runs · agent_events"]
        C2["explanations · corpus_pages · security_assessments"]
        C3["cve_findings · query_shape_yields · manager links"]
    end
    subgraph HIDDEN["Hidden, not deleted"]
        H1["investigation.hidden = 1<br/>removed from the list; still queryable by id"]
    end
    subgraph SURVIVES["Survives deletion — by design"]
        S1["ledger_runs · ledger_events · ledger_claims<br/>ledger_approvals · ledger_audit_drops"]
    end
    DEL(["DELETE /investigations/{id}"]) --> CASCADE
    DEL -.->|"cannot cascade"| SURVIVES
    H1 -.->|"a separate, explicit act"| DEL
    NOTE1["An audit record that were deleted along with the work<br/>it recorded would prove nothing. The trade is deliberate:<br/>the evidence outlives the thing."]

    SURVIVES ~~~ NOTE1
    classDef note fill:#fbfcfd,stroke:#c8d0da,stroke-dasharray:4 3,font-style:italic,color:#57606a
    class NOTE1 note
```

This is the sharpest privacy trade in the system and it deserves to be stated
plainly rather than buried: **deleting an investigation does not delete the
audit trail of that investigation.** The scoping rule gives per-investigation
deletion of collected content; the ledger is deliberately outside that scope.

## The audit-fail-open trade

```mermaid
stateDiagram-v2
    [*] --> recorded
    recorded --> recorded : the event lands on the chain
    recorded --> dropped : the write fails
    dropped --> recorded : an operator investigates and the trail resumes
    note right of dropped<br/>The chain write failing must not become<br/>a product 500. A tool that refuses to<br/>work when its log breaks is a tool<br/>people disable logging on.<br/>So the drop is recorded elsewhere:<br/>ledger_audit_drops — durable, countable,<br/>joinable to the run — and visible at<br/>GET /api/ledger/audit-drops.<br/>The gap is disclosed, not hidden.
    end note

```

A hole that exists only as a line on stderr is a hole nobody reads: it scrolls
past, is not queryable, and leaves no count. The drop table is where it goes
instead, so "did we lose anything?" has an answer after the fact.

## The mandate: what a run is allowed to do

The mandate is hashed into the run at creation and re-checked on every gated
action. It is the one place where policy is *enforced* rather than recorded.

```mermaid
flowchart TB
    M["mandate_json at create_run<br/>(hashed → mandate_hash)"] --> C{"check(kind, actor, tool, domain, counts)"}
    C -->|"internal kind"| P1["pass — the audit trail<br/>is never gated by itself"]
    C -->|"actor not allowed"| D1["deny · block"]
    C -->|"intent outside mandate"| D2["deny · block"]
    C -->|"tool outside mandate"| D3["deny · block"]
    C -->|"max_events / max_llm_calls exceeded"| D4["deny · block<br/>budget"]
    C -->|"kind is a human gate"| H["hold · warn<br/>awaiting_approval"]
    C -->|"intent not in the plan"| F1["flag · warn<br/>unplanned_intent"]
    C -->|"source domain outside scope"| F2["flag · warn<br/>scope_creep"]
    P1 --> R["recorded"]
    D1 --> R
    D2 --> R
    D3 --> R
    D4 --> R
    H --> R
    F1 --> R
    F2 --> R
    NOTE1["Hard failures deny; soft signals flag. And the human gate<br/>is checked *before* the soft signals, because “waiting on a person”<br/>must not be masked by “that wasn’t in the plan”."]

    D1 ~~~ NOTE1
    classDef note fill:#fbfcfd,stroke:#c8d0da,stroke-dasharray:4 3,font-style:italic,color:#57606a
    class NOTE1 note
```

## Identity

```mermaid
flowchart LR
    U["Person"] --> H1["X-AKM-Session<br/>(stable client key)"]
    U --> H2["X-AKM-Actor<br/>(name for the chain)"]
    H1 --> S["session resolves to a sitting"]
    H2 --> A["actor on every event"]
    A --> OK{"run open?"}
    OK -- yes --> R1["the human event lands on that run's chain"]
    OK -- "no run, session open" --> R2["the session spine — the same sitting, still provable"]
    OK -- neither --> R3["dropped rather than guessed at"]
    G["approver"] --> AP{"requester ≠ approver?"}
    AP -- no --> DENY["403 — no self-approval, ever"]
    AP -- "empty identity" --> DENY2["fails closed"]
    AP -- yes --> OK2["decision lands on the chain,<br/>with requester and approver both named"]
    NOTE1["Identity comes from a header, or the session key.<br/>A shared default like “user” could not tell two people apart,<br/>and an approval that cannot name its approver proves nothing."]

    R3 ~~~ NOTE1
    classDef note fill:#fbfcfd,stroke:#c8d0da,stroke-dasharray:4 3,font-style:italic,color:#57606a
    class NOTE1 note
```

## Threat model: what this design is defending against

```mermaid
flowchart TB
    subgraph ADVERSARY["Who we are defending against"]
        A1["A curious operator<br/>reading the database file"]
        A2["A model that<br/>hallucinates or is prompt-injected"]
        A3["A compromised page<br/>on the open web"]
        A4["A gateway outage or<br/>an attacker with the ledger"]
        A5["Two people sharing<br/>one instance"]
    end
    A1 --> D1{"Defence"}
    A1 --> D1["Everything is scoped to an investigation<br/>and cascade-deletes with it; the file is git-ignored"]
    A2 --> D2["Grounding drops uncited claims; the write guard<br/>strips unsourced specifics; the critique pass<br/>marks SUPPORTED/UNCERTAIN"]
    A3 --> D3["Fetches are sandboxed by OpenShell when the broker answers,<br/>and the report states sandbox: true/false rather than assuming it"]
    A4 --> D4["Audit is fail-open but drops are counted; chains are<br/>content-addressed, so tampering is detectable offline"]
    A5 --> D5["Session keys and actor names separate people;<br/>approvals cannot be self-granted"]

```

And what it does **not** defend against, stated plainly:

- **The database file itself.** Anyone who can read `akm.db` can read the
  artifacts, the completions and the chain. There is no encryption at rest.
  Per-investigation deletion scopes access by *convention*, not by
  cryptography.
- **A person who sets `LEDGER_CAPTURE_PAYLOADS=1`.** It is a deliberate,
  documented switch, and turning it on makes prompts permanent.
- **Traffic on the LAN.** The gateway hop is plain HTTP inside the local
  network; integrity there rests on the network, not on TLS.
- **A malicious gateway.** Proofs let you *detect* a substituted response; they
  do not make a dishonest gateway honest.
- **Legal/compulsion.** Nothing here implements retention-by-policy, hold, or
  legal hold. Retention is "until the file is deleted".

## What a person can see about themselves

| Question | Answer | Where |
|---|---|---|
| What did the app send to a model? | The prompt hash, character count, token counts, and the completion verbatim | Audit ledger → a run → its `llm.call` events |
| Which model actually served it? | `x-served-model` on the event, plus the gateway proof id | Audit ledger |
| What did it fetch from the web? | `mcp.call` events with the domain, and the OpenShell `sandbox` flag per fetch | Audit ledger, and Security → Evidence |
| Why was that answer phrased that way? | The full trace: sources, grounding violations, write-guard report, critique verdicts | Explainer → the answer's trace |
| Who approved this? | The approval request, the decider, and the chained decision event — never the same person | Security → the run's audit chain |
| Is the record still intact? | `GET /ledger/runs/{id}/verify` recomputes every hash; `break_at` names the seq where it changed | Audit ledger |
| Can I prove it without your database? | `GET /ledger/runs/{id}/export` + `POST /ledger/verify-export` — the bundle verifies standalone | Audit ledger |

## Summary: the claims, and where each is enforced

```mermaid
flowchart LR
    subgraph PROVABLE["Provable by construction"]
        P1["No third-party LLM API client exists<br/>— models are reached only via the local gateway"]
        P2["Credentials are redacted before<br/>immutable storage, recursively, with hashes exempted"]
        P3["Prompts are hashed by default;<br/>capture requires an explicit env var"]
        P4["An approval cannot be self-graded<br/>or granted anonymously"]
        P5["An audit failure never becomes<br/>a product failure, and is always counted"]
    end
    subgraph CONVENTIONAL["True by convention, not cryptography"]
        V1["Deleting an investigation removes its content<br/>— but not its audit trail"]
        V2["The db is git-ignored and lives on a named volume;<br/>whoever can read the file can read everything"]
        V3["The dashboard reads the same file; it is a<br/>trusted local service, not an access boundary"]
    end
    subgraph NOT_DONE["Not implemented — and not claimed"]
        N1["Encryption at rest, or per-user auth"]
        N2["Retention schedules or legal hold"]
        N3["TLS between the app and the gateway"]
        N4["Key rotation, or a secrets manager"]
    end

```

An honest privacy document has three sections, not one. The claims that are
provable, the ones that are conventional, and the ones that are simply not
implemented. The last section is the one most worth keeping, because it is
what stops the other two from being read as more than they are.

## Related

- Every rule above, as a numbered control with its enforcing file: [controls.md](controls.md)
- The ledger's own design: [../docs/ledger.md](../docs/ledger.md)
- Where the data physically lives: [data-model.md](data-model.md)
