# Agentic Knowledge Mapper — Shareable Mermaid Diagrams

LinkedIn does not render Mermaid, so these diagrams live here as copy-pasteable
source for **https://mermaid.live** (or any Mermaid renderer / docs site). Each
block has a one-line plain-English explanation. Pair with the text in
[linkedin-share.md](linkedin-share.md).

---

## 1. System architecture

```mermaid
flowchart TB
    subgraph GUI["GUI layer"]
        C["Classic Mapper :8204"]
        R["Risk Console :8204/console"]
        D["Executive brief — Security & Privacy"]
    end
    subgraph APP["Agentic Knowledge Mapper (FastAPI)"]
        M["Investigation & security agents"]
        SW["Swarm runtime (4 swarms) + MCP tools"]
        RSC["Deterministic core<br/>risk_scoring · register · FTS · kb"]
        LG["Audit ledger (hash-chained · proofs)"]
    end
    subgraph FOX["fox-services :8210"]
        GW["OpenAI-compatible /v1 · local model"]
        BR["OpenShell broker (sandboxed fetch)"]
    end
    subgraph GPU["GPU node — axiom-1 (2x RTX 5080)"]
        OLL["local Ollama · qwen3.8:27b"]
    end
    subgraph WEB["The open internet"]
        SRC["RSS · arXiv · DuckDuckGo · NVD/CIRCL"]
    end

    C --> M
    R --> M
    D --> M
    M --> SW
    SW --> RSC
    M --> LG
    SW -->|"prompt + completion"| GW
    SW -->|"enrich queries + page urls"| BR
    GW --> OLL
    BR --> SRC
```

Every GUI is a projection over one FastAPI backend; all model calls leave the
app only to the fox-services GPU node; the only way to reach the open internet
is through the sandboxed broker carrying queries and URLs.

---

## 2. The switchable core (UML)

```mermaid
classDiagram
    class FoxCoreFacade {
        +FOX_CORE_ENABLED: bool
        +is_fox_request(request) bool
        +core_for_request(request) str
        +swarm_for_task(task) str
        +mcp_for_intent(intent) str
    }
    class SwarmRuntime {
        +SWARMS: dict
        +SHARED_TOOLS: list
        +swarm_for_agent(agent) str
        +mcp_for_intent(intent) str
    }
    class MCPServer {
        +tools(): list
    }
    class DeterministicCore {
        +score_risk(...)
        +score_portfolio(...)
        +fingerprint(...)
        +search(...)
    }
    class Ledger {
        +text_digest(text) str
        +record_llm_call(...)
        +request_approval(...)
        +verify(proof) Verdict
    }
    class SQLite

    FoxCoreFacade --> SwarmRuntime : selects swarm by task
    SwarmRuntime --> MCPServer : A2A envelopes (task_id = ledger run)
    MCPServer --> DeterministicCore : idempotent JSON tools
    DeterministicCore --> SQLite : reads/writes
    Ledger --> SQLite : append-only chain, proofs
    MCPServer --> Ledger : approvals, events, verify
```

A thin facade picks between the classic engine and the Fox core; below it
everything converges on the same deterministic spine, so switching cores never
changes the numbers — only how the LLM is orchestrated.

---

## 3. Audit ledger — swarm control flow

```mermaid
flowchart LR
    O["model-orchestrator"] --> P["model-profiler"]
    O --> I["model-internals"]
    O --> C["research-collector"]
    O --> PR["model-privacy"]
    O --> REP["model-reporter"]
    P -. "profile" .-> I
    I -. "findings" .-> C
    C -. "evidence" .-> PR
    PR -. "scoring" .-> REP
```

A reviewer can walk each handoff (who delegated what, how long it took, which
model produced which step) and re-verify the whole chain offline.

---

## 4. Risk management lifecycle (activity)

```mermaid
flowchart TD
    TRIG["assessment done / CVE / schedule"] --> SYNC["risk_sync"]
    SYNC --> INTAKE["risk-intake · register (stable keys)"]
    INTAKE --> TRIAGE["risk-triage · deterministic priority"]
    TRIAGE --> TREAT{"new High / sparse?"}
    TREAT -- yes --> STUB["risk-treatment · controls/experiments"]
    TREAT -- no --> MON["risk-monitor · stale/CVE/SLA"]
    MON --> HUMAN{"human decision?"}
    HUMAN -- acceptance --> GOV["risk-governance package"]
    GOV --> GATE{"approval gate (requester ≠ approver)"}
    GATE -- grant --> REG["register updated · ledger records human"]
    GATE -- deny --> REG
    REG --> REP["risk-reporter · brief/digest"]
```

Agents propose and draft; humans own and decide; every accepted risk or policy
change crosses an approval gate and lands on the ledger.

---

## 5. Privacy & trust boundaries

```mermaid
flowchart TB
    subgraph TB0["TB0 · The person"]
        U["Browser · intent + session · never holds model creds"]
    end
    subgraph TB1["TB1 · The app"]
        API["FastAPI :8204"]
        subgraph TB1a["TB1a · Register + ledger"]
            L["hash-chained events · digests · approvals"]
        end
    end
    subgraph TB2["TB2 · fox-services GPU node"]
        GW["LLM gateway · PII counts only · redaction · digest proofs"]
    end
    subgraph TB3["TB3 · The open internet"]
        WEB["RSS · arXiv · web"]
    end
    U -->|"intent + session"| API
    API --> L
    API -->|"prompt + completion"| GW
    GW -->|"queries + urls"| WEB
```

The ledger holds digests, not prompts; PII is counted, never kept; the only
internet exit is the sandboxed broker carrying queries and URLs.

---

## 6. Deep-research drafting → evaluation run (chain)

```mermaid
flowchart LR
    DOM["domain + target"] --> DRAFT["eval-draft<br/>frame · axes · draft · quality pass"]
    DRAFT --> CAT["catalog.json<br/>stable keys · severity · weight"]
    CAT --> SEED["seed → EvaluationCatalog"]
    SEED --> RUN["EvaluationRun<br/>answer · score · report.md / .json"]
    DRAFT --> BRIEF["brief · agenda · adversarial"]
```

Same axis library (identity/binding, authorization, intent integrity, data
privacy, autonomy, adversarial, audit, third parties, regulatory, threat model,
ops) adapts across domains — agentic payments, data export, AI adoption in a
large enterprise — with an LLM draft and a deterministic fallback.