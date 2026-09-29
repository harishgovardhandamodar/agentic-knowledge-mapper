# 02 — UML structure

Component, class, and package views of the codebase: which module owns which
responsibility, and what depends on what.

Related: [01-system-context.md](01-system-context.md) · [data-model.md](data-model.md) ·
[interaction.md](interaction.md) · [../docs/architecture.md](../docs/architecture.md)

## Component diagram (internal)

```mermaid
flowchart TB
    subgraph PRESENTATION["Presentation"]
        UI["static/index.html<br/>switchApp → switchView → loaders<br/>overlays, polling, mermaid, vis-network"]
    end
    subgraph INTERFACE["Interface (HTTP)"]
        MAIN["main.py<br/>product routes + schemas"]
        LAPI["ledger_api.py<br/>audit routes, session dependency"]
    end
    subgraph DOMAIN["Domain / agents"]
        AGENT["agent.py<br/>CollectionAgent"]
        EXPL["explainer.py<br/>Explainer"]
        SAGENT["security_agent.py<br/>SecurityAgent"]
        A2A["agents.py<br/>A2A dispatch bus"]
        MGR["manager.py"]
    end
    subgraph ENGINE["Deterministic engines"]
        SEC["security.py<br/>threat pack + scoring + report"]
        STD["standards_matrix.py"]
        GRD["grounding.py<br/>quote gate"]
        WG["writeguard.py<br/>write-verify-repair"]
        DRIFT["drift.py"]
        YIELD["yield_.py"]
        REC["recommend.py"]
        EVAL["evalkit.py<br/>scoring regression gate"]
    end
    subgraph INFRA["Infrastructure"]
        SRCH["search.py"]
        LLM["llm.py"]
        LED["ledger.py"]
        OBS["obs.py"]
        SCHED["scheduler.py"]
        JQ["jobqueue.py"]
        CVEL["cve.py"]
        OPEN["openshell.py<br/>broker client + policy"]
        APPROV["approvals.py<br/>distinct-approver gate"]
        MODELS["models.py + ledger_models.py"]
        DB["database.py<br/>WAL + migrations"]
    end
    UI --> MAIN
    MAIN --> LAPI
    MAIN --> AGENT & EXPL & SAGENT & MGR & SCHED & JQ & CVEL & STD
    LAPI --> LED
    SAGENT --> APPROV & A2A
    SAGENT --> JQ
    A2A --> SEC & OPEN
    EXPL --> GRD & WG & DRIFT & YIELD
    AGENT --> YIELD
    MAIN --> REC
    EVAL -.->|"pins"| SEC
    AGENT & EXPL & SAGENT & A2A & MGR --> SRCH & LLM
    LLM -->|"every call"| LED
    AGENT & EXPL & SAGENT & A2A & MGR & SCHED & JQ -.-> OBS
    MAIN & LAPI & AGENT & EXPL & SAGENT & A2A & MGR & SEC & STD --> MODELS
    MODELS --> DB
    LED --> MODELS

```

## Key classes (UML)

```mermaid
classDiagram
    direction LR
    class FastAPI {
        +investigations() CRUD
        +runs() / events()
        +graph() / artifacts()
        +explain() / explanations()
        +security_assess()
        +manager_run() / manager_compile()
        +standards_score_matrix()
        +cves_collect()
    }
    class CollectionAgent {
        +launch_run(inv, max_items, max_rounds)
        +launch_run_with_goal(inv, goal)
        +run_investigation_agent(run_id)
    }
    class Explainer {
        +launch_explanation(inv, question, mode, depth, audience)
        +run_explainer(exp_id)
        +investigation_summary(inv_id)
        +research_gaps(inv_id)
    }
    class SecurityAgent {
        +launch_security_assessment(inv, params)
        +resume_security_assessment(run_id, approved_by)
        +security_run_busy(inv)
    }
    class A2ABus {
        +dispatch(envelope, db)
        +run_security_a2a_workflow(params)
        +get_agent_cards()
    }
    class SecurityEngine {
        +score_assessment(threats, controls, exposure)
        +build_report(assessment)
        +generate_diagrams()
    }
    class Manager {
        +parse_command(command)
        +start_run(plan, options)
        +compile_summary(run_id)
        +timeline(run_id)
    }
    class StandardsMatrix {
        +score_matrix(assessment_id)
        +rank_frameworks(assessment)
        +threat_pillars()
    }
    class Scheduler {
        +start()
        +_tick() 1 min
        +_tick_watched() 10 min
    }
    class JobQueue {
        +enqueue(kind, payload, key)
        +claim(kinds, lease_s)
        +complete(job)
        +fail(job, error)
        +recover_orphans()
    }
    class Ledger {
        +append(kind, actor, data)
        +verify_chain(run_id)
        +verify_proof(event_seq)
        +contamination(run_id, ref)
        +export_run(run_id)
    }
    class LLMClient {
        +chat(messages, model)
        +chat_json(messages)
        +health()
    }
    class SearchProviders {
        +search_rss(query)
        +search_arxiv(query)
        +search_web(query)
    }
    class WriteGuard {
        +audit_section(section, pages)
        +audit_answer(question, answer, pages)
    }
    class Grounding {
        +quote_is_verbatim(quote, source)
        +verify_grounding(claims, sources)
    }
    class OpenshellBroker {
        +broker_status()
        +broker_exec(command, sandbox)
        +fetch_url(url)
        +generate_policy_yaml(product, exposure, hosts)
    }

    FastAPI --> CollectionAgent : launches
    FastAPI --> Explainer : launches
    FastAPI --> SecurityAgent : launches, requires approval
    FastAPI --> Manager : runs, compiles
    FastAPI --> Scheduler : starts on boot
    FastAPI --> StandardsMatrix : serves
    SecurityAgent --> JobQueue : enqueues + claims
    SecurityAgent --> A2ABus : dispatches
    A2ABus --> SecurityEngine : scores + reports
    A2ABus --> OpenshellBroker : sandboxed fetch
    CollectionAgent --> SearchProviders : queries
    CollectionAgent --> LLMClient : plans + analyses
    Explainer --> LLMClient : research, compose, critique
    Explainer --> Grounding : gates every citation
    Explainer --> WriteGuard : audits composed prose
    CollectionAgent --> Ledger : records steps
    LLMClient --> Ledger : records every call
    Scheduler --> CollectionAgent : cron launch
    Scheduler --> Explainer : watch re-answer
    Ledger ..> JobQueue : run context

```

## Package diagram

```mermaid
flowchart TB
    subgraph P1["app — one package, four layers"]
        direction TB
        L1["Interface<br/>main.py · ledger_api.py"]
        L2["Agents<br/>agent.py · explainer.py · security_agent.py · agents.py · manager.py"]
        L3["Engines (pure, testable)<br/>security.py · standards_matrix.py · grounding.py · writeguard.py · drift.py · yield_.py · recommend.py · evalkit.py · openshell.py · cve.py · approvals.py"]
        L4["Infrastructure<br/>llm.py · search.py · ledger.py · obs.py · scheduler.py · jobqueue.py · models.py · database.py"]
    end
    subgraph P2["static — presentation"]
        S1["index.html<br/>no build step; ES2020 in a script tag"]
    end
    subgraph P3["tests — 27 suites"]
        T1["unit: grounding, writeguard, drift, yield, recommend, evalkit, approvals, jobqueue, ledger, security, openshell, standards"]
        T2["integration: investigations, explainer, manager, cves, db isolation, obs"]
    end
    subgraph P4["standards-dashboard — vendored"]
        D1["static build of the AI Standards &amp; Regulations dashboard<br/>served :5173, embedded by iframe"]
    end
    subgraph P5["design — this folder"]
        DG1["Mermaid diagrams of all of the above"]
    end
    P1 --> P2
    P3 -.->|"assert against"| P1
    P1 -.->|"reads data.json over compose"| P4
    P5 -.->|"describes"| P1

```

## Layering rules the code actually follows

```mermaid
flowchart LR
    subgraph ALLOWED["Allowed direction of dependency"]
        UI["static/index.html"] --> HTTP["main.py / ledger_api.py"]
        HTTP --> AGENTS["agents"]
        AGENTS --> ENGINES["engines"]
        AGENTS --> INFRA["infrastructure"]
        ENGINES --> INFRA
    end
    subgraph FORBIDDEN["Never"]
        F1["engines importing agents"]
        F2["engines importing models or db"]
        F3["grounding importing anything app-level"]
        F4["static importing Python"]
    end
    UI -.-x F4
    ENGINES -.-x F1
    ENGINES -.-x F2
    GRD["grounding.py<br/>stdlib only, no app imports, no I/O"] -.-x F3

```

Two of these rules were learned the hard way and are worth stating, because
their violation is a real bug rather than a style note:

- **`grounding.py` must stay a leaf.** The verbatim-quote rule used to be
  implemented twice — `ledger.quote_is_verbatim` and `explainer._quote_valid` —
  and kept in sync by hand. The ledger kept its own copy because importing the
  explainer would drag `bs4`/`feedparser` in through `llm`. The fix was to make
  the rule a stdlib-only leaf and delete the copy, not to document the copy.
- **LLM calls funnel through `llm.py`.** That module is the only place a model
  is called, which is what makes "every model call is on the chain" a property
  of the system rather than a promise in a docstring.

## The A2A envelope protocol

```mermaid
classDiagram
    class Envelope {
        +str protocol = "a2a/1.0"
        +str task_id
        +str from
        +str to
        +str intent
        +dict payload
        +list trace
    }
    class TraceHop {
        +str agent
        +str intent
        +str at
        +str note
    }
    class Verdict {
        +str action  allow|warn|hold|deny|block
        +str reason
        +str severity
        +dict detail
    }
    class Mandate {
        +list allowed_actors
        +list allowed_intents
        +list planned_intents
        +list allowed_tools
        +list allowed_domains
        +int max_events
        +int max_llm_calls
        +list human_gates
    }
    Envelope --> TraceHop : append-only
    Mandate --> Verdict : check(kind, actor, intent, tool, domain)

```

Envelope shape, verbatim, as `agents.new_envelope` builds it:

```json
{
  "protocol": "a2a/1.0",
  "task_id": "sec-a1b2c3d4",
  "from": "security-orchestrator",
  "to": "research-collector",
  "intent": "collect_research",
  "payload": {"product_name": "…", "investigation_id": 9, "threat_titles": ["…"]},
  "trace": [{"agent": "security-orchestrator", "intent": "plan_assessment",
             "at": "2026-09-28T20:37:52Z", "note": "task sec-76f215f7: …"}]
}
```

The five agent cards discoverable at `GET /api/agents/cards` and
`GET /.well-known/agents`:

| Agent | Skills | Envelope intents it answers |
|---|---|---|
| `security-orchestrator` | `plan_assessment`, `delegate_collection`, `assemble_report` | `plan_assessment`, `assemble_report` |
| `control-analyst` | `analyse_controls`, `judge_applicability`, `propose_control_plan` | `analyse_controls`, `judge_applicability` |
| `research-collector` | `agentic_search`, `rank_evidence` | `collect_research` |
| `threat-intel` | `map_attacks`, `cite_evidence`, `score_evidence_confidence` | `map_attacks` |
| `report-writer` | `write_exploits_section`, `write_exec_bullets` | `write_section` |

## Related

- Storage: [data-model.md](data-model.md)
- Exact call order: [interaction.md](interaction.md)
- Every control, with the file that enforces it: [controls.md](controls.md)
