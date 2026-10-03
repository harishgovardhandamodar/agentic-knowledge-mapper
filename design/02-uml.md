# 02 — UML structure

Component, class, and package views of the codebase: which module owns which
responsibility, and what depends on what.

Related: [01-system-context.md](01-system-context.md) · [data-model.md](data-model.md) ·
[interaction.md](interaction.md) · [../docs/architecture.md](../docs/architecture.md)

## Component diagram (internal)

```mermaid
flowchart TB
    subgraph PRESENTATION["Presentation"]
        UI["static/index.html<br/>Classic + Dashboard<br/>switchApp → switchView → loaders"]
        RC["static/console/index.html<br/>Risk Console shell<br/>persona presets · Risk Cards · Report Reader"]
    end
    subgraph INTERFACE["Interface (HTTP)"]
        MAIN["main.py<br/>~110 routes + /console + /api/console/*"]
        LAPI["ledger_api.py<br/>audit routes, session dependency"]
        CONS["console.py<br/>BFF aggregators (home/risks/brief)"]
        KBS["kb_search.py<br/>FTS5 → LIKE fallback"]
    end
    subgraph DOMAIN["Domain / agents"]
        AGENT["agent.py<br/>CollectionAgent + RLHF/memorization packs"]
        EXPL["explainer.py<br/>Explainer + manager_synthesis in summary"]
        SAGENT["security_agent.py<br/>SecurityAgent + PDP/SAF/RLHF/RM hooks"]
        A2A["agents.py<br/>A2A dispatch bus · 14 cards inc. mitigation-advisor"]
        MGR["manager.py<br/>provider template · fan-out · synthesis"]
        PORT["portfolio.py<br/>Initiative · unified register · leakage"]
        EXEC["executive.py<br/>availability · distribution · robustness"]
        PP["provider_posture.py<br/>PDP/SAF/RLHF + contribution map"]
        MEM["memorization.py<br/>RM01-06"]
    end
    subgraph ENGINE["Deterministic engines"]
        SEC["security.py<br/>threat pack + scoring + report"]
        MEVAL["model_eval.py<br/>memorization + alignment_data_leakage + subtypes<br/>method_general 0.25 · MM16 · 2.0.0/1.1.0"]
        STD["standards_matrix.py"]
        GRD["grounding.py<br/>quote gate"]
        WG["writeguard.py<br/>write-verify-repair + tier-gated phrases"]
        DRIFT["drift.py"]
        YIELD["yield_.py"]
        REC["recommend.py"]
        EVAL["evalkit.py<br/>50 cases / 21 invariants"]
        LEAK["leakage.py<br/>LP01-08 + PB01-07"]
    end
    subgraph ASSURANCE["Assurance (closed loop)"]
        AS["assurance.py<br/>declared vs verified residual · gates"]
        ALED["assurance_ledger.py<br/>assurance events · integrity monitor"]
        SWARM["swarm.py<br/>role contracts · policy engine · critic"]
        LEAD["leadership.py<br/>decision-grade dashboard views"]
    end
    subgraph INFRA["Infrastructure"]
        SRCH["search.py<br/>RSS · arXiv · DuckDuckGo"]
        LLM["llm.py"]
        LED["ledger.py"]
        OBS["obs.py"]
        SCHED["scheduler.py<br/>cron + dashboard_snapshots hourly"]
        JQ["jobqueue.py"]
        CVEL["cve.py"]
        OPEN["openshell.py<br/>broker client + policy"]
        APPROV["approvals.py<br/>distinct-approver gate"]
        MODELS["models.py + ledger_models.py<br/>20+ tables"]
        DB["database.py<br/>WAL + migrations"]
    end
    UI & RC --> MAIN
    MAIN --> LAPI & CONS & KBS
    MAIN --> AGENT & EXPL & SAGENT & MGR & SCHED & JQ & CVEL & STD & PORT & EXEC & PP & MEM
    MAIN --> LEAD
    SAGENT --> APPROV & A2A
    SAGENT --> JQ
    SAGENT --> SWARM
    SAGENT --> AS
    SAGENT --> ALED
    AS --> ALED
    SWARM --> ALED
    LEAD --> ALED & AS & SWARM
    A2A --> SEC & MEVAL & OPEN
    EXPL --> GRD & WG & DRIFT & YIELD
    AGENT --> YIELD
    MAIN --> REC
    EVAL -.->|"pins"| SEC & MEVAL & LEAK
    AGENT & EXPL & SAGENT & A2A & MGR --> SRCH & LLM
    LLM -->|"every call"| LED
    AGENT & EXPL & SAGENT & A2A & MGR & SCHED & JQ -.-> OBS
    MAIN & LAPI & AGENT & EXPL & SAGENT & A2A & MGR & SEC & MEVAL & STD & PORT & EXEC & PP & MEM --> MODELS
    MODELS --> DB
    LED --> MODELS
    CONS --> PORT & EXEC
    KBS --> MODELS

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
        +record_assurance_ledger(run, params, result)
    }
    class AssuranceEngine {
        +assess(exposure, threats, controls, artifacts)
        +decision_frame(verified, declared, gates)
        +architecture_gate(checklist, exposure)
        +evidence_gate(threats, artifacts)
        +injection_cap(threats, artifacts)
        +blast_radius(residual, inventory)
        +canonical_register_key(family, layer, ref)
    }
    class AssuranceLedger {
        +record_assurance(run_id, assurance)
        +record_swarm_event(run_id, role, phase)
        +record_human_decision(run_id, actor, decision)
        +record_lifecycle / record_artifact / record_tool / record_publication
        +integrity_report(run_id)
        +monitor_integrity()
        +export_siem_events()
        +re_score_triggers()
    }
    class Swarm {
        +ROLE_CONTRACTS / GATE_AUTHORITIES
        +policy_enforcement_point(exposure, gates)
        +policy_engine(gates, sources, budget)
        +topology(events) / health(events)
        +resume_state(events)
        +critic_review(events, assurance)
        +validate_handoff(message)
        +check_scope(tool, source, allow_list)
        +budget_allows(used, budget)
    }
    class Leadership {
        +risk_position(db)
        +decision_queue(db)
        +assurance_health(db)
        +system_integrity(db)
        +alerts(db) / exceptions(db) / change_log(db)
        +board(db, persona)
        +record_decision(db, assessment_id, decision)
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
    FastAPI --> Leadership : serves decision views
    FastAPI --> AssuranceLedger : integrity / siem / re-score
    FastAPI --> Manager : runs, compiles
    FastAPI --> Scheduler : starts on boot
    FastAPI --> StandardsMatrix : serves
    SecurityAgent --> JobQueue : enqueues + claims
    SecurityAgent --> A2ABus : dispatches
    SecurityAgent --> Swarm : policy before scoring
    SecurityAgent --> AssuranceEngine : assesses
    SecurityAgent --> AssuranceLedger : writes the run's events
    AssuranceEngine --> AssuranceLedger : one event per gate
    Swarm --> AssuranceLedger : role + policy events
    Leadership --> AssuranceLedger : integrity + completeness
    Leadership --> AssuranceEngine : stored verdict
    Leadership --> Swarm : system health
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
        L2["Agents<br/>agent.py · explainer.py · security_agent.py · agents.py · manager.py · leadership.py"]
        L3["Engines (pure, testable)<br/>security.py · assurance.py · swarm.py · standards_matrix.py · grounding.py · writeguard.py · drift.py · yield_.py · recommend.py · evalkit.py · openshell.py · cve.py · approvals.py"]
        L4["Infrastructure<br/>llm.py · search.py · ledger.py · assurance_ledger.py · obs.py · scheduler.py · jobqueue.py · models.py · database.py"]
    end
    subgraph P2["static — presentation"]
        S1["index.html<br/>no build step; ES2020 in a script tag"]
    end
    subgraph P3["tests — 55 suites"]
        T1["unit: grounding, writeguard, drift, yield, recommend, evalkit, approvals, jobqueue, ledger, security, openshell, standards, assurance, swarm, swarm-adversarial, assurance-ledger"]
        T2["integration: investigations, explainer, manager, cves, db isolation, obs, assurance-api, leadership"]
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
`GET /.well-known/agents`, plus the ten model-path cards taken by model
subjects across the three model assessments (see security-agent.md — same bus,
separate workflows, no standards mapping):

| Agent | Skills | Envelope intents it answers |
|---|---|---|
| `security-orchestrator` | `plan_assessment`, `delegate_collection`, `assemble_report` | `plan_assessment`, `assemble_report` |
| `control-analyst` | `analyse_controls`, `judge_applicability`, `propose_control_plan` | `analyse_controls`, `judge_applicability` |
| `research-collector` | `agentic_search`, `rank_evidence` | `collect_research` |
| `threat-intel` | `map_attacks`, `cite_evidence`, `score_evidence_confidence` | `map_attacks` |
| `report-writer` | `write_exploits_section`, `write_exec_bullets` | `write_section` |
| `model-profiler` | `profile_model` | `profile_model` |
| `model-internals` | `review_internals` | `review_internals` |
| `model-privacy` | `assess_model_privacy` | `assess_model_privacy` |
| `model-reporter` | `write_model_report` | `write_model_report` |
| `model-adversary` | `derive_capabilities` | `derive_capabilities` |
| `misuse-scout` | `engineer_scenarios` | `engineer_scenarios` |
| `misuse-reporter` | `write_misuse_report` | `write_misuse_report` |
| `hypothesis-analyst` | `draft_hypotheses` | `draft_hypotheses` |
| `hypothesis-verifier` | `verify_hypotheses` | `verify_hypotheses` |
| `hypothesis-reporter` | `write_hypothesis_report` | `write_hypothesis_report` |
| `model-adv-intel` | `map_model_attacks` + `map_rlhf_memorization` | `map_model_attacks` |
| `model-adoption-analyst` | `rate_adoption` (+ preference pathway notes) | `rate_adoption` |
| `model-mitigation-analyst` | `propose_model_mitigations` (prefers MM16 for feedback) | `propose_model_mitigations` |
| `mitigation-advisor` | `advise_portfolio_risks` + `advise_rlhf_memorization` | `advise_portfolio_risks` |
| `experiment-planner` | `plan_experiments` + RLHF templates | `plan_experiments` |
| `research-collector` | `agentic_search` + `query_rlhf_memorization` | `collect_research` |
| `model-eval-reporter` | `write_model_eval_report` + RLHF section RM01-06 | `write_model_eval_report` |

## Related

- Storage: [data-model.md](data-model.md)
- Exact call order: [interaction.md](interaction.md)
- Every control, with the file that enforces it: [controls.md](controls.md)
