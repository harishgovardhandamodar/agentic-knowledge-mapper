# AI Security agent (A2A)

The **AI Security Engineering & Evaluation Agent** (`app/security_agent.py`,
`app/agents.py`, `app/security.py`) performs deep security assessments of a
product used with sensitive data. It speaks an internal **agent-to-agent
protocol (`a2a/1.0`)**: the work is split across five sub-agents that
communicate only through JSON envelopes on a dispatch bus, each hop appended
to an auditable trace.

Related: [architecture](architecture.md) · [data-model](data-model.md) ·
[frontend](frontend.md) · [threatpack](threatpack.md) ·
[../design/controls.md](../design/controls.md)

## Agent cards

Fifteen cards, discoverable at `GET /api/agents/cards` and
`GET /.well-known/agents`. Five serve the catalog workflow, ten serve the
model paths:

| Agent | Skills | Endpoint |
|---|---|---|
| `security-orchestrator` | `plan_assessment`, `delegate_collection`, `assemble_report` | `POST /investigations/{id}/security/assess` |
| `control-analyst` | `analyse_controls`, `judge_applicability`, `propose_control_plan` | `POST /api/agents/invoke` |
| `research-collector` | `agentic_search`, `rank_evidence` | `POST /api/agents/invoke` |
| `threat-intel` | `map_attacks`, `cite_evidence`, `score_evidence_confidence` | `POST /api/agents/invoke` |
| `report-writer` | `write_exploits_section`, `write_exec_bullets` | `POST /api/agents/invoke` |
| `model-profiler` | `profile_model` | `POST /api/agents/invoke` |
| `model-internals` | `review_internals` | `POST /api/agents/invoke` |
| `model-privacy` | `assess_model_privacy` | `POST /api/agents/invoke` |
| `model-reporter` | `write_model_report` | `POST /api/agents/invoke` |
| `model-adversary` | `derive_capabilities` | `POST /api/agents/invoke` |
| `misuse-scout` | `engineer_scenarios` | `POST /api/agents/invoke` |
| `misuse-reporter` | `write_misuse_report` | `POST /api/agents/invoke` |
| `hypothesis-analyst` | `draft_hypotheses` | `POST /api/agents/invoke` |
| `hypothesis-verifier` | `verify_hypotheses` | `POST /api/agents/invoke` |
| `hypothesis-reporter` | `write_hypothesis_report` | `POST /api/agents/invoke` |

`model-profiler` and `research-collector` are shared: one subject profile and
one graph search serve all three model flows, so the same evidence graph is
searched once per run rather than three different ways.

The **Agents** sub-tab shows the cards for the path that produced the report
on screen with what each one actually returned, so the delegation is
inspectable rather than asserted.

## Envelope protocol

```json
{
  "protocol": "a2a/1.0",
  "task_id": "sec-a1b2c3d4",
  "from": "security-orchestrator",
  "to": "research-collector",
  "intent": "collect_research",
  "payload": {"product_name": "…", "investigation_id": 1, "threat_titles": […]},
  "trace": [{"agent": "…", "intent": "…", "at": "…", "note": "…"}]
}
```

The A2A `task_id` **doubles as the ledger run id**, which is how a report and
its evidence chain stay bound to each other. The Audit-chain sub-tab shows
exactly that one chain.

## Workflow sequence

```mermaid
sequenceDiagram
    autonumber
    actor R as Researcher
    participant UI as Security tab
    participant API as FastAPI
    participant RUN as Security run (job queue)
    participant ORC as orchestrator
    participant CA as control-analyst
    participant COL as research-collector
    participant INT as threat-intel
    participant WRI as report-writer
    participant LLM as LLM gateway
    participant DB as SQLite
    R->>UI: product + exposure + workflow
    UI->>API: POST /investigations/{id}/security/assess
    API->>RUN: enqueue(kind=security, key=sec:{run_id})
    RUN->>ORC: plan_assessment
    ORC->>CA: analyse_controls + judge_applicability
    CA-->>ORC: control plan + applicability 0..1 per threat
    ORC->>COL: collect_research (envelope)
    COL->>DB: multi-query search over investigation graph
    COL-->>ORC: research_collected (ranked evidence, matched_on, claim_hash)
    ORC->>INT: map_attacks (envelope)
    INT-->>ORC: attacks_mapped (KE-01…KE-08 × T01…T12 + local refs)
    ORC->>WRI: write_section (envelope)
    WRI->>LLM: grounded executive paragraph (fallback: deterministic)
    WRI-->>ORC: section_written (§6 markdown + bullets)
    RUN->>DB: SecurityAssessment row (report + trace + pack fingerprint)
    RUN->>DB: run=done, stats.assessment_id
    UI->>API: GET /security/assessments/{id}
    API-->>UI: report + diagrams + trace → render
```

## Job queue and the approval gate

A security run is a **row in `jobs` before it is a thread**. The worker claims
it with a lease, heartbeats while it works, and only re-queues on failure with
backoff. A lease that expires is recovered on the next boot, so a restart
resumes rather than duplicates. Security runs are currently the only work that
goes through the queue — collection and explainer runs still use a guarded
daemon thread each.

With **require approval** ticked, the run stops at
`AgentRun.status = awaiting_approval` and an approval request lands on the chain
with a `hold` verdict before any work is done. Note that the *job completes
normally* here — it did its work — and approval enqueues a fresh job under the
same key `security:{run_id}`, which is free because `done` is not in the live
set. A gate therefore blocks the **run**, not a queue slot:

- `POST /api/security/runs/{run_id}/approval` with `{approved_by,
  approved_control_plan}`.
- `approvals.same_actor` rejects an empty identity (fails closed) and a
  `403` when the approver is the requester.
- The decision is itself a chained event, so it cannot be edited afterwards.
- A plan that arrives with no recorded approver is ignored and the run re-parks,
  so the gate cannot be satisfied by the requester setting a field.

![The A2A agents for the path that produced this report](screenshots/22-security-agents.png)

## Model assessment path (no catalog, no standards)

When the subject profiles as a model (`security.profile_model_subject`:
nature, architecture, class, family, data, interface — each reported only on
explicit evidence), the assessment takes a separate A2A path instead of the
catalog workflow above:

```mermaid
sequenceDiagram
    actor R as Researcher
    participant UI as Security tab
    participant API as FastAPI
    participant ORC as model-orchestrator
    participant MP as model-profiler
    participant MI as model-internals
    participant COL as research-collector
    participant MPR as model-privacy
    participant ENG as scoring engine
    participant MR as model-reporter
    participant DB as SQLite
    R->>UI: model name + use case + exposure
    UI->>API: POST /investigations/{id}/security/assess
    API->>ORC: plan_model_assessment
    ORC->>MP: profile_model
    MP-->>ORC: profile (family/arch/class/data/interface)
    ORC->>MI: review_internals
    MI-->>ORC: findings M01… + ruled-out list
    ORC->>COL: collect_research (finding titles as queries)
    COL-->>ORC: ranked evidence
    ORC->>MPR: assess_model_privacy
    MPR-->>ORC: privacy findings P01…
    ORC->>ENG: dimension weights (privacy .35, integrity .25, surface .20, governance .20)
    ENG-->>ORC: model aggregate (residual = inherent in v1)
    ORC->>MR: write_model_report
    MR-->>ORC: model sections + grounded exec paragraph
    ORC->>DB: SecurityAssessment row (same contract, model content)
```

Weightage is explicit and stored: training-data privacy 35%, model integrity
25%, deployment surface 20%, governance 20% (`security.MODEL_DIMENSIONS`,
method `model-internals-v1`). Residual equals inherent — v1 maps no declared
controls onto model dimensions, and the report says so instead of inventing a
reduction. The what-if re-scorer refuses model rows (422): catalog arithmetic
on model findings would be numbers from the wrong method.

AI-standards mapping never happens on this path: `GET
/api/standards/score-matrix?assessment_id=` returns `skipped: true` with the
reason, and the Standards coverage sub-tab renders the explanation instead of
a matrix. Frameworks describe product controls; a weights-and-data question
is answered from the model.

## Adversarial-misuse path (a separate assessment, not a section)

The model path above asks whether the model is sound. A second, independent
question is what someone could **build with** it. That is a different question
with different agents, different weights and a different meaning for the
number, so it is a second assessment row, never a section of the first and
never averaged into it:

```mermaid
sequenceDiagram
    autonumber
    participant ORC as adversary-orchestrator
    participant MP as model-profiler
    participant MA as model-adversary
    participant MS as misuse-scout
    participant COL as research-collector
    participant ENG as scoring engine
    participant MR as misuse-reporter
    ORC->>MP: profile_model
    MP-->>ORC: profile
    ORC->>MA: derive_capabilities
    MA-->>ORC: what the model lets an attacker do
    ORC->>MS: engineer_scenarios
    MS-->>ORC: attack chains + prerequisites A01…
    ORC->>COL: collect_research (scenario titles as queries)
    ORC->>ENG: attacker-value weights
    ENG-->>ORC: misuse potential (method model-misuse-v1)
    ORC->>MR: write_misuse_report
```

The aggregate is **misuse potential**, not model risk: the model is the tool in
someone else's operation here. A well-built model can still be the most useful
thing in an attacker's hands — which is exactly why the two scores are stored
separately and never merged. The mode is resolved by
`security.resolve_model_mode`, and the route, the busy check and the engine
all call it, so an auto-mode request cannot slip past the lock held by the
explicit run it resolves to.

## Hypothesis-synthesis path (reads the other two)

A third question again: of everything the first two assessments found, which
claims are actually true, and what would settle each one? It is a separate run
because a claim drawn *across* both flows cannot be made until both have
finished:

```mermaid
sequenceDiagram
    autonumber
    participant ORC as hypothesis-orchestrator
    participant MP as model-profiler
    participant HA as hypothesis-analyst
    participant COL as research-collector
    participant HV as hypothesis-verifier
    participant ENG as scoring engine
    participant HR as hypothesis-reporter
    participant DB as SQLite
    Note over DB: stored rows of flow 1 and flow 2
    ORC->>MP: profile_model
    ORC->>HA: draft_hypotheses (+ both flows' stored rows)
    HA-->>ORC: falsifiable claims H01… with falsifiers
    ORC->>COL: collect_research (claim text as queries)
    ORC->>HV: verify_hypotheses
    HV-->>ORC: support, counter-evidence, testability, cross-flow flag
    ORC->>ENG: confidence weights
    ENG-->>ORC: confidence aggregate (method hypothesis-synthesis-v1)
    ORC->>HR: write_hypothesis_report
```

Rules this path holds to:

- **A hypothesis is a falsifiable claim.** A claim with no refutation is an
  assertion; the analyst drops it rather than storing it, and an empty
  falsifier collapses its testability score.
- **The number is a confidence, not a risk.** Higher means the claims are
  better evidenced, not that the system is more dangerous, so it is stored in
  `confidence_pct` with the meaning declared in the same dict. Reusing the
  risk colour scale would paint a well-evidenced claim set red.
- **Weights**: evidence support 40%, cross-flow corroboration 25%,
  testability 20%, stakes-if-true 15% (`security.HYPOTHESIS_DIMENSIONS`).
  Each dimension is the **mean across claims**, so one strong claim cannot
  vouch for ten vague ones; an unmeasured dimension takes the neutral 40
  baseline.
- **It reads stored rows, not a re-run.** `security._load_prior_model_rows`
  takes the most recent `model` and `model_adversarial` rows for the
  investigation, so a claim always describes the assessment the reader
  actually saw.
- **The mode is explicit.** `resolve_model_mode` never infers `hypothesis`
  from wording — which question to ask is the caller's call.
- **Ordered last.** The manager launches target → adversarial → hypothesis;
  the job queue claims in `(next_attempt_at, id)` order, so a freshly queued
  third run starts after the first two. Launched first — or started while an
  earlier flow is waiting out a retry backoff — it reads whatever rows exist
  and reports an explicit gap claim rather than an empty register.
- **Synthesised in the executive summary.** `GET /summary` carries a
  `model_synthesis` block with the latest row per workflow that ran, each
  workflow's own headline number and meaning, top items, exec paragraph, and
  mermaid diagram. The Summary tab and the node overlay render the same
  block; nothing is merged across workflows.
- **Every scoring dict names its path.** `model`, `model_adversarial`,
  `model_hypothesis`, and `standard` are stamped at scoring time, so readers
  key on the marker instead of re-deriving the path from the wording. Rows
  that predate the markers are still re-derived (target or standard only).

Like the other two model paths, it skips standards mapping and refuses the
what-if re-scorer (422).

## Threat model (STRIDE × OWASP LLM)

Twelve threats (T01–T12) scaled by exposure tier
(`restricted_data 1.0` → `public 0.3`); severity from `likelihood × impact`
banded Critical ≥ 20, High ≥ 12, Medium ≥ 6. First-class focus areas:

- **T01** accidental paste of sensitive content by employees,
- **T03** misclassified / mislabelled files laundered by AI suggestions.

```mermaid
flowchart TD
    A["Restricted / Confidential<br/>file or table"] --> B{"Classification<br/>correct?"}
    B -->|mislabelled| C["T03: AI launders<br/>wrong label"]
    B -->|correct| D["Assistant prompt"]
    D --> E{"DLP gateway?"}
    E -->|missing| F["T01: accidental paste<br/>leaves boundary"]
    E -->|present| G["LLM inference"]
    G --> H["T02/T07: retention /<br/>subprocessor copy"]
    G --> I["T05: injected instruction<br/>in asset text"]
    I --> J["T04/T06: over-share /<br/>exfiltration via docs"]
    C --> K["Published catalog<br/>(exposed)"]
    F --> K
    H --> K
    J --> K
```

Eight curated known attacks (KE-01 indirect prompt injection … KE-08
DLP-bypass exfiltration) are mapped onto the threat IDs and joined with the
locally-found evidence, producing **§6 Known exploits & research evidence**
plus executive-summary bullets and paragraph.

![Threat register with inherent and residual scores](screenshots/20-security-investigation-summary.png)

## The nine sub-tabs

| Sub-tab | Route | What it shows |
|---|---|---|
| Overview | `/api/security/assessments/{id}` | aggregates, posture, severity distribution, perspectives |
| Threats | same | T01–T12 with inherent → residual, impact, band |
| Controls | same | C01–C15, efficacy, applicability, proposed plan |
| Investigation | `/api/investigations/{id}/summary` | the evidence base, as an executive summary |
| Evidence | same | per-claim sources, `matched_on`, claim hash |
| Known issues | `/api/investigations/{id}/cves` | CVEs found in the evidence |
| Agents | same | the five A2A cards and their returns |
| Audit chain | `/api/ledger/runs/{a2a_task_id}/timeline` | the one chain behind this run |
| Report | `…/markdown`, `…/pdf` | §§1–11 + appendix, with the generated diagrams |

![Controls tab with efficacy, applicability and the proposed plan](screenshots/19-security-controls.png)

![Evidence with per-claim sources and claim hashes](screenshots/21-security-evidence.png)

![The run's hash-chained events, from the security pane](screenshots/23-security-audit-chain.png)

## Applicability (why scores differ)

Each threat carries an applicability 0..1: below 0.3 it is reported but
excluded from the aggregates, and the rest weight the aggregate by
relevance, renormalized so a uniform map scores exactly as unweighted
(pack 2.1.0, method `applicability-weighted-v1` in the fingerprint). The
control-analyst proposes it from product, use case and focus areas; then
threat-intel re-judges it against the collected evidence with the same
deterministic heuristic (`agents.heuristic_applicability`). Evidence and
focus can only confirm relevance — lift toward 1.0, never acquit below
what was proposed — so the 0.45 floor survives while real signals
differentiate topics. The keyword table carries finance-domain bridges
(payment, customer, ledger, PCI …) and model-data bridges (tabular,
dataframe, csv; memorization, membership, inversion, extraction); the LLM,
when reachable, still gets the last word per threat.

When the subject is a model, the analyst first profiles it
(`security.profile_model_subject`): nature, architecture, class, family,
data processed, and interface kind, each reported only on explicit
evidence. A model with no conversational surface has its chat-shaped
threats (T01, T05) set below the 0.3 scoring floor — still reported, never
scored, and never re-lifted by domain chatter in evidence — while
personal-data training lifts leakage (T02). The control-analyst prompt
names the actual product and profile instead of assuming a
writing-assistant shape, and the report carries a subject-profile block
plus a product-aware scope line.

## Report structure (§§)

1. Product & evidence base (fetched URLs + workflow context)
2. Reference workflow (mermaid)
3. Data-flow & trust boundary (mermaid)
4. Threat paths (mermaid)
5. Threat & risk register (table + per-threat cards)
5b. Security controls in scope · 5c. OpenShell protection posture
6. **Known exploits & research evidence** (A2A-generated)
7. Deep dive — accidental copy · 8. Deep dive — misclassification
9. Risk heat map · 10. Compliance (GDPR / ISO 27001 / SOC 2)
11. Recommendations 30/60/90
Appendix — sources and the A2A hop trail

Export: Markdown download, PDF (reportlab, tables + headings), browser print.

## Investigation sub-tab executive summary

The report's Investigation sub-tab opens with the investigation's executive
summary (`GET /api/investigations/{id}/summary`, same payload as the mapper's
overlay): prose, query brief, review flags, coverage counts, evidence diagram,
answered questions with supporting artifacts, top supporting artifacts (into
the detail overlay) and top residual threats. It loads when the sub-tab is selected and
retries in place on failure.

![Threat assessment with per-threat inherent and residual scores](screenshots/20-security-investigation-summary.png)

## OpenShell protection (C13-C15)

Threat pack 2.x adds three OpenShell controls: **C13** agent tool calls
run in an OpenShell sandbox (kernel-confined FS/syscalls), **C14**
declarative egress allowlist enforced at L7, **C15** credential brokering so
agents never hold secrets. They score like any other control (efficacy ×
threat weights) and appear in §5b automatically; §5c reports which are
active and how the run's pages were fetched.

Product/doc fetches try the managed sandbox first via the fox-services
broker (`OPENSHELL_BROKER_URL`, default `http://host.docker.internal:8210`;
`OPENSHELL_ENABLED=0` forces direct). The broker or gateway being down is
not an error: the fetch falls back to direct and each page records
`sandbox: true/false`, so the report states the protection instead of
assuming it. `app/openshell.py` owns the broker client, the deterministic
policy generator (egress = exactly the hosts the assessment fetched;
restricted/confidential tiers require human review to widen), and the
posture block stored in `controls_json["openshell"]` (survives rescore;
exposed as `openshell` in the assessment JSON).

Pinned in `tests/test_openshell.py`; pack expectations rebased in
`app/evalkit.py` (`all-controls` residual 24.3 → 24.2).

## Standards coverage sub-tab
Beside Assessment, the agent pane has a Standards coverage sub-tab: the AI
Standards & Regulations taxonomy (frameworks × 10 control pillars, 0|1|2)
served by `GET /api/standards/score-matrix` from the dashboard's `data.json`
over the compose network (`STANDARDS_BASE_URL`, cached `STANDARDS_CACHE_TTL_S`).
With an assessment open, each framework carries a deterministic relevance
score -- token overlap of its threats, active controls and known exploits
against the framework text (exact 2, substring ≥4 chars 1; stopwords dropped)
-- sorted relevance-first with the matched tokens shown as the reason.
Matrix, Detail (expandable rows with provenance, controls and pillar grid)
and Findings are one toggle apart. Findings maps each threat to control
pillars (`THREAT_PILLARS`, pinned to cover the whole threat catalogue) and
shows its standing per selected standard -- up to 3 side-by-side in Compare,
one in Single -- worst residual first, gaps before covered.

![The run's hash-chained events, from the security pane](screenshots/23-security-audit-chain.png)

## What the pack does and does not claim

The catalog is versioned (`akm-threat-pack` 2.1.0) and fingerprinted, so a
likelihood nudged from 4 to 5 changes the fingerprint, and the evalkit's eight
pinned cases plus its invariants fail CI rather than silently re-scoring every
assessment in the database. See [threatpack.md](threatpack.md) for the full
catalog, the scoring constants, and the procedure for changing it.

**C01–C15 are assessed data, not code this app implements.** The app does not
have a DLP, a DPIA, or a role mapper; it *weighs* them when scoring a product.
C13–C15 correspond to the OpenShell integration, which this app does drive.
The controls this app *enforces* over its own behaviour are catalogued
separately in [../design/controls.md](../design/controls.md).
