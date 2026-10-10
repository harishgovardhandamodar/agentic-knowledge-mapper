# Analysis engine

How a residual becomes a *measured* number: the calibration layer, the attack
scenarios, the probes, and the report that carries all three. This document is
for the reader who wants to know what the engine claims, what it refuses to
claim, and where each number comes from.

Related: [architecture](architecture.md) · [security-agent](security-agent.md) ·
[threatpack](threatpack.md) · [data-model](data-model.md) · [privacy](privacy.md)

## The problem it solves

`score_assessment` is deliberately arithmetic: inherent × (1 − coverage),
floored. That is what makes a number quotable, and it is also what makes a
single figure look more certain than the evidence behind it. Three facts make
that untenable, and each was measured before it was addressed:

1. **The score saturates.** Likelihood never falls below 35% of inherent, so
   the headline stops responding to controls once coverage passes 65%.
   Declaring all fifteen controls moves the residual 68.8 → 24.2, then
   flatlines — the last six are worth 0.0.
2. **Every efficacy is an estimate.** All fifteen control efficacies are
   single-analyst judgements with no external validation. The cited standard
   establishes that the control exists, not how effective it is.
3. **The catalogue is a checklist.** It can only report what was already
   thought of. A partially-mitigated system yields 39 derived scenarios its
   per-row scores cannot show.

The engine answers each with a different instrument, and the instruments
compose: the band widens under an unvalidated prior, the floor names the
controls it froze, the scenarios name the paths the rows imply, and the
probes are what can eventually narrow all of it.

## Components (UML)

```mermaid
classDiagram
    class Scoring {
        +score_assessment()
        +_floor_diagnostics()
        +control_evidence()
        +record_efficacy_trial()
    }
    class Uncertainty {
        +assessment_interval()
        +variance_budget()
        +efficacy_interval()
        +control_concentration()
    }
    class Privacy {
        +privacy_budget()
        +dp_accounting()
        +domain_spend()
        +detector_roc()
    }
    class Scenarios {
        +scenarios()
        +attack_tree()
        +uncovered_chains()
        +residual_amplifiers()
    }
    class Experiments {
        +rate_interval()
        +required_trials()
        +preregister()
        +score_result()
    }
    class Probes {
        +run_probe()
        +resolve_target()
        +record_probe_as_trial()
        +probe_library()
    }
    class Benchmarks {
        +ablation_report()
        +validate_scoring_contract()
        +grounding_confusion_matrix()
        +krippendorff_alpha()
    }
    class EvalKit {
        +run_eval()
        +engine_invariants()
    }
    Scoring --> Uncertainty : rows + provenance
    Uncertainty --> Scoring : band reads rows
    Probes --> Scoring : trials narrow priors
    Probes --> Experiments : exact intervals
    Experiments --> Scoring : verdicts become trials
    Scenarios --> Scoring : reads rows
    Privacy --> Benchmarks : ROC bounds detectors
    Benchmarks --> EvalKit : invariants gate
    Scoring --> EvalKit : contract pinned
```

`Scoring` (`app/scoring.py`) is the only module that produces a number; every
other module reads its output, questions it, or narrows it. Nothing here
re-derives the residual — the band, the budget, the scenarios and the report
all describe *this* result rather than computing their own. That one-way
dependency is what makes the guarantees composable instead of circular.

## Assessment to calibrated result (sequence)

```mermaid
sequenceDiagram
    autonumber
    participant R as Researcher
    participant API as FastAPI
    participant S as Scoring
    participant U as Uncertainty
    participant P as Privacy
    participant SC as Scenarios
    participant B as Benchmarks
    R->>API: POST /security/assessments
    API->>S: score_assessment(threats, controls)
    S-->>API: residual + floor + efficacy_evidence
    API->>U: assessment_interval(scoring)
    U-->>API: band + variance_budget
    API->>P: dp_accounting(evidence)
    P-->>API: epsilon + domain_spend
    API->>SC: scenarios(scoring)
    SC-->>API: chains + amplifiers + tree
    API->>B: ablation_report + contract check
    B-->>API: sensitivity + violations
    API-->>R: /report (all sections composed)
```

The ordering is the argument. The limitations — the variance budget, the
saturation count, the unvalidated efficacies — travel *with* the number in the
same response, because a limitations section at the end of a report is a
disclaimer, and the same limitations immediately after the number are part of
the result.

## The observation loop (activity)

This is the diagram that matters most. Everything else in this document is a
snapshot; this is the process by which the snapshots get better:

```mermaid
flowchart TD
    A[Assessment scored<br/>priors unvalidated] --> B{Band wide?}
    B -->|yes| C[Run probe against<br/>configured target]
    B -->|no| Z[Report with tight band]
    C --> D{Target reachable?}
    D -->|no| E[Unknown, not a pass<br/>no observation recorded]
    D -->|yes| F[Attack held or breached?]
    F -->|held| G[Record held trial<br/>posterior moves slightly]
    F -->|breached| H[Record breached trial<br/>posterior moves down]
    G --> I{Enough trials?}
    H --> I
    I -->|no| J[Band stays wide<br/>honestly]
    I -->|yes| K[Band narrows<br/>control becomes measured]
    E --> L[Next assessment]
    J --> L
    K --> L
    L --> B
```

Two properties make this a research instrument rather than a dashboard widget.
First, a single trial barely moves anything (0.70 → 0.76): tightening the band
*requires repeated outcomes*, which is exactly what should be demanded before a
"measured" claim. Second, a skipped or unreachable run records nothing — "could
not tell" never becomes "no problem".

## Experiment lifecycle (state)

```mermaid
stateDiagram-v2
    [*] --> proposed : plan_experiments
    proposed --> preregistered : preregister fixes n, alpha, decision rule
    preregistered --> executed : probe runs against target
    executed --> scored : exact interval computed
    scored --> effective : attack succeeded
    scored --> inconclusive : interval too wide
    scored --> consistent : clean but unproven
    effective --> [*] : breached trial recorded
    inconclusive --> preregistered : run more trials
    consistent --> [*] : held trials recorded
    proposed --> [*] : nothing open
```

The states a result can land in are deliberately asymmetric. There is no
"passed" state: `supported_but_unmeasured` is consistent-with-the-claim, not
proof of it, and `inconclusive` carries the recommended trial count rather than
a failure. A clean run over too few trials is the most common way a red-team
exercise overclaims, so it gets its own state instead of being rounded up.

## Probe execution (activity)

```mermaid
flowchart TD
    A[Probe requested] --> B{Probe id known?}
    B -->|no| R1[Refuse: unknown probe<br/>nothing sent]
    B -->|yes| C{Confirmed?}
    C -->|no| R2[Dry run: report plan<br/>nothing sent]
    C -->|yes| D{Target configured?}
    D -->|no| R3[Refuse: no target<br/>never guess one]
    D -->|yes| E{Host on allow-list?}
    E -->|no| R4[Refuse: not authorised<br/>to test this host]
    E -->|yes| F[Send fixed payloads<br/>sequentially, bounded]
    F --> G{Any HTTP 200?}
    G -->|no| R5[Unreachable: unknown<br/>not a pass]
    G -->|yes| H[Score each trial<br/>exact interval]
    H --> I{Attribute to controls?}
    I -->|yes| J[Record efficacy trials<br/>band can narrow]
    I -->|no| K[Report only]
```

Five exit paths refuse or report unknown, one path executes. That ratio is the
safety envelope made visible: a probe harness that could pick its own target
would be a vulnerability, not an instrument.

## Scenario derivation (flowchart)

```mermaid
flowchart LR
    R[Threat rows<br/>with coverage] --> D{Coverage<br/>declines?}
    D -->|pairwise| C[Chain: T05 via T01<br/>gap named]
    D -->|3-hop| M[Chain: T05 via T01 → T02<br/>gap named]
    R --> F{At the floor?}
    F -->|yes| A[Amplifier: incident<br/>lands here]
    R --> P{Same absence<br/>in several rows?}
    P -->|yes| X[Programme gap:<br/>one fix, many rows]
    C --> T[Attack tree<br/>nodes + edges]
    M --> T
    A --> S[Scenario set<br/>all traced]
    X --> S
```

The ordering constraint is what makes multi-hop enumeration tractable and
meaningful: a path only extends while coverage *falls*. Without monotone
decline the enumeration is combinatorial and says nothing. On the shipped
catalogue a four-control posture yields 24 chains, 8 amplifiers and 7
programme gaps — 39 findings no per-row score produces. Fully mitigated, the 13
remaining are all distinct (endpoint, gap) pairs, never restatements.

## Researcher interaction (sequence)

```mermaid
sequenceDiagram
    autonumber
    participant R as Researcher
    participant Cal as /calibration
    participant Sce as /scenarios
    participant Exp as /experiments
    participant Prb as /probes
    participant Rep as /report
    R->>Cal: where does the score saturate?
    Cal-->>R: curve + beyond-floor count
    R->>Sce: what paths does that imply?
    Sce-->>R: chains + attack tree
    R->>Exp: what would settle the worst one?
    Exp-->>R: pre-registered plan + trial count
    R->>Prb: run it against my target
    Prb-->>R: interval + recorded trial
    R->>Cal: did the band move?
    Cal-->>R: narrowed band or honest width
    R->>Rep: compose everything
    Rep-->>R: report with limitations inline
```

This is the PhD-level workflow the tool supports: calibrate → derive → plan →
execute → re-calibrate → publish. Each step names what it does not know, so
the loop converges on measured claims rather than on confident ones.

## What is measured, what is not

| Property | Status | Where |
|---|---|---|
| Residual saturation | measured (leave-one-out ablation) | `floor` block |
| Efficacy provenance | recorded (basis, n, concentration) | `control_evidence` |
| Interval width | propagated from provenance | `assessment_interval` |
| Variance attribution | decomposed (signed interaction) | `variance_budget` |
| (ε, δ) composition | accounted, **not enforced** | `dp_accounting` |
| Detector reliability | bounded (AUC 0.95 / 1.00) | `detector_roc` |
| Trial rates | exact (Clopper-Pearson) | `rate_interval` |
| Agreement | κ + α + AC1 side by side | `inter_rater` |
| Contract drift | pinned (24 invariants) | `engine_invariants` |

The one row in bold is the most important in the table. The engine adds no
noise, so `dp_accounting` returns `mechanism: "accounted-not-enforced"` and
states in its own note that this is NOT a differential-privacy guarantee — and
an invariant enforces the caveat, so a future edit cannot quietly drop it.
