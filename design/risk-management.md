# Risk Management — Agent Family

Deterministic propose & draft; humans own and decide. Ledger + approval gates still apply.

Related: [risk-scoring.md](risk-scoring.md) · [02-uml.md](02-uml.md) · [interaction.md](interaction.md) · [../docs/architecture.md](../docs/architecture.md)

## Agent cards (A2A `a2a/1.0`)

| Agent | Skills | Role |
|---|---|---|
| `risk-orchestrator` | `plan_risk_cycle`, `delegate_risk_tasks`, `assemble_risk_update` | Coordinates a `risk_sync`/`risk_review` run |
| `risk-intake` | `ingest_findings`, `upsert_register`, `dedupe_risks` | Assessment/CVE/intel → register (stable keys) |
| `risk-triage` | `score_priority`, `cluster_risks`, `suggest_sla` | Ordering & grouping (severity × exposure × aging × unknowns) |
| `risk-treatment` | `propose_treatment`, `link_controls`, `link_experiments` | Extends `mitigation-advisor` (catalog + playbooks) |
| `risk-monitor` | `detect_stale`, `detect_drift`, `attention_queue` | Hygiene: stale evidence, policy drift, new CVEs, SLA breaches |
| `risk-reporter` | `draft_brief`, `draft_digest`, `plain_language_summary` | Console/briefs, persona-aware, no vanity score |
| `risk-governance` | `draft_acceptance`, `draft_transfer`, `check_policy_gates` | Decision packages (human approves) |

Reuse: `mitigation-advisor` ← `risk-treatment`, `research-collector` for sparse risks, ledger approvals for `accepted`.

## Run types

- **risk_sync** (assessment `done` or manual Sync): intake → triage → treatment stub for new High → persist, emit attention
- **risk_review** (scheduler / Lead button): monitor (stale/unowned/overdue/superseded/new CVE) → triage refresh → reporter digest (deterministic fallback if LLM fails) → optional treatment for top N
- **risk_decide** (user selects risks → Prepare acceptance/treatment): governance/treatment drafts package → parks for approval (`requester ≠ approver`) → on grant update register + ledger
- **risk_enrich** (sparse evidence): `research-collector` targeted queries → intake attaches evidence → triage may adjust confidence (not severity theater)

All go through `jobqueue` `kind=risk_sync|risk_review|risk_decide|risk_enrich` (lease, heartbeat, orphan recovery, `task_id` = ledger run id, idempotent re-sync updates rows).

## Data contracts — register fields agents may write

`priority_score`, `cluster_id`/`cluster_label`, `suggested_owner_role`, `sla_due_at`, `treatment_plan_json` (`steps[]`, `control_ids[]`, `experiment_ids[]`, `residual_notes`), `last_agent_review_at`, `monitor_flags[]` (`stale_evidence`, `no_owner`, …), `plain_summary`.

Human fields `owner`, `status=accepted` only via explicit user action or **approved** governance job.

Priority (deterministic core, LLM may explain, not replace — pinned in `tests/test_risk_scoring.py`):

```
priority = w1*residual_norm + w2*aging_norm + w3*unowned + w4*untreated + w5*uncertainty + w6*cascade_boost  (0–100)
```

Accepted/closed drop out unless review overdue.

## Console hooks

| UI | Agent |
|---|---|
| Sync risks from assessment | `risk_sync` |
| Run risk review | `risk_review` |
| Suggest treatment | `risk_treatment` |
| Prepare acceptance | `risk_decide` / governance |
| Enrich evidence | `risk_enrich` |
| Attention queue | monitor |
| Insights cards | triage + monitor flags |
| Brief generate | `risk_reporter` |

Stages shown as intake → triage → treatment → report, polled like security runs. Persona defaults: Exec digests, Lead full review+assign, DPO/Legal privacy-filtered, Researcher enrich+experiments.

## Safety

- `accepted`/`closed` require human or approved package
- Policy-change treatment → approval gate
- No ledger/register audit field deletion, no severity downgrade on unknown, no bulk accept without governance + approval
- Write-guard: no “fully mitigated” without mapped controls + evidence

## Integration map

```
Assessment done → risk_sync → Register → Console
Scheduler/CVE/policy intel → risk_review → Attention + Digest
User Treat → risk_treatment → mitigation-advisor + experiments
User Accept → governance draft → approval → Register + Ledger
Search/Graph → read enriched register
Dashboard robustness → % with treatment_plan/owner/SLA
```
