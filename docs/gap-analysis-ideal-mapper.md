# Gap Analysis — Ideal Agentic Knowledge Mapper + AI Security Engineering & Evaluation Agent

Branch: `gap-analysis/ideal-mapper-security-eval`
Date: 2026-09-27
Scope: hallucination reduction, drift detection, proactive support / best yield,
audit + logging / traceback.

This is a findings-only report. No behavior changed on this branch.

## 0. What already exists (so gaps are relative)

- Hash-chained ledger: `app/ledger.py:981-1057` (`append`), `1321-1382`
  (`verify_chain`), `1206-1254` (`verify_proof`), `1479-1563`
  (`contamination`), `1627-1727` (`detect_drift`, 6 signals).
- Hallucination gate: `app/ledger.py:337-390`
  (`quote_is_verbatim` + `verify_grounding`), mirrored in
  `app/explainer.py:641-692` (`_quote_valid` + `_verify_grounding`).
- Single LLM choke point with audit: `app/llm.py:124-200` (`chat`
  → `ledger.record_llm_call` + gateway proof headers).
- Evidence→claim binding: `app/agents.py:323-349` (`_audit_evidence`).
- Topic drift prefilter + LLM judge: `app/drift.py:47-100`
  (`drift_candidates`, `classify_drift`).
- A2A security workflow + deterministic scoring:
  `app/agents.py:148-257,623-714`, `app/security.py:941-1092`,
  `app/security_agent.py:32-192`.
- Scheduler: `app/scheduler.py:29-42` (`next_time`, `compute_next`), cron rerun
  per investigation.
- Session/run timeline + insights: `app/ledger.py:744-912`
  (`session_insights`), `585-613` (`session_timeline`).

Ideal bar used below: every LLM claim is verifiable to an exact source span;
drift is measured (precision/recall, trend, alert), not just flagged;
the agent proactively maximizes information yield per cost; every hop is
replayable end-to-end (prompt → model → output → claim → action).

---

## 1. Hallucination — gaps

### H1. Verbatim-substring check only, no semantic entailment
- `quote_is_verbatim` (`app/ledger.py:337-352`) and `_quote_valid`
  (`app/explainer.py:641-649`): normalized `in` check + head(25)/tail(10)
  fallback, min 12 chars. Catches invented quotes but not:
  paraphrase drift, negation flip, number/unit swap inside a long quote,
  or claim that is lexically present but contextually contradicted.
- No NLI / entailment scorer, no embedding similarity fallback, duplicated
  logic in two files (import-cycle comment) → drift risk between the copies.
- Quotes truncated to 180 chars (`verify_grounding`, `_verify_grounding`)
  before storage → lossy provenance; no char-offset / page-span stored.

### H2. Single-source / low-corroboration claims still propagate
- Confidence = count of distinct sources (`1→low, 2→medium, 3+→high`),
  verdict `supported` with just 1 source (`app/ledger.py:355-390`,
  `app/explainer.py:652-692`). No source-independence check (two RSS mirrors
  of same wire = 2 sources), no source-quality / recency weight.
- Ungrounded claims are recorded and only surfaced later via
  `detect_drift:ungrounded_claim` (`app/ledger.py:1700-1711`) — no
  block-at-write policy option.

### H3. LLM-generated prose bypasses the gate
- `_llm_exec_paragraph` (`app/agents.py:599-620`): prompt says "cite evidence
  by artifact #id", temperature 0.2, but output is not passed through
  `verify_grounding` post-hoc. Empty/unavailable fallback is deterministic
  (`app/agents.py:685-703`) — good — but the LLM path has no quote check.
- `classify_drift` prompt (`app/drift.py:84-94`) and explainer `_compose`
  (`app/explainer.py:695-807`) rely on instruction-following, no JSON-schema /
  function-call enforcement; `chat_json` lenient parse can silently drop.

### H4. No claim decomposition, no calibration, no eval
- Long answers scored as whole claims; no atomic-claim splitting, no per-claim
  confidence calibration, no hallucination-rate dashboard / regression test.
- `_audit_evidence` (`app/agents.py:323-349`) grounds against
  `art.description or art.content` — if that field is truncated at ingest,
  verbatim check is against a truncated surrogate, not the fetched page.
- Threat catalog (`app/security.py`) is static; threat descriptions are not
  claim-bound, so security prose is ungrounded by construction.

**Fix direction:** shared `verify_grounding` single implementation + span
offsets; NLI/entailment second pass for `n_sources==1`; post-hoc verify on
exec paragraph + drift judge; atomic claims; nightly hallucination eval
(synthetic invented-quote + negation-flip fixtures); source-independence +
quality weights.

---

## 2. Drift detection — gaps

### D1. Content-blind prefilter
- `drift_candidates` (`app/drift.py:47-60`) uses only `title + tags`
  (`item_terms`), ignores `description/content`, drops tokens <3 chars
  (`content_tokens`, `app/drift.py:30-34`) so `AI`, `ML`, `IoT` never count.
  Docstring itself admits synonym blindness ("Reward misspecification" shares
  no words yet is on-topic) with no embedding fallback.

### D2. Fail-open silently clears real drift
- `classify_drift` (`app/drift.py:63-100`): any LLM error / bad shape / empty
  returns `set()` "so callers mark nothing rather than mis-marking". Correct
  to avoid false positives, but failure is silent — no `drift.judge_failed`
  ledger event, no retry, no metric. `limit=30, batch=8` truncates beyond 30
  with no overflow signal.
- Brief text truncated to 800 chars, item titles to 150 chars — long briefs
  lose constraints.

### D3. Ledger drift is rule-only, no statistical / temporal drift
- `detect_drift` (`app/ledger.py:1627-1727`) covers budget, unplanned intent,
  scope/domain, loop, `violation_not_halted`, ungrounded/unverified propagation
  — solid — but: no embedding/concept drift over time, no baseline vs. current
  distribution, no threshold auto-tune, no trend (`drift rate per run`).
- `INTERNAL_KINDS` / `system` exclusion is correct but brittle: a renamed
  internal kind self-reports drift.

### D4. No proactive drift UX
- Single-item hand-mark `set_artifact_drift` (`app/main.py:662-677`); no bulk
  re-eval, no drift trend chart, no webhook/alert on `severity==block`,
  no auto-quarantine option. Graph dims drift but review queue has no
  precision/recall feedback loop to tune `classify_drift`.

**Fix direction:** include `description/content` tokens + embedding candidate
recall; log `drift.judge_failed` with retry/DLQ; overflow event past limit;
temporal drift (per-investigation embedding centroid shift + threshold);
drift dashboard (rate, precision from human clear/mark, block alerts).

---

## 3. Proactive support / best yield — gaps

### P1. Scheduler is wall-clock only, not yield-aware
- `compute_next` / `next_time` (`app/scheduler.py:39-42,29-36`): cron + enabled
  flag only. No signal for: coverage gaps, new exploits, stale high-relevance
  artifacts, control-plan changes. No backoff when yield is repeatedly zero,
  no priority across investigations.

### P2. REFINE loop has no learning
- Agent loop `REFINE if yield is low` (README) is bounded by fixed
  `max_rounds / max_items`; no query-performance memory (which query shapes
  yielded), no bandit / MMR diversity, no dedupe across runs beyond URL/title,
  no cost-per-keep accounting (LLM calls vs. kept artifacts).
- Relevance `0..1` from LLM batch has no calibration plot; `relates_to[]`
  tag-overlap fallback can manufacture graph edges when the LLM drops them.

### P3. No proactive surfacing
- Missing: "stale brief" nudge, "dimension X has 0 coverage" suggestion,
  "new known-exploit maps to your stack" push, "control C04 would cut residual
  by N" recommender (data exists in `score_assessment` breakdown but no
  recommender calls it), scheduled re-assessment trigger on new evidence.
- `session_insights` (`app/ledger.py:744-912`) aggregates well but is
  pull-only; no digest / notification consumer.

**Fix direction:** yield ledger per query shape (kept/cost); MMR + novelty
filter; coverage-gap + control-leverage recommenders over existing scoring
breakdown; event-triggered reschedule (new exploit, drift spike) in addition
to cron; human-readable proactive digest from `session_insights`.

---

## 4. Audit, logging, traceback — gaps

### A1. Fail-open auditing loses trail silently
- All `record_*` wrappers go through `_safe` (`app/ledger.py:2219-2227`):
  exceptions swallowed, return `None`. `_audit_hop`
  (`app/agents.py:786-796`) only `print`s on drop. No dead-letter table,
  no `audit_dropped` counter, no alert. A full disk / locked SQLite silently
  yields gaps in the "immutable" chain.
- `record_human_action` drops when no run is open (`app/ledger.py:2253-2261`);
  session fallback exists (`record_session_action`) but `record_human`
  dispatch order means UI clicks outside a run land on a synthetic
  `{session}-ui` run — confusing for traceback.

### A2. Logging is `print`, not structured
- No JSON log lines, no log levels, no request-id middleware, no OpenTelemetry
  spans. Correlation relies on `task_id` / `run_id` passed manually
  (`_audit_run_id`, `app/agents.py:753-756`); HTTP ↔ A2A ↔ LLM ↔ scheduler
  hops do not share one trace-id header end-to-end.
- Gateway proof (`x-fox-request-id`, `x-fox-proof` in `app/llm.py:124-200`)
  only present on gateway path; direct/Ollama path emits digest-only
  `_report_proof` — replay granularity differs by backend.

### A3. Store + retention + auth gaps
- SQLite single file (`data/akm.db`): no WORM / append-only enforcement at
  storage layer (chain verifies tampering after the fact via
  `verify_chain`, but nothing prevents delete + rewrite + re-anchor).
  No signing key, no timestamp authority for `verify_export`
  (`app/ledger.py:1861-1867`), no retention / redaction-audit policy though
  `_redact` (`app/ledger.py:147-170`) exists.
- `request_actor` / `require_authorized` (`standards-dashboard/benchmark-api/
  app.py`, `app/ledger_api.py`) — no RBAC matrix; `record_action`
  (`app/ledger_api.py:385-408`) accepts any `actor` string with
  `actor_type` defaulting to `system`. Human vs. agent attribution is
  self-declared.
- `contamination(run_id, ref, max_depth=12)` (`app/ledger.py:1479-1563`)
  caps depth at 12 with no pagination of blast radius; no UI graph of
  claim → event → LLM prompt replay (prompt digest stored via
  `text_digest`, full prompt text handling unclear for replay).

**Fix direction:** DLQ table + `audit_dropped` metric + alert; structured JSON
logging with `trace_id` propagated in `open_session`/`dispatch`/`chat`;
per-backend proof normalization; export signing + retention policy doc;
authn actor (no self-declared `system`); contamination UI + full prompt replay
from stored digests/claims.

---

## 5. AI Security Engineering & Evaluation Agent — gaps

### S1. Static catalog, arithmetic scoring, no evaluation harness
- `_THREAT_CATALOG`, `EXPOSURE_META` weights, `_scale_likelihood`
  (`app/security.py`): deterministic and repeatable (good) but unvalidated —
  no MITRE ATT&CK / OWASP version pin, no CVSS mapping, no inter-rater study
  of `control-analyst` applicability vs. humans.
- `standards-dashboard/scripts/eval_scoring.py` (`evaluate_response`,
  `load_framework_names`) and `benchmark-api/app.py` (`require_authorized`,
  `_mutation_error`) are dashboard-scoped, not wired as a backend eval gate
  for `build_assessment`. No red-team / adversarial prompt suite, no
  regression benchmark on `overall_pct/inherent_pct/residual_pct`.

### S2. Control effectiveness is asserted, not measured
- `delta = inherent − residual` is arithmetic over declared controls; no
  post-deployment verification (was C04 actually enabled?), no exploit-
  likelihood update from `known_exploits` / in-app evidence weight.
  Approval gate (`app/security_agent.py:195-217`, `awaiting_approval`) can be
  bypassed with `approved_control_plan` override — no separate approver
  identity required.

### S3. Execution fragility
- `launch_security_assessment` uses bare `threading.Thread(daemon=True)`
  (`app/security_agent.py:195-217`): no job queue, no retry, no idempotency
  key, daemon death on restart loses runs. Heuristic fallback
  `_heuristic_applicability` keys T09 on `hallucinat/stale/accuracy…`
  (`app/agents.py:167-190`) — keyword match, not model behavior test.

**Fix direction:** versioned threat pack (MITRE/OWASP ids + CVSS); backend eval
gate calling `eval_scoring` on every `build_assessment` change; control
verification checklist + residual re-score on new evidence; job queue
(persisted runs, retry, idempotency); mandatory distinct approver for
`require_approval`; adversarial eval set for prompt-injection / data-exfil
paths.

---

## 6. Prioritized backlog (highest leverage first)

| # | Gap | File:line | Why first |
|---|-----|-----------|-----------|
| 1 | Post-hoc verify LLM prose + shared grounding impl | `app/agents.py:599-620`, `app/ledger.py:355-390`, `app/explainer.py:652-692` | Closes biggest hallucination hole |
| 2 | `drift.judge_failed` event + retry + overflow signal | `app/drift.py:63-100` | Turns silent fail-open into visible debt |
| 3 | Audit DLQ + structured trace-id logging | `app/ledger.py:2219-2227`, `app/agents.py:786-796`, `app/llm.py:124-200` | "Immutable" ledger currently losable |
| 4 | Embedding recall + content tokens for drift candidates | `app/drift.py:30-60` | Cheapest drift precision win |
| 5 | Yield ledger + coverage/control recommenders | `app/scheduler.py:29-42`, `app/security.py:723-938` | Proactive + best-yield unlock |
| 6 | Backend eval gate + versioned threat pack | `app/security.py:941-1092`, `standards-dashboard/scripts/eval_scoring.py` | Makes security agent an *evaluation* agent |
| 7 | Job queue + distinct-approver gate | `app/jobqueue.py`, `app/approvals.py` | Reliability + governance |
| 8 | Export signing + retention + RBAC | `app/ledger.py:1861-1867`, `app/ledger_api.py:385-408` | Audit completeness for traceback |

---

## 7. Suggested verification for each fix

- H: fixture suite with invented quotes, negation flips, number swaps →
  assert `verify_grounding` drops + `grounding_violations` recorded;
  hallucination rate metric per model (`llm_models` in `session_insights`).
- D: labeled drift fixture (in-brief synonyms vs. true off-brief) → report
  precision/recall of `drift_candidates + classify_drift`; chaos test with LLM
  gateway down → assert `drift.judge_failed` event, not silent empty set.
- P/Y: yield-per-query-shape table; A/B MMR vs. relevance-only on kept-rate
  and graph diversity; coverage-gap recommender acceptance rate.
- A: kill `-9` mid-run + disk-full injection → assert DLQ rows +
  `verify_chain` failure pinpoints missing seq; trace-id present on every hop
  in `session_timeline`; `verify_export` offline check passes with signature.
- S: versioned catalog diff test; `eval_scoring` gate blocks residual
  regression; red-team prompt-injection suite must not change control plan
  without approval event.
- Q/A: `kill -9` mid-assessment → restart → assert the `jobs` row is re-queued
  (lease expired) rather than the `AgentRun` sitting at "running"; a slow job
  with a live lease must **not** be re-claimed. Approval: requester ≠ approver
  (case-insensitive) → 403; `approved_control_plan` with no `approved_by` →
  ignored, run parks; decision lands on the ledger naming both.
