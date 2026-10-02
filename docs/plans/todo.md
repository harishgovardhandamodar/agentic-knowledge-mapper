# TODO — experiments, hypothesis builder, versioning

Plan: `docs/plans/experiments-hypothesis-versioning.md`.
Branch: `plan-experiments-hypothesis`.
Legend: `[ ]` todo · `[x]` done. Tick items off as PRs land; each PR must
keep the suite green and preserve the §0 non-negotiables (path separation,
null scores, MM-as-recommendation, ledger/approval rules, stored-rows-only
dossier, method+versions on every row).

## PR-1 — Stats completeness + confidence test pins
- [x] §2 Assessment line carries pack version + fingerprint (backend + preview)
- [x] Dossier test: planted assessment stats → §2 has residual + posture + fingerprint
- [x] History `stats_complete` field test (backend)
- [x] Summary `run_health` test (failed count + gap goals)
- [x] Full dossier/history/summary tests green (937 passed suite-wide)

## PR-2 — Version policy + superseded badge + re-score as new row
- [x] `CHANGE_POLICY` in `threatpack.py` + `model_eval.py`
- [x] Fingerprint-without-version-bump fails CI (test)
- [x] Version-bump-with-moved-numbers requires evalkit update (test)
- [x] Dossier §4 + history: superseded-pack badge
- [x] Rescore-persist creates new row + ledger event (was mutating in place)
- [x] Old row byte-identical after re-score (test)
- [x] Full suite green (946 passed)

## PR-3 — Shared research cache
- [x] `(investigation_id, subject_key)` cache lookup in collector
- [x] W1/W2/W3 + parallel manager jobs reuse (no triplicated fan-out)
- [x] Cache hit/miss tests (isolated DB)
- [x] Product path byte-identical behavior (regression tests green)

## PR-4 — Hypothesis register + builder
- [x] Claim dicts: `hypothesis_id`, `status`, `falsifiers[]` (migrate single string)
- [x] Register read/update API (scored `confidence_pct` untouched — test the invariant)
- [x] "Collect evidence" / "propose experiments" actions
- [x] Prior-row terminal gate (`allow_partial` override + gap claims)
- [x] Builder UI view
- [x] Dossier hypothesis section as register table

## PR-5 — Experiment builder
- [x] `experiment_plan_v1` schema stored on assessment
- [x] `experiment-planner` agent card + handler (deterministic filters first)
- [x] W4 wiring + on-demand build without full W3
- [x] Falsifier→experiment links; MM→validation links
- [x] Experiments UI section/tab + dossier section (all exports, plan-only disclaimer)
- [x] Evalkit fixtures (§4.6 cases)

## PR-6 — W3 tightening verification
- [x] Empty W1/W2 + W3 → explicit empty plan (evalkit or unit pin)
- [x] Deferred-with-reason renders (test)
- [x] Uncovered high-confidence attack stays visible (test)

## PR-7 — Re-score compare + pack diff
- [x] Side-by-side compare, methods must match (cross-method → 422)
- [x] Pack diff report (product only, explicit action)

## PR-8 — Changelog + deprecation + immutability evalkit
- [x] `PACK_CHANGELOG` artifact (+ model catalogs) + readable endpoint
- [x] Dossier changelog excerpt when pack ≠ current
- [x] `deprecated` + `replaced_by` (new rows ignore, old rows render)
- [x] N-1 pack row displays/exports without N arithmetic (test)
- [x] `score_assessment` purity test

## PR-9 — Product evidence quality
- [x] Unify vendor-doc query guarantee (product + model briefs)
- [x] Auto-refine once on zero vendor-primary keeps
- [x] Per-control `declared | evidenced | unknown` + dossier marking
- [x] Recommender: stale assessment / zero-evidence high-leverage control flags

## PR-10 — Efficiency + manager synthesis
- [x] Per-stage durations surfaced (run stats + dossier §2)
- [x] Manager synthesis: open gaps, incomplete stats, deferred MM, open falsifiers
- [x] explainer_gap durability kept (no regression)

---

# TODO — model security knowledge base & landscape

Plan: `docs/plans/model-security-kb-landscape.md`.
Branch: `model-security-kb-landscape`.
Legend: `[ ]` todo · `[x]` done. Inherits every §0 non-negotiable above.

## KB-1 — Schema (additive only)
- [x] `Artifact.stable_key` / `node_meta` / `assessment_id`
- [x] `Relationship.payload_json` / `stable_key`
- [x] `SecurityAssessment.kb_json` / `kb_fingerprint`
- [x] Migrations additive — no column rewrite or backfill of existing rows

## KB-2 — Sync layer
- [x] `model_kb.sync_model_kb(db, assessment_id)` idempotent (re-run = no dupes)
- [x] Post-assessment hook in `security_agent` — sync failure keeps the assessment
- [x] Snapshot built from stored columns only, never a live re-score

## KB-3 — Scope partition (own / inherited / cascade)
- [x] `model_specific`→own, `family`/`modality`→inherited
- [x] Cascade checked **first** — composition rows can never land in `inherited`
- [x] No-evidence stays `null`; cascade rows keep basis + mechanism + note
- [x] Explicit `assessment_path` honored (`standard` not re-judged by profiler)
- [x] Product assessments never create model nodes

## KB-4 — Landscape API + registers
- [x] `GET /security/landscape` (inventory, registers, gaps, catalogs)
- [x] `GET /security/landscape/graph` (filtered, scoped edges)
- [x] `POST /security/landscape/compare` — hard-gate filters, opt-in weights
- [x] No default winner; excluded models carry `exclusion_reasons`
- [x] Unknown filter/axis name → 422, never silently dropped
- [x] `POST /security/landscape/decision` — logged human judgement, no score
- [x] `supersedes` edges persisted, lineage-aware, comparable versions only
- [x] `POST /security/assessments/{id}/kb/sync` (stale/legacy rows)

## KB-5 — Dossier
- [x] KB snapshot JSON + Markdown section (partition counts, cascade, gaps, fingerprint)
- [x] Reads stored rows only; derivation provenance recorded

## KB-6 — Landscape UI
- [x] Inventory / Risk / Graph / Insights / Compare / Gaps views
- [x] Graph payload aliases match renderer field names
- [x] Compare renderer reads `selection_scorecard` keys
- [x] Decision recording (selected / rejected) with actor attribution

## KB-7 — Hypotheses + experiments
- [x] Falsifier→experiment links drive derived experiment plans
- [x] Plan is deterministic, stored-row derived; failure surfaces as `experiment_plan_error`

## KB-8 — Tests + evalkit
- [x] 66 KB tests (partition, idempotency, cascade, filters, weights, decisions)
- [x] Real-pipeline sync-hook test (`run_security_assessment` end to end)
- [x] Evalkit: 5 KB partition cases (15/15 green)
- [x] Full suite green with the known A2A hang deselected

# TODO — RLHF / preference-feedback retention

Branch: `rlhf-feedback-retention`.
Rule: preference, feedback and post-training rows are standings per (provider × tier × class) with `as_of` + sources; never applied across tiers; safety logs are not capability training.

## RLHF-1 — Catalog, assess, register
- [x] `akm-rlhf-feedback-retention` RLHF01–08 with classes A–F, tiers, layers, own fingerprint
- [x] Deterministic assess from accepted evidence (partial at best); human override sole path to supported
- [x] Register rows with `subclass: preference_feedback`, null severity, catalog stamps
- [x] No-bleed: API no-train claims leave safety-log rows unknown (pinned)

## RLHF-2 — Collection, graph, advice, synthesis
- [x] Planner prompt spreads policy/trust/feedback/safety; backstop families ordered, cap held at six
- [x] Contribution edge vocabulary (`feedback_submitted`, `sampled_for_review`, `training_opt_in`, `abuse_log`, `crawl`)
- [x] PB06 preference-and-feedback playbook; per-tier table; capability/safety/org-api datapoint answers
- [x] Synthesis RLHF subsection with tier tables and separated answers

## RLHF-3 — Tests, gate, docs
- [x] 12 RLHF tests (catalog, assess, no-bleed, override, tier table, answers, register, edges, playbook, synthesis)
- [x] 4 evalkit cases + 2 invariants (gate: 10 provider cases, 5 invariants)
- [x] Full suite green with the known A2A case deselected
- [x] Live image rebuild + live verification

# TODO — provider safety research context (addendum to PDP)

Branch: `provider-safety-research`.
Rule: safety literature contextualizes governance/eval practice; it never moves a PDP standing and never scores data safety.

## SAF-1 — Catalog + firewall
- [x] `provider_safety_context_v1` SAF01–SAF06 with claim classes, own fingerprint
- [x] Firewall: safety-typed sources reach PDP only with data terms in the same document
- [x] Human override the sole path to supported (both catalogs)

## SAF-2 — Collection, graph, synthesis
- [x] Safety planner families (RSP, system card, eval/red-team, RLHF) within the six-query cap
- [x] Safety-feedback contribution paths gated on evidenced PDP06
- [x] Synthesis safety subsection: framework coverage, dual transparency matrix, residual unknowns

## SAF-3 — Advice, intel, surfaces
- [x] PB05 safety checks (eval participation, tier clarity, no paper-count privacy)
- [x] Intel `new_posture_sources` (terms + safety publications as re-review triggers)
- [x] Dashboard safety source coverage under availability (never robustness)
- [x] 8 safety tests, 6 evalkit cases + 3 invariants
- [x] Summary renderer: `####`–`######` headers, mermaid fences via the shared render queue (was raw code), verified against live run #18 synthesis
- [x] AKM Executive-summary overlay: workflow `exec_paragraph` through the mini renderer (was escaped raw `**`), verified against live inv-4 payload
- [x] Dossier preview "reports, as written": report markdown rendered (was raw `<pre>`), verified against live assessment #95; fenced diagrams drawn live via the existing queue hook
- [x] AKM summary carries the manager synthesis: `manager_synthesis` in the summary payload + rendered section in the overlay (was one click away), verified against live run #18 / inv 71
- [x] Full suite green with the known A2A case deselected
- [x] Live image rebuild + live verification

# TODO — provider AGI data posture (`provider_data_posture`)

Branch: `provider-data-posture`.
Legend: `[ ]` todo · `[x]` done. Same non-negotiables plus: stated policy vs reporting vs unknown; no scores for posture; nothing invented about internal systems.

## PDP-1 — Manager template + collection
- [x] Deterministic provider-first parse (named providers + data question; capability-only rejected)
- [x] One topic per provider, canonical subjects, task preserved, single product-style assessment per topic
- [x] Situation defaults (org confidential+PII, API, employees+service accounts) + keyword marker seeded
- [x] Planner policy/trust/reporting query families, capped at six
- [x] Manager template chip pre-filling the command

## PDP-2 — Findings, register, contribution map
- [x] `provider_data_posture_v1` PDP01–PDP10, fingerprinted; standings (supported/partial/unknown/contradicted), never scores
- [x] Deterministic assess from accepted evidence only (partial at best); human override the sole path to supported
- [x] Register rows with null severity, `provider_posture` tag, catalog stamps; tag filter on the register endpoint
- [x] Direct/indirect contribution map + mermaid + datapoint one-pager
- [x] Claim guard stripping definite training assertions without tier terms

## PDP-3 — Synthesis, advice, surfaces
- [x] Compile compare section (PDP table, datapoint answers, indirect map, unknowns) for posture runs
- [x] PB05 provider playbook selected by confidential+external situations
- [x] Dashboard `by_provider` distribution + PDP coverage light
- [x] 24 provider tests, 6 evalkit cases + 3 invariants
- [x] Full suite green with the known A2A case deselected
- [x] Live image rebuild + live verification

# TODO — executive / leadership dashboard

Branch: `executive-dashboard`.
Legend: `[ ]` todo · `[x]` done. Same non-negotiables: read-only aggregates, no new scoring, no composite score, unknowns inflate attention.

## EX-1 — Backend aggregates (`app/executive.py`)
- [x] Scope validation (investigation/initiative/layer/exposure/accepted-only)
- [x] Availability: initiative/model/product coverage, register completeness, evidence freshness, stale queue, W2 unknowns, KB sync health, traffic lights
- [x] Distribution: by layer/scope/status/exposure/family/pattern/initiative, assessment volume, deterministic insight cards
- [x] Robustness: mapping rate, validation rate, acceptance discipline, inventory lift, approval hygiene (SLA + self-approval), hypothesis closure, re-assess follow-up, pack hygiene, standing limitations block
- [x] Attention queue with stated rank bands + drill-down links
- [x] Summary header strip + board-safe Markdown brief (+ PDF via existing builder)

## EX-2 — Snapshots + trends
- [x] `dashboard_snapshots` table + idempotent daily write + scheduler hourly tick
- [x] Trends endpoint renders gaps as gaps; empty series reads unknown, not flat
- [x] `POST /api/dashboard/snapshot` ledgered; brief `.md` + `.pdf` exports

## EX-3 — UI + tests
- [x] Dashboard subtab with CISO/Lead/Manager presets (reorder only), scope controls, drill-downs into Landscape/Portfolio
- [x] Top-level Leadership Dashboard app tab (independent pane, own investigation selector, `#dashboard` deep link); drill-downs cross into AI Security tabs
- [x] Fixed `currentInv.id` readers (currentInv is the id; `.id` broke Landscape/Portfolio/Dashboard scoping in-browser)
- [x] Dashboard boot loads investigations + auto-selects when opened directly (fresh session no longer shows an empty tab)
- [x] Repaired pane nesting swallowed by the top-level move (two missing closers hid every pane after Security; verified all six tabs by screenshot)
- [x] Fixed Portfolio JS living outside `</script>` (dead in browser until this change)
- [x] 25 executive tests (metric definitions, accepted-only toggle, hygiene violations, snapshots, brief)
- [x] Full suite green with the known A2A case deselected
- [x] Live image rebuild + live verification

# TODO — portfolio risk register addendum

Branch: `portfolio-risk-register`.
Legend: `[ ]` todo · `[x]` done. Same non-negotiables: additive schema, stored rows only, unknown stays unknown, advice never claims secured.

## PF-1 — Initiative + situation schema
- [x] `Initiative` object with business use case, owner, data classes, systems, obligations, control inventory, lifecycle
- [x] `SecurityAssessment.situation_json` + `initiative_id` + `requested_by` (additive migrations)
- [x] Versioned situation snapshots; readers unwrap the stated profile, not the audit envelope

## PF-2 — Leakage catalog + playbooks
- [x] Versioned `LP01`–`LP08` pathways with sinks, likelihood, exposure, controls, process patterns
- [x] Situation-keyed playbooks `PB01`–`PB04` with fingerprints
- [x] Declared-only controls contribute no coverage

## PF-3 — Unified register
- [x] Product/model/privacy/supply-chain rows with stable keys and catalog stamps
- [x] Human overlay (`status`, `owner`, `review_by`, mitigation IDs, acceptance) survives re-derivation
- [x] Every row names catalog-level control options; no empty-controls ambiguity
- [x] Acceptance requires `accepted_by` + note and rejects self-acceptance when the requester is known

## PF-4 — Cascade + advisor
- [x] Explicit and transitive cascade edges with `via` paths
- [x] Deterministic advisor with constraint filtering, inventory deltas, residual limitations
- [x] Initiative-scoped advice uses the initiative’s inventory and linked assessments only
- [x] `mitigation-advisor` A2A role (`advise_portfolio_risks`): card, bus handler, pipeline hop after KB sync, same deterministic pack as the tab

## PF-5 — Intel, metrics, surfaces
- [x] Intel feed, metrics without composite scores, initiative aggregates
- [x] Portfolio API endpoints, dossier situation snapshot, Portfolio tab views
- [x] API tests for initiatives, situation, register state, advisor, intel/metrics/cascade
- [x] Portfolio evalkit: 8 pinned cases + 4 invariants (multiplier honesty, coverage, mapping, cascade, fingerprints)
- [x] Live image rebuild + live verification (all 5 endpoints 200, card served, advisor POST returns deterministic pack; intel correctly flags 3 stale pack stamps)

# TODO — RLHF memorization risks (RM01–06)

Branch: `rlhf-memorization`.
Rule: model memorization science (W1) vs tenant eligibility (RLHF retention + situation) — no single privacy score; unknown stays unknown.

## RM-1 — Taxonomy + catalog
- [x] Add `memorization` (80) + `alignment_data_leakage` (75) to ATTACK_CLASSES; subtypes `preference_memorization`, `sft_memorization`, `preference_mi`, `rlhf_preference_extraction` with `valid_subtype` helper
- [x] `method_general` scope weight 0.25 (RLHF-as-technique, less than family); `scope_of_finding` passes subtype through
- [x] RM01–06 catalog `akm-rlhf-memorization` v1.0.0 with data_class, pipeline_stage, mitigations; fingerprint

## RM-2 — Register + KB + scoring
- [x] KB `_risk_register` subtype passthrough; portfolio `_rm_rows` (model + provider-joined RM05/06) with null severity → no band
- [x] W1 fallback keys for preference/SFT/RLHF memorization; LLM prompt subtypes + `method_general` allowed
- [x] W3 mitigation catalog extended (MM01/02/03/05/08/12 now cover new classes) + MM16 feedback minimization; W4 `_CLASS_EXPERIMENTS` for new classes
- [x] `preference_data_exposure` meta signal (unknown|low|high)

## RM-3 — Collection, hypothesis, advice
- [x] Agent cards: `model-adv-intel` map_rlhf_memorization, `experiment-planner` RLHF templates, `research-collector` rlhf_memorization pack
- [x] Query pack: RLHF memorization families injected when focus matches rlhf|preference|reward model
- [x] Hypothesis fallback H-RM01 (family preference memorization) + H-RM05 (org feedback exclusion)
- [x] Report section `RLHF / preference memorization (RM01–06)` after W1; leakage playbook PB07

## RM-4 — Graph, dossier, surfaces, guard
- [x] Unified register columns `retention_context`, `extractability_confidence`, `org_controllability` on RM rows; tags `rlhf_memorization`
- [x] Landscape/Portfolio tag filter `rlhf_memorization`
- [x] Dashboard distribution by provider covers RM rows (no new composite)
- [x] Write-guard phrases for memorization + reward-model claims (tier-gated)
- [x] 15 RM tests (taxonomy, scope, catalog, rows, join, query pack, hypotheses, KB, guard, evalkit); full suite green
- [x] Live image rebuild + live verification

## Follow-ups (not blocking)
- [ ] Verify inherited versioning baselines still deliberate for pack/model fingerprints
- [ ] `SecurityAssessRequest.allow_partial` semantics confirmed against the KB path
