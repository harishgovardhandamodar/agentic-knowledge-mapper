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
