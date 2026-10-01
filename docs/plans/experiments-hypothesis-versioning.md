# Plan: experiments + hypothesis builder + versioning

Branch: `plan-experiments-hypothesis` (planning only — no code changes).
Base: `master` after the W1/W2/W3 merge.
Source work order: revised agent instructions (§0–§11), grounded below
against the current tree. Non-negotiables in §0 hold for every PR.

## What already exists (do not rebuild)

| Work-order item | Status in tree |
|---|---|
| Security stats always written | Done: `security_run_stats()` (ids, posture, pack version/fp, duration, evidence counts), error-path partial stats, §2 Assessment lines |
| Dossier confidence / open gaps | Done: exec confidence block, gap-run goals, §8 register, `run_health` on summary, Coverage failed-runs/gaps |
| Incomplete-stats chip | Done in security history + dossier §2 fallback; **test missing** |
| No-evidence nulls | Done across scoring, dossier, preview, PDF, synthesis |
| MM-as-recommendation | Done: catalog, defer-with-reason, indicative residuals, approval park/resume |
| Job queue + ledger + requester≠approver | Done, tested |
| Dossier reads stored rows | Done (payload-in `dossier_markdown`) |
| Method + versions on rows | Model rows: yes (`w1/w2/w3` + fingerprints in scoring + `model_json`). Product rows: pack version/fp yes; scoring `method` present |
| Vendor-doc bias (model briefs) | Done: `_ensure_model_queries`, `_ensure_vendor_doc_query` |
| Declared vs evidenced controls | **Missing** |
| explainer_gap durability | Done: boot requeue (attempt-capped) |
| Yield-aware refine | Done: `yld.rank_queries` in loop + refine round |
| Hypothesis falsifiable-only | Partial: empty falsifier dropped/collapses testability, but no `status` field, single `falsifier` string (no `falsifiers[]`), no register API/UI |
| Experiments | **Missing entirely** |
| Shared collector cache | **Missing** (W1/W2/W3 each fan out separately) |
| Re-score as new row | Partial: what-if rescorer exists; persist semantics need audit (must be new-row, never in-place) |
| Changelog artifact | **Missing** |
| Deprecation fields | **Missing** |
| Pack diff / min_pack_version | **Missing** |
| Manager synthesis gaps | **Missing**: no open-gap/incomplete/deferred/falsifier mentions |
| Stage timings | Partial: event `created_at` chain + run `duration_ms`; not surfaced per stage |

## PR-1 — Stats + confidence test pins (small)

Close the last gaps of §8.1. Code is written; pin it.
- `tests/test_dossier.py`: §2 renders residual + posture + fingerprint for a
  planted assessment-stats run (incl. failed-run stats).
- Frontend/history chip: unit-test the `stats_complete === false` branch
  (jsdom-level or extract predicate to a tested helper — prefer the latter:
  move chip condition into a pure function).
- `run_health` on summary: assert failed count + gap goals survive.
- Files: `tests/` only. Acceptance: green suite, no behavior change.

## PR-2 — Version policy module + superseded-pack badge (medium)

- New: `CHANGE_POLICY` (docstring + constants) in `threatpack.py` and
  `model_eval.py`: what bumps major/minor/patch per catalog; rule
  “fingerprint change without version bump fails CI”; rule “version bump
  with moved numbers requires evalkit update”.
- CI rule needs a test, not just prose: `tests/test_evalkit.py` (or new
  `tests/test_versioning.py`) computes fingerprints and compares against
  pinned constants — any silent taxonomy edit fails.
- Dossier §4 + history rows: when row pack ≠ current pack, badge
  **“Scored with pack X (fp…) — superseded pack”**; never re-arithmetic.
- `POST .../rescore` with `persist:true` currently **mutates the row in
  place** (`app/main.py`: overwrites `controls_json`, `scoring_json`,
  `residual_pct`, `posture`, then commits). Change to new-row creation
  with `supersedes_id` pointer + ledger event (old/new version+fp); add
  a test asserting the old row is byte-identical afterwards.
- Files: `app/threatpack.py`, `app/model_eval.py`, `app/dossier.py`,
  `app/main.py` (rescore), `static/index.html` (history badge),
  `tests/test_versioning.py` (new).

## PR-3 — Shared research cache (medium)

- `research-collector` caches per `(investigation_id, subject_key)` where
  `subject_key` = stable hash of (mode, model_name/family or product,
  query families). W1/W2/W3 and manager's parallel model jobs hit the same
  rows instead of triplicating fan-out.
- Cache lives in existing tables (no new table): key on artifact
  `tags`/`origin` or a small `collector_cache` JSON on the run stats.
  Prefer: extend run `stats` with `collector_cache_key` + reuse artifacts
  already collected (they are all in-DB rows — the "cache" is a lookup, not
  storage).
- Tests: two collectors same key → second does zero new matches outside
  cache (assert via `artifacts_scanned` / query counts); different subject
  → miss. Product path byte-identical behavior.
- Files: `app/agents.py` (collector), `app/security_agent.py` (pass key),
  `tests/test_agent_cache.py` (new, offline).

## PR-4 — Hypothesis register + builder (large)

- Data: extend hypothesis claim dicts with `hypothesis_id` (`H01…`
  stable), `status` (`untested` default; `supported | refuted |
  contested` set only by verifier evidence), `falsifiers[]` (migrate the
  single `falsifier` string into a one-item list), support/counter artifact
  ids (already emitted), cross-flow flags (already emitted).
- Builder API on assessment or child JSON: read register; update
  falsifiers/status/evidence **without** touching scored `confidence_pct`
  (test this invariant explicitly); "collect evidence for claim" and
  "propose experiments" actions enqueue collection/experiment jobs.
- Orchestration: prefer hypothesis only when target + adversarial rows are
  terminal unless `allow_partial=true`; partial priors → explicit gap
  claims (already partially done — extend to register + summary
  confidence block).
- UI: builder view listing claims with status + falsifiers + evidence
  chips; dossier hypothesis section becomes the register table.
- Files: `app/agents.py` (analyst/verifier shapes), `app/security.py`
  (hypothesis scoring reads `falsifiers[]`), `app/main.py` (register
  endpoints), `static/index.html` (builder), `app/dossier.py`
  (register table), `tests/test_hypothesis_builder.py` (new).

## PR-5 — Experiment builder (large)

- Schema `experiment_plan_v1` exactly per work order §4.2, stored on
  assessment (`model_json.experiments` — no new column).
- `experiment-planner` skill: new agent card + handler, or extension of
  hypothesis/mitigation analysts — prefer **new card** (cleaner mandate
  audit). Inputs: profile, W1 findings, W2 unknowns, hypothesis
  falsifiers, MM plan, deployment constraints. Deterministic filters
  first (API-only → no weight-only experiments without `vendor_coop`),
  LLM ranks for information gain.
- Orchestration: optional W4 after W3, or on-demand "Build experiments"
  (runnable without full W3 when hypothesis/W2 gaps exist).
- Links: every open falsifier → ≥1 experiment or explicit
  "not testable here"; high-priority MM → validation experiment.
- UI/dossier: Experiments section/tab + dossier section after
  mitigations/hypothesis, Markdown/PDF/bundle, plan-only disclaimer in
  both. Evalkit fixtures per §4.6.
- Files: `app/model_eval.py` (method ids + weights if any),
  `app/agents.py` (planner + wiring), `app/dossier.py`,
  `static/index.html`, `tests/test_experiments.py` (new).

## PR-6 — W3 tightening verification (small)

Mostly done; verify + pin: prefilter tests exist, ranking tests exist,
indicative labels exist, approval park/resume tested. Add:
- Evalkit case: empty W1/W2 + W3 requested → explicit empty plan (not
  silent success) — mirror the orchestrator unit test already in
  `tests/test_model_eval.py` into `evalkit.model_cases` if it fits the
  runner shape, else leave as unit test and note why.
- Dossier test: deferred-with-reason renders; uncovered high-confidence
  attack stays visible after plan.

## PR-7 — Re-score as new row + pack diff (medium)

- Depends on PR-2 audit outcome. If rescore-persist mutates: change to
  new-row creation with `supersedes_id` pointer + ledger event
  (old/new version+fp).
- Side-by-side compare: product inherent/residual or model W1/W2 **only
  when methods comparable**; cross-method compare → 422 (mirror the
  existing rescore-guard style).
- Pack diff report (product only): same evidence, pack A vs B residuals.
  Keep behind an explicit action, not automatic.
- Tests: old row byte-identical after re-score; ledger event present;
  cross-method 422.

## PR-8 — Changelog + deprecation + version-immutability evalkit (medium)

- `PACK_CHANGELOG` (structured JSON in repo, e.g.
  `app/pack_changelog.json` + loader): version, date, id changes,
  constant deltas, evalkit case changes. Same file (or section) covers
  the three model catalogs.
- Dossier: when assessment pack ≠ current, include short changelog
  excerpt (cap lines).
- Deprecation: `deprecated: true` + `replaced_by` supported on
  threats/controls (and MM entries); new assessments ignore deprecated
  ids; old rows still render.
- Evalkit: N-1 pack row still displays/exports without N arithmetic;
  `score_assessment` purity in (exposure, threats, controls,
  applicability, pack snapshot).
- Design-tab readable changelog endpoint (cheap: serve the JSON file).

## PR-9 — Product evidence quality (medium)

- Planner: vendor+product brief forces ≥1 official-docs/trust/architecture
  family (mirror `_ensure_vendor_doc_query` — generalize it, it is
  currently model-brief-gated in one helper and product-gated in
  another; unify).
- Auto-refine once when round 1 keeps zero vendor-primary artifacts.
- Per-control `declared | evidenced | unknown`: evidenced = linked
  supporting artifact exists in graph; dossier §4 + residual narrative
  mark which reductions rest on declared-only controls.
- Recommender: flag stale assessment vs newer artifacts; high-leverage
  zero-evidence control.

## PR-10 — Efficiency + manager synthesis (small/medium)

- explainer_gap durability: done, keep.
- Stage timings: surface per-stage durations from the event chain
  (already timestamped) in run stats + dossier §2 (cheap aggregation,
  no schema change).
- Manager synthesis: separate score meanings (already), plus open gaps,
  incomplete stats, deferred MM, open falsifiers (new — small text
  additions to the compile path + tests).
- Yield-aware refine: done, keep.

## Risks / watch-outs

- Test-DB sharing: the suite shares one sqlite file per run; collector
  fallbacks read the whole graph — new collector-cache tests must
  isolate (delete/scope rows in setUp, cf. the `TestOrchestratorOffline`
  lesson).
- LLM flakiness: gateway sometimes reachable-but-slow — force offline
  (`mock.patch("app.llm.chat"...)`) in all deterministic tests.
- Mock-signature drift: `_analyze_batch` mocks needed `*a, **k`
  hardening when the signature grew — same discipline for any new
  handler params.
- Frontend size: `static/index.html` is one large file; keep new UI in
  the existing section patterns (no new framework).
- No in-place re-scores, no averaged meanings, no implemented MM —
  each PR states which invariant it preserves; reviewers check that
  line first.

## Acceptance mapping

Work-order §9 items map to PRs: product evidence → PR-9 (+PR-1);
meanings/nulls → already held, PR-2/4/5 must not regress (suite +
new pins); hypothesis builder → PR-4; experiments → PR-5; W3 → PR-6;
versioning → PR-2/7/8; efficiency → PR-3/10. Non-goals (§10) are
unchanged: no live execution/training, no C*/MM* merge, no averaged
meanings, no NLI grounding.
