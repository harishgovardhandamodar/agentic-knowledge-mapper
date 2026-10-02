# Work order — model security knowledge base & landscape

Status: implemented on `model-security-kb-landscape`.
Progress: see [`todo.md`](todo.md).

## Intent

Turn model-security assessment from one-off reports into a **living knowledge
base** scoped by investigation: incrementally collectable, queryable as
**graph + tables**, explicit about **own / inherited / cascade** risk, and
usable by a security team as a **landscape** view with **selection guidance**.

It is an *overlay* on the existing apps, not a sixth product. The scoring
engine stays in `model_eval`; the KB stores results and structure.

## Non-negotiables inherited from the previous work orders

- Product `T*`/`C*` and model `W1–W3` paths stay separate; no averaging.
- `null` means "no evidence", never a zero.
- `MM*` are recommendations, never implemented by the app.
- Evalkit + fingerprints gate silent numeric drift.
- Dossier reads **stored rows only** — no live re-score at export.
- Every assessment row records method + catalog versions + fingerprints.

## Slice (work order §7)

1. **Schema** — stable keys on artifacts/relationships, edge payload JSON,
   `kb_json` + `kb_fingerprint` on the assessment. Additive migrations only.
2. **Sync layer** — `model_kb.sync_model_kb(db, assessment_id)`.
3. **Registers** — risk / inheritance / cascade partition in API + dossier.
4. **Landscape tab** — inventory, registers, filtered graph.
5. **Insight cards** — deterministic.
6. **Selection compare + decision** — multi-axis, decisions logged.
7. **Hypothesis/experiment targets** — wired into coverage gaps.
8. **Tests + evalkit**.

## Design decisions

- **No second graph DB.** Nodes are `artifacts` (new `artifact_type` values),
  edges are `relationships` (new `relationship_type` values with
  `payload_json`). Tables are JSON snapshots on the assessment (`kb_json`),
  merged across assessments for the landscape.
- **Idempotency** by `(investigation_id, artifact_type, stable_key)` and
  `(source_key, relationship_type, target_key)` for edges. Re-running an
  assessment enriches a node; it never duplicates it.
- **Snapshot fingerprint** — hash of register keys + catalog versions, stored
  on the assessment so a later catalog edit cannot silently rewrite history.
- **Scope partition** is deterministic: `applies_to=model_specific` → own,
  `family|modality` → inherited, composition signals → cascade. Cascade is
  never counted as own (asserted in tests).
- **Landscape triage prefers accepted evidence.** Pending evidence is carried
  but flagged, so "pending" can never read as "known secure".

## What landed

| Slice | Where | Status |
| --- | --- | --- |
| 1 Schema | `app/models.py`, `app/database.py` | additive migrations only |
| 2 Sync layer | `app/model_kb.py:sync_model_kb` | idempotent, fail-open |
| 3 Registers | `app/model_kb.py` | own / inherited / cascade |
| 4 Landscape API | `app/main.py` | 6 endpoints |
| 5 Insight cards | `app/model_kb.py:insight_cards` | deterministic, no LLM |
| 6 Compare + decision | `app/model_kb.py:compare`, `record_decision` | no default winner |
| 7 Experiment targets | `app/model_kb.py:plan_experiments` | derived from stored rows |
| 8 Tests + evalkit | `tests/test_model_kb.py`, `app/evalkit.py` | 66 tests, 15/15 evalkit |

Dossier and Landscape read **stored rows only** — no live re-score, no
second graph database.

### Selection semantics

Filters are hard gates (an excluded model is absent from ranking and carries
`exclusion_reasons`). Weights are opt-in: without them there is **no ranking
and no winner**, by design. A named axis that does not exist returns `422`
rather than being silently ignored, so a typo cannot quietly change a result.

### Known instability (pre-existing, unrelated to this work order)

A background worker thread from `app/jobqueue.py` can submit to a
`ThreadPoolExecutor` after the interpreter starts shutting down, printing
`cannot schedule new futures after interpreter shutdown` and delaying process
exit. It does not fail tests — the summary line is written first — but a CI
harness that waits on process exit will look like a hang. The suite itself
runs green in ~135s. Worth fixing as its own change.
