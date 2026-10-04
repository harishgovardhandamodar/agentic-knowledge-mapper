# Leadership Dashboard — gap analysis & improvement to-do list

> **Status: implemented** on branch `leadership-dashboard` (P0–P2, items 1–15).
> See [Implementation notes](#implementation-notes) at the end for what each
> item turned into and where it landed. The analysis below is kept as the
> record of why the work was scoped this way.

## Current state

The assurance-grade leadership layer is **backend-complete but frontend-invisible**.

- `app/leadership.py` implements every §9 view: `risk_position` (tiers + confidence
  + verified-vs-declared share + trend), `decision_queue` (residual + confidence +
  gate status), `assurance_health` (controls verified %, forensics, ledger,
  stalled runs, time-to-close), `exposure_lens`, `system_integrity` (swarm health,
  pack currency), `alerts`, `exception_register`, `change_log`, and a
  persona-layered `board`.
- All are exposed over `/api/leadership/*` and covered by API tests.
- **But no frontend calls `/api/leadership/*`.** The browser's *Leadership
  Dashboard* tab and the Risk Console both render the **older risk-register**
  executive dashboard (`/api/dashboard/summary|availability|distribution|
  robustness|attention|trends` from `app/executive.py`). A CISO looking at the
  dashboard today sees register metrics, not the security-assessment risk
  position, decision queue, or assurance health.
- `POST /api/security/assessments/{id}/decision` (accept / guardrails / reject /
  exception) works and writes to the ledger — but **there is no button anywhere
  that calls it**.

So the highest-value improvement is wiring the existing backend to a real UI;
everything else is hardening on top.

## P0 — the dashboard is not visible (blocking)

1. **Render the assurance board in the UI.** Build a frontend surface for
   `/api/leadership/board` (or the individual views): risk position by tier,
   decision queue, assurance health, system integrity, alerts, exceptions.
   The existing *Leadership Dashboard* tab (or the Risk Console) is the home.
2. **Decide the dashboard identity.** The tab currently shows the risk-register
   executive dashboard. Either merge both into one layered screen, or clearly
   label them — "Risk register" vs "Security assessment leadership" — so a CISO
   does not mistake one for the other.
3. **Decision actions from the UI.** Accept / accept-with-guardrails / reject /
   exception buttons on each decision-queue row, calling
   `POST /api/security/assessments/{id}/decision` with actor + rationale (and
   expiry for exceptions). This is the loop closer: the dashboard exists to
   turn a residual into a signed, ledger-backed decision.

## P1 — contract and scoping fixes

4. **Align the `reject` decision value.** `AssuranceDecisionRequest.decision`
   is documented `accept | accept_with_mandatory_guardrails | reject | exception`,
   but `leadership.record_decision` only accepts
   `reject_until_architecture_gate_closed`. `POST {"decision": "reject"}` is a
   422. Accept the short form (map it to the constant) or fix the docstring.
5. **Decision-queue age.** Rows carry no `created_at` / `age_days`. A CISO
   cannot see how long an item has waited or whether it is over a review SLA.
   Add the assessment `created_at`, `age_days`, and a configurable SLA field;
   surface over-SLA items in `alerts()`.
6. **Portfolio filters.** The UI already passes `initiative_id` / `layer` /
   `accepted_only` to the old `/api/dashboard/*`; the new `/api/leadership/*`
   views accept only `investigation_id` and `window_days`. Add initiative/layer
   filtering so the board slices the same way the rest of the app does.
7. **Decision-queue filters.** Add tier filter, offset pagination, and sort by
   residual / age / confidence. Allow `states` to include `accepted` and
   `rejected` so leadership can review past sign-offs, not only the open queue.
8. **Board completeness.** `board()` omits `exception_register` and `change_log`.
   Add them so the one-screen executive view includes the exception register and
   the recent decision trail.

## P2 — analytics, alerts, exports

9. **Persona picker in the UI.** `board(persona=…)` exists backend-only. Add a
   persona switcher (Executive / CISO / DPO / Legal / Audit / Security
   Engineering) so each role gets its emphasis without a custom query.
10. **Richer trend.** `_trend` is a prior-vs-window split only. Add 30/90/365-day
    series, per-tier trend lines, and a portfolio residual sparkline on the risk
    position card.
11. **Per-tier threat breakdown.** `top_residual_threats` is portfolio-wide; add
    which T##s dominate within each data tier (and how many are gated by the
    evidence gate).
12. **Alert acknowledgement.** `alerts()` is recomputed fresh every call, so the
    same alerts repeat forever. Add a seen/actioned state (a small table keyed by
    alert id + assessment) so leadership can acknowledge and stop noise.
13. **Live updates.** The dashboard is pull-to-refresh only. Add periodic polling
    (or SSE) of `alerts` + `decision_queue` so new gate failures and overdue items
    surface without a manual refresh.
14. **Board export.** `evidence_pack` exists per assessment; add a portfolio-level
    board snapshot (JSON / Markdown / PDF) so a regulator gets the current risk
    position, decision queue, and exception register in one bundle.
15. **Drill-down links.** `decision_queue` already flags
    `vendor_questionnaire_available` and a `dossier_link`; wire UI drill buttons
    to the one-page summary and the vendor questionnaire.

## Non-goals (explicit)

- No authentication/authorisation on the persona views: role emphasis is a lens,
  not access control. Making it enforcement is a separate security project.
- No auto-rescoring from the board: a stale pack or a changed basis is *reported*
  and re-queued explicitly; the signed row is never edited.

## Implementation notes

**1–3 · P0, the board is now visible and actionable.** `static/index.html`
gains an explicit two-layer switcher in the Leadership Dashboard tab: an
**Assurance board** (default) reading `/api/leadership/board`, and the existing
**Portfolio register**, relabelled so the two cannot be mistaken for each other.
Decision buttons (`accept` / `accept_with_mandatory_guardrails` / `reject` /
`exception`) call `POST /api/security/assessments/{id}/decision`, prompting for
actor, rationale, and — for an exception — an expiry.

**4 · `reject` is now accepted.** `DECISION_ALIASES` / `canonical_decision`
in `app/leadership.py` map the short spellings a UI offers onto the long stored
constants. The response reports both `decision` and `decision_requested`, and an
override of the derived recommendation is flagged as one.

**5 · Queue age and SLA.** Rows carry `age_days`, `sla_days`, and `over_sla`
(`DECISION_SLA_DAYS = 14`). An accepted row ages from its signature, not from
its scoring date. Over-SLA items surface in `alerts()` as a `decision_sla`
category carrying the assessment id and the next action.

**6 · Portfolio filters.** `resolve_scope` and `_assessments` take
investigation / initiative / layer / exposure. An unknown value is a 422, never a
silently widened scope. Every board section receives the resolved scope, so a
tier filter cannot narrow the risk table while leaving the queue and alerts
showing the whole portfolio.

**7 · Queue filters.** Tier filter, offset pagination (`offset` / `limit` /
`returned` / `has_more`), sorting by residual / age / confidence / product, and
`states` including `accepted` and `rejected`.

**8 · Board completeness.** `board()` now carries `exceptions`, `change_log`,
`personas`, and a `contract` describing what a decision requires.

**9 · Persona picker.** Switcher in the UI; `/api/leadership/personas` publishes
the lenses with their emphasis so the UI is not hard-coding the list.

**10 · Richer trend.** 30/90/365-day windows with sample counts and
insufficient-history reporting, per-tier trend lines honouring the requested
window, and a residual sparkline on the risk card.

**11 · Per-tier threat breakdown.** `top_threats_by_tier` ranks dominant
threats within each tier, keeps the worst instance when a threat id repeats
across products, and counts how many were forced to inherent risk.

**12 · Alert acknowledgement.** `LeadershipAlertState` (`app/ledger_models.py`)
records who responded to which finding. Acknowledge, snooze, and un-acknowledge
are supported; the response is bound to the `finding_hash` the reader actually
saw, so a changed finding reappears rather than staying silently answered. The
acknowledged counter is read off the full set, so a filtered panel cannot report
zero responses.

**13 · Live updates.** The board polls every 60s, pausing on a hidden tab or
when another app is open.

**14 · Board export.** `GET /api/leadership/board.md` renders the whole board as
one Markdown snapshot carrying scope, persona lens, generation time, and every
residual beside its confidence.

**15 · Drill-downs.** Queue rows carry their own links (one-page summary,
evidence pack, vendor questionnaire, exception re-evaluation); the UI opens the
link the backend chose rather than guessing a route.

### Bugs the tests caught while implementing

- `board(tier=…)` was accepted and ignored; the queue and every other section
  now receive the resolved scope.
- `system_integrity` indexed a per-role `gate_failures` key that `SW.health`
  only reports in its portfolio total — a `KeyError` on the first investigation
  with any swarm activity.
- `_tier_trends` was hard-coded to a 90-day window regardless of the board's.
- `change_log` reported `supersedes_id` on the new row while reading it off the
  superseded row, so every entry was null; it now resolves `superseded_by_id`.
- A derived (auto) acceptance has no signature date, so ageing it from
  `decision_at` reported every such row as brand new.
- The Markdown export double-printed `%` on two lines.
- Alert snoozes were stored but never suppressed anything.
