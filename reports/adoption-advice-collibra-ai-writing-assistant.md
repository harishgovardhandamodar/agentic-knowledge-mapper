# Adoption advice — Collibra AI Writing Assistant

_Organisation:_ financial market infrastructure (payments, clearing, settlement, messaging); systemically important / critical function; subject to EU DORA (digital operational resilience), EU GDPR; restricted data; cross-border processing · _Question:_ security_risk · _Method:_ adoption_advice_v1 v1.1.0 (`f4366d380b87`) · _Generated:_ 2026-10-13T11:53:55 UTC

---

## Verdict

**Do not adopt at this organisation profile without change.** High-or-critical items remain after controls.

Measured residual (worst prior analysis): 80.3/100 · organisation scrutiny ×1.8 (high) · adoption pressure 100/100.

## Organisation nature

| Field | Reading |
|---|---|
| Sector | financial market infrastructure (payments, clearing, settlement, messaging) |
| Systemically important | yes |
| Data sensitivity | restricted |
| Supervisory regimes | dora, gdpr |
| Jurisdiction | unstated |
| Cross-border | yes |
| Third-party reliance | yes |

## Why the organisation raises the bar

| Factor | Δ scrutiny |
|---|---|
| financial market infrastructure (payments, clearing, settlement, messaging) | +0.3 |
| systemically important / critical function | +0.25 |
| EU DORA (digital operational resilience) | +0.15 |
| EU GDPR | +0.1 |
| restricted data in scope | +0.2 |
| cross-border processing | +0.1 |
| third-party reliance | +0.05 |

## Referenced prior analysis

The advice below quotes, and does not re-derive, these stored results.

| Analysis | Product | Exposure | Residual | Posture | Matched on |
|---|---|---|---|---|---|
| Collibra AI Writing Assistant on restricted/confidential data (DORA SIFMI) | Collibra AI Writing Assistant | Restricted data | 80.3/100 | HIGH RISK — do not enable for this data tier without the mitigations below | product_family |

## Conditions

Each condition names what it buys and what remains when it is in place.

| # | Condition | Why | Residual limitation | Source |
|---|---|---|---|---|
| AA01 | Classification gate and allow-list before the surface | restricted content may reach the model output, so the input surface must be restricted to classified, allow-listed material. | A gate is only as good as the labels it reads; one misclassified input defeats it. | organisation nature |
| AA09 | DLP and egress allow-list on prompts and responses | Confidentiality loss is the primary failure mode at this tier. | DLP misses paraphrased secrets and novel formats; it reduces, never eliminates, leakage. | organisation nature |
| AA07 | DPIA / data-protection assessment before production | Personal data processing triggers a documented assessment. | A DPIA records a decision; it is not itself a control. | organisation nature |
| AA03 | Residency and transfer mechanism pinned in contract and config | Processing crosses a border, so location and transfer basis must be fixed, not assumed. | Residency attestations often omit backup, replication and support-access regions. | organisation nature |
| AA04 | No-train and zero-retention terms, evidenced not declared | A third party receives the data, so retention and training use must be contractually barred and technically confirmed. | A no-train clause does not prove deletion, nor stop on-path logging by a subcontractor. | organisation nature |
| AA05 | Resilience, exit plan and concentration limits (DORA-style) | A critical function cannot depend on a supplier it cannot leave. | An exit plan untested at scale is a document, not resilience. | organisation nature |
| AA10 | Supervisory audit trail and incident reporting path | Supervisors will ask who did what and when. | An audit trail proves an action occurred, not that it was appropriate. | organisation nature |
| AA06 | Human review in the loop for restricted outputs | At this consequence, an unreviewed output is not acceptable. | Review degrades to rubber-stamping as volume grows. | organisation nature |
| AA08 | Least-privilege roles and SSO-bound access | The surface must not exceed the user's own entitlements. | Role drift and shared accounts quietly exceed the intended boundary. | baseline |
| AA11 | Logging and provenance on every model interaction | Without a record, neither misuse nor benefit is provable. | Logs prove the interaction happened, not that it was appropriate. | baseline |
| AA12 | Staged rollout behind a bounded pilot with stop criteria | The measured residual (80.3/100) does not support an unbounded production launch. | A pilot ticks a box unless it has a pre-agreed abort threshold. | prior analysis |

## What is missing

- Residual blocker T01: Accidental paste of sensitive content into the AI assistant (25.0/100)
- Residual blocker T02: Model training / retention leakage of submitted metadata (20.0/100)
- Residual blocker T03: Misclassified / mislabelled source files propagate via AI suggestions (20.0/100)
- Residual blocker T04: Over-permissive AI-generated descriptions leak schema semantics (16.0/100)
- Residual blocker T06: Insider exfiltration through generated documentation (15.0/100)

## Limitations

- This pack is deterministic and organisation-aware; it is not a control-level assessment and does not replace one.
- The organisation's nature is read from the request text and any explicit fields; unstated fields are treated as unstated.
- Prior-analysis numbers are quoted from stored rows, not re-derived, and move only when those rows do.
- No condition here is a clean bill of health; each carries the limitation that remains when it is in place.

---
*Organisation nature scales consequence, it does not measure the product. The product numbers are quoted; the conditions are the part you can act on, and each keeps its residual.*