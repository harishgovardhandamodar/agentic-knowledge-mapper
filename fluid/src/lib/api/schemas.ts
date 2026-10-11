/**
 * Zod schemas for the FastAPI backend responses this GUI reads.
 *
 * Every schema is deliberately lenient (`.passthrough()` on large objects,
 * optional fields where the backend omits them) because the API is the source
 * of truth and the GUI must not blank a screen because a field it does not use
 * appeared or disappeared. The schemas earn their keep by pinning the fields
 * the UI *does* branch on, so a rename fails loudly in one place instead of
 * silently rendering `undefined`.
 */
import { z } from 'zod';

export const zInvestigation = z
  .object({
    id: z.number(),
    title: z.string(),
    keywords: z.string().optional(),
    description: z.string().optional(),
    status: z.string().optional(),
    hidden: z.boolean().optional(),
    created_at: z.string().optional(),
  })
  .passthrough();
export type Investigation = z.infer<typeof zInvestigation>;

export const zInvestigationList = z
  .object({
    items: z.array(zInvestigation).optional(),
    investigations: z.array(zInvestigation).optional(),
  })
  .passthrough();

/** GET /api/security/health and friends. */
export const zHealth = z
  .object({
    status: z.string().optional(),
  })
  .passthrough();
export type Health = z.infer<typeof zHealth>;

/**
 * The credible band exposed on an assessment (app.uncertainty
 * assessment_interval, surfaced through main.py::_assessment_analysis).
 */
export const zUncertaintyBand = z.object({
  mean_pct: z.number(),
  lower_pct: z.number(),
  upper_pct: z.number(),
  level: z.number(),
  n_threats: z.number().optional(),
  headline_pct: z.number().nullable().optional(),
  headline_inside: z.boolean(),
});
export type UncertaintyBand = z.infer<typeof zUncertaintyBand>;

/** The external-reach budget (app.privacy.privacy_budget). */
export const zPrivacyBudget = z.object({
  spend: z.number(),
  remaining: z.number(),
  max_spend: z.number(),
  exhausted: z.boolean(),
  queries: z.number(),
  external_pages: z.number(),
  novel_pages: z.number(),
  distinct_domains: z.number(),
  domains: z.array(z.string()).optional(),
  advice: z.enum(['ok', 'degrade', 'refuse']),
});
export type PrivacyBudget = z.infer<typeof zPrivacyBudget>;

/** The reproducibility manifest (app.repro.manifest). */
export const zReproManifest = z
  .object({
    fingerprint: z.string(),
    label: z.string().optional(),
    environment: z.record(z.unknown()).optional(),
    versions: z.record(z.string()).optional(),
  })
  .passthrough();
export type ReproManifest = z.infer<typeof zReproManifest>;

/** Provenance for one control efficacy (app.security.control_evidence). */
export const zControlProvenance = z
  .object({
    control_id: z.string(),
    declared: z.number().nullable().optional(),
    posterior_mean: z.number().nullable().optional(),
    basis: z.string().optional(),
    source: z.string().optional(),
    n_observations: z.number().optional(),
    concentration: z.number().optional(),
    note: z.string().optional(),
    validated: z.boolean().optional(),
  })
  .passthrough();
export type ControlProvenance = z.infer<typeof zControlProvenance>;

export const zEfficacyEvidence = z
  .object({
    n_controls: z.number().optional(),
    validated_controls: z.array(z.string()).optional(),
    unvalidated_controls: z.array(z.string()).optional(),
    all_validated: z.boolean().optional(),
    widest_concentration: z.number().nullable().optional(),
    widest_control: z.string().nullable().optional(),
    basis_note: z.string().optional(),
    records: z.record(zControlProvenance).optional(),
  })
  .passthrough();

/** Why the residual score saturated (app.security._floor_diagnostics). */
export const zFloorDiagnostics = z
  .object({
    floor: z.number().optional(),
    floor_capped: z.boolean().optional(),
    floor_capped_threats: z.array(z.string()).optional(),
    floor_capped_count: z.number().optional(),
    floor_capped_pct: z.number().optional(),
    controls_beyond_floor: z.number().optional(),
    controls_beyond_floor_ids: z.array(z.string()).optional(),
    controls_effective: z.number().optional(),
    controls_effective_ids: z.array(z.string()).optional(),
    controls_orphaned: z.array(z.string()).optional(),
    noise_epsilon: z.number().optional(),
    note: z.string().optional(),
  })
  .passthrough();
export type FloorDiagnostics = z.infer<typeof zFloorDiagnostics>;

/** Decomposition of the credible interval (app.uncertainty.variance_budget). */
export const zVarianceBudget = z
  .object({
    total_variance: z.number().optional(),
    inherent_probability_variance: z.number().optional(),
    control_efficacy_variance: z.number().optional(),
    interaction_variance: z.number().optional(),
    share_inherent: z.number().optional(),
    share_efficacy: z.number().optional(),
    share_interaction: z.number().optional(),
    shares_sum: z.number().optional(),
    interaction_note: z.string().optional(),
    quantified: z.array(z.string()).optional(),
    unquantified: z.record(z.string()).optional(),
    control_provenance: z
      .object({
        n_controls: z.number().optional(),
        validated: z.number().optional(),
        unvalidated: z.number().optional(),
        all_validated: z.boolean().optional(),
        note: z.string().optional(),
      })
      .passthrough()
      .optional(),
    floor_capped: z.boolean().optional(),
    note: z.string().optional(),
  })
  .passthrough();
export type VarianceBudget = z.infer<typeof zVarianceBudget>;

/** One threat row from security.score_assessment. */
export const zThreatRow = z
  .object({
    id: z.string(),
    title: z.string().optional(),
    stride: z.string().optional(),
    owasp: z.string().optional(),
    likelihood: z.number(),
    impact: z.number(),
    inherent_score: z.number().optional(),
    residual_score: z.number().optional(),
    residual_severity: z.string().optional(),
    coverage: z.number().optional(),
    controls: z.array(z.string()).optional(),
    applicability: z.number().optional(),
    applicable: z.boolean().optional(),
  })
  .passthrough();
export type ThreatRow = z.infer<typeof zThreatRow>;

/**
 * An assessment as returned by GET /api/security/assessments/{id}. Only the
 * fields the shell and the three primitives need are pinned; the rest rides
 * through untouched.
 */
/**
 * The council's paper trail for one investigation: logs, actions, decisions
 * and generated hypotheses.
 *
 * Every section reads stored rows, never recomputation. A record that
 * recomputed would be a different review from the one whose scores sit beside
 * it — and on an investigation with no hypothesis assessment the hypotheses
 * section is empty rather than invented.
 */
export const zCouncilRecord = z
  .object({
    investigation_id: z.number(),
    logs: z
      .array(
        z
          .object({
            assessment_id: z.number(),
            path: z.string(),
            product: z.string().nullable().optional(),
            task_id: z.string().optional(),
            hops: z
              .array(
                z.object({
                  agent: z.string(),
                  intent: z.string(),
                  at: z.string().optional(),
                  note: z.string().optional(),
                }),
              )
              .optional(),
          })
          .passthrough(),
      )
      .optional(),
    runs: z
      .array(
        z
          .object({
            id: z.number(),
            status: z.string(),
            trigger: z.string().optional(),
            started_at: z.string().nullable().optional(),
            finished_at: z.string().nullable().optional(),
            error: z.string().nullable().optional(),
          })
          .passthrough(),
      )
      .optional(),
    actions: z.array(z.object({ kind: z.string() }).passthrough()).optional(),
    decisions: z
      .array(
        z
          .object({
            assessment_id: z.number(),
            product: z.string().nullable().optional(),
            assurance_decision: z.string().nullable().optional(),
            decided_by: z.string().nullable().optional(),
            decided_at: z.string().nullable().optional(),
            note: z.string().nullable().optional(),
            expires_at: z.string().nullable().optional(),
          })
          .passthrough(),
      )
      .optional(),
    hypotheses: z
      .array(
        z
          .object({
            assessment_id: z.number(),
            confidence: z.number().nullable().optional(),
            claims: z
              .array(
                z
                  .object({
                    hypothesis_id: z.string().optional(),
                    id: z.string().optional(),
                    claim: z.string().optional(),
                    falsifier: z.string().optional(),
                    confidence: z.number().nullable().optional(),
                    impact: z.number().nullable().optional(),
                    status: z.string().optional(),
                    council: z
                      .object({
                        seat: z.string().optional(),
                        attack_classes: z.array(z.string()).optional(),
                        falsifier_audit: z
                          .object({ grade: z.string().optional() })
                          .passthrough()
                          .optional(),
                        challenges: z
                          .array(
                            z.object({
                              seat: z.string().optional(),
                              ground: z.string().optional(),
                              why: z.string().optional(),
                            }),
                          )
                          .optional(),
                      })
                      .passthrough()
                      .optional(),
                  })
                  .passthrough(),
              )
              .optional(),
            council: z.object({}).passthrough().optional(),
          })
          .passthrough(),
      )
      .optional(),
  })
  .passthrough();
export type CouncilRecord = z.infer<typeof zCouncilRecord>;

/** One attack class in the council's coverage report. */
const zAttackClass = z
  .object({
    class: z.string(),
    label: z.string().optional(),
    severity: z.number().nullable().optional(),
    claims: z.array(z.string()).optional(),
    stored_rows: z.number().optional(),
  })
  .passthrough();

export const zAssessment = z
  .object({
    id: z.number(),
    investigation_id: z.number(),
    product_name: z.string().optional(),
    exposure: z.string().optional(),
    overall_pct: z.number().nullable().optional(),
    inherent_pct: z.number().nullable().optional(),
    residual_pct: z.number().nullable().optional(),
    scoring: z
      .object({ threats: z.array(zThreatRow).optional() })
      .passthrough()
      .optional(),
    threats: z.array(zThreatRow).optional(),
    uncertainty: zUncertaintyBand.nullable().optional(),
    privacy: zPrivacyBudget.nullable().optional(),
    repro: zReproManifest.nullable().optional(),
    floor_capped: z.boolean().nullable().optional(),
    floor: zFloorDiagnostics.nullable().optional(),
    efficacy_evidence: zEfficacyEvidence.nullable().optional(),
    judgments: z
      .array(
        z
          .object({
            kind: z.string().optional(),
            subject: z.string().optional(),
            value: z.number().optional(),
            author: z.string().optional(),
            rationale: z.string().optional(),
            recorded_at: z.string().optional(),
          })
          .passthrough(),
      )
      .optional(),
    assessment_path: z.string().optional(),
    /**
     * The review panel behind a hypothesis assessment: who sat on it, which
     * attack classes each owns, which claims were contested, and which classes
     * no seat reached.
     *
     * `unexamined` and `not_in_corpus` are deliberately different lists. A
     * class with stored evidence that no seat turned into a claim is a gap in
     * the review; a class the corpus never mentions is out of scope. Collapsing
     * them would let "nobody looked" read as "there is nothing there".
     */
    council: z
      .object({
        panel: z
          .object({
            n_seats: z.number(),
            note: z.string().optional(),
            seats: z
              .array(
                z.object({
                  id: z.string(),
                  discipline: z.string(),
                  remit: z.string(),
                  owns: z.array(z.string()),
                  blind_spot: z.string(),
                  demands: z.string().optional(),
                }),
              )
              .optional(),
          })
          .optional(),
        coverage: z
          .object({
            covered: z.array(zAttackClass).optional(),
            unexamined: z.array(zAttackClass).optional(),
            not_in_corpus: z.array(zAttackClass).optional(),
            coverage_pct: z.number().optional(),
            note: z.string().optional(),
          })
          .optional(),
        disagreement: z
          .object({
            applicable: z.boolean(),
            gwet_ac1: z.number().nullable().optional(),
            alpha: z.number().nullable().optional(),
            claims_with_split: z.number().optional(),
            n_claims: z.number().optional(),
            note: z.string().optional(),
          })
          .optional(),
        seats_contributing: z.array(z.string()).optional(),
        contested: z.number().optional(),
        unexamined: z.number().optional(),
      })
      .optional(),
    markdown: z.string().nullable().optional(),
  })
  .passthrough();
export type Assessment = z.infer<typeof zAssessment>;


/** GET /api/investigations/{id}/security/assessments (array or envelope). */
export const zAssessmentList = z.union([
  z.array(zAssessment),
  z
    .object({
      items: z.array(zAssessment).optional(),
      assessments: z.array(zAssessment).optional(),
    })
    .passthrough(),
]);

/** GET /api/security/assessments/{id}/analysis. */
export const zAssessmentAnalysis = z.object({
  assessment_id: z.number(),
  residual_pct: z.number().nullable().optional(),
  uncertainty: zUncertaintyBand.nullable(),
  privacy: zPrivacyBudget.nullable(),
  repro: zReproManifest.nullable(),
  // Calibration extras ride along with the band so a consumer cannot read the
  // interval without the list of what produced it and what it omits.
  variance_budget: zVarianceBudget.nullable().optional(),
  efficacy_evidence: zEfficacyEvidence.nullable().optional(),
  floor_capped: z.boolean().nullable().optional(),
});
export type AssessmentAnalysis = z.infer<typeof zAssessmentAnalysis>;

/** GET /api/investigations/{id}/research-gaps — open questions + novel areas. */
export const zResearchGaps = z.object({
  gaps: z
    .array(
      z
        .object({
          question: z.string(),
          kinds: z.array(z.string()).optional(),
          exps: z.array(z.unknown()).optional(),
          supporting: z.number(),
          novel: z.boolean(),
          lifecycle: z
            .object({
              status: z.string(),
              evidence: z.string().nullable().optional(),
              decided_by: z.string().nullable().optional(),
              updated_at: z.string().nullable().optional(),
            })
            .passthrough()
            .optional(),
        })
        .passthrough(),
    )
    .optional(),
  novel_areas: z
    .array(
      z.object({ topic: z.string(), artifacts: z.number() }).passthrough(),
    )
    .optional(),
});
export type ResearchGaps = z.infer<typeof zResearchGaps>;

/** GET /api/security/eval — the regression suite, as a gate report. */
export const zEvalReport = z
  .object({
    ok: z.boolean(),
    cases_run: z.number().optional(),
    cases_failed: z.number().optional(),
    invariants_run: z.number().optional(),
    invariants_failed: z.number().optional(),
    engine_invariants_run: z.number().optional(),
    engine_invariants_failed: z.number().optional(),
    engine_invariants: z
      .array(z.object({ name: z.string(), ok: z.boolean(), detail: z.unknown() }).passthrough())
      .optional(),
    failures: z.array(z.record(z.unknown())).optional(),
    pack: z.record(z.unknown()).optional(),
  })
  .passthrough();
export type EvalReport = z.infer<typeof zEvalReport>;

/** GET /api/security/controls — the catalogue with its provenance. */
export const zControlCatalog = z
  .object({
    items: z.array(zControlProvenance.passthrough()).optional(),
    controls: z.array(zControlProvenance.passthrough()).optional(),
  })
  .passthrough();

/** One planned experiment (app.model_eval.plan_experiments). */
export const zExperiment = z
  .object({
    id: z.string().optional(),
    control_id: z.string().optional(),
    title: z.string().optional(),
    question: z.string().optional(),
    hypothesis: z.string().nullable().optional(),
    method: z.string().nullable().optional(),
    status: z.string().nullable().optional(),
    priority: z.number().nullable().optional(),
    burden: z.string().nullable().optional(),
    limitations: z.array(z.string()).optional(),
    success_criteria: z.string().nullable().optional(),
  })
  .passthrough();
export type Experiment = z.infer<typeof zExperiment>;

/** One verified claim (app.claims.verify_claim). */
export const zVerifiedClaim = z
  .object({
    text: z.string(),
    start: z.number().nullable().optional(),
    end: z.number().nullable().optional(),
    verdict: z.enum(['supported', 'weak', 'unsupported']),
    support: z.number(),
    source: z.union([z.number(), z.string()]).nullable().optional(),
    span: z
      .object({ start: z.number().optional(), end: z.number().optional() })
      .passthrough()
      .nullable()
      .optional(),
    polarity: z.string().nullable().optional(),
    shared_terms: z.array(z.string()).optional(),
    cited: z.array(z.string()).optional(),
    invented: z.array(z.string()).optional(),
    claim_id: z.string(),
  })
  .passthrough();
export type VerifiedClaim = z.infer<typeof zVerifiedClaim>;

/** GET/POST claim verification payload (app.claims.verify_free_text). */
export const zVerifyResponse = z.object({
  claims: z.array(zVerifiedClaim),
  stats: z
    .object({
      total: z.number(),
      supported: z.number(),
      weak: z.number(),
      unsupported: z.number(),
      support_rate: z.number().nullable().optional(),
    })
    .passthrough(),
  violation: z.boolean(),
});
export type VerifyResponse = z.infer<typeof zVerifyResponse>;

/** GET /api/security/threat-pack. */
export const zThreatPack = z
  .object({
    manifest: z
      .object({
        pack_id: z.string().optional(),
        version: z.string().optional(),
        fingerprint: z.string().optional(),
      })
      .passthrough(),
    threats: z.array(z.record(z.unknown())).optional(),
  })
  .passthrough();
export type ThreatPack = z.infer<typeof zThreatPack>;
