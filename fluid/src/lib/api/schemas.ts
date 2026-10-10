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
    assessment_path: z.string().optional(),
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
});
export type AssessmentAnalysis = z.infer<typeof zAssessmentAnalysis>;

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
