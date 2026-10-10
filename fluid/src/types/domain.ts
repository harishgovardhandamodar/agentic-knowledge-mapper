/**
 * UI-domain vocabulary shared across components.
 *
 * These mirror the backend's own enums (app/grounding.py, app/claims.py,
 * app/uncertainty.py, app/privacy.py) so a value that arrives from the API can
 * be switched on exhaustively here. Keep them in lock-step: a status the UI
 * cannot name is a case a researcher cannot see.
 */

/** Support verdict for one atomic claim (app.grounding / app.claims). */
export const CLAIM_VERDICTS = ['supported', 'weak', 'unsupported', 'contradicted'] as const;
export type ClaimVerdict = (typeof CLAIM_VERDICTS)[number];

/** How a claim was grounded against its source (app.grounding). */
export const VERIFIED_BY = ['verbatim', 'entailment'] as const;
export type VerifiedBy = (typeof VERIFIED_BY)[number];

/** Evidence status of a support, from direct to absent (app.uncertainty). */
export const EVIDENCE_STATUSES = ['direct', 'family', 'modality', 'absent', 'contradicts'] as const;
export type EvidenceStatus = (typeof EVIDENCE_STATUSES)[number];

/** Residual severity band (app.security._severity). */
export const SEVERITY_BANDS = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type SeverityBand = (typeof SEVERITY_BANDS)[number];

/** Review state a node/claim can carry in the mapper (mirrors the backend). */
export const REVIEW_STATES = ['unreviewed', 'accepted', 'rejected', 'needs_evidence'] as const;
export type ReviewState = (typeof REVIEW_STATES)[number];

/** One cited source behind a claim. */
export interface ClaimSource {
  id: string;
  title?: string;
  url?: string;
  /** Provider/host that served it, for the privacy story. */
  domain?: string;
}

/** A character span in the original source that grounds a claim. */
export interface ClaimSpan {
  sourceId: string;
  /** The verbatim quote located in the source. */
  quote: string;
  /** Offsets into the original source text (app.grounding locate_quote). */
  start?: number | null;
  end?: number | null;
  verifiedBy?: VerifiedBy;
  /** Evidence strength behind this particular span. */
  status?: EvidenceStatus;
}

/**
 * A tension: two claims that share vocabulary but disagree, or a claim whose
 * number flipped against its source. Surfaced rather than averaged away
 * (app.claims.claim_graph emits `contradicts` edges).
 */
export interface ClaimTension {
  id: string;
  kind: 'contradicts' | 'number_swap' | 'negation_flip' | 'other';
  /** Free-text note or the shared terms that triggered the tension. */
  note?: string;
  againstClaimId?: string;
  againstText?: string;
  terms?: string[];
}

/**
 * A verifiable atomic claim, the unit everything else links to.
 *
 * The brief's central promise: a residual can be traced to the exact sentence
 * and span that supports it, and a claim's confidence is never shown without
 * the interval behind it when the backend provides one (brief §8).
 */
export interface Claim {
  id: string;
  text: string;
  verdict: ClaimVerdict;
  /** Normalized support 0..1 (app.claims verify_claim `support`). */
  support: number;
  /** Calibrated confidence 0..1 paired with a credible interval, if known. */
  confidence?: number;
  confidenceInterval?: [number, number];
  evidenceStatus?: EvidenceStatus;
  review?: ReviewState;
  spans: ClaimSpan[];
  sources: ClaimSource[];
  tensions: ClaimTension[];
  /** Citation ids the claim asserted but that resolve to no source. */
  inventedCitations?: string[];
  /** Which assessment/threat this claim belongs to, when scoped. */
  threatId?: string;
  investigationId?: number;
}

/** A residual figure shown with its credible interval (brief §7). */
export interface ResidualInterval {
  /** Point estimate in percent 0..100. */
  point: number;
  lower: number;
  upper: number;
  /** Credible level, e.g. 0.9 for a 90% interval. */
  level: number;
  /** True when the point estimate fell inside [lower, upper]. */
  headlineInside: boolean;
  /** Number of threats the interval aggregated over. */
  nThreats?: number;
}

/** Evidence-status histogram behind a residual (brief §4). */
export type EvidenceBreakdown = Partial<Record<EvidenceStatus, number>>;

/**
 * Provenance for one control efficacy, from the engine's calibration layer.
 *
 * `basis` is the epistemic claim: `expert_elicited` means a single analyst
 * chose the number and nobody has measured it. That distinction is the whole
 * reason this type exists — the residual score is a function of these values,
 * so a reader is entitled to know which ones are evidence and which are
 * opinion.
 */
export interface ControlProvenance {
  control_id: string;
  /** The catalogue value. */
  declared: number | null;
  /** Prior + observations, still retaining the prior's weight. */
  posterior_mean: number | null;
  basis: 'measured' | 'expert_elicited' | 'literature' | string;
  source: string;
  n_observations: number;
  concentration: number;
  note: string;
  validated: boolean;
  /** Filled by the client from the Beta interval, not sent by the engine. */
  lower?: number;
  upper?: number;
}

/** Rollup of provenance across one assessment's declared controls. */
export interface EfficacyEvidenceSummary {
  n_controls: number;
  validated_controls: string[];
  unvalidated_controls: string[];
  all_validated: boolean;
  widest_concentration: number | null;
  widest_control: string | null;
  basis_note: string;
  records: Record<string, ControlProvenance>;
}

/**
 * Why the residual score stopped responding to controls.
 *
 * The 35% likelihood floor means the headline saturates: past it, declaring
 * more real controls changes coverage but not the number. `controls_beyond_floor`
 * is the leave-one-out ablation count that makes that visible, so "I attested
 * more and nothing moved" has an answer.
 */
export interface FloorDiagnostics {
  floor: number;
  floor_capped: boolean;
  floor_capped_threats: string[];
  floor_capped_count: number;
  floor_capped_pct: number;
  controls_beyond_floor: number;
  controls_beyond_floor_ids: string[];
  controls_effective: number;
  controls_effective_ids: string[];
  /** Controls touching no included threat — inert, distinct from floored. */
  controls_orphaned: string[];
  noise_epsilon: number;
  note: string;
}

/** Decomposition of the credible interval by input, plus what it omits. */
export interface VarianceBudgetSummary {
  total_variance: number;
  inherent_probability_variance: number;
  control_efficacy_variance: number;
  interaction_variance: number;
  share_inherent: number;
  share_efficacy: number;
  share_interaction: number;
  shares_sum?: number;
  interaction_note?: string;
  quantified: string[];
  unquantified: Record<string, string>;
  control_provenance: {
    n_controls: number;
    validated: number;
    unvalidated: number;
    all_validated: boolean;
    note?: string;
  };
  floor_capped: boolean;
  note: string;
}
