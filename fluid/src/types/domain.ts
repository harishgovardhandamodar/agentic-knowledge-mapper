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
