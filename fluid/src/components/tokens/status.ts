/**
 * The single place a status is turned into a label, a glyph and a colour class.
 *
 * The brief is emphatic that severity/status colour must never be hard-coded in
 * a component and must never rely on hue alone (red/green colour-blindness).
 * Every entry therefore carries a text label and a distinct glyph; colour is a
 * redundant third channel. Components import these maps and nothing else.
 */
import type { ClaimVerdict, EvidenceStatus, ReviewState, SeverityBand } from '@/types/domain';

export interface StatusMeta {
  label: string;
  /** A non-colour channel (glyph) so the meaning survives greyscale. */
  glyph: string;
  /** Tailwind classes referencing the semantic tokens in globals.css. */
  className: string;
  /** Longer explanation for tooltips / assistive text. */
  description: string;
}

export const VERDICT_META: Record<ClaimVerdict, StatusMeta> = {
  supported: {
    label: 'Supported',
    glyph: '\u2713',
    className: 'text-evidence-direct border-evidence-direct',
    description: 'The claim is grounded in a cited source span.',
  },
  weak: {
    label: 'Weak',
    glyph: '\u25CB',
    className: 'text-evidence-modality border-evidence-modality',
    description: 'Some support, below the entailment floor — review before use.',
  },
  unsupported: {
    label: 'Unsupported',
    glyph: '\u2715',
    className: 'text-evidence-absent border-evidence-absent',
    description: 'No cited source supports the claim.',
  },
  contradicted: {
    label: 'Contradicted',
    glyph: '\u2260',
    className: 'text-evidence-contradicts border-evidence-contradicts',
    description: 'Another claim shares its vocabulary but disagrees.',
  },
};

export const EVIDENCE_META: Record<EvidenceStatus, StatusMeta> = {
  direct: {
    label: 'Direct',
    glyph: '\u25CF',
    className: 'text-evidence-direct border-evidence-direct',
    description: 'A source states this directly.',
  },
  family: {
    label: 'Family',
    glyph: '\u25D0',
    className: 'text-evidence-family border-evidence-family',
    description: 'A source of the same family supports this.',
  },
  modality: {
    label: 'Modality',
    glyph: '\u25D1',
    className: 'text-evidence-modality border-evidence-modality',
    description: 'Support depends on modality (may / should / must).',
  },
  absent: {
    label: 'Absent',
    glyph: '\u25CB',
    className: 'text-evidence-absent border-evidence-absent',
    description: 'No evidence found — treated as unknown, not as a zero risk.',
  },
  contradicts: {
    label: 'Contradicts',
    glyph: '\u2260',
    className: 'text-evidence-contradicts border-evidence-contradicts',
    description: 'Evidence points the other way.',
  },
};

export const SEVERITY_META: Record<SeverityBand, StatusMeta> = {
  critical: {
    label: 'Critical',
    glyph: '\u25B2\u25B2',
    className: 'text-severity-critical border-severity-critical',
    description: 'Critical residual risk.',
  },
  high: {
    label: 'High',
    glyph: '\u25B2',
    className: 'text-severity-high border-severity-high',
    description: 'High residual risk.',
  },
  medium: {
    label: 'Medium',
    glyph: '\u25A0',
    className: 'text-severity-medium border-severity-medium',
    description: 'Medium residual risk.',
  },
  low: {
    label: 'Low',
    glyph: '\u25BD',
    className: 'text-severity-low border-severity-low',
    description: 'Low residual risk.',
  },
  info: {
    label: 'Info',
    glyph: '\u25CB',
    className: 'text-severity-info border-severity-info',
    description: 'Informational.',
  },
};

export const REVIEW_META: Record<ReviewState, StatusMeta> = {
  unreviewed: {
    label: 'Unreviewed',
    glyph: '\u25CB',
    className: 'text-muted-foreground border-border',
    description: 'Awaiting a human decision.',
  },
  accepted: {
    label: 'Accepted',
    glyph: '\u2713',
    className: 'text-evidence-direct border-evidence-direct',
    description: 'Accepted by a reviewer.',
  },
  rejected: {
    label: 'Rejected',
    glyph: '\u2715',
    className: 'text-evidence-contradicts border-evidence-contradicts',
    description: 'Rejected by a reviewer.',
  },
  needs_evidence: {
    label: 'Needs evidence',
    glyph: '\u003F',
    className: 'text-evidence-modality border-evidence-modality',
    description: 'A reviewer asked for more evidence.',
  },
};

/**
 * Display-only severity hint for a 0..100 residual percentage.
 *
 * The backend bands a raw integer score (app.security.SEVERITY_BANDS), so when
 * a row carries its own `residual_severity` the UI must prefer that string and
 * only fall back here for the aggregate headline. This is a coarse visual
 * spread, not a re-derivation of the engine's band.
 */
export function severityFromPct(pct: number): SeverityBand {
  if (pct >= 80) return 'critical';
  if (pct >= 60) return 'high';
  if (pct >= 40) return 'medium';
  if (pct >= 20) return 'low';
  return 'info';
}

/** Normalize a backend severity string ("Critical", "High", …) to a band. */
export function normalizeSeverity(raw: string | null | undefined): SeverityBand | null {
  const s = (raw ?? '').trim().toLowerCase();
  if (s === 'critical') return 'critical';
  if (s === 'high') return 'high';
  if (s === 'medium') return 'medium';
  if (s === 'low') return 'low';
  if (s === 'info' || s === 'informational') return 'info';
  return null;
}
