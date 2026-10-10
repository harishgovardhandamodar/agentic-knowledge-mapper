/**
 * Adapters from backend payloads to the UI domain model.
 *
 * The GUI never renders a raw API object directly; it renders a {@link Claim},
 * a {@link ResidualInterval} or similar. Putting the mapping here means the
 * backend can reshape `verify_claim` output without touching a single
 * component, and the components stay testable against plain fixtures.
 */
import type {
  Claim,
  ClaimSource,
  ClaimSpan,
  ClaimTension,
  ClaimVerdict,
  EvidenceStatus,
} from '@/types/domain';
import type { VerifiedClaim, UncertaintyBand } from './schemas';

export interface SourceLookup {
  [id: string]: ClaimSource | undefined;
}

/** Map a backend verdict + grounding strength to an evidence status. */
export function evidenceStatusFor(
  verdict: ClaimVerdict,
  hasSpan: boolean,
  contradicted = false,
): EvidenceStatus {
  if (contradicted || verdict === 'contradicted') return 'contradicts';
  switch (verdict) {
    case 'supported':
      return hasSpan ? 'direct' : 'family';
    case 'weak':
      return 'modality';
    case 'unsupported':
    default:
      return 'absent';
  }
}

function spanFor(
  v: VerifiedClaim,
  sourceText?: (id: string) => string | undefined,
): ClaimSpan | null {
  const sourceId =
    v.source === null || v.source === undefined ? undefined : String(v.source);
  if (sourceId === undefined) return null;
  const start = v.span?.start ?? v.start ?? null;
  const end = v.span?.end ?? v.end ?? null;
  let quote = '';
  const text = sourceText?.(sourceId);
  if (text && typeof start === 'number' && typeof end === 'number') {
    quote = text.slice(start, end);
  }
  return {
    sourceId,
    quote,
    start,
    end,
    verifiedBy: quote ? 'verbatim' : 'entailment',
    status: evidenceStatusFor(v.verdict, Boolean(quote)),
  };
}

/**
 * Convert one verified claim into the UI {@link Claim}. `tensions` are attached
 * by {@link tensionsFromGraph}; pass them in when available so a contradicted
 * claim renders as such rather than as a clean support.
 */
export function toClaim(
  v: VerifiedClaim,
  opts: {
    sources?: SourceLookup;
    sourceText?: (id: string) => string | undefined;
    tensions?: ClaimTension[];
    threatId?: string;
    investigationId?: number;
    confidence?: number;
    confidenceInterval?: [number, number];
  } = {},
): Claim {
  const sources = opts.sources ?? {};
  const tensions = opts.tensions ?? [];
  const contradicted = tensions.some((t) => t.kind === 'contradicts');
  const span = spanFor(v, opts.sourceText);
  const cited = v.cited ?? [];
  const citedSources: ClaimSource[] = cited
    .map((id) => sources[id])
    .filter((s): s is ClaimSource => Boolean(s));

  const verdict: ClaimVerdict = contradicted ? 'contradicted' : v.verdict;

  return {
    id: v.claim_id,
    text: v.text,
    verdict,
    support: v.support,
    confidence: opts.confidence,
    confidenceInterval: opts.confidenceInterval,
    evidenceStatus: evidenceStatusFor(
      v.verdict,
      Boolean(span?.quote),
      contradicted,
    ),
    spans: span ? [span] : [],
    sources: citedSources,
    tensions,
    inventedCitations: v.invented && v.invented.length ? v.invented : undefined,
    threatId: opts.threatId,
    investigationId: opts.investigationId,
  };
}

/** Convert the `contradicts` edges of a claim_graph into UI tensions. */
export function tensionsFromGraph(graph: {
  nodes?: { id: string; text?: string }[];
  edges?: { from: number; to: number; kind: string; terms?: string[] }[];
}): Map<string, ClaimTension[]> {
  const byClaim = new Map<string, ClaimTension[]>();
  const nodes = graph.nodes ?? [];
  for (const e of graph.edges ?? []) {
    if (e.kind !== 'contradicts') continue;
    const a = nodes[e.from];
    const b = nodes[e.to];
    if (!a || !b) continue;
    const tension: ClaimTension = {
      id: `${a.id}~${b.id}`,
      kind: 'contradicts',
      againstClaimId: b.id,
      againstText: b.text,
      terms: e.terms,
      note: e.terms?.length ? `shares: ${e.terms.slice(0, 6).join(', ')}` : undefined,
    };
    byClaim.set(a.id, [...(byClaim.get(a.id) ?? []), tension]);
  }
  return byClaim;
}

/**
 * Turn a backend uncertainty band into the UI's {@link ResidualInterval}
 * (brief §7: a residual is never shown without its interval).
 */
export function toResidualInterval(band: UncertaintyBand): {
  point: number;
  lower: number;
  upper: number;
  level: number;
  headlineInside: boolean;
  nThreats?: number;
} {
  return {
    point: band.headline_pct ?? band.mean_pct,
    lower: band.lower_pct,
    upper: band.upper_pct,
    level: band.level,
    headlineInside: band.headline_inside,
    nThreats: band.n_threats,
  };
}
