import { describe, expect, it } from 'vitest';
import {
  evidenceStatusFor,
  tensionsFromGraph,
  toClaim,
  toResidualInterval,
} from './adapters';
import type { VerifiedClaim } from './schemas';

const verified: VerifiedClaim = {
  text: 'The platform is certified to ISO 27001.',
  start: 134,
  end: 156,
  verdict: 'supported',
  support: 0.77,
  source: 'src:blog-vendor',
  span: { start: 134, end: 156 },
  polarity: 'flip',
  shared_terms: ['iso', 'certified', 'platform'],
  cited: ['src:blog-vendor'],
  invented: [],
  claim_id: 'clm_test',
};

describe('evidenceStatusFor', () => {
  it('maps a supported verdict with a span to direct', () => {
    expect(evidenceStatusFor('supported', true)).toBe('direct');
  });
  it('maps supported without a span to family', () => {
    expect(evidenceStatusFor('supported', false)).toBe('family');
  });
  it('maps weak to modality and unsupported to absent', () => {
    expect(evidenceStatusFor('weak', true)).toBe('modality');
    expect(evidenceStatusFor('unsupported', false)).toBe('absent');
  });
  it('contradiction always wins over verdict', () => {
    expect(evidenceStatusFor('supported', true, true)).toBe('contradicts');
  });
});

describe('toClaim', () => {
  it('resolves the cited source and slices the quote from source text', () => {
    const text = 'x'.repeat(134) + 'certified to ISO 27001' + 'y'.repeat(20);
    const claim = toClaim(verified, {
      sources: { 'src:blog-vendor': { id: 'src:blog-vendor', domain: 'vendor.example' } },
      sourceText: (id) => (id === 'src:blog-vendor' ? text : undefined),
    });
    expect(claim.id).toBe('clm_test');
    expect(claim.verdict).toBe('supported');
    expect(claim.sources).toHaveLength(1);
    expect(claim.spans).toHaveLength(1);
    expect(claim.spans[0]!.quote).toBe('certified to ISO 27001');
    expect(claim.spans[0]!.verifiedBy).toBe('verbatim');
  });

  it('marks a claim contradicted when a tension is attached', () => {
    const claim = toClaim(verified, {
      tensions: [{ id: 't', kind: 'contradicts', againstClaimId: 'other' }],
    });
    expect(claim.verdict).toBe('contradicted');
    expect(claim.evidenceStatus).toBe('contradicts');
  });

  it('carries invented citations through', () => {
    const claim = toClaim({ ...verified, invented: ['src:nope'], cited: [] });
    expect(claim.inventedCitations).toEqual(['src:nope']);
    expect(claim.sources).toHaveLength(0);
  });
});

describe('tensionsFromGraph', () => {
  it('groups contradiction edges by source node', () => {
    const map = tensionsFromGraph({
      nodes: [
        { id: 'a', text: 'A' },
        { id: 'b', text: 'B' },
      ],
      edges: [{ from: 0, to: 1, kind: 'contradicts', terms: ['x', 'y', 'z'] }],
    });
    const a = map.get('a');
    expect(a).toHaveLength(1);
    expect(a![0]!.againstClaimId).toBe('b');
    expect(map.get('b')).toBeUndefined();
  });

  it('ignores non-contradiction edges', () => {
    const map = tensionsFromGraph({
      nodes: [{ id: 'a' }, { id: 'b' }],
      edges: [{ from: 0, to: 1, kind: 'cites_source' }],
    });
    expect(map.size).toBe(0);
  });
});

describe('toResidualInterval', () => {
  it('prefers the headline point but keeps the MC interval bounds', () => {
    const r = toResidualInterval({
      mean_pct: 40,
      lower_pct: 31,
      upper_pct: 58,
      level: 0.9,
      headline_pct: 42,
      headline_inside: true,
      n_threats: 12,
    });
    expect(r.point).toBe(42);
    expect(r.lower).toBe(31);
    expect(r.upper).toBe(58);
    expect(r.nThreats).toBe(12);
  });

  it('falls back to the mean when there is no headline', () => {
    const r = toResidualInterval({
      mean_pct: 40,
      lower_pct: 31,
      upper_pct: 58,
      level: 0.9,
      headline_inside: true,
    });
    expect(r.point).toBe(40);
  });
});
