import { describe, expect, it } from 'vitest';
import type { GraphData } from './graph';
import { cooccurring, mandateSplit, relatedNodes, similarityScope } from './graph';

function graph(): GraphData {
  return {
    generated: '2026-09-20',
    nodes: [
      { id: 'fw-a', type: 'framework', label: 'Framework A', cluster: 0, kind: 'regulation' },
      { id: 'fw-b', type: 'framework', label: 'Framework B', cluster: 0, kind: 'regulation' },
      { id: 'ctl-1', type: 'control', label: 'Human Oversight', cluster: 1 },
      { id: 'ctl-2', type: 'control', label: 'Risk Management', cluster: 1 },
    ],
    links: [
      { source: 'fw-a', target: 'ctl-1', relation: 'mandates', weight: 0.9, shared: ['risk'] },
      { source: 'fw-a', target: 'ctl-2', relation: 'mandates', weight: 0.7, shared: ['risk'] },
      { source: 'fw-b', target: 'ctl-1', relation: 'recommends', weight: 0.5, shared: [] },
      { source: 'fw-a', target: 'fw-b', relation: 'similar', weight: 0.8, shared: ['risk'] },
    ],
    clusterCount: 2,
    clusterLabels: ['Frameworks', 'Controls'],
  };
}

describe('relatedNodes', () => {
  it('excludes similar links below the minimum similarity', () => {
    const rels = relatedNodes(graph(), 'fw-a', 0.85);
    expect(rels.map((r) => r.node.id)).toEqual(['ctl-1', 'ctl-2']);
    expect(rels.every((r) => r.relation !== 'similar')).toBe(true);
  });

  it('ranks similar first, then by relation weight', () => {
    const rels = relatedNodes(graph(), 'fw-a', 0);
    expect(rels[0].relation).toBe('similar');
    expect(rels.slice(1).map((r) => r.relation)).toEqual(['mandates', 'mandates']);
  });
});

describe('similarityScope', () => {
  it('reports min/max/count over similar links', () => {
    const g = graph();
    g.links.push({ source: 'fw-b', target: 'fw-a', relation: 'similar', weight: 0.5, shared: [] });
    expect(similarityScope(g, 'fw-a')).toEqual({ min: 0.5, max: 0.8, n: 2 });
  });

  it('returns zeros when there are no similar links', () => {
    const g = graph();
    g.links = g.links.filter((l) => l.relation !== 'similar');
    expect(similarityScope(g, 'ctl-1')).toEqual({ min: 0, max: 0, n: 0 });
  });
});

describe('mandateSplit', () => {
  it('splits mandates from recommendations, frameworks only', () => {
    const { mandatedBy, recommendedBy } = mandateSplit(graph(), 'ctl-1');
    expect(mandatedBy.map((n) => n.id)).toEqual(['fw-a']);
    expect(recommendedBy.map((n) => n.id)).toEqual(['fw-b']);
  });

  it('has no mandates for an unrelated node', () => {
    const { mandatedBy } = mandateSplit(graph(), 'fw-a');
    expect(mandatedBy).toEqual([]);
  });
});

describe('cooccurring', () => {
  it('counts same-type sub-nodes sharing frameworks, capped by top', () => {
    const tiers = cooccurring(graph(), 'ctl-1', 1);
    expect(tiers).toEqual([{ node: expect.objectContaining({ id: 'ctl-2' }), n: 1 }]);
  });

  it('excludes nodes of a different type', () => {
    const tiers = cooccurring(graph(), 'fw-a');
    expect(tiers.every((t) => t.node.type === 'framework')).toBe(true);
  });
});