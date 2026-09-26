import { describe, expect, it } from 'vitest';
import type { Framework } from './engine';
import type { GraphData } from './graph';
import { familyGraph, queryAll } from './families';

function fw(over: Partial<Framework>): Framework {
  return {
    id: 'x', name: 'X', issuer: 'Issuer', jurisdiction: 'EU', kind: 'framework',
    version: '1.0', status: 'active', url: 'https://example.com/families',
    summary: 'Summary.', riskTiers: [], controls: [], scenarios: [],
    coverage: {}, lastChecked: '2026-09-01', ...over,
  };
}

const fwA = fw({ id: 'nist-rmf', name: 'NIST AI RMF', controls: ['govern', 'measure'] });
const fwB = fw({ id: 'iso-42001', name: 'ISO 42001', controls: ['management-system'] });

function graph(): GraphData {
  return {
    generated: '2026-09-20',
    nodes: [
      { id: 'nist-rmf', type: 'framework', label: 'NIST AI RMF', cluster: 0 },
      { id: 'iso-42001', type: 'framework', label: 'ISO 42001', cluster: 0 },
      { id: 'govern', type: 'control', label: 'Govern', cluster: 1 },
      { id: 'data-min', type: 'control', label: 'Data Minimization', cluster: 1 },
    ],
    links: [
      { source: 'nist-rmf', target: 'govern', relation: 'mandates', weight: 1, shared: ['govern'] },
      { source: 'iso-42001', target: 'data-min', relation: 'recommends', weight: 0.4, shared: [] },
      { source: 'nist-rmf', target: 'iso-42001', relation: 'similar', weight: 0.6, shared: ['risk'] },
    ],
    clusterCount: 2,
    clusterLabels: ['Frameworks', 'Controls'],
  };
}

describe('queryAll', () => {
  it('returns no hits for a blank query', () => {
    expect(queryAll([fwA, fwB], graph(), '   ')).toEqual([]);
  });

  it('ranks framework name matches before substring-only matches', () => {
    const hits = queryAll([fwA, fwB], graph(), 'rmf');
    expect(hits[0]).toMatchObject({ kind: 'framework', id: 'nist-rmf' });
  });

  it('matches control nodes from their label', () => {
    const hits = queryAll([fwA, fwB], graph(), 'minimization');
    expect(hits).toContainEqual(expect.objectContaining({ kind: 'control', id: 'data-min' }));
  });
});

describe('familyGraph', () => {
  it('keeps member nodes, non-similar neighbors, and their links', () => {
    const g = familyGraph(graph(), ['nist-rmf', 'govern']);
    expect(g.nodes.map((n) => n.id)).toEqual(['nist-rmf', 'govern']);
    expect(g.links).toEqual([{ source: 'nist-rmf', target: 'govern', relation: 'mandates', weight: 1, shared: ['govern'] }]);
  });
});