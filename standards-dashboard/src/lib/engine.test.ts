import { describe, expect, it } from 'vitest';
import type { Framework } from './engine';
import { adviseForScenario, coveragePercent, daysSinceChecked, heatmapRows, provenanceStatus, searchFrameworks, topOverlaps } from './engine';

const DIMS = ['risk', 'data', 'transparency', 'robustness', 'security'];

function fw(over: Partial<Framework>): Framework {
  const coverage: Record<string, 0 | 1 | 2> = {};
  for (const d of DIMS) coverage[d] = 0;
  return {
    id: 'x', name: 'X', issuer: 'Issuer', jurisdiction: 'EU', kind: 'regulation',
    version: '1.0', status: 'active', url: 'https://example.com/a11y',
    summary: 'Summary.', riskTiers: [], controls: [], scenarios: [],
    coverage, lastChecked: '2026-01-01', ...over,
  };
}

const fwA = fw({
  id: 'eu-ai-act', name: 'EU AI Act', issuer: 'European Commission', jurisdiction: 'EU',
  kind: 'regulation', summary: 'Horizontal regulation for high-risk AI.',
  controls: ['risk-management', 'human-oversight'], scenarios: ['high-risk', 'chatbot'],
  coverage: { risk: 2, data: 2, transparency: 2, robustness: 1, security: 1 },
});
const fwB = fw({
  id: 'owasp-llm', name: 'OWASP LLM Top 10', issuer: 'OWASP', jurisdiction: 'Global',
  kind: 'framework', summary: 'Security controls for LLM applications.',
  controls: ['prompt-injection', 'data-leakage'], scenarios: ['chatbot', 'rag'],
  coverage: { risk: 1, data: 1, transparency: 0, robustness: 2, security: 2 },
});
const fwC = fw({
  id: 'nist-rmf', name: 'NIST AI RMF', issuer: 'NIST', jurisdiction: 'US',
  kind: 'framework', summary: 'Risk management framework for AI.',
  controls: ['govern', 'measure'], scenarios: ['manufacturing'],
  coverage: { risk: 2, data: 1, transparency: 1, robustness: 1, security: 1 },
});
const fws = [fwA, fwB, fwC];

describe('searchFrameworks', () => {
  it('returns all frameworks for an empty query, respecting filters', () => {
    expect(searchFrameworks(fws, '')).toHaveLength(3);
    expect(searchFrameworks(fws, '', { jurisdiction: 'US' }).map((f) => f.id)).toEqual(['nist-rmf']);
    expect(searchFrameworks(fws, '', { kind: 'regulation' }).map((f) => f.id)).toEqual(['eu-ai-act']);
  });

  it('matches query tokens against name, controls, scenarios', () => {
    const hits = searchFrameworks(fws, 'prompt injection');
    expect(hits.map((f) => f.id)).toContain('owasp-llm');
  });

  it('ranks exact token matches above substring matches', () => {
    const hits = searchFrameworks(fws, 'chatbot');
    expect(hits[0].id).toBe('eu-ai-act');
    expect(hits.slice(1).map((f) => f.id)).toContain('owasp-llm');
  });

  it('filters with minCoverage', () => {
    const hits = searchFrameworks(fws, 'ai', { minCoverage: 100 });
    expect(hits).toHaveLength(0);
    const seventy = searchFrameworks(fws, 'ai', { minCoverage: 70 });
    expect(seventy.map((f) => f.id)).toEqual(['eu-ai-act']);
  });
});

describe('coveragePercent', () => {
  it('computes average across pillars (0|1|2)', () => {
    const f = fw({ coverage: { risk: 2, data: 2, transparency: 1, robustness: 0, security: 2 } });
    expect(coveragePercent(f)).toBe(70);
  });

  it('handles full and empty coverage', () => {
    const full = fw({ coverage: { risk: 2, data: 2, transparency: 2, robustness: 2, security: 2 } });
    expect(coveragePercent(full)).toBe(100);
    const none = fw({ coverage: { risk: 0, data: 0, transparency: 0, robustness: 0, security: 0 } });
    expect(coveragePercent(none)).toBe(0);
  });
});

describe('heatmapRows', () => {
  it('returns a copy of the input when no query, in coverage order', () => {
    const rows = heatmapRows(fws, '', 'coverage');
    expect(rows.map((f) => f.id)).toEqual(['eu-ai-act', 'owasp-llm', 'nist-rmf']);
    expect(rows).not.toBe(fws);
  });

  it('does not mutate the input array when sorting', () => {
    const before = fws.map((f) => f.id);
    heatmapRows(fws, '', 'name');
    expect(fws.map((f) => f.id)).toEqual(before);
  });

  it('sorts by name when requested', () => {
    const rows = heatmapRows(fws, '', 'name');
    expect(rows.map((f) => f.id)).toEqual(['eu-ai-act', 'nist-rmf', 'owasp-llm']);
  });

  it('filters rows by the query', () => {
    const rows = heatmapRows(fws, 'nist', 'name');
    expect(rows.map((f) => f.id)).toEqual(['nist-rmf']);
  });
});

describe('adviseForScenario', () => {
  it('returns binding regulations ranked above guidance on keyword hits', () => {
    const advice = adviseForScenario(fws, 'deploy chatbot in EU healthcare');
    expect(advice.length).toBeGreaterThan(0);
    expect(advice[0].framework.id).toBe('eu-ai-act');
  });

  it('flags zero-coverage dimensions as gaps', () => {
    const fwWithGap = fw({
      id: 'gappy', name: 'Gappy Framework', jurisdiction: 'EU', kind: 'guideline',
      coverage: { risk: 2, data: 2, transparency: 2, robustness: 0, security: 0 },
      scenarios: ['chatbot'],
    });
    const advice = adviseForScenario([fwWithGap], 'chatbot in the EU');
    expect(advice[0].missing).toContain('robustness');
    expect(advice[0].missing).toContain('security');
  });

  it('returns empty for a blank scenario', () => {
    expect(adviseForScenario(fws, '   ')).toEqual([]);
  });
});

describe('topOverlaps', () => {
  it('returns only cells involving the requested framework, top-n by jaccard', () => {
    const overlaps = [
      { a: 'eu-ai-act', b: 'owasp-llm', jaccard: 0.5, shared: ['chatbot'] },
      { a: 'eu-ai-act', b: 'nist-rmf', jaccard: 0.8, shared: ['risk'] },
      { a: 'owasp-llm', b: 'nist-rmf', jaccard: 0.9, shared: [] },
    ];
    const top = topOverlaps(overlaps, 'eu-ai-act', 1);
    expect(top.map((c) => c.b)).toEqual(['nist-rmf']);
  });
});

describe('provenanceStatus', () => {
  const NOW = new Date('2026-09-20T12:00:00Z');

  it('tiers freshness at 90/180-day boundaries', () => {
    expect(provenanceStatus(fw({ lastChecked: '2026-09-20' }), NOW)).toMatchObject({ tier: 'fresh', label: 'checked today' });
    expect(provenanceStatus(fw({ lastChecked: '2026-09-07' }), NOW)).toMatchObject({ tier: 'fresh', days: 13 });
    expect(provenanceStatus(fw({ lastChecked: '2026-06-22' }), NOW)).toMatchObject({ tier: 'fresh', days: 90 });
    expect(provenanceStatus(fw({ lastChecked: '2026-06-21' }), NOW).tier).toBe('aging');
    expect(provenanceStatus(fw({ lastChecked: '2026-03-24' }), NOW).tier).toBe('aging');
    expect(provenanceStatus(fw({ lastChecked: '2026-03-23' }), NOW)).toMatchObject({ tier: 'stale' });
  });

  it('reports unknown for missing or unparseable dates', () => {
    expect(provenanceStatus(fw({ lastChecked: '' }), NOW)).toEqual({ days: null, tier: 'unknown', label: 'check date unknown' });
    expect(provenanceStatus(fw({ lastChecked: 'not-a-date' }), NOW).tier).toBe('unknown');
  });

  it('clamps future check dates to today', () => {
    expect(daysSinceChecked(fw({ lastChecked: '2026-12-01' }), NOW)).toBe(0);
  });
});