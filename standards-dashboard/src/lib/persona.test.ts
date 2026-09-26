import { describe, expect, it } from 'vitest';
import type { Dimension, Framework } from './engine';
import { PERSONAS, personaDimCoverage, personaFrameworks } from './persona';

function fw(over: Partial<Framework>): Framework {
  return {
    id: 'x', name: 'X', issuer: 'Issuer', jurisdiction: 'EU', kind: 'framework',
    version: '1.0', status: 'active', url: 'https://example.com/persona',
    summary: 'Summary.', riskTiers: [], controls: [], scenarios: [],
    coverage: { privacy: 0, security: 0, accountability: 0 }, lastChecked: '2026-09-01', ...over,
  };
}

const governance = PERSONAS.find((p) => p.id === 'governance')!;
const evolved = PERSONAS.find((p) => p.id === 'security_evolved')!;

const fwIso = fw({ id: 'iso-42001', kind: 'standard', controls: ['access'] });
const fwOwasp = fw({ id: 'owasp-llm-top10', controls: ['prompt-injection'], coverage: { security: 2 } });
const fwOther = fw({ id: 'other', controls: ['accounting'] });

describe('personaFrameworks', () => {
  it('filters by the persona framework filter', () => {
    expect(personaFrameworks([fwIso, fwOwasp, fwOther], governance).map((f) => f.id)).toEqual(['iso-42001']);
    expect(personaFrameworks([fwIso, fwOwasp, fwOther], evolved).map((f) => f.id)).toEqual(['owasp-llm-top10']);
  });
});

describe('personaDimCoverage', () => {
  const dims: Dimension[] = governance.dimensions.map((id) => ({ id, label: id, description: id }));

  it('averages per-dimension coverage over the frameworks', () => {
    const crypto = fw({ coverage: { privacy: 0, security: 0, accountability: 2 } });
    const rows = personaDimCoverage([crypto], dims, governance);
    const acc = rows.find((r) => r.dim.id === 'accountability')!;
    expect(acc.avg).toBe(1);
  });

  it('returns zero average for an empty framework set', () => {
    const rows = personaDimCoverage([], dims, governance);
    expect(rows.every((r) => r.avg === 0)).toBe(true);
    expect(rows.map((r) => r.dim.id)).toEqual(governance.dimensions);
  });
});