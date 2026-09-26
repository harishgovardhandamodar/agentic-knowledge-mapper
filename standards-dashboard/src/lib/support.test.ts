import { describe, expect, it } from 'vitest';
import type { Framework } from './engine';
import { SUPPORT_MODES, supportDistribution, type SupportConfig } from './support';

function fw(over: Partial<Framework>): Framework {
  return {
    id: 'x', name: 'X', issuer: 'Issuer', jurisdiction: 'EU', kind: 'framework',
    version: '1.0', status: 'active', url: 'https://example.com/support',
    summary: 'Summary.', riskTiers: [], controls: [], scenarios: [],
    coverage: {}, lastChecked: '2026-09-01', ...over,
  };
}

const exposure: SupportConfig = SUPPORT_MODES.find((m) => m.id === 'exposure')!;

describe('SUPPORT_MODES', () => {
  it('has unique ids and stable shape', () => {
    const ids = SUPPORT_MODES.map((m) => m.id);
    expect(new Set(ids).size).toBe(SUPPORT_MODES.length);
    expect(SUPPORT_MODES.every((m) => m.short && m.label && m.icon && m.color && typeof m.getValues === 'function')).toBe(true);
  });
});

describe('supportDistribution', () => {
  it('counts getValues across frameworks, sorted by value desc', () => {
    const fws = [
      fw({ riskTiers: ['high-risk'] }),
      fw({ riskTiers: ['high-risk'] }),
      fw({ riskTiers: ['prohibited'] }),
    ];
    expect(supportDistribution(fws, exposure)).toEqual([
      { name: 'High', value: 2, color: expect.any(String) },
      { name: 'Unacceptable', value: 1, color: expect.any(String) },
    ]);
  });

  it('falls back to Regulated for regulations without a risk tier', () => {
    const fws = [fw({ kind: 'regulation', riskTiers: [] })];
    expect(supportDistribution(fws, exposure).map((r) => r.name)).toEqual(['Regulated']);
  });
});