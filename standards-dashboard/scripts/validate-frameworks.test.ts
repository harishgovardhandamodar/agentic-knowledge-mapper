import { existsSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { validateFrameworks } from './lib/validate-frameworks.mjs';

function tax(dims: string[]) {
  return { dimensions: dims.map((id) => ({ id, label: id, description: id })) };
}

const DIMS = tax(['risk', 'data', 'security']);

function fw(over: Record<string, unknown> = {}) {
  return {
    id: 'x', name: 'X', issuer: 'I', jurisdiction: 'EU', kind: 'regulation',
    version: '1', status: 'draft', url: 'https://example.com/x',
    summary: 's', riskTiers: [], controls: [], scenarios: [],
    coverage: { risk: 0, data: 0, security: 0 },
    lastChecked: '2026-01-01', ...over,
  };
}

describe('validateFrameworks', () => {
  it('accepts a valid framework', () => {
    expect(validateFrameworks({ frameworks: [fw()] }, DIMS)).toEqual([]);
  });

  it('rejects duplicate and missing ids', () => {
    const errors = validateFrameworks({ frameworks: [fw({ id: 'a' }), fw({ id: 'a' }), fw({ id: '' })] }, DIMS);
    expect(errors.some((e: string) => e.includes('duplicate/missing id: a'))).toBe(true);
  });

  it('rejects unknown dimensions', () => {
    const errors = validateFrameworks({ frameworks: [fw({ coverage: { risk: 0, mystery: 1, data: 0, security: 0 } })] }, DIMS);
    expect(errors).toContain('x: unknown dimension mystery');
  });

  it('rejects scores outside 0|1|2', () => {
    const errors = validateFrameworks({ frameworks: [fw({ coverage: { risk: 3, data: 0, security: 0 } })] }, DIMS);
    expect(errors).toContain('x: bad score risk=3');
  });

  it('rejects missing dimensions', () => {
    const errors = validateFrameworks({ frameworks: [fw({ coverage: { risk: 0, data: 0 } })] }, DIMS);
    expect(errors.some((e: string) => e.includes('missing dimension security'))).toBe(true);
  });

  it('rejects non-http urls', () => {
    const errors = validateFrameworks({ frameworks: [fw({ url: 'ftp://x' })] }, DIMS);
    expect(errors).toContain('x: bad url');
  });
});

describe('committed dataset', () => {
  it('framework data passes the same validation ingest runs', () => {
    const root = new URL('../../', import.meta.url).pathname;
    if (!existsSync(`${root}data/frameworks.json`)) return;
    const fwRaw = JSON.parse(readFileSync(`${root}data/frameworks.json`, 'utf8'));
    const taxRaw = JSON.parse(readFileSync(`${root}data/taxonomy.json`, 'utf8'));
    expect(validateFrameworks(fwRaw, taxRaw)).toEqual([]);
  });
});