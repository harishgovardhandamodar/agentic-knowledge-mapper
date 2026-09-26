import { describe, expect, it } from 'vitest';
import type { Framework } from './engine';
import { SECURITY_TOPICS, topicFrameworks } from './security';

function fw(over: Partial<Framework>): Framework {
  return {
    id: 'x', name: 'X', issuer: 'Pipeline', jurisdiction: 'EU', kind: 'framework',
    version: '1.0', status: 'active', url: 'https://example.com/security',
    summary: 'Summary.', riskTiers: [], controls: [], scenarios: [],
    coverage: { security: 0 }, lastChecked: '2026-09-01', ...over,
  };
}

const fwIam = fw({
  id: 'csa-ccm', name: 'CSA CCM', controls: ['access.control', 'authorization'],
  coverage: { security: 2 },
});
const fwGuardrails = fw({
  id: 'owasp-llm', name: 'OWASP LLM', controls: ['guardrail', 'prompt-injection'],
  coverage: { security: 2 },
});
const fwNone = fw({ id: 'unrelated', name: 'Unrelated', controls: ['accounting'] });

describe('SECURITY_TOPICS', () => {
  it('has equal traditional and evolved topics with unique ids and keywords', () => {
    const ids = SECURITY_TOPICS.map((t) => t.id);
    expect(new Set(ids).size).toBe(SECURITY_TOPICS.length);
    expect(SECURITY_TOPICS.filter((t) => t.stream === 'traditional')).toHaveLength(4);
    expect(SECURITY_TOPICS.filter((t) => t.stream === 'evolved')).toHaveLength(6);
    expect(SECURITY_TOPICS.every((t) => t.keywords.length > 0)).toBe(true);
  });
});

describe('topicFrameworks', () => {
  const fws = [fwIam, fwGuardrails, fwNone];
  const iam = SECURITY_TOPICS.find((t) => t.id === 'iam')!;
  const advml = SECURITY_TOPICS.find((t) => t.id === 'advml')!;

  it('matches frameworks on keyword hits across controls', () => {
    expect(topicFrameworks(fws, iam).map((f) => f.id)).toEqual(['csa-ccm']);
  });

  it('returns an empty list when no keyword matches', () => {
    expect(topicFrameworks(fws, advml)).toEqual([]);
  });
});