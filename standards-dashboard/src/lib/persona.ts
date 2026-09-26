import type { Framework } from './engine';
import type { Dimension } from './engine';
import { coveragePercent } from './engine';

export type PersonaId = 'data_scientist' | 'governance' | 'csuite' | 'dpo' | 'security_traditional' | 'security_evolved';

export interface Persona {
  id: PersonaId;
  label: string;
  short: string;
  icon: string;
  description: string;
  dimensions: string[]; // relevant dimension ids
  frameworkFilter: (f: Framework) => boolean;
  color: string;
  kpis: { label: string; get: (fws: Framework[], dims: Dimension[]) => string | number }[];
}

export const PERSONAS: Persona[] = [
  {
    id: 'csuite',
    label: 'C-Suite Executive',
    short: 'C-Suite',
    icon: '◈',
    description: 'High-level risk, compliance posture and business impact across all 34 frameworks.',
    dimensions: ['risk_management', 'accountability', 'incident_response', 'lifecycle_eval'],
    frameworkFilter: () => true,
    color: '#4da3ff',
    kpis: [
      { label: 'Avg Coverage', get: (fws) => `${Math.round(fws.reduce((s, f) => s + coveragePercent(f), 0) / fws.length)}%` },
      { label: 'Binding Regulations', get: (fws) => fws.filter((f) => f.kind === 'regulation').length },
      { label: 'High-Risk Frameworks', get: (fws) => fws.filter((f) => f.scenarios.includes('high-risk')).length },
    ],
  },
  {
    id: 'governance',
    label: 'Governance Team',
    short: 'Governance',
    icon: '⚖',
    description: 'Risk, accountability, lifecycle and maturity — ISO 42001, NIST RMF, EU AI Act alignment.',
    dimensions: ['risk_management', 'accountability', 'lifecycle_eval', 'human_oversight', 'incident_response'],
    frameworkFilter: (f) => ['iso-42001', 'iso-23894', 'nist-ai-rmf', 'eu-ai-act', 'oecd-ai-principles'].includes(f.id) || f.kind === 'standard',
    color: '#9d4edd',
    kpis: [
      { label: 'Governance Coverage', get: (fws) => `${Math.round(fws.reduce((s, f) => s + (f.coverage['accountability'] ?? 0) / 2 / fws.length * 100, 0))}%` },
      { label: 'Certifiable (ISO)', get: (fws) => fws.filter((f) => f.id.startsWith('iso-')).length },
    ],
  },
  {
    id: 'data_scientist',
    label: 'Data Scientist',
    short: 'Data Science',
    icon: '⬢',
    description: 'Data, robustness, evaluation and lifecycle — model cards, training data, evals and MLOps.',
    dimensions: ['data_governance', 'robustness', 'lifecycle_eval', 'transparency'],
    frameworkFilter: (f) => f.controls.some((c) => /data|robust|eval|mlops|lifecycle/i.test(c)) || f.scenarios.includes('eval'),
    color: '#2ec4b6',
    kpis: [
      { label: 'Data Gov Avg', get: (fws) => `${Math.round(fws.reduce((s, f) => s + (f.coverage['data_governance'] ?? 0) / 2 / fws.length * 100, 0))}%` },
      { label: 'Robustness Avg', get: (fws) => `${Math.round(fws.reduce((s, f) => s + (f.coverage['robustness'] ?? 0) / 2 / fws.length * 100, 0))}%` },
    ],
  },
  {
    id: 'dpo',
    label: 'Data Protection Officer',
    short: 'DPO',
    icon: '🛡',
    description: 'Privacy, data governance, DPIA and transparency — GDPR-adjacent duties across AI acts.',
    dimensions: ['privacy', 'data_governance', 'transparency', 'accountability'],
    frameworkFilter: (f) => (f.coverage['privacy'] ?? 0) > 0 || f.jurisdiction.includes('EU') || f.id.includes('privacy'),
    color: '#7bd389',
    kpis: [
      { label: 'Privacy Coverage', get: (fws) => `${Math.round(fws.reduce((s, f) => s + (f.coverage['privacy'] ?? 0) / 2 / fws.length * 100, 0))}%` },
      { label: 'With PII Controls', get: (fws) => fws.filter((f) => f.controls.join(' ').toLowerCase().includes('privacy') || f.controls.join(' ').toLowerCase().includes('pii')).length },
    ],
  },
  {
    id: 'security_traditional',
    label: 'Traditional Security',
    short: 'Traditional',
    icon: '⬣',
    description: 'IAM, hardening, SecOps, supply chain — classic controls applied to AI systems.',
    dimensions: ['security', 'incident_response', 'lifecycle_eval'],
    frameworkFilter: (f) => ['csa-ccm-ai', 'iso-42001', 'nist-ai-rmf'].includes(f.id) || f.controls.join(' ').toLowerCase().includes('access') || f.coverage['security'] === 1,
    color: '#5da9e9',
    kpis: [
      { label: 'Sec Coverage', get: (fws) => `${Math.round(fws.reduce((s, f) => s + (f.coverage['security'] ?? 0) / 2 / fws.length * 100, 0))}%` },
      { label: 'IAM Controls', get: (fws) => fws.filter((f) => f.controls.join(' ').toLowerCase().includes('access') || f.controls.join(' ').toLowerCase().includes('iam')).length },
    ],
  },
  {
    id: 'security_evolved',
    label: 'Evolved Security & Safety',
    short: 'Evolved Sec',
    icon: '⬡',
    description: 'AI/model hardening, data minimization, fingerprinting, adversarial ML, agent security, IP protection.',
    dimensions: ['security', 'robustness', 'privacy', 'incident_response'],
    frameworkFilter: (f) => ['owasp-llm-top10', 'owasp-agentic', 'mitre-atlas', 'nist-adversarial-ml', 'nist-genai-600-1'].includes(f.id) || f.coverage['security'] === 2,
    color: '#e71d36',
    kpis: [
      { label: 'Evolved Coverage', get: (fws) => `${Math.round(fws.reduce((s, f) => s + (f.coverage['security'] ?? 0) / 2 / fws.length * 100, 0))}%` },
      { label: 'AdvML Controls', get: (fws) => fws.filter((f) => f.id.includes('adv') || f.id.includes('owasp') || f.id.includes('atlas')).length },
    ],
  },
];

export function personaFrameworks(fws: Framework[], p: Persona): Framework[] {
  return fws.filter(p.frameworkFilter);
}

export function personaDimCoverage(fws: Framework[], dims: Dimension[], p: Persona): { dim: Dimension; avg: number }[] {
  return p.dimensions.map((id) => {
    const d = dims.find((x) => x.id === id)!;
    const avg = fws.length ? fws.reduce((s, f) => s + ((f.coverage[id] ?? 0) / 2), 0) / fws.length : 0;
    return { dim: d, avg };
  }).filter((x) => x.dim);
}
