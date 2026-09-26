export type SecurityStream = 'traditional' | 'evolved';

export interface SecurityTopic {
  id: string;
  label: string;
  short: string;
  icon: string;
  stream: SecurityStream;
  description: string;
  keywords: string[]; // to match controls/scenarios/summary
  color: string;
}

export const SECURITY_TOPICS: SecurityTopic[] = [
  // Traditional
  { id: 'iam', label: 'IAM & Access Control', short: 'IAM', icon: '◐', stream: 'traditional', description: 'Identity, authentication, authorization, least privilege, key management.', keywords: ['iam', 'access.control', 'authentication', 'authorization', 'least.privilege', 'key.management'], color: '#4da3ff' },
  { id: 'hardening', label: 'Hardening & Baseline', short: 'Hardening', icon: '⬣', stream: 'traditional', description: 'OS, network, endpoint hardening, CIS baselines, patching.', keywords: ['hardening', 'baseline', 'patching', 'cis', 'endpoint', 'network.hardening'], color: '#5da9e9' },
  { id: 'secops', label: 'SecOps & Monitoring', short: 'SecOps', icon: '◎', stream: 'traditional', description: 'SOC, logging, detection, IR, vuln management.', keywords: ['logging', 'monitoring', 'detection', 'soc', 'incident', 'vuln'], color: '#7bd389' },
  { id: 'supply', label: 'Supply Chain', short: 'Supply', icon: '⬢', stream: 'traditional', description: 'Third-party, SBOM, dependency, provenance.', keywords: ['supply.chain', 'sbom', 'dependency', 'third.party', 'provenance'], color: '#ff9f1c' },
  // Evolved — AI / model-centric
  { id: 'advml', label: 'Adversarial ML', short: 'AdvML', icon: '⚠', stream: 'evolved', description: 'Evasion, poisoning, extraction, inversion, prompt injection.', keywords: ['adversarial', 'evasion', 'poisoning', 'extraction', 'inversion', 'prompt.injection'], color: '#e71d36' },
  { id: 'hardening_ai', label: 'Security Hardening (AI)', short: 'AI Hardening', icon: '⬡', stream: 'evolved', description: 'Model hardening, guardrails, input/output filtering, sandboxing.', keywords: ['hardening', 'guardrail', 'filtering', 'sandbox', 'robustness'], color: '#b565d8' },
  { id: 'model_ip', label: 'Model IP Protection', short: 'Model IP', icon: '◍', stream: 'evolved', description: 'Weights protection, extraction defense, watermarking, licensing.', keywords: ['model.ip', 'extraction', 'watermark', 'weights', 'licensing'], color: '#9d4edd' },
  { id: 'fingerprint', label: 'Fingerprinting', short: 'Fingerprint', icon: '⌖', stream: 'evolved', description: 'Data & model fingerprinting, provenance, dataset hashing, model cards.', keywords: ['fingerprint', 'provenance', 'hashing', 'model.card', 'dataset.fingerprint'], color: '#2ec4b6' },
  { id: 'data_sec', label: 'Data Security', short: 'Data Sec', icon: '⬢', stream: 'evolved', description: 'Data minimization, DLP, PII, inference leakage, retention.', keywords: ['data.minim', 'dlp', 'pii', 'leakage', 'retention', 'minimisation'], color: '#f4d35e' },
  { id: 'agent_sec', label: 'Agent Security', short: 'Agent Sec', icon: '◑', stream: 'evolved', description: 'Tool abuse, least-privilege tools, memory poisoning, human gates.', keywords: ['agent', 'tool.abuse', 'memory.poison', 'least.privilege', 'human.gate', 'agentic'], color: '#ee964b' },
];

export function topicFrameworks(frameworks: import('./engine').Framework[], topic: SecurityTopic): import('./engine').Framework[] {
  const keys = topic.keywords.map((k) => k.toLowerCase());
  return frameworks.filter((f) => {
    const hay = [...f.controls, ...f.scenarios, ...f.riskTiers, f.summary, f.name].join(' ').toLowerCase();
    return keys.some((k) => hay.includes(k.replace('.', ' ').replace('\\', '')) || hay.includes(k.replace('\\.', '')));
  });
}
