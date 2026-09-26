import type { Framework } from './engine';
import type { GraphData } from './graph';

export interface Family {
  id: string;
  label: string;
  short: string;
  members: string[];
  about: string;
  applicability: string[];
}

/** Curated family blurbs (stable facts + source links live on member cards). */
export const FAMILIES: Family[] = [
  {
    id: 'eu',
    label: 'EU AI Act family',
    short: 'EU AI Act',
    members: ['eu-ai-act', 'eu-gpai-code', 'eu-pld-ai', 'coe-framework-convention'],
    about:
      'The EU regime centers on the Artificial Intelligence Act (Regulation (EU) 2024/1689): a risk-based horizontal ' +
      'law banning prohibited practices, imposing conformity duties on high-risk systems, transparency duties for ' +
      'synthetic content, and safety/security duties on general-purpose AI models. It is operationalized by the ' +
      'GPAI Code of Practice, backed by the revised Product Liability Directive for AI-caused harm, and complemented ' +
      'by the Council of Europe Framework Convention on human rights and the rule of law.',
    applicability: [
      'Providers placing AI systems or GPAI models on the EU market (including free/open weights with systemic risk).',
      'Deployers of high-risk systems: healthcare, hiring, education, biometrics, law enforcement, critical infrastructure.',
      'Deployers who must disclose AI interaction and label synthetic content (chatbots, image/voice generation).',
      'Product teams needing incident reporting, logging, and post-market monitoring evidence for liability defense.',
    ],
  },
  {
    id: 'nist',
    label: 'NIST family',
    short: 'NIST',
    members: ['nist-ai-rmf', 'nist-genai-600-1', 'nist-adversarial-ml'],
    about:
      'NIST gives the voluntary US backbone for AI risk management: the AI Risk Management Framework (Govern–Map–Measure–Manage), ' +
      'the Generative AI Profile (600-1) covering confabulation, CBRN, IP, and value-chain risks, and the Adversarial ML taxonomy ' +
      'cataloguing evasion, poisoning, prompt-injection, and privacy attacks with mitigations. Widely referenced by regulators and ' +
      'procurement worldwide, including alignment with the EU AI Act.',
    applicability: [
      'Any organization standing up an AI risk program or doing vendor diligence on AI suppliers.',
      'Teams shipping generative features (chat, RAG, image/code generation) needing risk profiles and eval practices.',
      'Security/red teams threat-modeling LLM and agent deployments (prompt injection, data leakage, poisoning).',
      'US federal suppliers aligning with OMB AI governance memoranda.',
    ],
  },
  {
    id: 'owasp',
    label: 'OWASP family',
    short: 'OWASP',
    members: ['owasp-llm-top10', 'owasp-agentic'],
    about:
      'OWASP provides the practitioner security baseline for LLM applications: the Top 10 for LLM Applications (prompt injection, ' +
      'data leakage, excessive agency, misinformation, supply chain) and the Agentic AI guidance (tool abuse, agent identity, memory ' +
      'poisoning, human-approval gates). Community-driven, control-oriented, and directly testable in CI and red-team exercises.',
    applicability: [
      'Engineering teams building chatbots, RAG pipelines, coding assistants, and tool-using agents.',
      'AppSec reviews and pentests scoping LLM-specific attack surface and mitigations.',
      'MLOps gates: input/output filtering, least-privilege tool access, human approval for high-stakes agent actions.',
    ],
  },
  {
    id: 'iso',
    label: 'ISO family',
    short: 'ISO',
    members: ['iso-42001', 'iso-23894', 'iso-23053', 'iso-24029', 'iso-24028'],
    about:
      'ISO/IEC turns governance into auditable systems: 42001 (certifiable AI management system), 23894 (risk management), ' +
      '23053 (ML lifecycle processes), 24029 (neural-network robustness assessment), and 24028 (trustworthiness characteristics ' +
      'such as fairness, explainability, and controllability). The natural certification path for EU AI Act alignment.',
    applicability: [
      'Organizations pursuing ISO 42001 certification or demonstrating “state of the art” compliance.',
      'Vendor assurance: asking suppliers for AIMS scope, risk registers, and lifecycle evidence.',
      'High-risk system owners needing documented robustness testing and trustworthiness evaluation.',
    ],
  },
];

function norm(s: string): string {
  return s.toLowerCase().trim();
}
function qtokens(s: string): string[] {
  return norm(s).split(/[^a-z0-9+]+/).filter((t) => t.length > 1);
}

/** Subgraph for a family: members + directly linked nodes + internal links (hive detail_graph analogue). */
export function familyGraph(graph: GraphData, members: string[]): GraphData {
  const mset = new Set(members);
  const keep = new Set<string>(members);
  for (const l of graph.links) {
    if (mset.has(l.source) && l.relation !== 'similar') keep.add(l.target);
    if (mset.has(l.target) && l.relation !== 'similar') keep.add(l.source);
  }
  return {
    generated: graph.generated,
    nodes: graph.nodes.filter((n) => keep.has(n.id)),
    links: graph.links.filter((l) => keep.has(l.source) && keep.has(l.target)),
    clusterCount: graph.clusterCount,
    clusterLabels: graph.clusterLabels,
  };
}

export interface QueryHit {
  kind: 'framework' | 'control' | 'topic' | 'exposure' | 'theme' | 'paper' | 'security_topic';
  id: string;
  label: string;
  score: number;
  detail: string;
}

/** Unified retrieval over frameworks, controls, topics, exposures, themes. */
export function queryAll(frameworks: Framework[], graph: GraphData, q: string): QueryHit[] {
  const qs = qtokens(q);
  if (!qs.length) return [];
  const hits: QueryHit[] = [];
  for (const f of frameworks) {
    const hay = new Set(qtokens([f.name, f.issuer, f.jurisdiction, f.kind, f.summary, f.controls.join(' '), f.scenarios.join(' '), f.riskTiers.join(' ')].join(' ')));
    let s = 0;
    for (const t of qs) {
      if (hay.has(t)) s += 2;
      else if ([...hay].some((h) => h.includes(t) || t.includes(h))) s += 1;
    }
    if (s > 0) hits.push({ kind: 'framework', id: f.id, label: f.name, score: s, detail: `${f.jurisdiction} · ${f.kind} — ${f.summary.slice(0, 140)}…` });
  }
  for (const n of graph.nodes) {
    if (n.type === 'framework') continue;
    const hay = qtokens(n.label);
    let s = 0;
    for (const t of qs) {
      if (hay.includes(t)) s += 2;
      else if (hay.some((h) => h.includes(t) || t.includes(h))) s += 1;
    }
    if (s > 0) {
      const extra = n.type === 'theme' ? 'control dimension' : `in ${n.count ?? 0} instruments`;
      hits.push({ kind: n.type, id: n.id, label: n.label, score: s, detail: `${n.type} · ${extra}` });
    }
  }
  return hits.sort((a, b) => b.score - a.score || a.label.localeCompare(b.label)).slice(0, 40);
}
