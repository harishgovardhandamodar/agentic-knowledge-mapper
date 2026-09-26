import type { Framework } from './engine';

export type SupportMode = 'consumption' | 'exposure' | 'data_settings' | 'data_exposure' | 'parties' | 'hosting' | 'customer' | 'model_origin' | 'agents';

export interface SupportConfig {
  id: SupportMode;
  label: string;
  short: string;
  icon: string;
  description: string;
  color: string;
  // how to compute value(s) for a framework
  getValues: (f: Framework) => string[];
}

function norm(s: string): string { return s.toLowerCase().trim(); }

export const SUPPORT_MODES: SupportConfig[] = [
  {
    id: 'consumption',
    label: 'AI Consumption',
    short: 'Consumption',
    icon: '◐',
    description: 'How AI is consumed — API, embedded, SaaS, open-weights, RAG, agentic tool-use.',
    color: '#4da3ff',
    getValues: (f) => {
      const vals = new Set<string>();
      const hay = [...f.scenarios, ...f.controls, ...f.riskTiers].map(norm).join(' ');
      if (/api|open-weights|foundation-model|gpa/i.test(hay)) vals.add('API / Foundation');
      if (/rag|retrieval/i.test(hay)) vals.add('RAG');
      if (/agent|tool-use|agentic/i.test(hay)) vals.add('Agentic');
      if (/saas|cloud/i.test(hay)) vals.add('SaaS Cloud');
      if (/embedded|on-prem|edge|device/i.test(hay)) vals.add('Embedded / On-prem');
      if (/chatbot|assistant|coding-assistant/i.test(hay)) vals.add('Chatbot / Assistant');
      if (vals.size === 0) vals.add('General');
      return [...vals];
    },
  },
  {
    id: 'exposure',
    label: 'Use Exposure Levels',
    short: 'Exposure',
    icon: '⚠',
    description: 'Risk/exposure tier per instrument — unacceptable, high-risk, limited, minimal, GPAI systemic.',
    color: '#e71d36',
    getValues: (f) => {
      const m: Record<string, string> = {
        'prohibited': 'Unacceptable', 'high-risk': 'High', 'high-impact': 'High', 'consequential-decisions': 'High',
        'limited-risk': 'Limited', 'minimal-risk': 'Minimal', 'transparency': 'Limited', 'gpai': 'GPAI', 'gpa': 'GPAI',
        'systemic-risk': 'GPAI Systemic', 'frontier': 'Frontier', 'foundation-model': 'GPAI',
      };
      const vals = new Set<string>();
      for (const t of f.riskTiers.map(norm)) {
        for (const [k, v] of Object.entries(m)) if (t.includes(k)) vals.add(v);
      }
      if (vals.size === 0) {
        if (f.kind === 'regulation') vals.add('Regulated');
        else vals.add('Voluntary');
      }
      return [...vals];
    },
  },
  {
    id: 'data_settings',
    label: 'Data Settings',
    short: 'Data Settings',
    icon: '⬢',
    description: 'Data governance posture — training data quality, provenance, bias, retention, documentation.',
    color: '#2ec4b6',
    getValues: (f) => {
      const vals = new Set<string>();
      const hay = f.controls.map(norm).join(' ') + ' ' + f.summary.toLowerCase();
      if (/training-data|dataset|data-quality|provenance/i.test(hay)) vals.add('Training Data');
      if (/bias|fairness/i.test(hay)) vals.add('Bias & Fairness');
      if (/retention|decommission|logging/i.test(hay)) vals.add('Retention / Logging');
      if (/documentation|model-card|data-card/i.test(hay)) vals.add('Documentation');
      if (/provenance|lineage/i.test(hay)) vals.add('Provenance');
      if (f.coverage['data_governance'] === 2) vals.add('Strong Gov');
      else if (f.coverage['data_governance'] === 1) vals.add('Partial Gov');
      if (vals.size === 0) vals.add('General');
      return [...vals];
    },
  },
  {
    id: 'data_exposure',
    label: 'Data Exposure Settings',
    short: 'Data Exposure',
    icon: '◎',
    description: 'How data is exposed — PII, sensitive, public, inference leakage, DLP, minimisation.',
    color: '#7bd389',
    getValues: (f) => {
      const vals = new Set<string>();
      const hay = [...f.controls, ...f.riskTiers].map(norm).join(' ') + ' ' + f.summary.toLowerCase();
      if (/pii|personal/i.test(hay)) vals.add('PII');
      if (/sensitive|confidential/i.test(hay)) vals.add('Sensitive');
      if (/leakage|exfiltration|privacy/i.test(hay)) vals.add('Privacy Leakage');
      if (/minimisation|minimization/i.test(hay)) vals.add('Minimisation');
      if (/public|disclosure|transparency/i.test(hay)) vals.add('Public Disclosure');
      if (f.coverage['privacy'] === 2) vals.add('High Privacy');
      else if (f.coverage['privacy'] === 1) vals.add('Partial Privacy');
      if (vals.size === 0) vals.add('General');
      return [...vals];
    },
  },
  {
    id: 'parties',
    label: 'Parties',
    short: 'Parties',
    icon: '⬣',
    description: 'Actors in scope — provider, deployer, importer, distributor, user, affected person.',
    color: '#9d4edd',
    getValues: (f) => {
      const vals = new Set<string>();
      const hay = [...f.controls, ...f.scenarios, ...f.riskTiers, f.summary, f.kind].map(norm).join(' ');
      if (/provider|developer|gpa[^a-z]*provider/i.test(hay)) vals.add('Provider');
      if (/deployer|user|customer/i.test(hay)) vals.add('Deployer');
      if (/importer/i.test(hay)) vals.add('Importer');
      if (/distributor/i.test(hay)) vals.add('Distributor');
      if (/affected|data-subject|consumer/i.test(hay)) vals.add('Affected Person');
      if (/third.party|supplier|vendor/i.test(hay)) vals.add('Third Party');
      if (f.kind === 'regulation') vals.add('Regulator');
      if (vals.size === 0) vals.add('General');
      return [...vals];
    },
  },
  {
    id: 'hosting',
    label: 'Local Hosted',
    short: 'Hosting',
    icon: '⌖',
    description: 'Deployment hosting — local/on-prem, cloud, hybrid, edge.',
    color: '#ff9f1c',
    getValues: (f) => {
      const vals = new Set<string>();
      const hay = [...f.scenarios, ...f.controls].map(norm).join(' ');
      if (/on.prem|local|edge|embedded/i.test(hay)) vals.add('Local / On-prem');
      if (/cloud|saas|api/i.test(hay)) vals.add('Cloud');
      if (/hybrid/i.test(hay)) vals.add('Hybrid');
      if (vals.size === 0) {
        if (f.jurisdiction === 'EU' || f.jurisdiction === 'US') vals.add('Cloud-first');
        else vals.add('Hybrid');
      }
      return [...vals];
    },
  },
  {
    id: 'model_origin',
    label: 'Model Origin',
    short: 'Origin',
    icon: '◍',
    description: 'Model provenance — open weights, open source, closed, proprietary, source-available, API-only.',
    color: '#5da9e9',
    getValues: (f) => {
      const vals = new Set<string>();
      const hay = [...f.scenarios, ...f.controls, ...f.riskTiers, f.summary].map((s) => s.toLowerCase()).join(' ');
      if (/open.weights|open.weights/i.test(hay)) vals.add('Open Weights');
      if (/open.source|open-source/i.test(hay)) vals.add('Open Source');
      if (/closed|proprietary|closed.source/i.test(hay)) vals.add('Closed / Proprietary');
      if (/source.available|source-available/i.test(hay)) vals.add('Source-Available');
      if (/api.only|api.model|hosted.api/i.test(hay)) vals.add('API-Only');
      if (/foundation.model|frontier|gpa/i.test(hay)) vals.add('Foundation / Frontier');
      if (vals.size === 0) {
        if (f.kind === 'regulation' && f.jurisdiction.includes('EU')) vals.add('Regulated (any origin)');
        else vals.add('General');
      }
      return [...vals];
    },
  },
  {
    id: 'agents',
    label: 'Agents Nature & Depth',
    short: 'Agents',
    icon: '⬡',
    description: 'Agentic nature (tool-use, multi-agent, autonomous, human-in-loop) and depth (single, multi-step, planning).',
    color: '#b565d8',
    getValues: (f) => {
      const vals = new Set<string>();
      const hay = [...f.scenarios, ...f.controls].map((s) => s.toLowerCase()).join(' ');
      if (/multi.agent|multi-agent/i.test(hay)) vals.add('Multi-Agent');
      else if (/agent/i.test(hay)) vals.add('Single Agent');
      if (/tool.use|tool-use|function.call/i.test(hay)) vals.add('Tool-Using');
      if (/autonomous|auto./i.test(hay)) vals.add('Autonomous');
      if (/human.in.loop|human.oversight|human.approval/i.test(hay)) vals.add('Human-in-Loop');
      if (/planning|reasoning|chain.of.thought/i.test(hay)) vals.add('Planning / Reasoning');
      if (/single.step|single-step/i.test(hay)) vals.add('Single-Step');
      if (/multi.step|multi-step|depth/i.test(hay)) vals.add('Multi-Step');
      if (vals.size === 0) {
        if (f.scenarios.includes('agent') || f.scenarios.includes('tool-use')) vals.add('Agentic');
        else vals.add('Non-Agentic');
      }
      return [...vals];
    },
  },
  {
    id: 'customer',
    label: 'Customer Facing',
    short: 'Customer',
    icon: '◑',
    description: 'Customer-facing vs internal — B2C, B2B, internal tool, public sector.',
    color: '#f4d35e',
    getValues: (f) => {
      const vals = new Set<string>();
      const hay = [...f.scenarios, ...f.summary].map(norm).join(' ');
      if (/customer|b2c|chatbot|assistant|public.facing/i.test(hay)) vals.add('Customer-Facing');
      if (/b2b|enterprise|vendor/i.test(hay)) vals.add('B2B');
      if (/internal|workforce|employee/i.test(hay)) vals.add('Internal');
      if (/public.sector|government|benefits/i.test(hay)) vals.add('Public Sector');
      if (vals.size === 0) vals.add('General');
      return [...vals];
    },
  },
];

export function supportDistribution(frameworks: Framework[], mode: SupportConfig): { name: string; value: number; color: string }[] {
  const counts = new Map<string, number>();
  for (const f of frameworks) for (const v of mode.getValues(f)) counts.set(v, (counts.get(v) ?? 0) + 1);
  const colors = ['#4da3ff', '#ff9f1c', '#2ec4b6', '#e71d36', '#9d4edd', '#7bd389', '#f4d35e', '#ee964b'];
  return [...counts.entries()].map(([name, value], i) => ({ name, value, color: colors[i % colors.length] })).sort((a, b) => b.value - a.value);
}

export function supportHeatmap(frameworks: Framework[], mode: SupportConfig): { framework: string; values: string[]; coverage: number }[] {
  return frameworks.map((f) => ({ framework: f.id, values: mode.getValues(f), coverage: Math.round(((Object.values(f.coverage) as number[]).reduce((a, b) => a + b, 0) / (Object.keys(f.coverage).length * 2)) * 100) }));
}
