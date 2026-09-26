// Export instruction-tuning dataset from the curated frameworks.
// Usage: npm run export:finetune  ->  data/finetune.jsonl (+ data/finetune-sample.json)
// Each record: {instruction, input, output, source, framework_id}
import { readFileSync, writeFileSync } from 'node:fs';

const root = new URL('..', import.meta.url).pathname;
const fw = JSON.parse(readFileSync(`${root}data/frameworks.json`, 'utf8')).frameworks;
const tax = JSON.parse(readFileSync(`${root}data/taxonomy.json`, 'utf8'));
const dimLabel = Object.fromEntries(tax.dimensions.map((d) => [d.id, d.label]));

const rows = [];
const push = (framework_id, source, instruction, input, output) =>
  rows.push({ instruction, input, output, source, framework_id });

for (const f of fw) {
  const cov = Object.entries(f.coverage)
    .map(([k, v]) => `${dimLabel[k] ?? k}: ${v === 2 ? 'directly covered' : v === 1 ? 'partially covered' : 'not covered'}`)
    .join('; ');
  push(f.id, f.url, `Summarize the AI governance source "${f.name}".`, '', `${f.name} (${f.issuer}, ${f.version}; status: ${f.status}). ${f.summary} Controls: ${f.controls.join(', ')}. Coverage — ${cov}. Source: ${f.url}`);
  push(f.id, f.url, `Which obligations does "${f.name}" impose on a developer?`, '', `Under ${f.name} (${f.jurisdiction}, ${f.kind}): ${f.summary} Key controls to implement: ${f.controls.join('; ')}. Risk tiers: ${f.riskTiers.join(', ')}. Always verify against the primary source: ${f.url}`);
  push(f.id, f.url, `What is the coverage profile of "${f.name}" across control dimensions?`, '', cov);
  for (const s of f.scenarios.slice(0, 3)) {
    push(f.id, f.url, 'Given a build scenario, which frameworks apply and what are the gaps?', `Scenario: ${s}. Candidate: ${f.name}.`, `${f.name} is relevant to "${s}" (${f.jurisdiction} ${f.kind}). Implement: ${f.controls.slice(0, 5).join('; ')}. Gaps to cover with other sources: ${Object.entries(f.coverage).filter(([, v]) => v === 0).map(([k]) => dimLabel[k] ?? k).join(', ') || 'none'}. Source: ${f.url}`);
  }
  push(f.id, f.url, `Compare "${f.name}" with overlapping sources. Which controls overlap?`, '', `Use the dashboard overlap matrix for ${f.id}; highest-Jaccard neighbours share controls: ${f.controls.slice(0, 4).join(', ')}. Combine binding regulations (e.g. EU AI Act) with technical mitigations (OWASP LLM Top 10, MITRE ATLAS) and management systems (ISO 42001, NIST AI RMF).`);
}

writeFileSync(`${root}data/finetune.jsonl`, rows.map((r) => JSON.stringify(r)).join('\n') + '\n');
writeFileSync(`${root}data/finetune-sample.json`, JSON.stringify(rows.slice(0, 3), null, 2));
console.log(`export ok: ${rows.length} examples -> data/finetune.jsonl`);
