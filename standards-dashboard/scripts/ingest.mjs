// Monthly ingest: validates data/frameworks.json + taxonomy, computes
// coverage stats + control overlap (Jaccard), writes public/data.json.
// Usage: npm run ingest [-- --refresh-dates] [--check-urls]
// Invariants: never drops a framework without explicit removal; scores stay 0|1|2;
// generated date always bumps; lastChecked bumps only with --refresh-dates.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { validateFrameworks } from './lib/validate-frameworks.mjs';

const args = new Set(process.argv.slice(2));
const root = new URL('..', import.meta.url).pathname;

const fwRaw = JSON.parse(readFileSync(`${root}data/frameworks.json`, 'utf8'));
const taxRaw = JSON.parse(readFileSync(`${root}data/taxonomy.json`, 'utf8'));
const dimIds = new Set(taxRaw.dimensions.map((d) => d.id));

const errors = validateFrameworks(fwRaw, taxRaw);
if (errors.length) {
  console.error('INGEST VALIDATION FAILED:\n' + errors.join('\n'));
  process.exit(1);
}

if (args.has('--refresh-dates')) {
  const today = new Date().toISOString().slice(0, 10);
  for (const f of fwRaw.frameworks) f.lastChecked = today;
  fwRaw.updated = today;
  writeFileSync(`${root}data/frameworks.json`, JSON.stringify(fwRaw, null, 2) + '\n');
  console.log(`refreshed lastChecked for ${fwRaw.frameworks.length} frameworks`);
}

const norm = (s) => s.toLowerCase().trim();
const tagSet = (f) => new Set([...(f.controls ?? []), ...(f.scenarios ?? [])].map(norm));

// Jaccard overlap on control+scenario tags (symmetric, cheap, explainable).
const overlap = [];
const fr = fwRaw.frameworks;
for (let i = 0; i < fr.length; i++) {
  for (let j = i + 1; j < fr.length; j++) {
    const a = tagSet(fr[i]);
    const b = tagSet(fr[j]);
    const shared = [...a].filter((t) => b.has(t));
    const union = new Set([...a, ...b]);
    const jaccard = union.size === 0 ? 0 : Math.round((shared.length / union.size) * 1000) / 1000;
    overlap.push({ a: fr[i].id, b: fr[j].id, jaccard, shared: shared.slice(0, 12) });
  }
}
overlap.sort((x, y) => y.jaccard - x.jaccard);

// --- Knowledge graph (hive-style node-link: theme clusters + blended similarity
// edges = 0.7*cosine(coverage) + 0.3*jaccard(tags)) -> public/graph.json
// Union-find collapses on this dense space (giant-or-dust), so clusters are
// deterministic k-means (k=6, farthest-point init, fixed order) on coverage vectors.
const cosCov = (a, b) => {
  const A = Object.values(a.coverage);
  const B = Object.values(b.coverage);
  let s = 0, na = 0, nb = 0;
  for (let i = 0; i < A.length; i++) { s += A[i] * B[i]; na += A[i] * A[i]; nb += B[i] * B[i]; }
  return na && nb ? s / Math.sqrt(na * nb) : 0;
};
const tagJac = (a, b) => {
  const A = tagSet(a); const B = tagSet(b);
  const inter = [...A].filter((t) => B.has(t)).length;
  const union = new Set([...A, ...B]).size;
  return union ? inter / union : 0;
};
const blend = (a, b) => Math.round((0.7 * cosCov(a, b) + 0.3 * tagJac(a, b)) * 1000) / 1000;

const K = 6;
const vecs = fr.map((f) => Object.values(f.coverage));
const dist2 = (a, b) => a.reduce((s, v, i) => s + (v - b[i]) ** 2, 0);
// Farthest-point init (deterministic: start from first framework)
const centers = [vecs[0]];
while (centers.length < K) {
  let best = -1; let bestD = -1;
  for (const v of vecs) {
    const d = Math.min(...centers.map((c) => dist2(v, c)));
    if (d > bestD) { bestD = d; best = v; }
  }
  centers.push(centers.includes(best) ? vecs[centers.length % vecs.length] : best);
}
const assign = new Array(fr.length).fill(0);
for (let it = 0; it < 25; it++) {
  let moved = false;
  for (let i = 0; i < vecs.length; i++) {
    let bi = 0; let bd = Infinity;
    for (let k = 0; k < K; k++) { const d = dist2(vecs[i], centers[k]); if (d < bd) { bd = d; bi = k; } }
    if (assign[i] !== bi) { assign[i] = bi; moved = true; }
  }
  if (!moved) break;
  for (let k = 0; k < K; k++) {
    const members = vecs.filter((_, i) => assign[i] === k);
    if (members.length) centers[k] = centers[k].map((_, d) => members.reduce((s, v) => s + v[d], 0) / members.length);
  }
}
// Label each cluster by its top-2 coverage dimensions
const dimList = [...dimIds];
const clusterLabel = (k) => {
  const c = centers[k];
  const top = c.map((v, i) => [v, dimList[i]]).sort((a, b) => b[0] - a[0]).slice(0, 2).map(([, d]) => taxRaw.dimensions.find((x) => x.id === d)?.label ?? d);
  return top.join(' + ');
};
const simPairs = [];
for (let i = 0; i < fr.length; i++) {
  for (let j = i + 1; j < fr.length; j++) {
    const a = fr[i]; const b = fr[j];
    const sim = blend(a, b);
    const shared = [...tagSet(a)].filter((t) => tagSet(b).has(t)).slice(0, 12);
    simPairs.push({ a: a.id, b: b.id, sim, shared });
  }
}
const covPct = (f) => {
  const v = Object.values(f.coverage);
  return Math.round((v.reduce((x, y) => x + y, 0) / (v.length * 2)) * 100);
};
const BINDING = new Set(['regulation', 'standard']); // mandates; else recommends (optional)
const fwCluster = new Map(fr.map((f, i) => [f.id, assign[i]]));
const tagFw = { control: new Map(), topic: new Map(), exposure: new Map() };
for (const f of fr) {
  for (const t of new Set(f.controls.map(norm))) {
    if (!tagFw.control.has(t)) tagFw.control.set(t, []);
    tagFw.control.get(t).push(f.id);
  }
  for (const t of new Set(f.scenarios.map(norm))) {
    if (!tagFw.topic.has(t)) tagFw.topic.set(t, []);
    tagFw.topic.get(t).push(f.id);
  }
  for (const t of new Set(f.riskTiers.map(norm))) {
    if (!tagFw.exposure.has(t)) tagFw.exposure.set(t, []);
    tagFw.exposure.get(t).push(f.id);
  }
}
const majorityCluster = (ids) => {
  const counts = new Map();
  for (const id of ids) { const c = fwCluster.get(id) ?? 0; counts.set(c, (counts.get(c) ?? 0) + 1); }
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0] - b[0])[0]?.[0] ?? 0;
};
const subNodes = (map, type) => [...map.entries()].map(([tag, ids]) => ({
  id: `${type}:${tag}`, type, label: tag, cluster: majorityCluster(ids), count: ids.length,
}));
// arXiv papers (optional)
let arxivPapers = [];
try { arxivPapers = JSON.parse(readFileSync(`${root}data/arxiv-papers.json`, 'utf8')).papers ?? []; } catch {}
const arxivByTopic = new Map();
for (const pap of arxivPapers) {
  const tid = pap.topic ?? 'advml';
  if (!arxivByTopic.has(tid)) arxivByTopic.set(tid, []);
  arxivByTopic.get(tid).push(pap);
}
const nodes = [
  ...fr.map((f, i) => ({
    id: f.id, type: 'framework', label: f.name, cluster: assign[i],
    clusterLabel: clusterLabel(assign[i]),
    jurisdiction: f.jurisdiction, kind: f.kind, coverage: covPct(f), url: f.url,
  })),
  ...[...dimIds].map((d) => {
    const tax = taxRaw.dimensions.find((x) => x.id === d);
    return { id: `theme:${d}`, type: 'theme', label: tax?.label ?? d, cluster: -1 };
  }),
  ...subNodes(tagFw.control, 'control'),
  ...subNodes(tagFw.topic, 'topic'),
  ...subNodes(tagFw.exposure, 'exposure'),
  // security topics as nodes
  ...[...new Set(arxivPapers.map((p) => p.topic))].map((tid) => ({
    id: `security_topic:${tid}`, type: 'security_topic', label: tid, cluster: [...arxivByTopic.keys()].indexOf(tid),
  })),
  // papers
  ...arxivPapers.map((pap) => ({
    id: `paper:${pap.id}`, type: 'paper', label: pap.title.slice(0, 80), cluster: [...arxivByTopic.keys()].indexOf(pap.topic),
    topic: pap.topic, url: pap.url, authors: pap.authors, year: pap.year, summary: pap.summary,
  })),
];
const links = [
  ...simPairs.map((p) => ({ source: p.a, target: p.b, relation: 'similar', weight: p.sim, shared: p.shared })),
  ...fr.flatMap((f) =>
    Object.entries(f.coverage)
      .filter(([, v]) => v > 0)
      .map(([dim, v]) => ({ source: f.id, target: `theme:${dim}`, relation: v === 2 ? 'covers' : 'partially-covers', weight: v / 2, shared: [] })),
  ),
  // mandates (binding instruments) vs recommends/optional (voluntary guidance)
  ...fr.flatMap((f) => [...new Set(f.controls.map(norm))].map((t) => ({
    source: f.id, target: `control:${t}`,
    relation: BINDING.has(f.kind) ? 'mandates' : 'recommends', weight: 1, shared: [],
  }))),
  ...fr.flatMap((f) => [...new Set(f.scenarios.map(norm))].map((t) => (
    { source: f.id, target: `topic:${t}`, relation: 'applies-to', weight: 1, shared: [] }
  ))),
  ...fr.flatMap((f) => [...new Set(f.riskTiers.map(norm))].map((t) => (
    { source: f.id, target: `exposure:${t}`, relation: 'flags', weight: 1, shared: [] }
  ))),
  // paper edges
  ...arxivPapers.map((pap) => ({ source: `paper:${pap.id}`, target: `security_topic:${pap.topic}`, relation: 'covers', weight: 1, shared: [] })),
  ...arxivPapers.flatMap((pap) => {
    const hay = (pap.title + ' ' + pap.summary).toLowerCase();
    // link to frameworks whose controls/scenarios overlap keywords
    const kws = hay.split(/[^a-z0-9]+/).filter((w) => w.length > 4).slice(0, 8);
    return fr.filter((f) => {
      const fh = [...f.controls, ...f.scenarios, f.summary].join(' ').toLowerCase();
      return kws.some((k) => fh.includes(k));
    }).slice(0, 3).map((f) => ({ source: `paper:${pap.id}`, target: f.id, relation: 'cites', weight: 0.6, shared: [] }));
  }),
];
writeFileSync(`${root}public/graph.json`, JSON.stringify({
  generated: fwRaw.updated ?? new Date().toISOString().slice(0, 10),
  nodes, links, clusterCount: K,
  clusterLabels: Array.from({ length: K }, (_, k) => clusterLabel(k)),
}, null, 2) + '\n');

if (args.has('--check-urls')) {
  // Best-effort liveness probe; never fails the build (monthly cron reports only).
  const results = await Promise.all(
    fr.map(async (f) => {
      try {
        const r = await fetch(f.url, { method: 'HEAD', redirect: 'follow', signal: AbortSignal.timeout(10000) });
        return `${r.status} ${f.id} ${f.url}`;
      } catch (e) {
        return `ERR ${f.id} ${f.url} (${e.cause?.code ?? e.message})`;
      }
    }),
  );
  console.log(results.join('\n'));
}

mkdirSync(`${root}public`, { recursive: true });
const out = {
  generated: fwRaw.updated ?? new Date().toISOString().slice(0, 10),
  frameworks: fr,
  overlap,
};
writeFileSync(`${root}public/data.json`, JSON.stringify(out, null, 2) + '\n');
const stale = fr.filter((f) => {
  const days = (Date.now() - new Date(f.lastChecked).getTime()) / 864e5;
  return days > 45;
});
console.log(`ingest ok: ${fr.length} frameworks, ${overlap.length} pairs -> public/data.json`);
if (stale.length) console.log(`STALE (>45d): ${stale.map((f) => f.id).join(', ')}`);
