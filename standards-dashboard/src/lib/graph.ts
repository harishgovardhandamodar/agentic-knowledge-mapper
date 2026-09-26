export type NodeType = 'framework' | 'theme' | 'control' | 'topic' | 'exposure' | 'paper' | 'security_topic';
export type Relation =
  | 'similar' | 'covers' | 'partially-covers'
  | 'mandates' | 'recommends' | 'applies-to' | 'flags'
  | 'cites';

export interface GNode {
  id: string;
  type: NodeType;
  label: string;
  cluster: number;
  clusterLabel?: string;
  jurisdiction?: string;
  kind?: string;
  coverage?: number;
  url?: string;
  count?: number;
  authors?: string;
  year?: number;
  summary?: string;
  topic?: string;
}

export interface GLink {
  source: string;
  target: string;
  relation: Relation;
  weight: number;
  shared: string[];
}

export interface GraphData {
  generated: string;
  nodes: GNode[];
  links: GLink[];
  clusterCount: number;
  clusterLabels: string[];
}

/** Hive-style categorical palette (dark-background friendly). */
export const CLUSTER_COLORS = ['#4da3ff', '#ff9f1c', '#2ec4b6', '#e71d36', '#9d4edd', '#7bd389'];
export const KIND_COLORS: Record<string, string> = {
  regulation: '#e71d36',
  standard: '#4da3ff',
  framework: '#ff9f1c',
  guideline: '#2ec4b6',
};
const JURIS_COLORS = [
  '#4da3ff', '#ff9f1c', '#2ec4b6', '#e71d36', '#9d4edd', '#7bd389',
  '#f4d35e', '#ee964b', '#5da9e9', '#b565d8', '#43aa8b', '#f95738',
];

export function colorFor(node: GNode, colorBy: 'cluster' | 'jurisdiction' | 'kind', jurisdictions: string[]): string {
  if (node.type === 'theme') return '#e6c34a';
  if (node.type === 'paper') return '#ff6b6b';
  if (node.type === 'security_topic') return '#ffd93d';
  if (node.type === 'framework') {
    if (colorBy === 'kind') return KIND_COLORS[node.kind ?? ''] ?? '#9fb0c0';
    if (colorBy === 'jurisdiction') {
      const i = jurisdictions.indexOf(node.jurisdiction ?? '');
      if (i >= 0) return JURIS_COLORS[i % JURIS_COLORS.length];
    }
  }
  // Sub-elements (controls/topics/exposures) and fallback: theme-cluster color.
  return CLUSTER_COLORS[((node.cluster % CLUSTER_COLORS.length) + CLUSTER_COLORS.length) % CLUSTER_COLORS.length];
}

export interface Related {
  node: GNode;
  relation: GLink['relation'];
  weight: number;
  shared: string[];
}

/** Detail subgraph for the overlay: all incident links, similar-first. */
export function relatedNodes(graph: GraphData, id: string, minSim: number): Related[] {
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const out: Related[] = [];
  for (const l of graph.links) {
    if (l.relation === 'similar' && l.weight < minSim) continue;
    if (l.source !== id && l.target !== id) continue;
    const other = byId.get(l.source === id ? l.target : l.source);
    if (other) out.push({ node: other, relation: l.relation, weight: l.weight, shared: l.shared });
  }
  const rank: Record<Relation, number> = {
    similar: 0, mandates: 1, flags: 2, covers: 3,
    'applies-to': 4, recommends: 5, 'partially-covers': 6, cites: 7,
  };
  return out.sort((a, b) => rank[a.relation] - rank[b.relation] || b.weight - a.weight);
}

export function similarityScope(graph: GraphData, id: string): { min: number; max: number; n: number } {
  const sims = graph.links.filter((l) => l.relation === 'similar' && (l.source === id || l.target === id)).map((l) => l.weight);
  if (!sims.length) return { min: 0, max: 0, n: 0 };
  return { min: Math.min(...sims), max: Math.max(...sims), n: sims.length };
}

const SUB_RELS: Relation[] = ['mandates', 'recommends', 'applies-to', 'flags'];

/** Frameworks linked to a sub-element node, split into mandates vs optional. */
export function mandateSplit(graph: GraphData, id: string): { mandatedBy: GNode[]; recommendedBy: GNode[] } {
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const mandatedBy: GNode[] = [];
  const recommendedBy: GNode[] = [];
  for (const l of graph.links) {
    if (l.source !== id && l.target !== id) continue;
    const other = byId.get(l.source === id ? l.target : l.source);
    if (!other || other.type !== 'framework') continue;
    if (l.relation === 'mandates') mandatedBy.push(other);
    else recommendedBy.push(other);
  }
  return { mandatedBy, recommendedBy };
}

/** Same-type sub-nodes sharing the most frameworks (co-occurrence). */
export function cooccurring(graph: GraphData, id: string, top = 6): { node: GNode; n: number }[] {
  const fw = new Set<string>();
  for (const l of graph.links) {
    if (!SUB_RELS.includes(l.relation)) continue;
    if (l.source === id) fw.add(l.target);
    else if (l.target === id) fw.add(l.source);
  }
  // Sub-node links always run framework -> sub-node; keep framework-side ids.
  const fwIds = new Set<string>();
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  for (const x of fw) {
    const n = byId.get(x);
    if (n?.type === 'framework') fwIds.add(x);
    else {
      // id itself is a framework (caller is a sub-node): neighbors collected above are frameworks already
      fwIds.add(x);
    }
  }
  const self = byId.get(id);
  const counts = new Map<string, number>();
  for (const l of graph.links) {
    if (!SUB_RELS.includes(l.relation)) continue;
    if (fwIds.has(l.source) && l.target !== id) counts.set(l.target, (counts.get(l.target) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([cid, n]) => ({ node: byId.get(cid)!, n }))
    .filter((x) => x.node && x.node.type === self?.type)
    .sort((a, b) => b.n - a.n)
    .slice(0, top);
}

/** True for data-centric controls (data governance, provenance, privacy, ...). */
export function isDataControl(node: GNode): boolean {
  return node.type === 'control' && /data|dataset|provenance|privacy|pii|provenance/i.test(node.label);
}
