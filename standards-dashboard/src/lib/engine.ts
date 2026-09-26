export interface Dimension {
  id: string;
  label: string;
  description: string;
}

export interface Framework {
  id: string;
  name: string;
  issuer: string;
  jurisdiction: string;
  kind: 'regulation' | 'standard' | 'framework' | 'guideline';
  version: string;
  status: string;
  url: string;
  summary: string;
  riskTiers: string[];
  controls: string[];
  coverage: Record<string, 0 | 1 | 2>;
  scenarios: string[];
  lastChecked: string;
}

export interface OverlapCell {
  a: string;
  b: string;
  jaccard: number;
  shared: string[];
}

export interface IngestedData {
  generated: string;
  dimensions: Dimension[];
  frameworks: Framework[];
  overlap: OverlapCell[];
}

function norm(s: string): string {
  return s.toLowerCase().trim();
}

function tokens(s: string): string[] {
  return norm(s).split(/[^a-z0-9+]+/).filter((t) => t.length > 1);
}

/** Tokenized full-text search with jurisdiction/kind filters. */
export function searchFrameworks(
  frameworks: Framework[],
  query: string,
  filters: { jurisdiction?: string; kind?: string; minCoverage?: number } = {},
): Framework[] {
  const qs = tokens(query);
  return frameworks
    .map((f) => {
      const hay = [
        f.name, f.issuer, f.jurisdiction, f.kind, f.summary,
        f.controls.join(' '), f.scenarios.join(' '), f.riskTiers.join(' '),
      ].join(' ');
      const hayTokens = new Set(tokens(hay));
      let score = 0;
      for (const q of qs) {
        if (hayTokens.has(q)) score += 2;
        else if ([...hayTokens].some((h) => h.includes(q) || q.includes(h))) score += 1;
      }
      // Empty query => include all (score 0), filters decide.
      return { f, score };
    })
    .filter(({ f, score }) => {
      if (qs.length > 0 && score === 0) return false;
      if (filters.jurisdiction && filters.jurisdiction !== 'all' && !f.jurisdiction.includes(filters.jurisdiction)) return false;
      if (filters.kind && filters.kind !== 'all' && f.kind !== filters.kind) return false;
      if (filters.minCoverage) {
        const vals = Object.values(f.coverage) as number[];
        const avg = vals.reduce((a, b) => a + b, 0) / (vals.length * 2);
        if (avg * 100 < filters.minCoverage) return false;
      }
      return true;
    })
    .sort((x, y) => y.score - x.score || x.f.name.localeCompare(y.f.name))
    .map((r) => r.f);
}

export function coveragePercent(f: Framework): number {
  const vals = Object.values(f.coverage) as number[];
  const sum = vals.reduce((a, b) => a + b, 0);
  return Math.round((sum / (vals.length * 2)) * 100);
}

/** Build the heatmap's rows: filter by query (if any), then sort a copy. */
export function heatmapRows(
  frameworks: Framework[],
  heatQuery: string,
  sort: 'coverage' | 'name',
): Framework[] {
  const rows = heatQuery.trim() ? searchFrameworks(frameworks, heatQuery) : [...frameworks];
  return rows.sort((a, b) =>
    sort === 'name' ? a.name.localeCompare(b.name) : coveragePercent(b) - coveragePercent(a),
  );
}

/** Rule-based scenario advisor: keyword match on scenario tags + coverage ranking. */
export function adviseForScenario(
  frameworks: Framework[],
  scenarioText: string,
): { framework: Framework; reasons: string[]; missing: string[] }[] {
  const qs = new Set(tokens(scenarioText));
  if (qs.size === 0) return [];
  const scored = frameworks.map((f) => {
    const reasons: string[] = [];
    const tagHay = new Set([...f.scenarios.flatMap(tokens), ...f.controls.flatMap(tokens)]);
    let hits = 0;
    for (const q of qs) {
      if (tagHay.has(q)) {
        hits += 2;
        reasons.push(`matches "${q}"`);
      } else if ([...tagHay].some((h) => h.includes(q) || q.includes(h))) {
        hits += 1;
      }
      // jurisdiction hint e.g. "eu", "china", "us", "korea"
      if (norm(f.jurisdiction).includes(q) || norm(f.name).includes(q)) {
        hits += 2;
        reasons.push(`jurisdiction "${f.jurisdiction}"`);
      }
    }
    // Prefer binding regulations + broad coverage for deployment scenarios.
    const bonus = coveragePercent(f) / 100 + (f.kind === 'regulation' ? 0.5 : 0);
    return { framework: f, hits, bonus, reasons: [...new Set(reasons)].slice(0, 4) };
  });
  const relevant = scored.filter((s) => s.hits > 0).sort((a, b) => b.hits - a.hits || b.bonus - a.bonus).slice(0, 12);
  return relevant.map((r) => {
    const weak = Object.entries(r.framework.coverage)
      .filter(([, v]) => (v as number) === 0)
      .map(([k]) => k);
    return { framework: r.framework, reasons: r.reasons, missing: weak.slice(0, 4) };
  });
}

export function topOverlaps(overlap: OverlapCell[], id: string, n = 5): OverlapCell[] {
  return overlap
    .filter((c) => c.a === id || c.b === id)
    .sort((x, y) => y.jaccard - x.jaccard)
    .slice(0, n);
}

export type Freshness = 'fresh' | 'aging' | 'stale' | 'unknown';

/** Days from lastChecked to now; null when the date is missing or unparseable. */
export function daysSinceChecked(f: Framework, now: Date = new Date()): number | null {
  if (!f.lastChecked) return null;
  const checked = new Date(`${f.lastChecked}T00:00:00Z`);
  if (Number.isNaN(checked.getTime())) return null;
  return Math.max(0, Math.floor((now.getTime() - checked.getTime()) / 86_400_000));
}

/** Freshness tier for a framework record: fresh ≤90d, aging ≤180d, stale beyond. */
export function provenanceStatus(f: Framework, now: Date = new Date()): { days: number | null; tier: Freshness; label: string } {
  const days = daysSinceChecked(f, now);
  if (days === null) return { days, tier: 'unknown', label: 'check date unknown' };
  const tier: Freshness = days <= 90 ? 'fresh' : days <= 180 ? 'aging' : 'stale';
  const label = days === 0 ? 'checked today' : `checked ${days}d ago`;
  return { days, tier, label };
}
