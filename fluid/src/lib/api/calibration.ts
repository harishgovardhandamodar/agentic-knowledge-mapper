/**
 * Adapters that turn engine output into what the charts draw.
 *
 * Kept separate from `adapters.ts` (which maps API payloads to the claim
 * domain) because these derive *new* series from engine fields rather than
 * reshaping what arrived.
 *
 * The saturation curve is a reconstruction: the engine reports one point (the
 * declared control set) plus a leave-one-out count of controls that no longer
 * move it. To draw the curve we re-run the engine's own arithmetic for each
 * prefix of the declared set. That is only sound because it uses the same
 * inputs — the real per-control efficacy and per-threat weights from
 * `/api/security/controls` — so the final column reproduces the stored
 * `residual_pct`. Anything less would be a chart of invented numbers, which
 * is precisely the failure mode the calibration work exists to remove.
 */
import type { ControlProvenance, ResidualInterval } from '@/types/domain';
import type { Assessment } from './schemas';
import type { ControlFloorPoint } from '@/components/charts/control-floor-chart';
import type { EfficacyPoint } from '@/components/charts/efficacy-provenance-chart';

/** A catalogue control with the fields the curve needs. */
export interface CatalogControl {
  id: string;
  efficacy: number;
  /** threat id -> per-threat weight. */
  threats: Record<string, number>;
}

const TOP_N = 5;
const WORST_WEIGHT = 0.55;
const BREADTH_WEIGHT = 0.45;
const MAX_SCORE = 25; // the 1..5 x 1..5 L x I range the engine normalizes over

function normalizeControls(rows: unknown): CatalogControl[] {
  const list = Array.isArray(rows) ? rows : [];
  const out: CatalogControl[] = [];
  for (const r of list) {
    if (!r || typeof r !== 'object') continue;
    const rec = r as Record<string, unknown>;
    const id = typeof rec.id === 'string' ? rec.id : (rec.control_id as string | undefined);
    const eff = typeof rec.efficacy === 'number' ? rec.efficacy : null;
    if (!id || eff === null) continue;
    const threats =
      rec.threats && typeof rec.threats === 'object'
        ? (rec.threats as Record<string, number>)
        : {};
    out.push({ id, efficacy: eff, threats });
  }
  return out;
}

/** Coverage for one threat: 1 - prod(1 - efficacy_i * weight_i). */
function coverage(threatId: string, active: string[], byId: Map<string, CatalogControl>): number {
  let survive = 1;
  for (const cid of active) {
    const c = byId.get(cid);
    if (!c) continue;
    const w = c.threats[threatId];
    if (w === undefined) continue;
    survive *= 1 - Math.min(0.95, Math.max(0, c.efficacy * w));
  }
  return 1 - survive;
}

interface AssessmentScoring {
  threats?: { id: string; likelihood: number; impact: number; coverage?: number; controls?: string[] }[];
  active_controls?: string[];
  residual_pct?: number;
  breakdown?: { min_residual_floor?: number };
  floor?: { controls_beyond_floor_ids?: string[] } | null;
}

export function assessmentScoring(a?: Assessment | null): AssessmentScoring {
  return ((a?.scoring ?? {}) as AssessmentScoring) ?? {};
}

/**
 * Residual on a 0..100 scale, using the engine's aggregate: 55% worst (mean of
 * the top 5) + 45% breadth (mean of all), over the 1..25 range.
 */
function residualPct(threats: NonNullable<AssessmentScoring['threats']>, active: string[], byId: Map<string, CatalogControl>, floor: number): { residual: number; meanCoverage: number } {
  const rows = threats.map((t) => {
    const cov = coverage(t.id, active, byId);
    const likR = Math.max(t.likelihood * floor, t.likelihood * (1 - cov));
    return { residual: likR * t.impact, coverage: cov };
  });
  if (rows.length === 0) return { residual: 0, meanCoverage: 0 };
  const vals = rows.map((r) => r.residual).sort((a, b) => b - a);
  const top = vals.slice(0, TOP_N);
  const worst = top.reduce((s, v) => s + v, 0) / top.length;
  const breadth = vals.reduce((s, v) => s + v, 0) / vals.length;
  const aggregate = WORST_WEIGHT * worst + BREADTH_WEIGHT * breadth;
  return {
    residual: Math.min(100, (aggregate / MAX_SCORE) * 100),
    meanCoverage: (rows.reduce((s, r) => s + r.coverage, 0) / rows.length) * 100,
  };
}

/**
 * Residual risk as controls are added.
 *
 * Returns [] when the assessment carries no threats or the catalogue supplied
 * no controls — the chart then says so rather than drawing a curve from
 * defaults. `residual_pct` on the final point should match the stored
 * headline; `controlFloorCurveReproduction` asserts that.
 */
export function controlFloorCurve(
  assessment: Assessment | null | undefined,
  catalog: ControlProvenance[] | ControlCatalogRow[] | null | undefined,
): ControlFloorPoint[] {
  const scoring = assessmentScoring(assessment);
  const threats = scoring.threats ?? [];
  const active = scoring.active_controls ?? [];
  if (threats.length === 0 || active.length === 0) return [];

  const controls = normalizeControls(catalog);
  if (controls.length === 0) return [];
  const byId = new Map(controls.map((c) => [c.id, c]));

  const floor = scoring.breakdown?.min_residual_floor ?? 0.35;
  const inert = new Set(scoring.floor?.controls_beyond_floor_ids ?? []);

  const points: ControlFloorPoint[] = [];
  for (let n = 0; n <= active.length; n += 1) {
    const subset = active.slice(0, n);
    const { residual, meanCoverage } = residualPct(threats, subset, byId, floor);
    const cid: string | null = n === 0 ? null : (active[n - 1] ?? null);
    points.push({
      label: cid ?? 'none',
      n,
      residual,
      meanCoverage,
      beyondFloor: cid !== null && inert.has(cid),
    });
  }
  return points;
}

/** Minimal catalogue shape; matches the `/api/security/controls` rows. */
export interface ControlCatalogRow {
  id?: string;
  control_id?: string;
  efficacy?: number;
  threats?: Record<string, number>;
  evidence?: { basis?: string; n_observations?: number; concentration?: number; validated?: boolean; source?: string };
  [k: string]: unknown;
}

/**
 * Provenance records -> chart points, sorted widest interval first so the
 * biggest evidence gap is at the top of the table beneath the chart.
 */
export function toEfficacyPoints(
  records: Record<string, ControlProvenance> | ControlCatalogRow[] | null | undefined,
): EfficacyPoint[] {
  if (!records) return [];
  const list = Array.isArray(records) ? records : Object.values(records);
  return list
    .map((r) => {
      const rec = r as ControlCatalogRow & Partial<ControlProvenance>;
      const ev = (rec.evidence ?? {}) as Record<string, unknown>;
      const declared =
        typeof rec.declared === 'number'
          ? rec.declared
          : typeof rec.efficacy === 'number'
            ? rec.efficacy
            : null;
      if (declared === null) return null;
      const mean =
        typeof rec.posterior_mean === 'number'
          ? rec.posterior_mean
          : (rec.posterior_mean as number | undefined) ?? declared;
      const conc =
        (rec.concentration as number | undefined) ??
        (ev.concentration as number | undefined) ??
        4;
      const n =
        (rec.n_observations as number | undefined) ?? (ev.n_observations as number | undefined) ?? 0;
      // Client-side Beta approximation for the whisker; the authoritative
      // numbers come from the API's variance budget.
      const width = 0.3 / Math.sqrt(Math.max(0.5, conc));
      return {
        id: rec.control_id ?? rec.id ?? '',
        declared,
        mean,
        lower: Math.max(0, declared - width),
        upper: Math.min(1, declared + width),
        basis: (rec.basis as string | undefined) ?? (ev.basis as string | undefined) ?? 'unknown',
        validated: Boolean(rec.validated ?? ev.validated),
        n,
      } satisfies EfficacyPoint;
    })
    .filter((p): p is EfficacyPoint => p !== null && p.id !== '')
    .sort((a, b) => (b.upper - b.lower) - (a.upper - a.lower));
}

/** Map an assessment's band + floor into the shape ResidualDisplay expects. */
export function toResidualIntervalFromAnalysis(a: {
  uncertainty?: { mean_pct: number; lower_pct: number; upper_pct: number; level: number; headline_pct?: number | null; headline_inside?: boolean; n_threats?: number } | null;
}): ResidualInterval | null {
  const u = a.uncertainty;
  if (!u) return null;
  return {
    point: u.headline_pct ?? u.mean_pct,
    lower: u.lower_pct,
    upper: u.upper_pct,
    level: u.level,
    headlineInside: u.headline_inside ?? true,
    nThreats: u.n_threats,
  };
}