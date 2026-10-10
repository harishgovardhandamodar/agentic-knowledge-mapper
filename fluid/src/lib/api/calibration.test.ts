/**
 * The saturation curve must not become a chart of invented numbers.
 *
 * The single most important property: the final column reproduces the
 * assessment's own stored `residual_pct`. If it does not, the chart is lying
 * about the engine, which is worse than having no chart.
 */
import { describe, expect, it } from 'vitest';
import { controlFloorCurve, toEfficacyPoints } from './calibration';
import type { ControlCatalogRow } from './calibration';
import type { Assessment } from './schemas';

// Mirrors app.security: C01 efficacy 0.70, weight 1.0 on T01; C02 0.70.
const CATALOG: ControlCatalogRow[] = [
  { id: 'C01', efficacy: 0.7, threats: { T01: 1.0 } },
  { id: 'C02', efficacy: 0.7, threats: { T01: 0.5 } },
  { id: 'C03', efficacy: 0.65, threats: { T01: 0.9 } },
];

const BASE_ASSESSMENT = {
  scoring: {
    active_controls: ['C01', 'C02', 'C03'],
    breakdown: { min_residual_floor: 0.35 },
    floor: { controls_beyond_floor_ids: ['C03'] },
    threats: [
      { id: 'T01', likelihood: 4, impact: 5 },
      { id: 'T02', likelihood: 3, impact: 4 },
    ],
  },
} as unknown as Assessment;

describe('controlFloorCurve', () => {
  it('produces one point per control plus the zero-control baseline', () => {
    const pts = controlFloorCurve(BASE_ASSESSMENT, CATALOG);
    expect(pts).toHaveLength(4);
    expect(pts[0]!.n).toBe(0);
    expect(pts[0]!.label).toBe('none');
    expect(pts[3]!.n).toBe(3);
    expect(pts[3]!.label).toBe('C03');
  });

  it('reproduces the engine headline at the final column', () => {
    // The engine's value for this threat set, computed by the same rules.
    // Recomputed here independently rather than copied, so a change in either
    // implementation fails this test.
    const pts = controlFloorCurve(BASE_ASSESSMENT, CATALOG);
    const final = pts[pts.length - 1]!.residual;
    const expected = (() => {
      const threats = BASE_ASSESSMENT.scoring!.threats!;
      const rows = threats.map((t) => {
        let survive = 1;
        for (const c of CATALOG) {
          const w = (c.threats as Record<string, number>)[t.id];
          if (w === undefined) continue;
          survive *= 1 - Math.min(0.95, (c.efficacy as number) * w);
        }
        const cov = 1 - survive;
        const likR = Math.max(t.likelihood * 0.35, t.likelihood * (1 - cov));
        return { residual: likR * t.impact, coverage: cov };
      });
      const vals = rows.map((r) => r.residual).sort((a, b) => b - a);
      const top = vals.slice(0, 5);
      const worst = top.reduce((s, v) => s + v, 0) / top.length;
      const breadth = vals.reduce((s, v) => s + v, 0) / vals.length;
      return Math.min(100, ((0.55 * worst + 0.45 * breadth) / 25) * 100);
    })();
    expect(final).toBeCloseTo(expected, 6);
  });

  it('falls monotonically as controls are added', () => {
    const pts = controlFloorCurve(BASE_ASSESSMENT, CATALOG);
    const residuals = pts.map((p) => p.residual);
    for (let i = 1; i < residuals.length; i += 1) {
      expect(residuals[i]!).toBeLessThanOrEqual(residuals[i - 1]! + 1e-9);
    }
  });

  it('raises coverage monotonically', () => {
    const cov = controlFloorCurve(BASE_ASSESSMENT, CATALOG).map((p) => p.meanCoverage);
    for (let i = 1; i < cov.length; i += 1) {
      expect(cov[i]!).toBeGreaterThanOrEqual(cov[i - 1]! - 1e-9);
    }
  });

  it('marks only the controls the engine reported as beyond the floor', () => {
    const pts = controlFloorCurve(BASE_ASSESSMENT, CATALOG);
    const marked = pts.filter((p) => p.beyondFloor).map((p) => p.label);
    expect(marked).toEqual(['C03']);
  });

  it('returns nothing rather than guessing when inputs are missing', () => {
    // The important negative: a chart of invented numbers is worse than none.
    expect(controlFloorCurve(BASE_ASSESSMENT, [])).toEqual([]);
    expect(controlFloorCurve(null, CATALOG)).toEqual([]);
    expect(
      controlFloorCurve(
        { scoring: { active_controls: [], threats: [] } } as unknown as Assessment,
        CATALOG,
      ),
    ).toEqual([]);
  });

  it('ignores a catalogue entry with no efficacy rather than defaulting', () => {
    const bogus = [{ id: 'C01', threats: { T01: 1 } } as ControlCatalogRow];
    expect(controlFloorCurve(BASE_ASSESSMENT, bogus)).toEqual([]);
  });

  it('ignores a control that does not apply to any threat in the set', () => {
    // Declaring C99 (which covers only T99) must not move the score: the curve
    // is driven by active_controls, and a control with no applicable threat
    // contributes nothing to coverage.
    const withExtra = {
      scoring: {
        ...BASE_ASSESSMENT.scoring,
        active_controls: ['C01', 'C02', 'C03', 'C99'],
      },
    } as unknown as Assessment;
    const pts = controlFloorCurve(withExtra, [
      ...CATALOG,
      { id: 'C99', efficacy: 0.9, threats: { T99: 1 } },
    ]);
    const base = controlFloorCurve(BASE_ASSESSMENT, CATALOG);
    expect(pts).toHaveLength(5);
    expect(pts[4]!.residual).toBeCloseTo(base[3]!.residual, 6);
    expect(pts[4]!.meanCoverage).toBeCloseTo(base[3]!.meanCoverage, 6);
  });
});

describe('toEfficacyPoints', () => {
  it('maps provenance records to chart points', () => {
    const pts = toEfficacyPoints({
      C01: {
        control_id: 'C01',
        declared: 0.7,
        posterior_mean: 0.7,
        basis: 'expert_elicited',
        source: '',
        n_observations: 0,
        concentration: 4,
        note: '',
        validated: false,
      },
    });
    expect(pts).toHaveLength(1);
    expect(pts[0]!.declared).toBe(0.7);
    expect(pts[0]!.validated).toBe(false);
  });

  it('reads efficacy from catalogue rows', () => {
    const pts = toEfficacyPoints([{ id: 'C05', efficacy: 0.85, threats: {} }]);
    expect(pts).toHaveLength(1);
    expect(pts[0]!.id).toBe('C05');
    expect(pts[0]!.declared).toBe(0.85);
  });

  it('gives a validated control a narrower interval than an unvalidated one', () => {
    const pts = toEfficacyPoints([
      { id: 'A', efficacy: 0.7, evidence: { concentration: 4, validated: false } },
      { id: 'B', efficacy: 0.7, evidence: { concentration: 24, validated: true } },
    ] as ControlCatalogRow[]);
    const a = pts.find((p) => p.id === 'A')!;
    const b = pts.find((p) => p.id === 'B')!;
    expect(b.upper - b.lower).toBeLessThan(a.upper - a.lower);
  });

  it('skips rows with no usable efficacy', () => {
    expect(toEfficacyPoints([{ id: 'X', threats: {} } as ControlCatalogRow])).toEqual([]);
    expect(toEfficacyPoints(null)).toEqual([]);
  });
});