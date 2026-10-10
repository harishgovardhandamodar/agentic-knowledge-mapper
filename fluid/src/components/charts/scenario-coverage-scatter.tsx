'use client';

import * as React from 'react';
import {
  CartesianGrid,
  Cell,
  ReferenceLine,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
  ZAxis,
} from 'recharts';
import { ScenarioScatterTooltip } from './scenario-coverage-tooltip';
import { cn } from '@/lib/utils';
import type { ScenarioPoint } from './scenario-types';

export interface ScenarioCoverageScatterProps {
  scenarios: ScenarioPoint[];
  className?: string;
  height?: number;
}

/** Which colour a scenario gets, by how it was derived. */
const ORIGIN_FILL: Record<string, string> = {
  control_gap_chain: 'hsl(var(--severity-high))',
  residual_amplifier: 'hsl(var(--severity-critical))',
  cross_cutting_gap: 'hsl(var(--severity-info))',
};

export const ORIGIN_COLOR = ORIGIN_FILL;

/**
 * Coverage on the exploit leg against the residual it leaves behind.
 *
 * The point of the chart is the bottom-left corner: barely covered and still
 * risky. That is where a derived scenario lives, and it is invisible when the
 * same assessment is read as a list of independent rows — a row looks fine
 * until you ask what reaches it.
 */
export function ScenarioCoverageScatter({
  scenarios,
  className,
  height = 280,
}: ScenarioCoverageScatterProps) {
  const points = scenarios
    .filter((s) => typeof s.coverage_of_exploit === 'number')
    .map((s) => ({
      ...s,
      x: s.coverage_of_exploit as number,
      y: s.residual_score ?? 0,
    }));

  if (points.length === 0) {
    return (
      <p className="rounded-md border border-dashed p-6 text-center text-sm text-muted-foreground">
        No scenario carries a coverage figure to plot.
      </p>
    );
  }

  return (
    <div className={cn('flex flex-col gap-2', className)}>
      <div style={{ height }} role="img" aria-label="Scenario coverage against residual">
        <ResponsiveContainer width="100%" height="100%">
          <ScatterChart margin={{ top: 8, right: 12, bottom: 16, left: -14 }}>
            <CartesianGrid strokeDasharray="2 4" stroke="hsl(var(--border))" />
            <XAxis
              type="number"
              dataKey="x"
              name="coverage"
              domain={[0, 100]}
              tick={{ fontSize: 10, fill: 'hsl(var(--muted-foreground))' }}
              tickFormatter={(v: number) => `${v}%`}
              label={{
                value: 'coverage of the exploit leg',
                position: 'insideBottom',
                offset: -10,
                fontSize: 10,
                fill: 'hsl(var(--muted-foreground))',
              }}
            />
            <YAxis
              type="number"
              dataKey="y"
              name="residual"
              domain={[0, 25]}
              tick={{ fontSize: 10, fill: 'hsl(var(--muted-foreground))' }}
              label={{
                value: 'residual',
                angle: -90,
                position: 'insideLeft',
                fontSize: 10,
                fill: 'hsl(var(--muted-foreground))',
              }}
            />
            <ZAxis range={[60, 60]} />
            <Tooltip content={ScenarioScatterTooltip} cursor={{ strokeDasharray: '3 3' }} />
            {/* The coverage a control is expected to deliver; left of it a
                scenario is doing real work. */}
            <ReferenceLine
              x={50}
              stroke="hsl(var(--muted-foreground))"
              strokeDasharray="4 4"
              label={{ value: '50%', fontSize: 9, fill: 'hsl(var(--muted-foreground))', position: 'top' }}
            />
            <Scatter data={points} shape="circle">
              {points.map((p, i) => (
                <Cell
                  key={`${p.id}-${i}`}
                  fill={ORIGIN_FILL[p.origin] ?? 'hsl(var(--muted-foreground))'}
                  fillOpacity={0.75}
                />
              ))}
            </Scatter>
          </ScatterChart>
        </ResponsiveContainer>
      </div>
      <div className="flex flex-wrap gap-3 text-[11px] text-muted-foreground">
        {Object.entries(ORIGIN_FILL).map(([origin, fill]) => (
          <span key={origin} className="flex items-center gap-1.5">
            <span className="size-2 rounded-full" style={{ background: fill }} aria-hidden />
            {origin.replace(/_/g, ' ')}
          </span>
        ))}
      </div>
      <p className="text-[11px] leading-relaxed text-muted-foreground">
        Bottom-left is the interesting corner: barely covered, still risky. Those are the
        scenarios a per-row reading of the assessment cannot show.
      </p>
    </div>
  );
}