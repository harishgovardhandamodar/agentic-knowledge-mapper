'use client';

import * as React from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ReferenceArea,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { ControlFloorChartTooltip } from './control-floor-chart-tooltip';
import { SEVERITY_BG, severityFromPct } from '@/components/tokens/status';
import { cn } from '@/lib/utils';

export interface ControlFloorPoint {
  /** Label for this column: "" for the "none declared" bar. */
  label: string;
  n: number;
  residual: number;
  meanCoverage: number;
  /** True when this control no longer moves the headline. */
  beyondFloor: boolean;
}

export interface ControlFloorChartProps {
  points: ControlFloorPoint[];
  /** The floor, as a share of the 0..100 residual axis. */
  floor?: number;
  className?: string;
  height?: number;
}

/**
 * Residual risk as controls are added — the chart that answers "did my
 * controls do anything?".
 *
 * The shape is the whole point. The line falls steeply while coverage is
 * earning its keep and then flattens exactly where the residual floor takes
 * over. Bars whose removal moves the headline by less than the noise
 * threshold are drawn hollow and labelled, because a reader who attests
 * those needs to know the number stopped responding for a modelling reason,
 * not because their control failed.
 */
export function ControlFloorChart({
  points,
  floor = 35,
  className,
  height = 260,
}: ControlFloorChartProps) {
  const beyond = points.filter((p) => p.beyondFloor);
  const beyondFrom = points.length - beyond.length;

  return (
    <div className={cn('flex flex-col gap-2', className)}>
      <div style={{ height }} role="img" aria-label="Residual risk as controls are added">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={points} margin={{ top: 8, right: 8, left: -18, bottom: 4 }}>
            <CartesianGrid strokeDasharray="2 4" stroke="hsl(var(--border))" vertical={false} />
            <XAxis
              dataKey="label"
              tick={{ fontSize: 10, fill: 'hsl(var(--muted-foreground))' }}
              interval={0}
              angle={-35}
              textAnchor="end"
              height={52}
            />
            <YAxis
              domain={[0, 100]}
              tick={{ fontSize: 10, fill: 'hsl(var(--muted-foreground))' }}
              tickLine={false}
              axisLine={false}
            />
            <Tooltip content={ControlFloorChartTooltip} cursor={{ fill: 'hsl(var(--muted))', opacity: 0.4 }} />
            <ReferenceArea
              y1={floor}
              y2={0}
              fill="hsl(var(--muted))"
              fillOpacity={0.35}
              label={{ value: 'floor-dominated', fontSize: 9, fill: 'hsl(var(--muted-foreground))', position: 'insideTopLeft' }}
            />
            <ReferenceLine y={floor} stroke="hsl(var(--muted-foreground))" strokeDasharray="4 4" />
            <Bar dataKey="residual" radius={[3, 3, 0, 0]} maxBarSize={46}>
              {points.map((p, i) => (
                <Cell
                  key={`${p.label}-${i}`}
                  fill={SEVERITY_BG[severityFromPct(p.residual)]}
                  // Hollow == the floor owns this column.
                  fillOpacity={p.beyondFloor ? 0.28 : 1}
                  stroke={SEVERITY_BG[severityFromPct(p.residual)]}
                  strokeWidth={p.beyondFloor ? 1.5 : 0}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
      <p className="text-[11px] leading-relaxed text-muted-foreground">
        Residual falls while coverage earns its keep, then saturates: likelihood never drops
        below {Math.round(floor)}% of inherent. From control {beyondFrom + 1} onward the
        headline is set by that floor, so the hollow bars change coverage but not the number.
      </p>
    </div>
  );
}