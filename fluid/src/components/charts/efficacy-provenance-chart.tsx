'use client';

import * as React from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ErrorBar,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { SEVERITY_VAR } from '@/components/tokens/status';
import { EfficacyChartTooltip } from './efficacy-chart-tooltip';
import { cn } from '@/lib/utils';

export interface EfficacyPoint {
  id: string;
  declared: number;
  /** Beta posterior mean; equals `declared` until observations exist. */
  mean: number;
  /** Credible interval from the recorded provenance. */
  lower: number;
  upper: number;
  basis: string;
  validated: boolean;
  n: number;
}

export interface EfficacyProvenanceChartProps {
  points: EfficacyPoint[];
  className?: string;
  height?: number;
}

/**
 * Every control efficacy with the interval its provenance justifies.
 *
 * A wide bar means "we do not know how effective this is" — which is the
 * current, honest state of the catalogue. When a control gains observations
 * its interval tightens and it flips to the measured colour, so the chart is
 * also the progress bar for closing that gap.
 */
export function EfficacyProvenanceChart({
  points,
  className,
  height = 260,
}: EfficacyProvenanceChartProps) {
  const anyValidated = points.some((p) => p.validated);
  const anyUnvalidated = points.some((p) => !p.validated);

  return (
    <div className={cn('flex flex-col gap-2', className)}>
      <div style={{ height }} role="img" aria-label="Control efficacy with credible intervals">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={points} margin={{ top: 12, right: 12, left: -18, bottom: 4 }}>
            <CartesianGrid strokeDasharray="2 4" stroke="hsl(var(--border))" vertical={false} />
            <XAxis
              dataKey="id"
              tick={{ fontSize: 10, fill: 'hsl(var(--muted-foreground))' }}
              interval={0}
              angle={-35}
              textAnchor="end"
              height={52}
            />
            <YAxis
              domain={[0, 1]}
              tick={{ fontSize: 10, fill: 'hsl(var(--muted-foreground))' }}
              tickFormatter={(v: number) => `${v * 100}%`}
              tickLine={false}
              axisLine={false}
            />
            <Tooltip
              content={EfficacyChartTooltip}
              cursor={{ fill: 'hsl(var(--muted))', opacity: 0.4 }}
            />
            <Bar dataKey="mean" radius={[3, 3, 0, 0]} maxBarSize={42}>
              {points.map((p) => (
                <Cell
                  key={p.id}
                  fill={p.validated ? SEVERITY_VAR.low : SEVERITY_VAR.high}
                  fillOpacity={p.validated ? 0.9 : 0.55}
                />
              ))}
              <ErrorBar
                dataKey={(p: EfficacyPoint) => p.upper - p.lower}
                stroke="hsl(var(--foreground))"
                strokeWidth={1.5}
                width={3}
              />
            </Bar>
            {/* The catalogue's declared value, so a posterior that moved away
                from it is visible rather than silent. */}
            <ReferenceLine
              y={0.7}
              stroke="hsl(var(--muted-foreground))"
              strokeDasharray="4 4"
              label={{ value: 'declared 0.70', fontSize: 9, fill: 'hsl(var(--muted-foreground))', position: 'insideTopRight' }}
            />
          </BarChart>
        </ResponsiveContainer>
      </div>
      <p className="text-[11px] leading-relaxed text-muted-foreground">
        Bar height is the posterior mean; whiskers are the credible interval its provenance
        justifies.
        {anyUnvalidated && (
          <>
            {' '}
            <span className="text-evidence-modality">
              {points.filter((p) => !p.validated).length} of {points.length}
            </span>{' '}
            are unvalidated analyst priors — wide because nobody has measured them, not because
            they are weak.
          </>
        )}
        {anyValidated && (
          <>
            {' '}
            <span className="text-evidence-direct">
              {points.filter((p) => p.validated).length}
            </span>{' '}
            have recorded observations and are drawn tight.
          </>
        )}
      </p>
    </div>
  );
}
