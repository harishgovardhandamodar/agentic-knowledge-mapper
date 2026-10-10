'use client';

import * as React from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  LabelList,
  ResponsiveContainer,
  XAxis,
  YAxis,
} from 'recharts';
import { SEVERITY_VAR } from '@/components/tokens/status';
import { cn } from '@/lib/utils';

export interface VarianceBudget {
  share_inherent?: number;
  share_efficacy?: number;
  share_interaction?: number;
  shares_sum?: number;
  interaction_note?: string;
  unquantified?: Record<string, string>;
  total_variance?: number;
}

export interface VarianceBudgetChartProps {
  budget: VarianceBudget;
  className?: string;
  height?: number;
}

const SHARE_COLORS = {
  inherent: SEVERITY_VAR.medium,
  efficacy: SEVERITY_VAR.high,
  interaction: SEVERITY_VAR.info,
} as const;

/**
 * What actually produced the credible interval, and what is missing from it.
 *
 * The top panel attributes the modelled variance to its inputs. The lower list
 * is the more important half: the engine holds several inputs exactly fixed, so
 * the band is narrower than the true uncertainty of the assessment. Naming
 * them is what stops "90% interval" from being read as total confidence.
 */
export function VarianceBudgetChart({
  budget,
  className,
  height = 120,
}: VarianceBudgetChartProps) {
  const data = [
    {
      key: 'inherent',
      label: 'Likelihood',
      share: budget.share_inherent ?? 0,
    },
    {
      key: 'efficacy',
      label: 'Control efficacy',
      share: budget.share_efficacy ?? 0,
    },
    {
      key: 'interaction',
      label: 'Interaction',
      share: budget.share_interaction ?? 0,
    },
  ];

  const unquantified = Object.entries(budget.unquantified ?? {});
  const negative = (budget.share_interaction ?? 0) < 0;

  return (
    <div className={cn('flex flex-col gap-3', className)}>
      <div style={{ height }} role="img" aria-label="Share of modelled variance by input">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} layout="vertical" margin={{ top: 4, right: 36, left: 4, bottom: 4 }}>
            <CartesianGrid strokeDasharray="2 4" stroke="hsl(var(--border))" horizontal={false} />
            <XAxis
              type="number"
              domain={[0, 1]}
              tick={{ fontSize: 10, fill: 'hsl(var(--muted-foreground))' }}
              tickFormatter={(v: number) => `${Math.round(v * 100)}%`}
              tickLine={false}
              axisLine={false}
            />
            <YAxis
              type="category"
              dataKey="label"
              width={92}
              tick={{ fontSize: 10, fill: 'hsl(var(--muted-foreground))' }}
              tickLine={false}
              axisLine={false}
            />
            <Bar dataKey="share" radius={[0, 3, 3, 0]}>
              {data.map((d) => (
                <Cell key={d.key} fill={SHARE_COLORS[d.key as keyof typeof SHARE_COLORS]} />
              ))}
              <LabelList
                dataKey="share"
                position="right"
                formatter={(v: unknown) => `${Math.round(Number(v) * 100)}%`}
                style={{ fontSize: 10, fill: 'hsl(var(--muted-foreground))' }}
              />
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {negative && budget.interaction_note && (
        <p className="text-[11px] leading-relaxed text-muted-foreground">
          The interaction term is negative: the residual floor clips draws, so saturation
          removes variance instead of adding it. That is why the band cannot express how
          close the model sits to its floor.
        </p>
      )}

      {unquantified.length > 0 && (
        <div className="rounded-md border border-severity-medium/40 bg-severity-medium/5 p-3">
          <h4 className="text-xs font-semibold text-severity-medium">
            Not in this interval ({unquantified.length})
          </h4>
          <p className="mt-1 text-[11px] text-muted-foreground">
            These inputs are held exactly fixed by the deterministic engine, so no band in this
            system reflects uncertainty in them.
          </p>
          <ul className="mt-2 flex flex-col gap-1.5">
            {unquantified.map(([key, note]) => (
              <li key={key} className="text-[11px] leading-relaxed">
                <span className="font-medium">{humanize(key)}</span>
                {note ? <span className="text-muted-foreground"> — {note}</span> : null}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

/** `threat_impact_values` -> `Threat impact values` */
function humanize(key: string): string {
  const words = key.replace(/_/g, ' ');
  return words.charAt(0).toUpperCase() + words.slice(1);
}