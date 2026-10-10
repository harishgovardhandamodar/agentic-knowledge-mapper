'use client';

import type { TooltipContentProps } from 'recharts';
import type { ScenarioPoint } from './scenario-types';

export function ScenarioScatterTooltip(props: TooltipContentProps) {
  const { active, payload } = props;
  if (!active || !payload || payload.length === 0) return null;
  const p = payload[0]?.payload as ScenarioPoint | undefined;
  if (!p) return null;

  return (
    <div className="max-w-72 rounded-md border bg-popover px-3 py-2 text-xs shadow-md">
      <div className="font-medium">{p.title}</div>
      <div className="mt-0.5 text-[11px] text-muted-foreground">
        {String(p.origin).replace(/_/g, ' ')}
      </div>
      <dl className="mt-1.5 grid grid-cols-[auto,auto] gap-x-3 gap-y-0.5 tabular">
        <dt className="text-muted-foreground">Coverage</dt>
        <dd className="text-right">{p.coverage_of_exploit?.toFixed(1)}%</dd>
        <dt className="text-muted-foreground">Residual</dt>
        <dd className="text-right">{p.residual_score?.toFixed(2)}</dd>
      </dl>
      {p.why && <p className="mt-1.5 text-[11px] text-muted-foreground">{p.why}</p>}
    </div>
  );
}