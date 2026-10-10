'use client';

import type { TooltipContentProps } from 'recharts';
import type { EfficacyPoint } from './efficacy-provenance-chart';

export function EfficacyChartTooltip({
  active,
  payload,
}: TooltipContentProps) {
  if (!active || !payload || payload.length === 0) return null;
  const p = payload[0]?.payload as EfficacyPoint | undefined;
  if (!p) return null;

  return (
    <div className="rounded-md border bg-popover px-3 py-2 text-xs shadow-md">
      <div className="font-medium">
        {p.id} · {p.basis.replace(/_/g, ' ')}
      </div>
      <dl className="mt-1 grid grid-cols-[auto,auto] gap-x-3 gap-y-0.5 tabular">
        <dt className="text-muted-foreground">Declared</dt>
        <dd className="text-right">{p.declared.toFixed(2)}</dd>
        <dt className="text-muted-foreground">Posterior</dt>
        <dd className="text-right">{p.mean.toFixed(2)}</dd>
        <dt className="text-muted-foreground">90% interval</dt>
        <dd className="text-right">
          {p.lower.toFixed(2)}–{p.upper.toFixed(2)}
        </dd>
      </dl>
      <p className="mt-1 max-w-60 text-[11px] text-muted-foreground">
        {p.validated
          ? `${p.n} recorded observation${p.n === 1 ? '' : 's'} — the interval reflects measurement.`
          : 'No recorded measurement. The cited standard establishes the control exists, not how effective it is.'}
      </p>
    </div>
  );
}