'use client';

import type { TooltipContentProps } from 'recharts';
import type { ControlFloorPoint } from './control-floor-chart';

/**
 * Recharts passes the active payload; the shape is narrowed here so the chart
 * component stays typed at its own boundary.
 */
export function ControlFloorChartTooltip({
  active,
  payload,
}: TooltipContentProps) {
  if (!active || !payload || payload.length === 0) return null;
  const p = payload[0]?.payload as ControlFloorPoint | undefined;
  if (!p) return null;

  return (
    <div className="rounded-md border bg-popover px-3 py-2 text-xs shadow-md">
      <div className="font-medium">
        {p.n === 0 ? 'No controls declared' : `${p.n} control${p.n > 1 ? 's' : ''} declared`}
      </div>
      <dl className="mt-1 grid grid-cols-[auto,auto] gap-x-3 gap-y-0.5 tabular">
        <dt className="text-muted-foreground">Residual</dt>
        <dd className="text-right">{p.residual.toFixed(1)}</dd>
        <dt className="text-muted-foreground">Mean coverage</dt>
        <dd className="text-right">{p.meanCoverage.toFixed(1)}%</dd>
      </dl>
      {p.beyondFloor && (
        <p className="mt-1 max-w-56 text-[11px] text-muted-foreground">
          Adding a control here raises coverage but cannot lower the headline further — the
          residual floor is already binding.
        </p>
      )}
    </div>
  );
}