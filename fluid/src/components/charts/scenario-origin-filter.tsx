'use client';

import { ORIGIN_COLOR } from './scenario-coverage-scatter';
import { cn } from '@/lib/utils';

export interface ScenarioOriginFilterProps {
  byOrigin: Record<string, number>;
  value: string;
  onChange: (v: string) => void;
  className?: string;
}

const LABELS: Record<string, string> = {
  control_gap_chain: 'Chain',
  residual_amplifier: 'At floor',
  cross_cutting_gap: 'Programme',
};

/**
 * Filter by derivation method, with the counts shown.
 *
 * The count matters as much as the label: "7 chains" tells a reader there is
 * something to look at, and "0" tells them a method found nothing rather than
 * that the method is broken.
 */
export function ScenarioOriginFilter({
  byOrigin,
  value,
  onChange,
  className,
}: ScenarioOriginFilterProps) {
  const total = Object.values(byOrigin).reduce((a, b) => a + b, 0);
  const entries = Object.entries(byOrigin);

  return (
    <div className={cn('flex flex-wrap items-center gap-2', className)}>
      <button
        type="button"
        onClick={() => onChange('all')}
        aria-pressed={value === 'all'}
        className={cn(
          'rounded-full border px-3 py-1 text-xs transition-colors',
          value === 'all' ? 'border-primary bg-primary/10' : 'hover:bg-accent/50',
        )}
      >
        All <span className="tabular ml-1 text-muted-foreground">{total}</span>
      </button>
      {entries.map(([origin, count]) => (
        <button
          key={origin}
          type="button"
          onClick={() => onChange(origin)}
          aria-pressed={value === origin}
          className={cn(
            'inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs transition-colors',
            value === origin ? 'border-primary bg-primary/10' : 'hover:bg-accent/50',
          )}
        >
          <span
            className="size-2 rounded-full"
            style={{ background: ORIGIN_COLOR[origin] ?? 'hsl(var(--muted-foreground))' }}
            aria-hidden
          />
          {LABELS[origin] ?? origin.replace(/_/g, ' ')}
          <span className="tabular text-muted-foreground">{count}</span>
        </button>
      ))}
    </div>
  );
}