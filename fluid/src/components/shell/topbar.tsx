'use client';

import { useHealth } from '@/lib/api/queries';
import { InvestigationSelector } from '@/components/shell/investigation-selector';
import { ThemeToggle } from '@/components/shell/theme-toggle';
import { cn } from '@/lib/utils';

function HealthDot() {
  const { isSuccess, isError, isLoading } = useHealth();
  const state = isLoading ? 'pending' : isError ? 'down' : isSuccess ? 'up' : 'pending';
  const label =
    state === 'up' ? 'Backend reachable' : state === 'down' ? 'Backend unreachable' : 'Checking backend';
  const dot =
    state === 'up'
      ? 'bg-evidence-direct'
      : state === 'down'
        ? 'bg-severity-critical'
        : 'bg-muted-foreground';
  return (
    <span className="flex items-center gap-1.5 text-xs text-muted-foreground" title={label}>
      <span className={cn('size-2 rounded-full', dot)} aria-hidden />
      <span className="sr-only">{label}</span>
    </span>
  );
}

/** Top bar: brand, global investigation scope, backend health, theme. */
export function Topbar() {
  return (
    <header className="flex h-14 shrink-0 items-center justify-between gap-4 border-b bg-card/40 px-4">
      <div className="flex items-center gap-3">
        <InvestigationSelector />
        <HealthDot />
      </div>
      <div className="flex items-center gap-3">
        <ThemeToggle />
      </div>
    </header>
  );
}
