'use client';

import * as React from 'react';
import { Check, ChevronsUpDown, FlaskConical } from 'lucide-react';
import { useInvestigations } from '@/lib/api/queries';
import { useUi } from '@/lib/stores/ui';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';

/**
 * Global investigation selector. Every workspace screen is scoped to the
 * chosen investigation, so this is the shell's primary context control and the
 * value is persisted in the UI store.
 */
export function InvestigationSelector() {
  const { data, isLoading, isError } = useInvestigations();
  const { investigationId, setInvestigation } = useUi();
  const [open, setOpen] = React.useState(false);
  const ref = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    function onDoc(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') setOpen(false);
    }
    document.addEventListener('mousedown', onDoc);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDoc);
      document.removeEventListener('keydown', onKey);
    };
  }, []);

  React.useEffect(() => {
    if (investigationId === null && data && data.length > 0) {
      setInvestigation(data[0]!.id);
    }
  }, [data, investigationId, setInvestigation]);

  const current = data?.find((i) => i.id === investigationId);

  if (isLoading) {
    return <Skeleton className="h-9 w-56" />;
  }

  return (
    <div ref={ref} className="relative">
      <Button
        variant="outline"
        size="sm"
        aria-haspopup="listbox"
        aria-expanded={open}
        disabled={isError}
        onClick={() => setOpen((v) => !v)}
        className="w-56 justify-between font-normal"
      >
        <span className="flex min-w-0 items-center gap-2">
          <FlaskConical className="size-4 shrink-0 text-muted-foreground" aria-hidden />
          <span className="truncate">
            {current ? current.title : isError ? 'Backend unavailable' : 'Select investigation'}
          </span>
        </span>
        <ChevronsUpDown className="size-4 shrink-0 text-muted-foreground" aria-hidden />
      </Button>

      {open && (
        <ul
          role="listbox"
          aria-label="Investigations"
          className="absolute z-50 mt-1 max-h-72 w-72 overflow-auto rounded-md border bg-popover p-1 shadow-md"
        >
          {(data ?? []).length === 0 && (
            <li className="px-2 py-1.5 text-xs text-muted-foreground">No investigations yet.</li>
          )}
          {(data ?? []).map((inv) => {
            const selected = inv.id === investigationId;
            return (
              <li key={inv.id} role="option" aria-selected={selected}>
                <button
                  type="button"
                  onClick={() => {
                    setInvestigation(inv.id);
                    setOpen(false);
                  }}
                  className={cn(
                    'flex w-full items-center justify-between gap-2 rounded-sm px-2 py-1.5 text-left text-sm hover:bg-accent',
                    selected && 'bg-accent/60',
                  )}
                >
                  <span className="min-w-0">
                    <span className="block truncate">{inv.title}</span>
                    {inv.keywords && (
                      <span className="block truncate text-xs text-muted-foreground">
                        {inv.keywords}
                      </span>
                    )}
                  </span>
                  {selected && <Check className="size-4 shrink-0" aria-hidden />}
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
