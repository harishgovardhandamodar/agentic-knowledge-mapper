'use client';

import * as React from 'react';
import { cn } from '@/lib/utils';

export interface AttackTreeNode {
  id: string;
  title: string;
  coverage: number;
  residual: number;
  floor_capped?: boolean;
}

export interface AttackTreeEdge {
  from: string;
  to: string;
  uncovered_by: string[];
  weakest: boolean;
}

export interface AttackTreeData {
  nodes: AttackTreeNode[];
  edges: AttackTreeEdge[];
  stats: { nodes: number; edges: number; max_hops: number };
  note?: string;
}

export interface AttackTreeViewProps {
  data: AttackTreeData;
  selected: string | null;
  onSelect: (id: string | null) => void;
  className?: string;
}

/**
 * The derived chains as a layered graph.
 *
 * Layout is by *coverage band* rather than by a physics simulation: the whole
 * claim of this view is that coverage declines along a path, so the columns
 * are the argument. A force layout would animate the very thing the diagram is
 * meant to state.
 */
export function AttackTreeView({ data, selected, onSelect, className }: AttackTreeViewProps) {
  if (data.nodes.length === 0) {
    return (
      <p className={cn('rounded-md border border-dashed p-6 text-center text-sm text-muted-foreground', className)}>
        No uncovered chains to lay out — every composition the rows imply is covered.
      </p>
    );
  }

  // Bucket nodes by coverage: well-covered (precondition) → poorly covered
  // (exploit). Three bands keep the columns readable.
  const bands = [
    { key: 'strong', label: 'covered', test: (c: number) => c >= 50 },
    { key: 'mid', label: 'partial', test: (c: number) => c > 0 && c < 50 },
    { key: 'weak', label: 'uncovered', test: (c: number) => c <= 0 },
  ];
  const byBand = bands.map((b) => ({
    ...b,
    nodes: data.nodes.filter((n) => b.test(n.coverage)),
  }));

  const posOf = new Map<string, { band: number; index: number; count: number }>();
  byBand.forEach((b, bi) => {
    b.nodes.forEach((n, i) => posOf.set(n.id, { band: bi, index: i, count: b.nodes.length }));
  });

  return (
    <div className={cn('flex flex-col gap-3', className)}>
      <div className="flex gap-3 overflow-x-auto pb-2">
        {byBand.map((b) => (
          <div key={b.key} className="flex shrink-0 flex-col gap-2" style={{ width: 150 }}>
            <span className="text-center text-[10px] uppercase tracking-wider text-muted-foreground">
              {b.label}
            </span>
            {b.nodes.map((n) => {
              const dim = selected != null && selected !== n.id;
              return (
                <button
                  key={n.id}
                  type="button"
                  onClick={() => onSelect(selected === n.id ? null : n.id)}
                  title={n.title}
                  className={cn(
                    'flex h-9 items-center gap-2 rounded-md border px-2 text-left transition-all',
                    selected === n.id
                      ? 'border-primary bg-primary/15'
                      : 'hover:border-primary/50',
                    dim && 'opacity-35',
                  )}
                  style={{ marginTop: 0 }}
                >
                  <span
                    className={cn(
                      'size-1.5 shrink-0 rounded-full',
                      n.coverage <= 0
                        ? 'bg-severity-critical'
                        : n.coverage < 50
                          ? 'bg-severity-high'
                          : 'bg-severity-low',
                    )}
                    aria-hidden
                  />
                  <span className="truncate font-mono text-[11px]">{n.id}</span>
                  <span className="tabular ml-auto text-[10px] text-muted-foreground">
                    {n.coverage.toFixed(0)}%
                  </span>
                </button>
              );
            })}
            {b.nodes.length === 0 && (
              <div className="rounded-md border border-dashed p-3 text-center text-[11px] text-muted-foreground">
                none
              </div>
            )}
          </div>
        ))}
      </div>

      {selected && (
        <div className="rounded-md border bg-muted/30 p-3 text-xs">
          {(() => {
            const node = data.nodes.find((n) => n.id === selected);
            if (!node) return null;
            const inEdges = data.edges.filter((e) => e.to === selected);
            const outEdges = data.edges.filter((e) => e.from === selected);
            return (
              <>
                <div className="flex flex-wrap items-baseline gap-2">
                  <span className="font-mono">{node.id}</span>
                  <span className="font-medium">{node.title}</span>
                  <span className="tabular text-muted-foreground">
                    {node.coverage.toFixed(1)}% covered · residual {node.residual.toFixed(2)}
                  </span>
                  {node.floor_capped && (
                    <span className="text-severity-medium">at floor</span>
                  )}
                </div>
                {inEdges.length > 0 && (
                  <p className="mt-1 text-muted-foreground">
                    Reached from {inEdges.map((e) => e.from).join(', ')} — gap:{' '}
                    {[...new Set(inEdges.flatMap((e) => e.uncovered_by))].join(', ') || 'n/a'}
                  </p>
                )}
                {outEdges.length > 0 && (
                  <p className="text-muted-foreground">
                    Leads to {outEdges.map((e) => e.to).join(', ')}
                  </p>
                )}
              </>
            );
          })()}
        </div>
      )}

      {data.note && (
        <p className="text-[11px] leading-relaxed text-muted-foreground">{data.note}</p>
      )}
    </div>
  );
}