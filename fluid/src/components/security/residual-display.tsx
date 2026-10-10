'use client';

import { Info } from 'lucide-react';
import type { EvidenceBreakdown, ResidualInterval, SeverityBand } from '@/types/domain';
import { EVIDENCE_META, SEVERITY_META } from '@/components/tokens/status';
import { StatusBadge } from '@/components/ui/status-badge';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';

const SEVERITY_BG: Record<SeverityBand, string> = {
  critical: 'bg-severity-critical',
  high: 'bg-severity-high',
  medium: 'bg-severity-medium',
  low: 'bg-severity-low',
  info: 'bg-severity-info',
};

export interface ResidualDisplayProps {
  /** null when the backend reported a point with no computed interval. */
  residual: ResidualInterval | null;
  /**
   * A bare point estimate to show *with an explicit "no interval" state* when
   * {@link residual} is null. The brief forbids printing this as if it were a
   * finished figure, so it is only ever shown alongside the missing-interval
   * warning.
   */
  pointWithoutInterval?: number | null;
  /** Backend-provided severity; a hint is derived from the point if absent. */
  severity?: SeverityBand | null;
  label?: string;
  subtitle?: string;
  /** Evidence composition explaining the interval's width. */
  evidence?: EvidenceBreakdown;
  compact?: boolean;
  className?: string;
}

function n(v: number): string {
  return Number.isInteger(v) ? String(v) : v.toFixed(1);
}

/**
 * A residual percentage rendered with the credible interval it came with.
 *
 * This is the brief's non-negotiable: the point estimate is never printed alone
 * (§7). The interval is the primary mark; the number sits inside it. When the
 * point falls outside its own band (which can happen when the headline uses a
 * different aggregation than the Monte-Carlo), that discrepancy is stated, not
 * hidden.
 */
export function ResidualDisplay({
  residual,
  pointWithoutInterval = null,
  severity = null,
  label = 'Residual risk',
  subtitle,
  evidence,
  compact = false,
  className,
}: ResidualDisplayProps) {
  if (!residual) {
    return (
      <Card className={className}>
        <CardHeader className="flex-row items-start justify-between gap-3 space-y-0">
          <div className="min-w-0">
            <h3 className="text-sm font-semibold">{label}</h3>
            {subtitle && <p className="mt-0.5 text-xs text-muted-foreground">{subtitle}</p>}
          </div>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          {pointWithoutInterval != null && (
            <span className="tabular text-4xl font-semibold text-muted-foreground">
              {n(pointWithoutInterval)}
              <span className="text-base">%</span>
            </span>
          )}
          <div className="flex items-start gap-2 rounded-md border border-severity-medium/50 bg-severity-medium/5 px-3 py-2 text-xs text-severity-medium">
            <Info className="mt-0.5 size-3.5 shrink-0" aria-hidden />
            <span>No interval was computed for this residual — treat the point as provisional.</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  const band = severity ?? hintBand(residual.point);
  const meta = SEVERITY_META[band];
  const clamp = (v: number) => Math.max(0, Math.min(100, v));
  const lo = clamp(residual.lower);
  const hi = clamp(residual.upper);
  const point = clamp(residual.point);
  const levelPct = Math.round(residual.level * 100);
  const width = Math.max(1, hi - lo);

  return (
    <Card className={className}>
      <CardHeader className="flex-row items-start justify-between gap-3 space-y-0">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold">{label}</h3>
            <StatusBadge meta={meta} />
          </div>
          {subtitle && <p className="mt-0.5 text-xs text-muted-foreground">{subtitle}</p>}
        </div>
        {typeof residual.nThreats === 'number' && (
          <span className="tabular shrink-0 text-[11px] text-muted-foreground">
            n={residual.nThreats}
          </span>
        )}
      </CardHeader>

      <CardContent className="flex flex-col gap-4">
        <div className="flex items-end gap-2">
          <span className={cn('tabular font-semibold tabular-nums', compact ? 'text-2xl' : 'text-4xl')}>
            {n(residual.point)}
            <span className="text-base text-muted-foreground">%</span>
          </span>
          <span className="tabular pb-1 text-sm text-muted-foreground">
            {levelPct}% interval {n(residual.lower)}–{n(residual.upper)}%
          </span>
        </div>

        <div>
          <div
            className="relative h-3 w-full overflow-hidden rounded-full bg-muted"
            role="img"
            aria-label={`Residual ${n(residual.point)} percent, ${levelPct} percent interval from ${n(
              residual.lower,
            )} to ${n(residual.upper)} percent`}
          >
            {/* The interval band — the primary, always-present mark. */}
            <div
              className={cn('absolute inset-y-0 rounded-full opacity-70', SEVERITY_BG[band])}
              style={{ left: `${lo}%`, width: `${width}%` }}
            />
            {/* The point marker, drawn on top and inside the band. */}
            <div
              className="absolute inset-y-[-2px] w-0.5 -translate-x-1/2 rounded bg-foreground"
              style={{ left: `${point}%` }}
            />
          </div>
          <div className="mt-1 flex justify-between text-[10px] tabular text-muted-foreground">
            <span>0%</span>
            <span>50%</span>
            <span>100%</span>
          </div>
        </div>

        {!residual.headlineInside && (
          <div className="flex items-start gap-2 rounded-md border border-severity-medium/50 bg-severity-medium/5 px-3 py-2 text-xs text-severity-medium">
            <Info className="mt-0.5 size-3.5 shrink-0" aria-hidden />
            <span>
              The headline ({n(residual.point)}%) sits outside its own interval [
              {n(residual.lower)}–{n(residual.upper)}]. Read the interval, not the point.
            </span>
          </div>
        )}

        {evidence && <EvidenceStrip breakdown={evidence} />}
      </CardContent>
    </Card>
  );
}

function EvidenceStrip({ breakdown }: { breakdown: EvidenceBreakdown }) {
  const parts = (Object.keys(EVIDENCE_META) as (keyof typeof EVIDENCE_META)[])
    .map((key) => ({ key, count: breakdown[key] ?? 0 }))
    .filter((p) => p.count > 0);
  const total = parts.reduce((sum, p) => sum + p.count, 0);
  if (total === 0) return null;

  return (
    <div className="flex flex-col gap-2">
      <span className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
        Evidence composition
      </span>
      <div className="flex h-2 w-full overflow-hidden rounded-full bg-muted">
        {parts.map((p) => {
          const meta = EVIDENCE_META[p.key];
          return (
            <Tooltip key={p.key}>
              <TooltipTrigger asChild>
                <div
                  className={cn('h-full', meta.className.replace('text-', 'bg-').replace('border-', ''))}
                  style={{ width: `${(p.count / total) * 100}%` }}
                  aria-label={`${meta.label}: ${p.count}`}
                />
              </TooltipTrigger>
              <TooltipContent>
                {meta.label}: {p.count} of {total}
              </TooltipContent>
            </Tooltip>
          );
        })}
      </div>
      <div className="flex flex-wrap gap-x-3 gap-y-1">
        {parts.map((p) => (
          <span key={p.key} className="flex items-center gap-1 text-[11px] text-muted-foreground">
            <StatusBadge meta={EVIDENCE_META[p.key]} className="border-0 bg-transparent px-0" />
            <span className="tabular">{p.count}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

/** Fallback band when the backend did not send a severity string. */
function hintBand(pct: number): SeverityBand {
  if (pct >= 80) return 'critical';
  if (pct >= 60) return 'high';
  if (pct >= 40) return 'medium';
  if (pct >= 20) return 'low';
  return 'info';
}
