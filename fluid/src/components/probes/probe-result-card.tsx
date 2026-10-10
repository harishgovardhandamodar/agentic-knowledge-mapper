'use client';

import * as React from 'react';
import { AlertTriangle, CheckCircle2, MinusCircle, ShieldOff } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import type { ProbeResult } from './probe-types';

const VERDICT: Record<string, { glyph: string; label: string; cls: string; Icon: typeof CheckCircle2 }> = {
  control_not_effective: {
    glyph: '✕',
    label: 'Control not effective',
    cls: 'text-evidence-contradicts border-evidence-contradicts',
    Icon: AlertTriangle,
  },
  inconclusive: {
    glyph: '−',
    label: 'Inconclusive',
    cls: 'text-evidence-modality border-evidence-modality',
    Icon: MinusCircle,
  },
  supported_but_unmeasured: {
    glyph: '○',
    label: 'Consistent, not proven',
    cls: 'text-evidence-family border-evidence-family',
    Icon: CheckCircle2,
  },
};

function pct(v: number | null | undefined): string {
  return v == null ? '—' : `${(v * 100).toFixed(1)}%`;
}

/**
 * What the probe measured, and what it did not.
 *
 * A skipped or unreachable run is reported as such rather than as a pass: the
 * whole design of the harness is that "could not tell" never becomes "no
 * problem". When the run completed and was attributed, the updated efficacy
 * provenance is shown so the effect on the next band is visible.
 */
export function ProbeResultCard({ result }: { result: ProbeResult }) {
  if (result.status !== 'completed' || !result.score) {
    return (
      <Card className="border-severity-medium/50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldOff className="size-4 text-severity-medium" aria-hidden />
            {result.status === 'unreachable' ? 'Target unreachable' : 'Nothing was sent'}
          </CardTitle>
          <CardDescription>
            {result.status === 'unreachable'
              ? 'The target did not answer. This is unknown, not a pass.'
              : 'Dry run — the plan was reported without sending anything.'}
          </CardDescription>
        </CardHeader>
        <CardContent className="text-sm">
          <p className="text-muted-foreground">{result.reason}</p>
          {result.would_send && (
            <p className="tabular mt-2 text-xs text-muted-foreground">
              Would have sent {result.would_send.trials} trial
              {result.would_send.trials > 1 ? 's' : ''} to{' '}
              {result.would_send.endpoint_host || 'the configured host'}.
            </p>
          )}
        </CardContent>
      </Card>
    );
  }

  const v = VERDICT[result.score.verdict] ?? {
    glyph: '•',
    label: result.score.verdict,
    cls: 'text-muted-foreground border-border',
    Icon: MinusCircle,
  };
  const Icon = v.Icon;
  const r = result.score.rate;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2">
          <Icon className="size-4" aria-hidden />
          <span className="font-mono text-xs text-muted-foreground">{result.probe_id}</span>
          <span aria-hidden>{v.glyph}</span>
          {v.label}
        </CardTitle>
        <CardDescription>
          {result.attack_class} against {result.endpoint_host}
        </CardDescription>
      </CardHeader>

      <CardContent className="flex flex-col gap-3 text-sm">
        <div className="tabular flex flex-wrap items-baseline gap-4">
          <span className="text-2xl font-semibold">
            {r.successes}/{r.trials}
          </span>
          <span className="text-muted-foreground">{pct(r.rate)}</span>
          <span className="text-muted-foreground">
            interval [{pct(r.lower)}, {pct(r.upper)}]
          </span>
          <Badge variant="outline" className="font-mono text-[10px]">
            {r.method}
          </Badge>
        </div>

        <p className={cn('text-xs', v.cls.split(' ')[0])}>{result.score.conclusion}</p>

        {result.attempts && result.attempts.some((a) => a.excerpt) && (
          <div className="flex flex-col gap-1.5">
            <span className="text-[11px] uppercase tracking-wide text-muted-foreground">
              what came back
            </span>
            {result.attempts
              .filter((a) => a.excerpt)
              .slice(0, 2)
              .map((a) => (
                <p
                  key={a.trial}
                  className="truncate rounded bg-muted/50 px-2 py-1 font-mono text-[11px]"
                  title={a.excerpt}
                >
                  {a.excerpt}
                </p>
              ))}
          </div>
        )}

        {result.efficacy_provenance && result.efficacy_provenance.length > 0 && (
          <div className="flex flex-col gap-1.5 rounded-md border border-primary/40 bg-primary/5 p-3 text-xs">
            <span className="font-medium">Recorded as an efficacy observation</span>
            <ul className="flex flex-col gap-1">
              {result.efficacy_provenance.map((p) => (
                <li key={p.control_id} className="tabular flex items-center gap-2">
                  <span className="font-mono">{p.control_id}</span>
                  <span className="text-muted-foreground">
                    {p.n_held} held / {p.n_breached} breached · n={p.n_observations} ·
                    posterior {p.posterior_mean?.toFixed(3)}
                  </span>
                  {p.validated && <Badge variant="outline">measured</Badge>}
                </li>
              ))}
            </ul>
            <span className="text-[11px] text-muted-foreground">
              One trial moves the mean slightly and barely narrows the interval. Repeated
              outcomes are what tighten a control&apos;s band.
            </span>
          </div>
        )}

        <p className="text-[11px] text-muted-foreground">
          {result.score.recommended_next_trials} trials needed before this can conclude
          anything. {result.score.note}
        </p>
      </CardContent>
    </Card>
  );
}