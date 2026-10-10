'use client';

import * as React from 'react';
import { ChevronRight, AlertTriangle } from 'lucide-react';
import type { Claim } from '@/types/domain';
import { VERDICT_META, EVIDENCE_META } from '@/components/tokens/status';
import { StatusBadge } from '@/components/ui/status-badge';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardFooter, CardHeader } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { EvidenceSpanViewer } from '@/components/claims/evidence-span-viewer';
import { cn } from '@/lib/utils';

export interface ClaimCardProps {
  claim: Claim;
  /** Full source text lookup, forwarded to the span viewer for context. */
  sourceText?: (sourceId: string) => string | undefined;
  onOpenSource?: (sourceId: string) => void;
  /** Start with the evidence panel open. */
  defaultExpanded?: boolean;
  className?: string;
}

function pct(n: number): string {
  return `${Math.round(n * 100)}%`;
}

/** A single atomic claim: verdict, support, and its evidence behind one click. */
export function ClaimCard({
  claim,
  sourceText,
  onOpenSource,
  defaultExpanded = false,
  className,
}: ClaimCardProps) {
  const [expanded, setExpanded] = React.useState(defaultExpanded);
  const verdict = VERDICT_META[claim.verdict];
  const evidence = claim.evidenceStatus ? EVIDENCE_META[claim.evidenceStatus] : null;
  const hasEvidence = claim.spans.length > 0;
  const invented = claim.inventedCitations ?? [];

  return (
    <Card className={cn('overflow-hidden', className)}>
      <CardHeader className="flex-row items-start justify-between gap-3 space-y-0">
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge meta={verdict} />
          {evidence && <StatusBadge meta={evidence} />}
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="tabular cursor-default rounded border px-1.5 py-0.5 text-[11px] text-muted-foreground">
                support {pct(claim.support)}
                {claim.confidenceInterval
                  ? ` [${pct(claim.confidenceInterval[0])}–${pct(claim.confidenceInterval[1])}]`
                  : ''}
              </span>
            </TooltipTrigger>
            <TooltipContent>
              {claim.confidenceInterval
                ? 'Support with its credible interval — never the point alone.'
                : 'Raw entailment support. No interval was computed for this claim.'}
            </TooltipContent>
          </Tooltip>
        </div>
        <span className="tabular shrink-0 text-[11px] text-muted-foreground">{claim.id.slice(0, 10)}</span>
      </CardHeader>

      <CardContent className="flex flex-col gap-3">
        <p className="text-sm leading-relaxed text-foreground">{claim.text}</p>

        {invented.length > 0 && (
          <div className="flex items-start gap-2 rounded-md border border-severity-high/50 bg-severity-high/5 px-3 py-2 text-xs text-severity-high">
            <AlertTriangle className="mt-0.5 size-3.5 shrink-0" aria-hidden />
            <span>
              Cites {invented.length} source{invented.length > 1 ? 's' : ''} that could not be
              resolved: <span className="font-mono">{invented.join(', ')}</span>
            </span>
          </div>
        )}

        {claim.tensions.length > 0 && (
          <ul className="flex flex-col gap-1">
            {claim.tensions.map((t) => (
              <li
                key={t.id}
                className="flex items-start gap-2 rounded-md border border-evidence-contradicts/40 bg-evidence-contradicts/5 px-3 py-2 text-xs"
              >
                <span aria-hidden className="font-mono text-evidence-contradicts">
                  {claim.tensions.some((x) => x.kind === 'contradicts') ? '\u2260' : '!'}
                </span>
                <span className="text-muted-foreground">
                  {t.againstText
                    ? `Tension with “${t.againstText}”`
                    : t.note ?? 'Tension with another claim'}
                </span>
              </li>
            ))}
          </ul>
        )}

        {expanded && (
          <EvidenceSpanViewer
            claim={claim}
            sourceText={sourceText}
            onOpenSource={onOpenSource}
          />
        )}
      </CardContent>

      <CardFooter className="justify-between">
        <div className="flex flex-wrap items-center gap-1.5">
          {claim.sources.length > 0 ? (
            claim.sources.map((s) => (
              <Badge key={s.id} variant="outline" className="font-mono">
                {s.domain ?? s.title ?? s.id}
              </Badge>
            ))
          ) : (
            <span className="text-[11px] text-muted-foreground">No resolved sources</span>
          )}
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => setExpanded((v) => !v)}
          disabled={!hasEvidence}
          aria-expanded={expanded}
        >
          {hasEvidence ? (expanded ? 'Hide evidence' : 'View evidence') : 'No evidence'}
          <ChevronRight
            className={cn('transition-transform', expanded && 'rotate-90')}
            aria-hidden
          />
        </Button>
      </CardFooter>
    </Card>
  );
}
