'use client';

import * as React from 'react';
import { ExternalLink, Quote } from 'lucide-react';
import type { Claim, ClaimSpan } from '@/types/domain';
import { EVIDENCE_META } from '@/components/tokens/status';
import { StatusBadge } from '@/components/ui/status-badge';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

export interface EvidenceSpanViewerProps {
  claim: Claim;
  /**
   * Full text of each cited source keyed by source id. When present, the viewer
   * renders the span in context with the quote highlighted; otherwise it shows
   * the bare quote. The brief's promise — two clicks from a residual to the
   * source sentence — lands here.
   */
  sourceText?: (sourceId: string) => string | undefined;
  contextChars?: number;
  onOpenSource?: (sourceId: string) => void;
  className?: string;
}

interface RenderedSpan {
  id: string; // `${sourceId}:${start}`
  sourceId: string;
  span: ClaimSpan;
  before: string;
  match: string;
  after: string;
  hasOffsets: boolean;
}

function buildSpans(
  claim: Claim,
  sourceText: (id: string) => string | undefined,
  contextChars: number,
): RenderedSpan[] {
  return claim.spans.map((span, i) => {
    const text = sourceText(span.sourceId);
    const start = span.start ?? null;
    const end = span.end ?? null;
    const hasOffsets =
      typeof start === 'number' && typeof end === 'number' && text !== undefined;
    if (hasOffsets && text !== undefined) {
      const a = Math.max(0, start - contextChars);
      const b = Math.min(text.length, end + contextChars);
      return {
        id: `${span.sourceId}:${start}`,
        sourceId: span.sourceId,
        span,
        before: text.slice(a, start),
        match: text.slice(start, end),
        after: text.slice(end, b),
        hasOffsets: true,
      };
    }
    return {
      id: `${span.sourceId}:${i}`,
      sourceId: span.sourceId,
      span,
      before: '',
      match: span.quote,
      after: '',
      hasOffsets: false,
    };
  });
}

const NO_SOURCE = (): string | undefined => undefined;

/** Renders the evidence spans behind a claim, in source context. */
export function EvidenceSpanViewer({
  claim,
  sourceText,
  contextChars = 120,
  onOpenSource,
  className,
}: EvidenceSpanViewerProps) {
  const lookup = sourceText ?? NO_SOURCE;
  const spans = React.useMemo(
    () => buildSpans(claim, lookup, contextChars),
    [claim, lookup, contextChars],
  );

  if (spans.length === 0) {
    return (
      <div
        className={cn(
          'rounded-md border border-dashed p-4 text-sm text-muted-foreground',
          className,
        )}
      >
        No evidence span was found for this claim.
      </div>
    );
  }

  return (
    <ul className={cn('flex flex-col gap-3', className)}>
      {spans.map(({ id, sourceId, span, before, match, after, hasOffsets }) => {
        const source = claim.sources.find((s) => s.id === sourceId);
        const meta = span.status ? EVIDENCE_META[span.status] : null;
        return (
          <li key={id} className="rounded-md border bg-muted/30 p-3">
            <div className="mb-2 flex items-center justify-between gap-2">
              <div className="flex min-w-0 items-center gap-2">
                <Quote className="size-3.5 shrink-0 text-muted-foreground" aria-hidden />
                <span className="truncate text-xs font-medium">
                  {source?.title ?? sourceId}
                </span>
                {span.verifiedBy && (
                  <Badge variant="muted" className="font-mono">
                    {span.verifiedBy}
                  </Badge>
                )}
              </div>
              <div className="flex items-center gap-2">
                {meta && <StatusBadge meta={meta} />}
                {onOpenSource && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => onOpenSource(sourceId)}
                    className="h-7 px-2"
                  >
                    <ExternalLink className="size-3.5" />
                    Source
                  </Button>
                )}
              </div>
            </div>

            <blockquote className="rounded border-l-2 border-primary/60 bg-background/60 px-3 py-2 font-mono text-[13px] leading-relaxed text-foreground/90">
              {hasOffsets ? (
                <span>
                  {before}
                  <mark className="rounded-sm bg-primary/20 px-0.5 text-foreground">
                    {match}
                  </mark>
                  {after}
                </span>
              ) : (
                <span>
                  <mark className="rounded-sm bg-primary/20 px-0.5 text-foreground">
                    {match}
                  </mark>
                </span>
              )}
            </blockquote>

            {hasOffsets && (
              <div className="mt-2 text-[11px] tabular text-muted-foreground">
                offset {span.start}–{span.end}
              </div>
            )}
          </li>
        );
      })}
    </ul>
  );
}
