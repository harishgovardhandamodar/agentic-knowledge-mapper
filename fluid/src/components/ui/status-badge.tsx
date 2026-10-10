import * as React from 'react';
import { cn } from '@/lib/utils';
import type { StatusMeta } from '@/components/tokens/status';

export interface StatusBadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  meta: StatusMeta;
  /** Show the glyph as well as the label (default) — colour is redundant. */
  showGlyph?: boolean;
}

/**
 * Renders a {@link StatusMeta} as a pill. Glyph + label + colour, always, so
 * the status is legible in greyscale and to a colour-blind reader.
 */
export function StatusBadge({ meta, showGlyph = true, className, ...props }: StatusBadgeProps) {
  return (
    <span
      title={meta.description}
      aria-label={`${meta.label}: ${meta.description}`}
      className={cn(
        'inline-flex items-center gap-1 rounded-full border bg-transparent px-2 py-0.5 text-[11px] font-medium leading-none',
        meta.className,
        className,
      )}
      {...props}
    >
      {showGlyph && (
        <span aria-hidden className="font-mono text-[10px] leading-none">
          {meta.glyph}
        </span>
      )}
      {meta.label}
    </span>
  );
}
