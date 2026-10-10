import { FlaskConical } from 'lucide-react';
import { cn } from '@/lib/utils';

/**
 * Marks a surface that is rendering fixtures because the backing endpoint is
 * not wired yet. Honesty about sample data beats pretending it is live.
 */
export function SampleDataBanner({ note, className }: { note?: string; className?: string }) {
  return (
    <div
      className={cn(
        'mb-4 flex items-start gap-2 rounded-md border border-severity-medium/40 bg-severity-medium/5 px-3 py-2 text-xs text-severity-medium',
        className,
      )}
      role="status"
    >
      <FlaskConical className="mt-0.5 size-3.5 shrink-0" aria-hidden />
      <span>
        Sample data — {note ?? 'this endpoint is not wired in the foundation slice yet.'}
      </span>
    </div>
  );
}
