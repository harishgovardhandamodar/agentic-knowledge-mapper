'use client';

import { useHealth } from '@/lib/api/queries';
import type { LlmHealth } from '@/lib/api/schemas';

/** host[:port] of a base URL, for the warning text. */
export function gatewayHost(url?: string | null): string {
  if (!url) return 'unknown';
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

/**
 * Presentational warning: renders nothing unless the preferred gateway is
 * unreachable and a fallback is answering. Split from the fetching component so
 * the branch is testable without a query client.
 *
 * Axiom is always tried first (`app.llm._bases` puts it at the head of the
 * chain), so a fallback being active means the preferred gateway was down for
 * this call, not that another backend was preferred.
 */
export function LlmFallbackNotice({ llm }: { llm?: LlmHealth }) {
  if (!llm?.fallback_active) return null;
  const preferred = gatewayHost(llm.preferred_url || llm.base_url);
  const served = gatewayHost(llm.served_by || llm.fallback_url);
  return (
    <div
      role="status"
      aria-live="polite"
      data-testid="llm-fallback-banner"
      className="flex items-start gap-2 border-b border-amber-500/40 bg-amber-500/10 px-4 py-2 text-xs text-amber-800 dark:text-amber-200"
    >
      <span aria-hidden className="mt-px">
        ⚠
      </span>
      <p>
        <strong className="font-semibold">LLM fallback in use.</strong> Requests are
        being served by <code>{served}</code> because the preferred Axiom gateway{' '}
        <code>{preferred}</code> is unreachable. Axiom is always tried first; this
        clears automatically once it responds.
      </p>
    </div>
  );
}

/** App-wide banner driven by the health poll. */
export function LlmFallbackBanner() {
  const { data } = useHealth();
  return <LlmFallbackNotice llm={data?.llm} />;
}
