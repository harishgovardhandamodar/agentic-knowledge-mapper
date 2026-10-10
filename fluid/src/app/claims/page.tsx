'use client';

import * as React from 'react';
import { PageHeader } from '@/components/shell/page-header';
import { SampleDataBanner } from '@/components/shell/sample-banner';
import { ClaimCard } from '@/components/claims/claim-card';
import { Badge } from '@/components/ui/badge';
import { SAMPLE_CLAIMS, SAMPLE_SOURCE_TEXT } from '@/lib/fixtures';
import { CLAIM_VERDICTS, type Claim, type ClaimVerdict } from '@/types/domain';
import { VERDICT_META } from '@/components/tokens/status';
import { cn } from '@/lib/utils';

type Filter = 'all' | ClaimVerdict;

export default function ClaimsPage() {
  const [filter, setFilter] = React.useState<Filter>('all');
  const claims = SAMPLE_CLAIMS;
  const shown = filter === 'all' ? claims : claims.filter((c) => c.verdict === filter);

  const counts = React.useMemo(() => {
    const c: Record<string, number> = { all: claims.length };
    for (const v of CLAIM_VERDICTS) c[v] = claims.filter((x) => x.verdict === v).length;
    return c;
  }, [claims]);

  return (
    <div>
      <PageHeader
        title="Claims"
        description="Every atomic claim, its verdict and support interval, and the source span that grounds it."
      />
      <SampleDataBanner note="the claim-verification endpoint is not exposed over HTTP yet, so these are representative claims." />

      <div className="mb-4 flex flex-wrap items-center gap-1.5" role="tablist" aria-label="Filter by verdict">
        <FilterChip active={filter === 'all'} onClick={() => setFilter('all')} label="All" count={counts.all ?? 0} />
        {CLAIM_VERDICTS.map((v) => (
          <FilterChip
            key={v}
            active={filter === v}
            onClick={() => setFilter(v)}
            label={VERDICT_META[v].label}
            count={counts[v] ?? 0}
          />
        ))}
      </div>

      <div className="flex flex-col gap-3">
        {shown.map((claim: Claim) => (
          <ClaimCard
            key={claim.id}
            claim={claim}
            sourceText={(id) => SAMPLE_SOURCE_TEXT[id]}
          />
        ))}
        {shown.length === 0 && (
          <p className="rounded-md border border-dashed p-6 text-center text-sm text-muted-foreground">
            No {filter} claims.
          </p>
        )}
      </div>
    </div>
  );
}

function FilterChip({
  active,
  onClick,
  label,
  count,
}: {
  active: boolean;
  onClick: () => void;
  label: string;
  count: number;
}) {
  return (
    <button
      type="button"
      role="tab"
      aria-selected={active}
      onClick={onClick}
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs transition-colors',
        active ? 'border-primary/60 bg-primary/10 text-foreground' : 'text-muted-foreground hover:bg-accent/50',
      )}
    >
      {label}
      <Badge variant="muted" className="px-1.5">
        {count}
      </Badge>
    </button>
  );
}
