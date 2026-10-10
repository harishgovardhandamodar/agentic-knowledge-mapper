'use client';

'use client';

import { PageHeader } from '@/components/shell/page-header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { StatusBadge } from '@/components/ui/status-badge';
import { ResidualDisplay } from '@/components/security/residual-display';
import { ClaimCard } from '@/components/claims/claim-card';
import { EvidenceSpanViewer } from '@/components/claims/evidence-span-viewer';
import {
  EVIDENCE_META,
  REVIEW_META,
  SEVERITY_META,
  VERDICT_META,
} from '@/components/tokens/status';
import {
  SAMPLE_CLAIMS,
  SAMPLE_EVIDENCE,
  SAMPLE_RESIDUAL,
  SAMPLE_RESIDUAL_OUTSIDE,
  SAMPLE_SOURCE_TEXT,
} from '@/lib/fixtures';

export default function DesignPage() {
  return (
    <div className="flex flex-col gap-8">
      <PageHeader
        title="Design system"
        description="Every status carries a glyph, a label and a colour — colour is never the only channel."
      />

      <section className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <TokenGroup title="Claim verdicts" items={Object.values(VERDICT_META)} />
        <TokenGroup title="Evidence" items={Object.values(EVIDENCE_META)} />
        <TokenGroup title="Severity" items={Object.values(SEVERITY_META)} />
        <TokenGroup title="Review" items={Object.values(REVIEW_META)} />
      </section>

      <section className="grid gap-4 lg:grid-cols-2">
        <ResidualDisplay residual={SAMPLE_RESIDUAL} evidence={SAMPLE_EVIDENCE} label="Residual (headline inside)" />
        <ResidualDisplay residual={SAMPLE_RESIDUAL_OUTSIDE} label="Residual (headline outside)" />
        <ResidualDisplay residual={null} pointWithoutInterval={42} label="Residual (no interval)" />
      </section>

      <section className="grid gap-4 lg:grid-cols-2">
        <div className="flex flex-col gap-4">
          {SAMPLE_CLAIMS.map((c) => (
            <ClaimCard key={c.id} claim={c} sourceText={(id) => SAMPLE_SOURCE_TEXT[id]} />
          ))}
        </div>
        <div className="flex flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Evidence span viewer (standalone)</CardTitle>
            </CardHeader>
            <CardContent>
              <EvidenceSpanViewer
                claim={SAMPLE_CLAIMS[0]!}
                sourceText={(id) => SAMPLE_SOURCE_TEXT[id]}
              />
            </CardContent>
          </Card>
        </div>
      </section>
    </div>
  );
}

function TokenGroup({ title, items }: { title: string; items: { label: string; description: string; glyph: string; className: string }[] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-xs uppercase tracking-wide text-muted-foreground">{title}</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-wrap gap-1.5">
        {items.map((m) => (
          <StatusBadge key={m.label} meta={m} />
        ))}
      </CardContent>
    </Card>
  );
}
