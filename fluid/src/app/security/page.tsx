'use client';

import Link from 'next/link';
import { ArrowRight } from 'lucide-react';
import { useAssessments } from '@/lib/api/queries';
import { useUi } from '@/lib/stores/ui';
import { PageHeader } from '@/components/shell/page-header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { normalizeSeverity, SEVERITY_META } from '@/components/tokens/status';
import { StatusBadge } from '@/components/ui/status-badge';

export default function SecurityPage() {
  const { investigationId } = useUi();
  const { data, isLoading, isError } = useAssessments(investigationId);

  return (
    <div>
      <PageHeader
        title="Security"
        description={
          investigationId
            ? 'Threat assessments for the selected investigation.'
            : 'Select an investigation to see its threat assessments.'
        }
      />

      {isError && (
        <p className="rounded-md border border-destructive/40 bg-destructive/5 p-4 text-sm text-destructive">
          Could not load assessments. Check that the backend is reachable.
        </p>
      )}

      {isLoading && (
        <div className="flex flex-col gap-3">
          <Skeleton className="h-24 w-full" />
          <Skeleton className="h-24 w-full" />
        </div>
      )}

      {!isLoading && data?.length === 0 && (
        <p className="rounded-md border border-dashed p-6 text-center text-sm text-muted-foreground">
          No assessments for this investigation yet.
        </p>
      )}

      <div className="flex flex-col gap-3">
        {(data ?? []).map((a) => {
          const sev = normalizeSeverity(
            a.threats?.find((t) => t.residual_severity)?.residual_severity,
          );
          return (
            <Link key={a.id} href={`/security/assessment?id=${a.id}`} className="group">
              <Card className="transition-colors group-hover:border-primary/50">
                <CardHeader className="flex-row items-center justify-between gap-3 space-y-0">
                  <div className="min-w-0">
                    <CardTitle className="flex items-center gap-2">
                      Assessment #{a.id}
                      {a.product_name && (
                        <span className="font-normal text-muted-foreground">· {a.product_name}</span>
                      )}
                    </CardTitle>
                    <CardDescription>
                      {a.exposure ? `Exposure: ${a.exposure}` : 'No exposure tier recorded'}
                    </CardDescription>
                  </div>
                  <div className="flex items-center gap-3">
                    {a.residual_pct != null && (
                      <span className="tabular text-sm text-muted-foreground">
                        residual {a.residual_pct}%
                      </span>
                    )}
                    {sev && <StatusBadge meta={SEVERITY_META[sev]} />}
                    <ArrowRight className="size-4 text-muted-foreground" aria-hidden />
                  </div>
                </CardHeader>
                {a.threats && a.threats.length > 0 && (
                  <CardContent className="flex flex-wrap gap-1.5">
                    <Badge variant="muted">{a.threats.length} threats</Badge>
                  </CardContent>
                )}
              </Card>
            </Link>
          );
        })}
      </div>
    </div>
  );
}
