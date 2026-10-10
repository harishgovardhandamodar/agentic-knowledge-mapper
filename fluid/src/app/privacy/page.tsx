'use client';

import { useAssessmentAnalysis, useAssessments } from '@/lib/api/queries';
import { useUi } from '@/lib/stores/ui';
import { PageHeader } from '@/components/shell/page-header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';

export default function PrivacyPage() {
  const { investigationId, assessmentId } = useUi();
  const { data: assessments } = useAssessments(investigationId);
  const id = assessmentId ?? assessments?.[0]?.id ?? null;
  const { data: analysis, isLoading } = useAssessmentAnalysis(id);
  const privacy = analysis?.privacy ?? null;

  return (
    <div>
      <PageHeader
        title="Privacy"
        description="How far the investigation's research reached beyond the corpus, and the commitments that bound it."
      />
      {isLoading && <Skeleton className="h-52 w-full" />}

      {!isLoading && (
        <div className="grid gap-4 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">External-reach budget</CardTitle>
              <CardDescription>
                Each external request spends budget; exhaustion forces degradation or refusal.
              </CardDescription>
            </CardHeader>
            <CardContent className="text-sm">
              {privacy ? (
                <div className="flex flex-col gap-3">
                  <div className="flex items-baseline gap-2">
                    <span className="tabular text-3xl font-semibold">{privacy.remaining}</span>
                    <span className="text-muted-foreground">of {privacy.max_spend} remaining</span>
                  </div>
                  <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
                    <div
                      className="h-full bg-primary"
                      style={{ width: `${Math.min(100, (privacy.spend / Math.max(1, privacy.max_spend)) * 100)}%` }}
                    />
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    <Badge variant="muted">{privacy.queries} queries</Badge>
                    <Badge variant="muted">{privacy.external_pages} external pages</Badge>
                    <Badge variant="muted">{privacy.novel_pages} novel</Badge>
                    <Badge variant="muted">{privacy.distinct_domains} domains</Badge>
                    <Badge variant={privacy.advice === 'ok' ? 'muted' : 'default'}>
                      {privacy.advice}
                    </Badge>
                  </div>
                  {privacy.domains && privacy.domains.length > 0 && (
                    <div className="flex flex-wrap gap-1 pt-1">
                      {privacy.domains.slice(0, 12).map((d) => (
                        <Badge key={d} variant="outline" className="font-mono">
                          {d}
                        </Badge>
                      ))}
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-muted-foreground">
                  No research was recorded for this assessment — reach is unknown, not zero.
                </p>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-sm">What the budget protects</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-2 text-sm text-muted-foreground">
              <p>
                The budget caps how many external pages a run may fetch, so a research agent
                cannot quietly enumerate a subject across the web.
              </p>
              <p>
                Membership inference canaries and erasure commitments are computed by the
                engine; their reports surface on the assessment once the privacy endpoints are
                wired into this slice.
              </p>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
