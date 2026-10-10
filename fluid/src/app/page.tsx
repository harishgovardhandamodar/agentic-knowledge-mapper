'use client';

import Link from 'next/link';
import { ArrowRight, FileText, Shield, Lock } from 'lucide-react';
import { useAssessmentAnalysis, useAssessments, useInvestigation } from '@/lib/api/queries';
import { useUi } from '@/lib/stores/ui';
import { PageHeader } from '@/components/shell/page-header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { ResidualDisplay } from '@/components/security/residual-display';
import { SAMPLE_RESIDUAL, SAMPLE_EVIDENCE } from '@/lib/fixtures';
import { toResidualInterval } from '@/lib/api/adapters';

const WORKSPACES = [
  {
    href: '/claims',
    icon: FileText,
    title: 'Claims',
    body: 'Read every atomic claim with its verdict, support interval and the source span behind it.',
  },
  {
    href: '/security',
    icon: Shield,
    title: 'Security',
    body: 'Threat assessments where every residual is shown with its credible interval.',
  },
  {
    href: '/privacy',
    icon: Lock,
    title: 'Privacy',
    body: 'External-reach budget, extraction resistance and erasure commitments.',
  },
];

export default function OverviewPage() {
  const { investigationId, assessmentId, setAssessment } = useUi();
  const { data: inv, isLoading: invLoading } = useInvestigation(investigationId);
  const { data: assessments } = useAssessments(investigationId);
  const latestId = assessmentId ?? assessments?.[0]?.id ?? null;
  const { data: analysis } = useAssessmentAnalysis(latestId);

  return (
    <div>
      <PageHeader
        title={invLoading ? 'Overview' : (inv?.title ?? 'Overview')}
        description={
          inv?.keywords ??
          'The shell scopes every workspace to the investigation selected above.'
        }
      />

      <section className="mb-8 grid gap-4 sm:grid-cols-3">
        {WORKSPACES.map(({ href, icon: Icon, title, body }) => (
          <Link key={href} href={href} className="group">
            <Card className="h-full transition-colors group-hover:border-primary/50">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Icon className="size-4 text-muted-foreground" aria-hidden />
                  {title}
                  <ArrowRight
                    className="ml-auto size-4 -translate-x-1 text-muted-foreground opacity-0 transition-all group-hover:translate-x-0 group-hover:opacity-100"
                    aria-hidden
                  />
                </CardTitle>
                <CardDescription>{body}</CardDescription>
              </CardHeader>
            </Card>
          </Link>
        ))}
      </section>

      <section className="grid gap-4 lg:grid-cols-2">
        {analysis?.uncertainty ? (
          <ResidualDisplay
            residual={toResidualInterval(analysis.uncertainty)}
            label="Residual risk"
            subtitle="Live from the latest assessment's uncertainty band."
          />
        ) : (
          <ResidualDisplay
            residual={SAMPLE_RESIDUAL}
            evidence={SAMPLE_EVIDENCE}
            label="Residual risk (sample)"
            subtitle="Shown until an assessment with an uncertainty band exists."
          />
        )}

        <Card>
          <CardHeader>
            <CardTitle>Assessments</CardTitle>
            <CardDescription>
              {assessments?.length
                ? `${assessments.length} assessment${assessments.length > 1 ? 's' : ''} for this investigation.`
                : 'No assessments yet for this investigation.'}
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-1.5 text-sm">
            {(assessments ?? []).slice(0, 6).map((a) => (
              <button
                key={a.id}
                type="button"
                onClick={() => setAssessment(a.id)}
                className="flex items-center justify-between rounded-md border px-3 py-2 text-left transition-colors hover:bg-accent/50"
              >
                <span className="truncate">
                  #{a.id} {a.product_name ?? ''}
                </span>
                <span className="tabular shrink-0 text-xs text-muted-foreground">
                  {a.residual_pct != null ? `residual ${a.residual_pct}%` : 'no residual'}
                </span>
              </button>
            ))}
            {(!assessments || assessments.length === 0) && (
              <Link href="/security" className="text-primary hover:underline">
                Go to Security →
              </Link>
            )}
          </CardContent>
        </Card>
      </section>
    </div>
  );
}
