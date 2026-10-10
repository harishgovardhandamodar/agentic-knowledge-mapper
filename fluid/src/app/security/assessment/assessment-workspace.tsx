'use client';

import * as React from 'react';
import { useSearchParams } from 'next/navigation';
import { useAssessment, useAssessmentAnalysis, useAssessments } from '@/lib/api/queries';
import { useUi } from '@/lib/stores/ui';
import { getParsed } from '@/lib/api/client';
import { z } from 'zod';
import { toResidualInterval } from '@/lib/api/adapters';
import { PageHeader } from '@/components/shell/page-header';
import { ResidualDisplay } from '@/components/security/residual-display';
import {
  normalizeSeverity,
  SEVERITY_META,
} from '@/components/tokens/status';
import { StatusBadge } from '@/components/ui/status-badge';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import type { ThreatRow } from '@/lib/api/schemas';

export function AssessmentWorkspace() {
  const params = useSearchParams();
  const idParam = params.get('id');
  const id = idParam ? Number(idParam) : NaN;

  const { data: assessment, isLoading, isError } = useAssessment(Number.isFinite(id) ? id : null);
  const { data: analysis } = useAssessmentAnalysis(Number.isFinite(id) ? id : null);

  if (!Number.isFinite(id)) {
    return (
      <p className="rounded-md border border-dashed p-6 text-center text-sm text-muted-foreground">
        No assessment selected. Open one from the Security workspace.
      </p>
    );
  }

  return (
    <div>
      <PageHeader
        title={assessment ? `Assessment #${assessment.id}` : `Assessment #${id}`}
        description={assessment?.product_name ?? assessment?.exposure ?? undefined}
      />

      {isError && (
        <p className="rounded-md border border-destructive/40 bg-destructive/5 p-4 text-sm text-destructive">
          Could not load assessment #{id}.
        </p>
      )}

      {isLoading && <Skeleton className="h-52 w-full" />}

      {assessment && (
        <div className="flex flex-col gap-6">
          <div className="grid gap-4 lg:grid-cols-2">
            {analysis?.uncertainty ? (
              <ResidualDisplay
                residual={toResidualInterval(analysis.uncertainty)}
                label="Residual risk"
                subtitle="Headline with its Monte-Carlo credible interval."
              />
            ) : (
              <ResidualDisplay
                residual={null}
                pointWithoutInterval={assessment.residual_pct ?? null}
                label="Residual risk"
              />
            )}

            <div className="grid gap-4">
              <PrivacyPanel privacy={analysis?.privacy ?? assessment.privacy ?? null} />
              <ReproPanel fingerprint={analysis?.repro?.fingerprint ?? assessment.repro?.fingerprint ?? null} />
            </div>
          </div>

          <ThreatTable threats={assessment.scoring?.threats ?? assessment.threats ?? []} />

          <JudgmentsCard judgments={assessment.judgments ?? []} />

          <CompareCard currentId={assessment.id} />
        </div>
      )}
    </div>
  );
}

const zCompareVerdict = z
  .object({
    verdict: z.string(),
    direction: z.string().optional(),
    reason: z.string().optional(),
    overlap_pct_points: z.number().optional(),
    overlap_share: z.number().optional(),
  })
  .passthrough();

const zCompare = z
  .object({
    a: z.object({ id: z.number() }).passthrough(),
    b: z.object({ id: z.number() }).passthrough(),
    residual_pct: z
      .object({
        a: z.number().nullable().optional(),
        b: z.number().nullable().optional(),
        delta: z.number().nullable().optional(),
      })
      .passthrough()
      .optional(),
    verdict: zCompareVerdict.optional(),
  })
  .passthrough();

/**
 * Who set the weights behind this score.
 *
 * Applicability is an analyst assignment, not a measurement. Without authorship
 * it can never be calibrated; with it, a later reviewer can ask "whose 0.8 was
 * this" and get an answer. Legacy rows report an empty list rather than an
 * unattributed one.
 */
function JudgmentsCard({ judgments }: { judgments: { kind?: string; subject?: string; value?: number; author?: string; rationale?: string }[] }) {
  if (judgments.length === 0) return null;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">Judgments</CardTitle>
        <CardDescription>
          Who set the weights behind this score. Unsigned weights stay unsigned here
          rather than gaining an author retroactively.
        </CardDescription>
      </CardHeader>
      <CardContent className="overflow-x-auto p-0">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b text-left text-xs uppercase tracking-wide text-muted-foreground">
              <th className="px-4 py-2 font-medium">What</th>
              <th className="px-4 py-2 font-medium">Value</th>
              <th className="px-4 py-2 font-medium">Author</th>
              <th className="px-4 py-2 font-medium">Rationale</th>
            </tr>
          </thead>
          <tbody>
            {judgments.map((j, i) => (
              <tr key={`${j.kind}-${j.subject}-${i}`} className="border-b last:border-0 hover:bg-accent/30">
                <td className="px-4 py-2 font-mono text-xs">
                  {j.kind}:{j.subject}
                </td>
                <td className="tabular px-4 py-2 text-right">{j.value}</td>
                <td className="px-4 py-2 font-mono text-xs">{j.author ?? 'unknown'}</td>
                <td className="px-4 py-2 text-xs text-muted-foreground">{j.rationale || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </CardContent>
    </Card>
  );
}

/**
 * Do two assessments differ by more than their intervals allow?
 *
 * Two point estimates invite subtraction; the verdict asks first whether the
 * intervals can be told apart at all. Overlapping bands render as
 * "indistinguishable" rather than as a delta begging to be quoted.
 */
function CompareCard({ currentId }: { currentId: number }) {
  const { investigationId } = useUi();
  const { data: assessments } = useAssessments(investigationId);
  const [otherId, setOtherId] = React.useState<number | null>(null);
  const [result, setResult] = React.useState<z.infer<typeof zCompare> | null>(null);
  const [loading, setLoading] = React.useState(false);

  const options = (assessments ?? []).filter((a) => a.id !== currentId);

  const compare = async (oid: number) => {
    setOtherId(oid);
    setLoading(true);
    try {
      setResult(await getParsed(zCompare, `/security/assessments/${currentId}/compare/${oid}`));
    } catch {
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  const verdict = result?.verdict;
  const delta = result?.residual_pct?.delta;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">Compare</CardTitle>
        <CardDescription>
          Against another assessment of this investigation. Same method only — a
          confidence next to a residual is refused, not averaged.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <div className="flex flex-wrap gap-1.5">
          {options.slice(0, 10).map((a) => (
            <button
              key={a.id}
              onClick={() => compare(a.id)}
              className={`rounded-full border px-2.5 py-0.5 text-xs transition-colors ${
                otherId === a.id ? 'border-primary bg-primary/10' : 'hover:bg-accent/50'
              }`}
            >
              #{a.id} {a.product_name ?? ''}
            </button>
          ))}
          {options.length === 0 && (
            <span className="text-xs text-muted-foreground">No other assessments to compare with.</span>
          )}
        </div>

        {loading && <Skeleton className="h-16 w-full" />}

        {verdict && (
          <div className="rounded-md border p-3 text-sm">
            <div className="flex flex-wrap items-baseline gap-2">
              <Badge
                variant={verdict.verdict === 'distinguishable' ? 'default' : 'muted'}
              >
                {verdict.verdict === 'distinguishable'
                  ? `distinguishable (${verdict.direction})`
                  : verdict.verdict === 'indistinguishable'
                    ? 'indistinguishable'
                    : 'unmeasured'}
              </Badge>
              {delta != null && (
                <span className="tabular text-xs text-muted-foreground">
                  headline delta {delta > 0 ? '+' : ''}{delta}
                </span>
              )}
            </div>
            {verdict.reason && (
              <p className="mt-1.5 text-xs text-muted-foreground">{verdict.reason}</p>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function ThreatTable({ threats }: { threats: ThreatRow[] }) {
  if (threats.length === 0) return null;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Threats</CardTitle>
        <CardDescription>{threats.length} threats scored for this assessment.</CardDescription>
      </CardHeader>
      <CardContent className="overflow-x-auto p-0">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b text-left text-xs uppercase tracking-wide text-muted-foreground">
              <th className="px-4 py-2 font-medium">ID</th>
              <th className="px-4 py-2 font-medium">Threat</th>
              <th className="px-4 py-2 text-right font-medium">L</th>
              <th className="px-4 py-2 text-right font-medium">I</th>
              <th className="px-4 py-2 text-right font-medium">Residual</th>
              <th className="px-4 py-2 text-right font-medium">Coverage</th>
              <th className="px-4 py-2 font-medium">Severity</th>
            </tr>
          </thead>
          <tbody>
            {threats.map((t) => {
              const sev = normalizeSeverity(t.residual_severity);
              return (
                <tr key={t.id} className="border-b last:border-0 hover:bg-accent/30">
                  <td className="px-4 py-2 font-mono text-xs">{t.id}</td>
                  <td className="px-4 py-2">{t.title ?? t.stride ?? t.id}</td>
                  <td className="tabular px-4 py-2 text-right">{t.likelihood}</td>
                  <td className="tabular px-4 py-2 text-right">{t.impact}</td>
                  <td className="tabular px-4 py-2 text-right">
                    {t.residual_score != null ? t.residual_score : '—'}
                  </td>
                  <td className="tabular px-4 py-2 text-right">
                    {t.coverage != null ? `${Math.round(t.coverage * 100)}%` : '—'}
                  </td>
                  <td className="px-4 py-2">{sev ? <StatusBadge meta={SEVERITY_META[sev]} /> : '—'}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </CardContent>
    </Card>
  );
}

function PrivacyPanel({ privacy }: { privacy: import('@/lib/api/schemas').PrivacyBudget | null }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">Privacy budget</CardTitle>
      </CardHeader>
      <CardContent className="text-sm">
        {privacy ? (
          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">External spend</span>
              <span className="tabular">
                {privacy.spend} / {privacy.max_spend}
              </span>
            </div>
            <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
              <div
                className="h-full bg-primary"
                style={{
                  width: `${Math.min(100, (privacy.spend / Math.max(1, privacy.max_spend)) * 100)}%`,
                }}
              />
            </div>
            <div className="flex flex-wrap gap-1.5 pt-1">
              <Badge variant="muted">{privacy.queries} queries</Badge>
              <Badge variant="muted">{privacy.distinct_domains} domains</Badge>
              <Badge variant={privacy.exhausted ? 'default' : 'muted'}>
                {privacy.exhausted ? 'exhausted' : `${privacy.remaining} left`}
              </Badge>
            </div>
          </div>
        ) : (
          <p className="text-muted-foreground">
            No research recorded — reach is unknown, not zero.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

function ReproPanel({ fingerprint }: { fingerprint: string | null }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">Reproducibility</CardTitle>
      </CardHeader>
      <CardContent className="text-sm">
        {fingerprint ? (
          <div className="flex flex-col gap-1">
            <span className="text-muted-foreground">Manifest fingerprint</span>
            <code className="break-all rounded bg-muted px-2 py-1 font-mono text-xs">
              {fingerprint}
            </code>
          </div>
        ) : (
          <p className="text-muted-foreground">No manifest for this assessment.</p>
        )}
      </CardContent>
    </Card>
  );
}
