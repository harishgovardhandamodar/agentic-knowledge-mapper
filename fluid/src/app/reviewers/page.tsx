'use client';

import * as React from 'react';
import { Download, Users, Scale, Database } from 'lucide-react';
import { getParsed } from '@/lib/api/client';
import { z } from 'zod';
import { useUi } from '@/lib/stores/ui';
import { PageHeader } from '@/components/shell/page-header';
import { SampleDataBanner } from '@/components/shell/sample-banner';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';

const zDisagreements = z
  .object({
    assessment_id: z.number(),
    conflicts: z.array(
      z
        .object({
          artifact_id: z.number(),
          votes: z.record(z.string()),
          n_reviewers: z.number(),
          majority: z.string(),
        })
        .passthrough(),
    ),
    stats: z
      .object({
        n_reviewers: z.number(),
        reviewers: z.array(z.string()),
        n_artifacts_judged: z.number(),
        n_conflicts: z.number(),
        per_reviewer: z.record(
          z.object({ agree_with_majority: z.number().nullable(), n_judged: z.number() }),
        ),
        kappa: z.number().nullable().optional(),
        krippendorff_alpha: z.number().nullable().optional(),
        gwet_ac1: z.number().nullable().optional(),
        note: z.string().optional(),
      })
      .passthrough(),
  })
  .passthrough();

const zDatasetMeta = z
  .object({
    investigation_id: z.number(),
    dataset_version: z.string(),
    counts: z.record(z.number()),
    tables: z.record(z.array(z.record(z.unknown()))),
    manifest: z.object({ fingerprint: z.string() }).passthrough(),
    columns: z.record(z.array(z.string())),
    note: z.string().optional(),
  })
  .passthrough();

/**
 * The group behind the verdicts.
 *
 * Two panels because they answer different questions. *Reviewers* says who
 * judged what and how often each agrees with the majority -- the input to
 * every inter-rater statistic. *Dataset* exports the whole investigation as
 * tidy tables, because everything a group might want to do in R or Python is
 * currently impossible without scraping the API row by row.
 */
export default function ReviewersPage() {
  const { investigationId, assessmentId } = useUi();
  const [dis, setDis] = React.useState<z.infer<typeof zDisagreements> | null>(null);
  const [meta, setMeta] = React.useState<z.infer<typeof zDatasetMeta> | null>(null);
  const [downloading, setDownloading] = React.useState(false);

  React.useEffect(() => {
    setDis(null);
    if (!assessmentId) return;
    let cancelled = false;
    getParsed(zDisagreements, `/security/assessments/${assessmentId}/reviews/disagreements`)
      .then((d) => !cancelled && setDis(d))
      .catch(() => !cancelled && setDis(null));
    return () => {
      cancelled = true;
    };
  }, [assessmentId]);

  React.useEffect(() => {
    setMeta(null);
    if (!investigationId) return;
    let cancelled = false;
    getParsed(zDatasetMeta, `/investigations/${investigationId}/dataset`)
      .then((d) => !cancelled && setMeta(d))
      .catch(() => !cancelled && setMeta(null));
    return () => {
      cancelled = true;
    };
  }, [investigationId]);

  const download = async () => {
    if (!investigationId || downloading) return;
    setDownloading(true);
    try {
      // One fetch of the documented tables plus manifest; the file is exactly
      // what the schema describes, so a consumer can validate it on load.
      const full = await getParsed(zDatasetMeta, `/investigations/${investigationId}/dataset`);
      const file = new Blob([JSON.stringify(full, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(file);
      const a = document.createElement('a');
      a.href = url;
      a.download = `investigation-${investigationId}-dataset-v${full.dataset_version}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Reviewers & dataset"
        description="Who judged what and whether they agreed — plus the whole investigation as tidy tables for external analysis."
        actions={
          <Button size="sm" onClick={download} disabled={!investigationId || downloading}>
            <Download className="size-4" />
            {downloading ? 'Preparing…' : 'Download dataset'}
          </Button>
        }
      />

      {!investigationId && (
        <SampleDataBanner note="select an investigation to see its reviewers and dataset." />
      )}

      {assessmentId && !dis && (
        <Skeleton className="h-40 w-full" />
      )}

      {dis && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Users className="size-4 text-muted-foreground" aria-hidden />
              Agreement
              {dis.stats.n_conflicts > 0 ? (
                <Badge variant="default">{dis.stats.n_conflicts} conflict{dis.stats.n_conflicts > 1 ? 's' : ''}</Badge>
              ) : (
                <Badge variant="muted">no conflicts</Badge>
              )}
            </CardTitle>
            <CardDescription>
              {dis.stats.n_reviewers} reviewer{dis.stats.n_reviewers === 1 ? '' : 's'} ·{' '}
              {dis.stats.n_artifacts_judged} artifact{dis.stats.n_artifacts_judged === 1 ? '' : 's'} judged
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <div className="grid gap-2 sm:grid-cols-3">
              <AgreementStat label="Cohen's κ" value={dis.stats.kappa} hint="chance-corrected, prevalence-sensitive" />
              <AgreementStat label="Krippendorff's α" value={dis.stats.krippendorff_alpha} hint="handles skew" />
              <AgreementStat label="Gwet's AC1" value={dis.stats.gwet_ac1} hint="stable on skewed verdicts" />
            </div>
            {dis.stats.note && (
              <p className="text-xs text-muted-foreground">{dis.stats.note}</p>
            )}

            {Object.entries(dis.stats.per_reviewer).length > 0 && (
              <div>
                <h4 className="mb-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  Reviewers
                </h4>
                <ul className="flex flex-col gap-1.5">
                  {Object.entries(dis.stats.per_reviewer).map(([who, s]) => (
                    <li key={who} className="flex items-center justify-between rounded-md border px-3 py-1.5 text-sm">
                      <span className="font-mono text-xs">{who}</span>
                      <span className="tabular text-xs text-muted-foreground">
                        {s.n_judged} judged
                        {s.agree_with_majority != null &&
                          ` · ${Math.round(s.agree_with_majority * 100)}% with majority`}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {dis.conflicts.length > 0 && (
              <div>
                <h4 className="mb-1.5 flex items-center gap-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  <Scale className="size-3" aria-hidden />
                  Conflicts
                </h4>
                <ul className="flex flex-col gap-1.5">
                  {dis.conflicts.map((c) => (
                    <li key={c.artifact_id} className="rounded-md border border-severity-medium/40 bg-severity-medium/5 px-3 py-2 text-sm">
                      <span className="font-mono text-xs">artifact #{c.artifact_id}</span>
                      <span className="ml-2 text-xs text-muted-foreground">
                        {Object.entries(c.votes)
                          .map(([who, v]) => `${who}: ${v}`)
                          .join(' · ')}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {meta && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Database className="size-4 text-muted-foreground" aria-hidden />
              Dataset
              <Badge variant="outline" className="font-mono">v{meta.dataset_version}</Badge>
            </CardTitle>
            <CardDescription>
              fingerprint{' '}
              <code className="font-mono text-[11px]">{meta.manifest.fingerprint.slice(0, 16)}</code>
              {' '}· cite by hash, not by download date
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <div className="grid gap-2 sm:grid-cols-5">
              {Object.entries(meta.counts).map(([table, n]) => (
                <div key={table} className="rounded-md border p-2.5">
                  <div className="text-[11px] uppercase tracking-wide text-muted-foreground">{table}</div>
                  <div className="tabular mt-0.5 text-xl font-semibold">{n}</div>
                </div>
              ))}
            </div>
            {meta.note && <p className="text-xs text-muted-foreground">{meta.note}</p>}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function AgreementStat({ label, value, hint }: { label: string; value: number | null | undefined; hint: string }) {
  return (
    <div className={cn('rounded-md border p-2.5', value == null && 'border-dashed opacity-70')}>
      <div className="text-[11px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="tabular mt-0.5 text-xl font-semibold">
        {value == null ? '—' : value.toFixed(2)}
      </div>
      <div className="text-[10px] text-muted-foreground">{hint}</div>
    </div>
  );
}