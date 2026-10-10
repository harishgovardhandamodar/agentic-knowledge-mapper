'use client';

import * as React from 'react';
import { Download, FileText, Copy, Check } from 'lucide-react';
import { getParsed } from '@/lib/api/client';
import { z } from 'zod';
import { useAssessments } from '@/lib/api/queries';
import { useUi } from '@/lib/stores/ui';
import { PageHeader } from '@/components/shell/page-header';
import { SampleDataBanner } from '@/components/shell/sample-banner';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { Badge } from '@/components/ui/badge';

const zReport = z
  .object({
    assessment_id: z.number(),
    markdown: z.string(),
    sections: z.array(
      z
        .object({
          key: z.string(),
          title: z.string(),
          lines: z.array(z.string()),
        })
        .passthrough(),
    ),
    contract_violations: z.array(z.string()),
  })
  .passthrough();

/**
 * The artifact a reviewer actually receives.
 *
 * Assembled live from the measured properties rather than replaying the stored
 * markdown, so the interval, its variance budget and the saturation finding
 * travel with the claim instead of living in a separate tab. Copy or download;
 * the ordering — headline, then what it does not cover — is preserved because
 * a limitations section at the end is a disclaimer, and the same limitations
 * immediately after the number are part of the result.
 */
export default function ReportPage() {
  const { investigationId, assessmentId, setAssessment } = useUi();
  const { data: assessments } = useAssessments(investigationId);
  const id = assessmentId ?? assessments?.[0]?.id ?? null;
  const [report, setReport] = React.useState<z.infer<typeof zReport> | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [copied, setCopied] = React.useState(false);

  const load = React.useCallback(async () => {
    if (!id) return;
    setLoading(true);
    try {
      setReport(await getParsed(zReport, `/security/assessments/${id}/report`));
    } catch {
      setReport(null);
    } finally {
      setLoading(false);
    }
  }, [id]);

  React.useEffect(() => {
    setReport(null);
    if (id) void load();
  }, [id, load]);

  const download = () => {
    if (!report) return;
    const blob = new Blob([report.markdown], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `assessment-${report.assessment_id}-research-report.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copy = async () => {
    if (!report) return;
    await navigator.clipboard.writeText(report.markdown);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Research report"
        description="The limitations travel with the claims: the interval, its variance budget and the saturation finding are assembled into the same artifact."
        actions={
          <>
            <Button variant="outline" size="sm" onClick={copy} disabled={!report}>
              {copied ? <Check className="size-4" /> : <Copy className="size-4" />}
              {copied ? 'Copied' : 'Copy'}
            </Button>
            <Button size="sm" onClick={download} disabled={!report}>
              <Download className="size-4" />
              Download .md
            </Button>
          </>
        }
      />

      <div className="flex flex-wrap items-center gap-2">
        {(assessments ?? []).slice(0, 8).map((a) => (
          <button
            key={a.id}
            onClick={() => setAssessment(a.id)}
            className={`rounded-full border px-2.5 py-0.5 text-xs transition-colors ${
              a.id === id ? 'border-primary bg-primary/10' : 'hover:bg-accent/50'
            }`}
          >
            #{a.id} {a.product_name ?? ''}
          </button>
        ))}
      </div>

      {!id && <SampleDataBanner note="select an assessment to build its report." />}
      {loading && <Skeleton className="h-96 w-full" />}

      {report && report.contract_violations.length > 0 && (
        <div className="rounded-md border border-severity-critical/50 bg-severity-critical/5 p-3 text-xs">
          <b className="text-severity-critical">Scoring contract violated</b>
          <ul className="mt-1 list-inside list-disc">
            {report.contract_violations.map((v) => (
              <li key={v}>{v}</li>
            ))}
          </ul>
        </div>
      )}

      {report && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FileText className="size-4 text-muted-foreground" aria-hidden />
              Assessment #{report.assessment_id}
            </CardTitle>
            <CardDescription>
              {report.sections.length} sections · assembled from this row’s measured
              properties
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-5">
            {report.sections.map((s) => (
              <section key={s.key}>
                <h3 className="mb-1.5 text-sm font-semibold">{s.title}</h3>
                <div className="flex flex-col gap-1">
                  {s.lines.map((ln, i) => (
                    <p key={i} className="text-sm leading-relaxed text-muted-foreground">
                      {ln}
                    </p>
                  ))}
                </div>
              </section>
            ))}
            <p className="border-t pt-3 text-[11px] text-muted-foreground">
              <Badge variant="muted" className="mr-2">note</Badge>
              Generated from the measured properties of this assessment; the limitations are
              part of the result, not a disclaimer.
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}