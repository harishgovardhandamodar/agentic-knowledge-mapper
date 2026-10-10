'use client';

import * as React from 'react';
import { FlaskConical, ShieldQuestion } from 'lucide-react';
import { getParsed } from '@/lib/api/client';
import { z } from 'zod';
import { useAssessments } from '@/lib/api/queries';
import { useUi } from '@/lib/stores/ui';
import { PageHeader } from '@/components/shell/page-header';
import { SampleDataBanner } from '@/components/shell/sample-banner';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { ProbeRunForm } from '@/components/probes/probe-run-form';
import { ProbeResultCard } from '@/components/probes/probe-result-card';
import type { ProbeResult } from '@/components/probes/probe-types';

const zLibrary = z.object({
  probes: z.array(
    z.object({ id: z.string(), attack_class: z.string(), description: z.string() }).passthrough(),
  ),
  max_trials: z.number(),
  note: z.string(),
});

/**
 * Execute a probe and see what it actually measured.
 *
 * The page leads with the safety envelope rather than burying it: probes only
 * run against a host you have explicitly allowed, and a dry run shows the plan
 * instead of sending anything. The result is an interval, never a bare rate --
 * a clean run over too few trials reports as inconclusive, which is the whole
 * reason this screen exists.
 */
export default function ProbesPage() {
  const { investigationId, assessmentId, setAssessment } = useUi();
  const { data: assessments } = useAssessments(investigationId);
  const id = assessmentId ?? assessments?.[0]?.id ?? null;
  const [library, setLibrary] = React.useState<z.infer<typeof zLibrary> | null>(null);
  const [result, setResult] = React.useState<ProbeResult | null>(null);

  React.useEffect(() => {
    getParsed(zLibrary, '/probes').then(setLibrary).catch(() => setLibrary(null));
  }, []);

  React.useEffect(() => {
    setResult(null);
  }, [id]);

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Probes"
        description="Run an adversarial probe against a configured target and record what it measured. The result is an interval, not a rate."
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

      {!id && <SampleDataBanner note="select an assessment to attribute probe results to." />}

      <div className="flex items-start gap-2 rounded-md border border-severity-medium/40 bg-severity-medium/5 px-3 py-2 text-xs">
        <ShieldQuestion className="mt-0.5 size-3.5 shrink-0 text-severity-medium" aria-hidden />
        <div>
          <b className="text-severity-medium">Probes send adversarial payloads.</b>{' '}
          They only run against a host on your configured allow-list, and only when you
          confirm. Dry runs show the plan without sending anything. Make sure you own the
          target and are authorised to test it.
        </div>
      </div>

      {library && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FlaskConical className="size-4 text-muted-foreground" aria-hidden />
              Probe library
            </CardTitle>
            <CardDescription>{library.note}</CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="grid gap-2 sm:grid-cols-2">
              {library.probes.map((p) => (
                <li key={p.id} className="rounded-md border p-3 text-xs">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono">{p.id}</span>
                    <Badge variant="outline" className="text-[10px]">
                      {p.attack_class}
                    </Badge>
                  </div>
                  <p className="mt-1 text-muted-foreground">{p.description}</p>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      {id && (
        <ProbeRunForm
          assessmentId={id}
          library={library?.probes ?? []}
          maxTrials={library?.max_trials ?? 50}
          onResult={setResult}
        />
      )}

      {result && <ProbeResultCard result={result} />}
    </div>
  );
}