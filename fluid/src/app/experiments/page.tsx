'use client';

import * as React from 'react';
import { FlaskConical, PlayCircle } from 'lucide-react';
import { useAssessments, useAssessment } from '@/lib/api/queries';
import { useUi } from '@/lib/stores/ui';
import { useMutation } from '@tanstack/react-query';
import { postParsed } from '@/lib/api/client';
import { z } from 'zod';
import { PageHeader } from '@/components/shell/page-header';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { SampleDataBanner } from '@/components/shell/sample-banner';
import { ControlFloorChart } from '@/components/charts/control-floor-chart';
import { controlFloorCurve } from '@/lib/api/calibration';
import { useControlCatalog } from '@/lib/api/queries';

const zExperimentPlan = z
  .object({
    experiments: z
      .array(
        z
          .object({
            control_id: z.string().optional(),
            title: z.string().optional(),
            hypothesis: z.string().nullable().optional(),
            method: z.string().nullable().optional(),
            priority: z.number().nullable().optional(),
            burden: z.string().nullable().optional(),
            limitations: z.array(z.string()).optional(),
            success_criteria: z.string().nullable().optional(),
          })
          .passthrough(),
      )
      .optional(),
  })
  .passthrough();

type Experiment = {
  control_id?: string;
  title?: string;
  hypothesis?: string | null;
  method?: string | null;
  priority?: number | null;
  burden?: string | null;
  limitations?: string[];
  success_criteria?: string | null;
};

/**
 * What would settle this, before you spend effort on it.
 *
 * The engine only *plans* — nothing here executes. Each card carries its
 * hypothesis, its method and its success criteria, because a proposed test
 * without a falsifiable criterion is a to-do item, not an experiment. What
 * enabling each control would buy is shown against the saturation curve, so a
 * control that cannot move the score is visibly not worth testing first.
 */
export default function ExperimentsPage() {
  const { investigationId, assessmentId, setAssessment } = useUi();
  const { data: assessments } = useAssessments(investigationId);
  const id = assessmentId ?? assessments?.[0]?.id ?? null;
  const { data: assessment } = useAssessment(id);
  const { data: catalog } = useControlCatalog();
  const [plan, setPlan] = React.useState<Experiment[] | null>(null);

  const build = useMutation({
    mutationFn: async (aid: number) => {
      const r = await postParsed(zExperimentPlan, `/security/assessments/${aid}/experiments/build`, {}, { lenient: true });
      return (r.experiments ?? []) as Experiment[];
    },
    onSuccess: setPlan,
  });

  const curve = React.useMemo(() => controlFloorCurve(assessment, catalog), [assessment, catalog]);
  const beyondFloor = new Set(assessment?.floor?.controls_beyond_floor_ids ?? []);

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Experiments"
        description="Ranked plans for what is still open, with the hypothesis, the method and the criterion that would settle it."
      />

      <div className="flex flex-wrap items-center gap-2">
        {(assessments ?? []).slice(0, 8).map((a) => (
          <button
            key={a.id}
            onClick={() => {
              setAssessment(a.id);
              setPlan(null);
            }}
            className={`rounded-full border px-2.5 py-0.5 text-xs transition-colors ${
              a.id === id ? 'border-primary bg-primary/10' : 'hover:bg-accent/50'
            }`}
          >
            #{a.id} {a.product_name ?? ''}
          </button>
        ))}
      </div>

      {!id && <SampleDataBanner note="select an assessment to plan experiments against it." />}

      {id && (
        <Card>
          <CardHeader>
            <CardTitle>Plan</CardTitle>
            <CardDescription>
              Planning reads the stored rows and never touches scores. Nothing executes here.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button onClick={() => build.mutate(id)} disabled={build.isPending}>
              <PlayCircle className="size-4" />
              {build.isPending ? 'Planning…' : 'Build experiment plan'}
            </Button>
            {build.isError && (
              <p className="mt-2 text-xs text-destructive">
                Could not build a plan for this assessment.
              </p>
            )}
          </CardContent>
        </Card>
      )}

      {curve.length > 1 && (
        <Card>
          <CardHeader>
            <CardTitle>What enabling a control would buy</CardTitle>
            <CardDescription>
              The same saturation curve, read as a prioritisation: hollow bars cannot move the
              score, so testing them first would not change the answer.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ControlFloorChart
              points={curve}
              floor={assessment?.floor?.floor ?? 0.35}
            />
          </CardContent>
        </Card>
      )}

      {plan && plan.length > 0 && (
        <div className="flex flex-col gap-3">
          {plan.map((e, i) => (
            <Card key={`${e.control_id ?? 'x'}-${i}`}>
              <CardHeader className="flex-row items-start justify-between gap-3 space-y-0">
                <div className="min-w-0">
                  <CardTitle className="flex flex-wrap items-center gap-2">
                    <FlaskConical className="size-4 text-muted-foreground" aria-hidden />
                    {e.title ?? e.control_id ?? 'Experiment'}
                    {e.control_id && <Badge variant="outline" className="font-mono">{e.control_id}</Badge>}
                    {e.control_id && beyondFloor.has(e.control_id) && (
                      <Badge variant="muted">beyond floor</Badge>
                    )}
                  </CardTitle>
                  {e.hypothesis && <CardDescription className="mt-1">{e.hypothesis}</CardDescription>}
                </div>
                {e.priority != null && (
                  <Badge variant="muted" className="shrink-0">priority {e.priority}</Badge>
                )}
              </CardHeader>
              <CardContent className="flex flex-col gap-2 text-sm">
                {e.method && (
                  <div>
                    <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Method</span>
                    <p className="mt-0.5">{e.method}</p>
                  </div>
                )}
                {e.success_criteria && (
                  <div>
                    <span className="text-xs font-medium uppercase tracking-wide text-evidence-direct">Settled when</span>
                    <p className="mt-0.5">{e.success_criteria}</p>
                  </div>
                )}
                {e.burden && (
                  <p className="text-xs text-muted-foreground">Effort: {e.burden}</p>
                )}
                {e.limitations && e.limitations.length > 0 && (
                  <ul className="list-inside list-disc text-xs text-muted-foreground">
                    {e.limitations.map((l, j) => <li key={j}>{l}</li>)}
                  </ul>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {build.isSuccess && plan?.length === 0 && (
        <Card className="border-dashed">
          <CardContent className="py-8 text-center text-sm text-muted-foreground">
            The engine found no open experiments for this assessment — nothing scored is still
            unverified.
          </CardContent>
        </Card>
      )}
    </div>
  );
}