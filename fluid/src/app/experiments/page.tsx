'use client';

import * as React from 'react';
import { FlaskConical, PlayCircle, Lock, CheckCircle2, AlertTriangle, MinusCircle } from 'lucide-react';
import { postParsed } from '@/lib/api/client';
import { z } from 'zod';
import { useAssessments, useAssessment, useControlCatalog } from '@/lib/api/queries';
import { useUi } from '@/lib/stores/ui';
import { PageHeader } from '@/components/shell/page-header';
import { SampleDataBanner } from '@/components/shell/sample-banner';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ControlFloorChart } from '@/components/charts/control-floor-chart';
import { controlFloorCurve } from '@/lib/api/calibration';
import { cn } from '@/lib/utils';

// Mirrors app.model_eval.plan_experiments exactly. Field names here are the
// contract; a rename on either side must fail loudly rather than render an
// experiment with no method, no criteria and no prerequisites.
const zExperiment = z
  .object({
    id: z.string(),
    title: z.string(),
    method_type: z.string(),
    targets: z
      .object({
        attack_classes: z.array(z.string()).optional(),
        adoption_dimensions: z.array(z.string()).optional(),
        hypothesis_ids: z.array(z.string()).optional(),
        mitigation_ids: z.array(z.string()).optional(),
      })
      .passthrough(),
    data_requirements: z.string().optional(),
    metrics: z.array(z.string()).optional(),
    success_criteria: z.string().optional(),
    fail_criteria: z.string().optional(),
    effort: z.string().optional(),
    prerequisites: z.array(z.string()).optional(),
    linked_evidence_ids: z.array(z.number()).optional(),
    status: z.string().optional(),
    rationale: z.string().optional(),
  })
  .passthrough();

const zPlan = z
  .object({
    experiments: z.array(zExperiment).optional(),
    roadmap: z.record(z.array(z.string())).optional(),
    method: z.string().optional(),
    method_version: z.string().optional(),
    method_fingerprint: z.string().optional(),
    note: z.string().optional(),
  })
  .passthrough();

const zRate = z
  .object({
    successes: z.number(),
    trials: z.number(),
    rate: z.number().nullable().optional(),
    lower: z.number().nullable().optional(),
    upper: z.number().nullable().optional(),
    method: z.string().optional(),
    note: z.string().optional(),
  })
  .passthrough();

const zPrereg = z
  .object({
    experiment_id: z.string(),
    n_trials: z.number(),
    alpha: z.number(),
    primary_metric: z.string(),
    success_criteria: z.string(),
    fail_criteria: z.string(),
    interval_if_zero_events: zRate,
    minimum_for_power: z
      .object({ n: z.number().nullable(), power: z.number().optional(), note: z.string().optional() })
      .passthrough(),
    decision_rule: z.record(z.string()),
    integrity_note: z.string(),
  })
  .passthrough();

const zResult = z
  .object({
    experiment_id: z.string(),
    rate: zRate,
    verdict: z.string(),
    conclusion: z.string(),
    minimum_trials_for_power: z.number(),
    recommended_next_trials: z.number(),
    note: z.string(),
  })
  .passthrough();

type Prereg = z.infer<typeof zPrereg>;
type Result = z.infer<typeof zResult>;

const VERDICT_STYLE: Record<string, { glyph: string; cls: string; label: string }> = {
  control_not_effective: {
    glyph: '✕',
    cls: 'text-evidence-contradicts border-evidence-contradicts',
    label: 'Control not effective',
  },
  inconclusive: {
    glyph: '−',
    cls: 'text-evidence-modality border-evidence-modality',
    label: 'Inconclusive',
  },
  supported_but_unmeasured: {
    glyph: '○',
    cls: 'text-evidence-family border-evidence-family',
    label: 'Consistent, not proven',
  },
};

const METHOD_LABEL: Record<string, string> = {
  membership_inference: 'Membership inference',
  extraction_probe: 'Extraction probe',
  canary: 'Canary',
  unlearning_check: 'Unlearning check',
  watermark_detect: 'Watermark detection',
  robustness_grid: 'Robustness grid',
  privacy_accounting: 'Privacy accounting',
  doc_audit: 'Document audit',
};

/**
 * What would settle this — with the decision rule fixed *before* the run.
 *
 * The preregistration step is the point of this page. An experiment whose
 * sample size and interval are decided after seeing the result is a way of
 * reporting whatever you hoped for, so the protocol is frozen first, and a
 * clean run over too few trials is reported as inconclusive rather than as a
 * pass. The saturation curve underneath says which controls cannot move the
 * score at all, so a "beyond the floor" test is visibly not worth running first.
 */
export default function ExperimentsPage() {
  const { investigationId, assessmentId, setAssessment } = useUi();
  const { data: assessments } = useAssessments(investigationId);
  const id = assessmentId ?? assessments?.[0]?.id ?? null;
  const { data: assessment } = useAssessment(id);
  const { data: catalog } = useControlCatalog();
  const curve = React.useMemo(
    () => controlFloorCurve(assessment, catalog),
    [assessment, catalog],
  );

  const [plan, setPlan] = React.useState<z.infer<typeof zPlan> | null>(null);
  const [building, setBuilding] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [prereg, setPrereg] = React.useState<Prereg | null>(null);
  const [result, setResult] = React.useState<Result | null>(null);
  const [trials, setTrials] = React.useState(30);
  const [successes, setSuccesses] = React.useState(0);
  const [busy, setBusy] = React.useState(false);

  const build = React.useCallback(async () => {
    if (!id) return;
    setBuilding(true);
    setError(null);
    try {
      const p = await postParsed(zPlan, `/security/assessments/${id}/experiments/build`, {});
      setPlan(p);
      setPrereg(null);
      setResult(null);
    } catch {
      setError('Could not build an experiment plan for this assessment.');
    } finally {
      setBuilding(false);
    }
  }, [id]);

  React.useEffect(() => {
    setPlan(null);
    setPrereg(null);
    setResult(null);
  }, [id]);

  const freeze = async (exp: z.infer<typeof zExperiment>) => {
    if (!id) return;
    setBusy(true);
    try {
      setPrereg(await postParsed(
        zPrereg,
        `/security/assessments/${id}/experiments/${exp.id}/preregister`,
        { method_type: exp.method_type, title: exp.title, rationale: exp.rationale,
          targets: exp.targets, n_trials: trials },
      ));
      setResult(null);
    } finally {
      setBusy(false);
    }
  };

  const score = async (exp: z.infer<typeof zExperiment>) => {
    if (!id) return;
    setBusy(true);
    try {
      setResult(await postParsed(
        zResult,
        `/security/assessments/${id}/experiments/${exp.id}/result`,
        { method_type: exp.method_type, successes, trials },
      ));
    } finally {
      setBusy(false);
    }
  };

  const experiments = plan?.experiments ?? [];

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Experiments"
        description="Ranked plans with the decision rule fixed in advance. A clean run over too few trials is inconclusive, not a pass."
      />

      <div className="flex flex-wrap items-center gap-2">
        {(assessments ?? []).slice(0, 8).map((a) => (
          <button
            key={a.id}
            onClick={() => setAssessment(a.id)}
            className={cn(
              'rounded-full border px-2.5 py-0.5 text-xs transition-colors',
              a.id === id ? 'border-primary bg-primary/10' : 'hover:bg-accent/50',
            )}
          >
            #{a.id} {a.product_name ?? ''}
          </button>
        ))}
      </div>

      {!id && <SampleDataBanner note="select an assessment to plan experiments against it." />}

      <Card>
        <CardHeader>
          <CardTitle>Plan</CardTitle>
          <CardDescription>
            {plan?.method ? (
              <>Method {plan.method} v{plan.method_version} · fingerprint{' '}
                <code className="font-mono text-[10px]">{plan.method_fingerprint?.slice(0, 12)}</code></>
            ) : (
              'Planning reads the stored rows and never touches scores. Nothing executes here.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <Button onClick={build} disabled={!id || building}>
            <PlayCircle className="size-4" />
            {building ? 'Planning…' : plan ? 'Rebuild plan' : 'Build experiment plan'}
          </Button>
          {error && <p className="text-xs text-destructive">{error}</p>}
          {plan?.note && <p className="text-xs text-muted-foreground">{plan.note}</p>}
        </CardContent>
      </Card>

      {curve.length > 1 && (
        <Card>
          <CardHeader>
            <CardTitle>What enabling a control would buy</CardTitle>
            <CardDescription>
              Hollow bars are past the residual floor: the test would raise coverage
              without moving the headline, so it will not change the answer.
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

      {experiments.length > 0 && (
        <div className="flex flex-col gap-3">
          {experiments.map((e) => (
            <Card key={e.id}>
              <CardHeader className="flex-row items-start justify-between gap-3 space-y-0">
                <div className="min-w-0">
                  <CardTitle className="flex flex-wrap items-center gap-2">
                    <FlaskConical className="size-4 text-muted-foreground" aria-hidden />
                    <span className="font-mono text-xs text-muted-foreground">{e.id}</span>
                    {e.title}
                  </CardTitle>
                  <CardDescription className="mt-1">
                    {METHOD_LABEL[e.method_type] ?? e.method_type}
                    {e.effort ? ` · effort ${e.effort}` : ''}
                  </CardDescription>
                </div>
                <Badge variant={e.status === 'proposed' ? 'outline' : 'muted'} className="shrink-0">
                  {e.status ?? 'proposed'}
                </Badge>
              </CardHeader>

              <CardContent className="flex flex-col gap-3 text-sm">
                {e.rationale && (
                  <p className="text-muted-foreground">{e.rationale}</p>
                )}

                <div className="flex flex-col gap-1.5 rounded-md border bg-muted/30 p-3 text-xs">
                  <div>
                    <span className="font-medium text-evidence-direct">Settled when</span>
                    <span className="text-muted-foreground"> — {e.success_criteria}</span>
                  </div>
                  <div>
                    <span className="font-medium text-evidence-contradicts">Not settled when</span>
                    <span className="text-muted-foreground"> — {e.fail_criteria}</span>
                  </div>
                  {e.metrics && e.metrics.length > 0 && (
                    <div>
                      <span className="font-medium">Metrics</span>
                      <span className="text-muted-foreground"> — {e.metrics.join(', ')}</span>
                    </div>
                  )}
                  {e.data_requirements && (
                    <div>
                      <span className="font-medium">Needs</span>
                      <span className="text-muted-foreground"> — {e.data_requirements}</span>
                    </div>
                  )}
                  {e.prerequisites && e.prerequisites.length > 0 && (
                    <div className="flex flex-wrap items-center gap-1.5 pt-1">
                      <span className="font-medium">Prerequisites</span>
                      {e.prerequisites.map((p) => (
                        <Badge key={p} variant="outline" className="font-mono text-[10px]">
                          {p}
                        </Badge>
                      ))}
                    </div>
                  )}
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <label className="text-xs text-muted-foreground" htmlFor={`n-${e.id}`}>
                    Trials
                  </label>
                  <input
                    id={`n-${e.id}`}
                    type="number"
                    min={1}
                    max={500}
                    value={trials}
                    onChange={(ev) => setTrials(Math.max(1, Number(ev.target.value) || 1))}
                    className="w-20 rounded-md border bg-background px-2 py-1 text-xs tabular"
                  />
                  <Button size="sm" variant="outline" onClick={() => freeze(e)} disabled={busy}>
                    <Lock className="size-3.5" />
                    Pre-register
                  </Button>
                  <span className="text-[11px] text-muted-foreground">
                    Fixes the protocol before the run.
                  </span>
                </div>

                {prereg?.experiment_id === e.id && (
                  <div className="flex flex-col gap-2 rounded-md border border-primary/40 bg-primary/5 p-3 text-xs">
                    <div className="flex items-center gap-2 font-medium">
                      <Lock className="size-3.5" aria-hidden />
                      Registered — {prereg.n_trials} trials, α = {prereg.alpha}
                    </div>
                    <p className="text-muted-foreground">
                      If every trial comes back clean the exact {Math.round((1 - prereg.alpha) * 100)}%
                      interval is{' '}
                      <span className="tabular">
                        [{(prereg.interval_if_zero_events.lower ?? 0).toFixed(3)},{' '}
                        {(prereg.interval_if_zero_events.upper ?? 0).toFixed(3)}]
                      </span>
                      . That upper bound is what makes ‘it held’ a claim you can check.
                    </p>
                    <p className="text-muted-foreground">
                      {prereg.minimum_for_power.n ?? '—'} trials needed for{' '}
                      {prereg.minimum_for_power.power} power at a 20% effect.
                    </p>
                    <div className="flex flex-wrap items-center gap-2 pt-1">
                      <label className="text-muted-foreground" htmlFor={`s-${e.id}`}>
                        Successes
                      </label>
                      <input
                        id={`s-${e.id}`}
                        type="number"
                        min={0}
                        max={trials}
                        value={successes}
                        onChange={(ev) =>
                          setSuccesses(Math.min(trials, Math.max(0, Number(ev.target.value) || 0)))
                        }
                        className="w-20 rounded-md border bg-background px-2 py-1 text-xs tabular"
                      />
                      <Button size="sm" onClick={() => score(e)} disabled={busy}>
                        Score result
                      </Button>
                    </div>
                    <p className="text-[11px] text-muted-foreground">{prereg.integrity_note}</p>
                  </div>
                )}

                {result?.experiment_id === e.id && (
                  <VerdictCard result={result} />
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {plan && experiments.length === 0 && (
        <Card className="border-dashed">
          <CardContent className="py-8 text-center text-sm text-muted-foreground">
            No open experiments — nothing scored here is still unverified.
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function VerdictCard({ result }: { result: Result }) {
  const style = VERDICT_STYLE[result.verdict] ?? {
    glyph: '•',
    cls: 'text-muted-foreground border-border',
    label: result.verdict,
  };
  const Icon =
    result.verdict === 'control_not_effective'
      ? AlertTriangle
      : result.verdict === 'inconclusive'
        ? MinusCircle
        : CheckCircle2;
  const r = result.rate;

  return (
    <div
      className={cn(
        'flex flex-col gap-2 rounded-md border p-3 text-xs',
        style.cls.replace('text-', 'border-').split(' ')[1],
      )}
    >
      <div className="flex items-center gap-2 font-medium">
        <Icon className="size-3.5" aria-hidden />
        {style.glyph} {style.label}
      </div>
      <div className="tabular flex flex-wrap items-baseline gap-3">
        <span className="text-lg font-semibold">
          {r.successes}/{r.trials}
        </span>
        <span className="text-muted-foreground">
          {r.rate != null ? `${(r.rate * 100).toFixed(1)}%` : '—'}
        </span>
        <span className="text-muted-foreground">
          interval [{((r.lower ?? 0) * 100).toFixed(1)}%, {((r.upper ?? 0) * 100).toFixed(1)}%]
        </span>
        <Badge variant="outline" className="font-mono text-[10px]">
          {r.method}
        </Badge>
      </div>
      <p className="text-muted-foreground">{result.conclusion}</p>
      <p className="text-muted-foreground">
        {result.recommended_next_trials} trials needed before this can conclude anything.
      </p>
      <p className="text-[11px] text-muted-foreground">{result.note}</p>
    </div>
  );
}