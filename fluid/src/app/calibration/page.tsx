'use client';

import * as React from 'react';
import { AlertTriangle, CheckCircle2 } from 'lucide-react';
import {
  useAssessments,
  useAssessment,
  useAssessmentAnalysis,
  useControlCatalog,
  useEval,
} from '@/lib/api/queries';
import { useUi } from '@/lib/stores/ui';
import { controlFloorCurve, toEfficacyPoints } from '@/lib/api/calibration';
import { PageHeader } from '@/components/shell/page-header';
import { SampleDataBanner } from '@/components/shell/sample-banner';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { ResidualDisplay } from '@/components/security/residual-display';
import { ControlFloorChart } from '@/components/charts/control-floor-chart';
import { VarianceBudgetChart } from '@/components/charts/variance-budget-chart';
import { EfficacyProvenanceChart } from '@/components/charts/efficacy-provenance-chart';
import { toResidualInterval } from '@/lib/api/adapters';
import type { Assessment } from '@/lib/api/schemas';

export default function CalibrationPage() {
  const { investigationId, assessmentId } = useUi();
  const { data: list } = useAssessments(investigationId);
  const id = assessmentId ?? list?.[0]?.id ?? null;

  const { data: assessment, isLoading } = useAssessment(id);
  const { data: analysis } = useAssessmentAnalysis(id);
  const { data: catalog } = useControlCatalog();
  const { data: report } = useEval();

  const curve = React.useMemo(
    () => controlFloorCurve(assessment, catalog),
    [assessment, catalog],
  );
  const efficacy = React.useMemo(() => toEfficacyPoints(catalog), [catalog]);
  const floor = assessment?.floor ?? null;
  const budget = analysis?.variance_budget ?? null;
  const band = analysis?.uncertainty ?? null;

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Calibration"
        description="What the residual score can support: where it saturates, how much of it rests on unmeasured priors, and what the credible interval leaves out."
      />

      <AssessmentPicker
        assessments={list ?? []}
        currentId={id}
        onPick={(aid) => useUi.getState().setAssessment(aid)}
      />

      {isLoading && <Skeleton className="h-56 w-full" />}

      {!isLoading && !assessment && (
        <SampleDataBanner note="no assessment is selected, so there is nothing to calibrate yet." />
      )}

      {assessment && (
        <>
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                Engine gate
                <EngineGate ok={report?.ok} report={report} />
              </CardTitle>
              <CardDescription>
                The scoring regression suite, run live against this build. A green gate means
                the number below is the number the engine intends.
              </CardDescription>
            </CardHeader>
          </Card>

          <div className="grid gap-4 lg:grid-cols-2">
            {band ? (
              <ResidualDisplay
                residual={toResidualInterval(band)}
                label="Residual with its interval"
                subtitle={floor?.floor_capped ? 'The score has saturated — see the curve below.' : undefined}
              />
            ) : (
              <ResidualDisplay
                residual={null}
                pointWithoutInterval={assessment.residual_pct ?? null}
                label="Residual"
              />
            )}

            <Card>
              <CardHeader>
                <CardTitle>Saturation</CardTitle>
                <CardDescription>
                  Whether declaring more controls can still move the headline.
                </CardDescription>
              </CardHeader>
              <CardContent className="flex flex-col gap-3 text-sm">
                <SaturationFacts floor={floor} nControls={catalog?.length ?? 0} />
                <div className="flex flex-wrap gap-1.5">
                  {(floor?.controls_beyond_floor_ids ?? []).map((cid) => (
                    <Badge key={cid} variant="outline" className="font-mono">
                      {cid}
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Residual as controls are added</CardTitle>
              <CardDescription>
                Reconstructed from this assessment’s own rows and the control catalogue. The
                final column reproduces the stored headline exactly.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {curve.length > 1 ? (
                <ControlFloorChart points={curve} floor={floor?.floor ?? 0.35} />
              ) : (
                <p className="rounded-md border border-dashed p-6 text-center text-sm text-muted-foreground">
                  Not enough declared controls to draw a curve for this assessment.
                </p>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Control efficacy provenance</CardTitle>
              <CardDescription>
                Every efficacy in the catalogue, with the interval its provenance justifies. A
                wide bar means unmeasured — not weak.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {efficacy.length > 0 ? (
                <EfficacyProvenanceChart points={efficacy} />
              ) : (
                <Skeleton className="h-64 w-full" />
              )}
            </CardContent>
          </Card>

          {budget && (
            <Card>
              <CardHeader>
                <CardTitle>Variance budget</CardTitle>
                <CardDescription>
                  Which inputs produce the interval — and, more importantly, which it does not.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <VarianceBudgetChart budget={budget} />
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  );
}

function SaturationFacts({
  floor,
  nControls,
}: {
  floor: Assessment['floor'];
  nControls: number;
}) {
  if (!floor) {
    return (
      <p className="text-muted-foreground">
        This assessment predates the calibration layer, so its saturation is unknown rather
        than absent.
      </p>
    );
  }
  return (
    <>
      <p>
        Likelihood never falls below <strong>{Math.round((floor.floor ?? 0.35) * 100)}%</strong>{' '}
        of inherent, so the score saturates once coverage passes{' '}
        <strong>{Math.round((1 - (floor.floor ?? 0.35)) * 100)}%</strong>.
      </p>
      <div className="flex flex-wrap gap-2">
        <Badge variant="muted">{floor.floor_capped_count ?? 0} threats floored</Badge>
        <Badge variant={floor.controls_beyond_floor ? 'default' : 'muted'}>
          {floor.controls_beyond_floor ?? 0} of {nControls || '?'} controls beyond the floor
        </Badge>
        {(floor.controls_orphaned ?? []).length > 0 && (
          <Badge variant="outline">{floor.controls_orphaned!.length} orphaned</Badge>
        )}
      </div>
      <p className="text-xs text-muted-foreground">{floor.note}</p>
    </>
  );
}

function EngineGate({ ok, report }: { ok?: boolean; report: unknown }) {
  if (ok === undefined) return <Skeleton className="h-5 w-24" />;
  const r = report as
    | {
        cases_run?: number;
        invariants_run?: number;
        engine_invariants_failed?: number;
        engine_invariants_run?: number;
      }
    | undefined;
  return (
    <span
      className={`inline-flex items-center gap-1.5 text-xs ${ok ? 'text-evidence-direct' : 'text-severity-critical'}`}
    >
      {ok ? <CheckCircle2 className="size-3.5" /> : <AlertTriangle className="size-3.5" />}
      <span className="tabular">
        {r?.cases_run ?? 0} cases · {r?.engine_invariants_run ?? 0} calibration invariants
        {ok ? '' : ' — failing'}
      </span>
    </span>
  );
}

function AssessmentPicker({
  assessments,
  currentId,
  onPick,
}: {
  assessments: { id: number; product_name?: string | null }[];
  currentId: number | null;
  onPick: (id: number) => void;
}) {
  if (assessments.length === 0) return null;
  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="text-xs uppercase tracking-wide text-muted-foreground">Assessment</span>
      {assessments.slice(0, 8).map((a) => (
        <button
          key={a.id}
          onClick={() => onPick(a.id)}
          className={`rounded-full border px-2.5 py-0.5 text-xs transition-colors ${
            a.id === currentId
              ? 'border-primary bg-primary/10'
              : 'hover:bg-accent/50'
          }`}
        >
          #{a.id} {a.product_name ?? ''}
        </button>
      ))}
    </div>
  );
}
