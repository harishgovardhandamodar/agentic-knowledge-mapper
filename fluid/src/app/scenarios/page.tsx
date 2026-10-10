'use client';

import * as React from 'react';
import { Link2, ShieldAlert, Layers, GitBranch } from 'lucide-react';
import { getParsed } from '@/lib/api/client';
import { z } from 'zod';
import { useAssessments } from '@/lib/api/queries';
import { useUi } from '@/lib/stores/ui';
import { PageHeader } from '@/components/shell/page-header';
import { SampleDataBanner } from '@/components/shell/sample-banner';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { SEVERITY_META, severityFromPct } from '@/components/tokens/status';
import { StatusBadge } from '@/components/ui/status-badge';
import { ScenarioOriginFilter } from '@/components/charts/scenario-origin-filter';
import { ScenarioCoverageScatter } from '@/components/charts/scenario-coverage-scatter';
import { AttackTreeView, type AttackTreeData } from '@/components/charts/attack-tree-view';

const zScenario = z
  .object({
    id: z.string(),
    origin: z.string(),
    title: z.string(),
    chain: z.array(z.string()).optional(),
    weakest_link: z.string().optional(),
    precondition: z.string().optional(),
    exploit: z.string().optional(),
    uncovered_by: z.array(z.string()).optional(),
    coverage_of_exploit: z.number().optional(),
    residual_score: z.number().optional(),
    why: z.string().optional(),
    floor_capped: z.boolean().optional(),
  })
  .passthrough();

const zScenarios = z.object({
  scenarios: z.array(zScenario),
  stats: z.object({
    total: z.number(),
    by_origin: z.record(z.number()),
    rows_considered: z.number(),
    floor_capped_rows: z.number(),
  }),
  method: z.object({ id: z.string(), version: z.string() }),
  note: z.string().optional(),
});

const zAttackTree = z.object({
  nodes: z.array(
    z
      .object({
        id: z.string(),
        title: z.string(),
        coverage: z.number(),
        residual: z.number(),
        floor_capped: z.boolean().optional(),
      })
      .passthrough(),
  ),
  edges: z
    .array(
      z
        .object({
          from: z.string(),
          to: z.string(),
          uncovered_by: z.array(z.string()),
          weakest: z.boolean(),
        })
        .passthrough(),
    )
    .optional(),
  stats: z.object({ nodes: z.number(), edges: z.number(), max_hops: z.number() }),
  note: z.string().optional(),
});

const ORIGIN_META: Record<string, { label: string; glyph: string; blurb: string }> = {
  control_gap_chain: {
    label: 'Chain',
    glyph: '→',
    blurb: 'Each link scores acceptably; the path does not.',
  },
  residual_amplifier: {
    label: 'At floor',
    glyph: '⊤',
    blurb: 'Pinned by the residual floor — an incident lands here.',
  },
  cross_cutting_gap: {
    label: 'Programme',
    glyph: '⊞',
    blurb: 'One absence explains several rows at once.',
  },
};

/**
 * Attack paths the per-row score cannot produce.
 *
 * The threat table answers "how is each risk scored". This answers "what would
 * an attacker actually do, and where does the model have nothing to say". Every
 * card names the rows and controls it was derived from — a scenario that cannot
 * say what produced it is a story, and this view does not render those.
 */
export default function ScenariosPage() {
  const { investigationId, assessmentId, setAssessment } = useUi();
  const { data: assessments } = useAssessments(investigationId);
  const id = assessmentId ?? assessments?.[0]?.id ?? null;
  const [data, setData] = React.useState<z.infer<typeof zScenarios> | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [origin, setOrigin] = React.useState<string>('all');
  const [tree, setTree] = React.useState<AttackTreeData | null>(null);
  const [selectedNode, setSelectedNode] = React.useState<string | null>(null);

  React.useEffect(() => {
    let cancelled = false;
    if (!id) {
      setData(null);
      return;
    }
    setLoading(true);
    void getParsed(zScenarios, `/security/assessments/${id}/scenarios`)
      .then((d) => !cancelled && setData(d))
      .catch(() => !cancelled && setData(null))
      .finally(() => !cancelled && setLoading(false));
    void getParsed(zAttackTree, `/security/assessments/${id}/attack-tree`)
      .then((d) => !cancelled && setTree({ ...d, edges: d.edges ?? [] }))
      .catch(() => !cancelled && setTree(null));
    return () => {
      cancelled = true;
    };
  }, [id]);

  const shown = (data?.scenarios ?? []).filter((s) => origin === 'all' || s.origin === origin);

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Scenarios"
        description="Compositions the per-row score cannot produce: uncovered chains, rows already at the floor, and the absences that explain several rows at once."
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

      {!id && <SampleDataBanner note="select an assessment to derive its scenarios." />}
      {loading && <Skeleton className="h-64 w-full" />}

      {data && data.stats.total === 0 && (
        <Card className="border-dashed">
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            No scenarios derived. That usually means every threat is well covered
            and none is pinned at the floor.
          </CardContent>
        </Card>
      )}

      {data && data.stats.total > 0 && (
        <>
          <div className="grid gap-4 sm:grid-cols-4">
            <Stat label="Derived scenarios" value={data.stats.total} />
            <Stat label="Rows considered" value={data.stats.rows_considered} />
            <Stat label="Rows at the floor" value={data.stats.floor_capped_rows} />
            <Stat
              label="Method"
              value={`${data.method.id} v${data.method.version}`}
              small
            />
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Where the gaps sit</CardTitle>
              <CardDescription>
                Coverage on the exploit leg against its residual. Bottom-left is where an
                incident would land: barely covered, still risky.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ScenarioCoverageScatter scenarios={data.scenarios} />
            </CardContent>
          </Card>

          {tree && tree.stats.edges > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Attack tree</CardTitle>
                <CardDescription>
                  Columns are coverage bands: each derived path declines from left to right,
                  because that decline is the finding. Longest path {tree.stats.max_hops} hops.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <AttackTreeView
                  data={tree}
                  selected={selectedNode}
                  onSelect={setSelectedNode}
                />
              </CardContent>
            </Card>
          )}

          <ScenarioOriginFilter
            byOrigin={data.stats.by_origin}
            value={origin}
            onChange={setOrigin}
          />

          <div className="flex flex-col gap-3">
            {shown.map((s) => {
              const meta = ORIGIN_META[s.origin] ?? {
                label: s.origin,
                glyph: '•',
                blurb: '',
              };
              const band = severityFromPct(((s.residual_score ?? 0) / 25) * 100);
              return (
                <Card key={s.id}>
                  <CardHeader className="flex-row items-start justify-between gap-3 space-y-0">
                    <div className="min-w-0">
                      <CardTitle className="flex flex-wrap items-center gap-2">
                        {s.origin === 'control_gap_chain' ? (
                          <GitBranch className="size-4 text-muted-foreground" aria-hidden />
                        ) : s.origin === 'residual_amplifier' ? (
                          <ShieldAlert className="size-4 text-muted-foreground" aria-hidden />
                        ) : (
                          <Layers className="size-4 text-muted-foreground" aria-hidden />
                        )}
                        {s.title}
                      </CardTitle>
                      <CardDescription className="mt-1">
                        <span className="font-mono">{meta.glyph}</span> {meta.blurb}
                      </CardDescription>
                    </div>
                    <div className="flex shrink-0 flex-col items-end gap-1">
                      <StatusBadge meta={SEVERITY_META[band]} />
                      <span className="tabular text-[11px] text-muted-foreground">
                        {s.coverage_of_exploit?.toFixed(0)}% covered
                      </span>
                    </div>
                  </CardHeader>
                  <CardContent className="flex flex-col gap-3">
                    {s.chain && s.chain.length > 1 && (
                      <div className="flex items-center gap-2 font-mono text-xs">
                        {s.chain.map((leg, i) => (
                          <React.Fragment key={leg}>
                            {i > 0 && <span className="text-muted-foreground">→</span>}
                            <span
                              className={
                                leg === s.weakest_link
                                  ? 'rounded bg-severity-medium/15 px-1.5 py-0.5 text-severity-medium'
                                  : 'rounded bg-muted px-1.5 py-0.5'
                              }
                            >
                              {leg}
                            </span>
                          </React.Fragment>
                        ))}
                      </div>
                    )}
                    {s.uncovered_by && s.uncovered_by.length > 0 && (
                      <div className="flex flex-wrap items-center gap-1.5">
                        <Link2 className="size-3 text-muted-foreground" aria-hidden />
                        <span className="text-[11px] text-muted-foreground">
                          not reaching the exploit leg:
                        </span>
                        {s.uncovered_by.slice(0, 8).map((c) => (
                          <Badge key={c} variant="outline" className="font-mono">
                            {c}
                          </Badge>
                        ))}
                      </div>
                    )}
                    <p className="text-sm leading-relaxed text-muted-foreground">{s.why}</p>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}

function Stat({ label, value, small }: { label: string; value: number | string; small?: boolean }) {
  return (
    <Card>
      <CardContent className="p-4">
        <div className="text-[11px] uppercase tracking-wide text-muted-foreground">{label}</div>
        <div className={`tabular mt-1 font-semibold ${small ? 'text-sm' : 'text-2xl'}`}>
          {value}
        </div>
      </CardContent>
    </Card>
  );
}