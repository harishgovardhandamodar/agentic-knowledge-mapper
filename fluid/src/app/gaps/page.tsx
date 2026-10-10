'use client';

import * as React from 'react';
import { Compass, Lightbulb, Search } from 'lucide-react';
import { useResearchGaps } from '@/lib/api/queries';
import { useUi } from '@/lib/stores/ui';
import { PageHeader } from '@/components/shell/page-header';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Button } from '@/components/ui/button';
import { SampleDataBanner } from '@/components/shell/sample-banner';
import { cn } from '@/lib/utils';

type Gap = {
  question: string;
  kinds?: string[];
  exps?: unknown[];
  supporting: number;
  novel: boolean;
};

/**
 * What this tool does not yet know, ranked by how little supports it.
 *
 * Two views, because they answer different questions. A *gap* is a question the
 * investigation already raised but could not support — closing it is a known
 * task. A *novel area* is a topic the corpus covers that nobody has asked
 * about — that is where a genuinely new scenario would come from, which is the
 * harder half of research and the one a dashboard usually hides.
 */
export default function GapsPage() {
  const { investigationId } = useUi();
  const { data, isLoading, isError } = useResearchGaps(investigationId);
  const [onlyNovel, setOnlyNovel] = React.useState(false);

  const gaps: Gap[] = data?.gaps ?? [];
  const novelAreas = data?.novel_areas ?? [];
  const shown = onlyNovel ? gaps.filter((g) => g.novel) : gaps;

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Gap analysis"
        description="Open questions ranked by how little supports them, plus the areas the corpus covers that nobody has asked about."
      />

      {!investigationId && (
        <SampleDataBanner note="select an investigation to load its gap analysis." />
      )}
      {isError && (
        <Card className="border-destructive/40">
          <CardContent className="p-4 text-sm text-destructive">
            Could not load the gap analysis. Check that the backend is reachable.
          </CardContent>
        </Card>
      )}
      {isLoading && <Skeleton className="h-64 w-full" />}

      {investigationId && !isLoading && gaps.length === 0 && novelAreas.length === 0 && (
        <Card className="border-dashed">
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            No gaps recorded yet — run some research against this investigation first.
          </CardContent>
        </Card>
      )}

      {gaps.length > 0 && (
        <Card>
          <CardHeader className="flex-row items-start justify-between gap-3 space-y-0">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Search className="size-4 text-muted-foreground" aria-hidden />
                Open questions
              </CardTitle>
              <CardDescription>
                Sorted weakest-support first. A question with no supporting explanation is a
                hypothesis you have not tested yet.
              </CardDescription>
            </div>
            <Button variant="outline" size="sm" onClick={() => setOnlyNovel((v) => !v)}>
              {onlyNovel ? 'Show all' : 'Novel only'}
            </Button>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            {shown.map((g, i) => (
              <div
                key={`${g.question}-${i}`}
                className={cn(
                  'rounded-md border p-3',
                  g.novel && !g.supporting && 'border-evidence-contradicts/40 bg-evidence-contradicts/5',
                )}
              >
                <div className="flex items-start justify-between gap-3">
                  <p className="text-sm">{g.question}</p>
                  <Badge variant={g.novel ? 'default' : 'muted'} className="shrink-0">
                    {g.novel ? 'novel' : `${g.supporting} supporting`}
                  </Badge>
                </div>
                {g.kinds && g.kinds.length > 0 && (
                  <div className="mt-1.5 flex flex-wrap gap-1">
                    {g.kinds.map((k) => (
                      <Badge key={k} variant="outline" className="text-[10px]">
                        {k}
                      </Badge>
                    ))}
                  </div>
                )}
              </div>
            ))}
            {shown.length === 0 && (
              <p className="py-6 text-center text-sm text-muted-foreground">
                No novel gaps — every open question has supporting material.
              </p>
            )}
          </CardContent>
        </Card>
      )}

      {novelAreas.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Lightbulb className="size-4 text-evidence-modality" aria-hidden />
              Unasked areas
            </CardTitle>
            <CardDescription>
              Topics the corpus already covers that no investigation has raised as a question.
              These are the cheapest sources of a genuinely new scenario.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="flex flex-wrap gap-2">
              {novelAreas.map((a) => (
                <li key={a.topic}>
                  <span className="inline-flex items-center gap-1.5 rounded-full border border-evidence-modality/40 bg-evidence-modality/5 px-3 py-1 text-xs">
                    <Compass className="size-3" aria-hidden />
                    {a.topic}
                    <span className="tabular text-muted-foreground">{a.artifacts}</span>
                  </span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  );
}