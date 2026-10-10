'use client';

import * as React from 'react';
import { Compass, Lightbulb, Search } from 'lucide-react';
import { useResearchGaps, useRuledOutGaps, useSetGapStatus } from '@/lib/api/queries';
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
  lifecycle?: { status: string; evidence?: string | null; decided_by?: string | null };
};

const LIFECYCLE_LABEL: Record<string, string> = {
  open: 'Open',
  investigating: 'Investigating',
  answered: 'Answered',
  ruled_out: 'Ruled out',
  verified: 'Verified',
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
  const { data: ruledOut } = useRuledOutGaps(investigationId);
  const setStatus = useSetGapStatus(investigationId);
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
                  <div className="flex shrink-0 items-center gap-1.5">
                    {g.lifecycle && g.lifecycle.status !== 'open' && (
                      <Badge variant="outline" className="text-[10px]">
                        {LIFECYCLE_LABEL[g.lifecycle.status] ?? g.lifecycle.status}
                      </Badge>
                    )}
                    <Badge variant={g.novel ? 'default' : 'muted'}>
                      {g.novel ? 'novel' : `${g.supporting} supporting`}
                    </Badge>
                  </div>
                </div>
                <GapActions
                  status={g.lifecycle?.status ?? 'open'}
                  onSet={(status, evidence) =>
                    setStatus.mutate({ question: g.question, status, evidence })
                  }
                />
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

      {ruledOut && ruledOut.count > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              Ruled out
              <Badge variant="outline">{ruledOut.count}</Badge>
            </CardTitle>
            <CardDescription>
              Investigated and found absent — with what ruled each one out. These stop
              the next researcher re-investigating the same dead end.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="flex flex-col gap-2">
              {ruledOut.ruled_out.map((r) => (
                <li key={r.question} className="rounded-md border p-3 text-sm">
                  <p>{r.question}</p>
                  <p className="mt-1 text-xs text-muted-foreground">
                    Ruled out by {r.evidence ?? 'unnamed evidence'}
                    {r.decided_by ? ` · ${r.decided_by}` : ''}
                  </p>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function GapActions({
  status,
  onSet,
}: {
  status: string;
  onSet: (status: string, evidence?: string) => void;
}) {
  const [rulingOut, setRulingOut] = React.useState(false);
  const [evidence, setEvidence] = React.useState('');
  const [error, setError] = React.useState<string | null>(null);

  if (rulingOut) {
    return (
      <div className="mt-2 flex flex-col gap-1.5">
        <div className="flex gap-1.5">
          <input
            value={evidence}
            onChange={(e) => setEvidence(e.target.value)}
            placeholder="What ruled it out? (required)"
            className="min-w-0 flex-1 rounded-md border bg-background px-2 py-1 text-xs"
          />
          <Button
            size="sm"
            variant="outline"
            onClick={() => {
              if (!evidence.trim()) {
                setError('Ruling out requires naming the evidence.');
                return;
              }
              setError(null);
              onSet('ruled_out', evidence.trim());
              setRulingOut(false);
              setEvidence('');
            }}
          >
            Rule out
          </Button>
          <Button size="sm" variant="ghost" onClick={() => setRulingOut(false)}>
            Cancel
          </Button>
        </div>
        {error && <p className="text-[11px] text-destructive">{error}</p>}
      </div>
    );
  }

  return (
    <div className="mt-2 flex flex-wrap gap-1.5">
      {status === 'open' && (
        <Button size="sm" variant="ghost" onClick={() => onSet('investigating')}>
          Investigate
        </Button>
      )}
      {status === 'investigating' && (
        <>
          <Button size="sm" variant="ghost" onClick={() => onSet('answered')}>
            Mark answered
          </Button>
          <Button size="sm" variant="ghost" onClick={() => setRulingOut(true)}>
            Rule out…
          </Button>
        </>
      )}
      {(status === 'answered' || status === 'ruled_out') && (
        <Button size="sm" variant="ghost" onClick={() => onSet('open')}>
          Reopen
        </Button>
      )}
    </div>
  );
}