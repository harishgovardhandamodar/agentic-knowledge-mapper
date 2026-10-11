'use client';

/**
 * The review panel behind a hypothesis assessment.
 *
 * A claim list on its own does not say who wrote it, who attacked it, or which
 * part of the attack surface nobody covered. The last omission is the
 * dangerous one: fifteen confident claims that never mention poisoning read as
 * thorough, and the reader has no way to notice the difference without being
 * shown it. So the gaps are shown next to the claims, in the same panel, with
 * the same visual weight.
 *
 * Three distinctions this component is careful not to collapse:
 *   - a class no seat covered ≠ a class that is safe
 *   - a claim no seat objected to ≠ a claim that is verified
 *   - a claim whose refutation test names nothing observable ≠ a falsifier
 */
import { EyeOff, MessageSquareWarning, ShieldHalf, Microscope } from 'lucide-react';
import type { Assessment } from '@/lib/api/schemas';
import { cn } from '@/lib/utils';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './ui/card';
import { Badge } from './ui/badge';

type Seat = NonNullable<NonNullable<Assessment['council']>['panel']> extends infer P
  ? P extends { seats?: infer S }
    ? S extends Array<infer E>
      ? E
      : never
    : never
  : never;

type AttackClass = NonNullable<
  NonNullable<Assessment['council']>['coverage']
> extends infer C
  ? C extends { unexamined?: infer U }
    ? U extends Array<infer E>
      ? E
      : never
    : never
  : never;

export function CouncilPanel({
  assessment,
  className,
}: {
  assessment: Assessment;
  className?: string;
}) {
  const council = assessment.council;
  if (!council?.panel && !council?.coverage) return null;

  const panel = council?.panel;
  const coverage = council?.coverage;
  const seats = (panel?.seats ?? []) as Seat[];
  const contributing = new Set(council?.seats_contributing ?? []);
  const unexamined = (coverage?.unexamined ?? []) as AttackClass[];
  const notInCorpus = (coverage?.not_in_corpus ?? []) as AttackClass[];
  const contested = council?.contested ?? 0;
  const noObjection = council?.unexamined ?? 0;

  if (seats.length === 0 && unexamined.length === 0 && notInCorpus.length === 0) {
    return null;
  }

  return (
    <Card className={cn('border-dashed', className)}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <ShieldHalf className="size-4 text-muted-foreground" aria-hidden />
          The council
        </CardTitle>
        <CardDescription>
          {panel?.n_seats ?? seats.length} reviewer seats sat on this review,{' '}
          {contributing.size} filed a claim, and {contested} were contested by a seat that did not
          draft them. Each seat declares the weakness it is known to have — a panel that claims to
          cover everything covers nothing. Read the gaps alongside the claims.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {noObjection > 0 && (
          <p className="rounded-md border border-evidence-contradicts/40 bg-evidence-contradicts/5 p-3 text-sm">
            <b>{noObjection} claim(s) drew no objection at all.</b> Read that as the reach of this
            review, not as the claim&rsquo;s safety: unattacked is not the same as unrefutable, and
            the scoring treats it that way.
          </p>
        )}

        {unexamined.length > 0 && (
          <div>
            <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold">
              <EyeOff className="size-4 text-muted-foreground" aria-hidden />
              Unreached by the panel — evidence exists, no seat claimed it
            </h3>
            <p className="mb-2 text-xs text-muted-foreground">
              That is a gap in the review, not a clean result.
            </p>
            <ul className="flex flex-col gap-1.5">
              {unexamined.map((c) => (
                <li
                  key={c.class}
                  className="flex flex-wrap items-center gap-2 rounded-md border border-dashed p-2 text-sm"
                >
                  <span>{c.label ?? c.class}</span>
                  <code className="text-[11px] text-muted-foreground">{c.class}</code>
                  {c.severity != null && (
                    <Badge variant="outline" className="text-[10px]">
                      severity {c.severity}
                    </Badge>
                  )}
                  <span className="text-xs text-muted-foreground">
                    {c.stored_rows ?? 0} stored row(s) bear on this
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {notInCorpus.length > 0 && (
          <div>
            <h3 className="mb-1.5 flex items-center gap-2 text-sm font-semibold">
              <Microscope className="size-4 text-muted-foreground" aria-hidden />
              Out of scope — the corpus never mentions these
            </h3>
            <p className="text-xs text-muted-foreground">
              Unmeasured, which is not the same as absent.
            </p>
            <div className="mt-1.5 flex flex-wrap gap-1.5">
              {notInCorpus.map((c) => (
                <Badge key={c.class} variant="muted" className="text-[10px]">
                  {c.label ?? c.class}
                </Badge>
              ))}
            </div>
          </div>
        )}

        {coverage?.coverage_pct != null && (
          <p className="text-xs text-muted-foreground">
            Attack-class coverage <b className="tabular">{coverage.coverage_pct}%</b> of the classes
            the stored corpus speaks to.
          </p>
        )}

        {seats.length > 0 && (
          <ul className="grid grid-cols-1 gap-2 md:grid-cols-2">
            {seats.map((s) => {
              const spoke = contributing.has(s.id);
              return (
                <li
                  key={s.id}
                  className={cn(
                    'rounded-md border p-3',
                    spoke ? 'border-border' : 'border-dashed opacity-90',
                  )}
                >
                  <div className="mb-1.5 flex items-baseline justify-between gap-2">
                    <b className="text-sm">{s.discipline}</b>
                    <span className="whitespace-nowrap text-[10px] uppercase tracking-wide text-muted-foreground">
                      {spoke ? 'filed a claim' : 'stayed silent'}
                    </span>
                  </div>
                  <p className="text-xs leading-relaxed text-foreground">{s.remit}</p>
                  <p className="mt-1.5 flex gap-1.5 border-t border-dashed pt-1.5 text-[11px] leading-relaxed text-muted-foreground">
                    <MessageSquareWarning className="mt-0.5 size-3 shrink-0" aria-hidden />
                    <span>
                      <b>Blind spot:</b> {s.blind_spot}
                    </span>
                  </p>
                </li>
              );
            })}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
