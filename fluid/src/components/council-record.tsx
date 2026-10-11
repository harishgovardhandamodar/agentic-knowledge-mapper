'use client';

/**
 * The council's paper trail for one investigation: logs, actions, decisions
 * and generated hypotheses.
 *
 * The artifacts views show what an investigation *collected*. This shows what
 * the council *did*: the A2A deliberation log (which seat spoke, with what
 * intent, what it concluded), what humans changed, which verdicts stand, and
 * the generated claims with their seats and objections.
 *
 * Rendered from GET /investigations/{id}/council-record, which reads stored
 * rows only. A record that recomputed would be a different review from the one
 * whose scores sit beside it — and on an investigation with no hypothesis
 * assessment the hypotheses section is empty rather than invented. Two labels
 * this component never confuses:
 *   - a claim no seat objected to is unreviewed, not verified;
 *   - an attack class nobody reached is unmeasured, not absent.
 */
import { FlaskConical, Gavel, Hand, ListOrdered } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './ui/card';
import { Badge } from './ui/badge';
import { Skeleton } from './ui/skeleton';
import { cn } from '@/lib/utils';
import type { CouncilRecord } from '@/lib/api/schemas';
import { CouncilCharts } from '@/components/charts/council-charts';

function Section({
  icon,
  title,
  hint,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <h3 className="mb-1.5 flex items-center gap-2 text-sm font-semibold">
        <span className="text-muted-foreground" aria-hidden>
          {icon}
        </span>
        {title}
      </h3>
      {hint && <p className="mb-2 text-xs text-muted-foreground">{hint}</p>}
      {children}
    </div>
  );
}

/**
 * Numbered dispatch → worker pairs, not a flat hop list. Step 0 is the plan
 * itself; each step shows what went in and what came out; an incomplete or
 * failed step is marked as such rather than silently ending the list.
 */
function PlanSteps({
  steps,
}: {
  steps: NonNullable<NonNullable<CouncilRecord['logs']>[number]['plan']>;
}) {
  return (
    <ol className="relative flex flex-col gap-2.5 border-l-2 border-border pl-0 text-sm">
      {steps.map((st) => {
        const open = st.status !== 'done' && st.status !== 'planned';
        return (
          <li key={`${st.n}-${st.phase}`} className="relative pl-6 leading-relaxed">
            <span
              aria-hidden
              className={cn(
                'absolute left-0 top-0.5 flex size-5 -translate-x-1/2 items-center justify-center rounded-full text-[10px] font-bold',
                open ? 'bg-amber-500 text-black' : 'bg-muted text-foreground',
              )}
            >
              {st.n}
            </span>
            <div>
              <b>{st.phase}</b>{' '}
              <span className="text-xs text-muted-foreground">
                {st.worker ? `${st.by ?? ''} → ${st.worker}` : (st.by ?? '')}
                {st.duration_s != null ? ` · ${st.duration_s}s` : ''}
              </span>
            </div>
            {st.plan ? <div className="text-xs">{st.plan}</div> : null}
            {st.input_note ? (
              <div className="text-xs">
                <span className="text-muted-foreground">in: </span>
                {st.input_note}
              </div>
            ) : null}
            {st.output_note ? (
              <div className="text-xs">
                <span className="text-muted-foreground">out: </span>
                {st.output_note}
              </div>
            ) : null}
            {open ? (
              <div className="text-xs font-semibold text-amber-600 dark:text-amber-400">
                {st.status}
              </div>
            ) : null}
          </li>
        );
      })}
    </ol>
  );
}

export function CouncilRecordView({
  record,
  isLoading,
  className,
}: {
  record: CouncilRecord | undefined;
  isLoading?: boolean;
  className?: string;
}) {
  if (isLoading) return <Skeleton className="h-40 w-full" />;
  if (!record) return null;

  const logs = (record.logs ?? []).filter(
    (l) => (l.plan ?? []).length > 0 || (l.hops ?? []).length > 0,
  );
  const decisions = (record.decisions ?? []).filter((d) => d.assurance_decision);
  const claimCount = (record.hypotheses ?? []).reduce(
    (n, h) => n + (h.claims ?? []).length,
    0,
  );
  if (logs.length === 0 && claimCount === 0 && decisions.length === 0) return null;

  return (
    <Card className={cn('border-dashed', className)}>
      <CardHeader>
        <CardTitle className="text-base">Council record</CardTitle>
        <CardDescription>
          Logs, actions, decisions and generated hypotheses for the security and privacy
          analysis — the deliberation, not the collection. A claim no seat objected to is
          unreviewed, not verified.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-5">
        {logs.length > 0 && (
          <Section
            icon={<ListOrdered className="size-4" />}
            title="Logs — the plan, step by step"
          >
            {logs.map((l) => (
              <div key={l.assessment_id} className="mb-3">
                <div className="mb-1.5 text-xs text-muted-foreground">
                  #{l.assessment_id} {l.path}
                </div>
                {(l.plan ?? []).length > 0 ? (
                  <PlanSteps steps={l.plan ?? []} />
                ) : (
                  <ol className="flex list-decimal flex-col gap-2 pl-5 text-sm">
                    {(l.hops ?? []).map((hop, i) => (
                      <li key={`${l.assessment_id}-${i}`} className="leading-relaxed">
                        <b>{hop.agent}</b>{' '}
                        <code className="text-[11px] text-muted-foreground">{hop.intent}</code>
                        {hop.note ? <span> — {hop.note}</span> : null}
                      </li>
                    ))}
                  </ol>
                )}
              </div>
            ))}
          </Section>
        )}

        {(record.actions ?? []).length > 0 && (
          <Section icon={<Hand className="size-4" />} title="Actions — what humans did">
            <ul className="flex flex-col gap-1.5 text-sm">
              {(record.actions ?? []).map((a, i) => (
                <li key={i} className="leading-relaxed">
                  {a.kind === 'register_edit' && (
                    <>
                      Register edit:{' '}
                      <b>
                        {(a as { hypothesis_id?: string }).hypothesis_id ?? '—'}
                      </b>{' '}
                      → {(a as { status?: string }).status ?? 'untested'}
                    </>
                  )}
                  {a.kind === 'assurance_decision' && (
                    <>
                      Assurance verdict:{' '}
                      <b>{(a as { decision?: string }).decision}</b> by{' '}
                      {(a as { actor?: string }).actor ?? '?'}
                    </>
                  )}
                  {a.kind === 'assessment_requested' && (
                    <>
                      Assessment requested by {(a as { actor?: string }).actor ?? '?'}
                    </>
                  )}
                  {a.kind === 'artifact_reviews' && (
                    <>
                      {(a as { accepted_or_rejected?: number }).accepted_or_rejected ?? 0}{' '}
                      artifact(s) accepted or rejected
                    </>
                  )}
                </li>
              ))}
            </ul>
          </Section>
        )}

        {decisions.length > 0 && (
          <Section icon={<Gavel className="size-4" />} title="Decisions — the verdicts that stand">
            <ul className="flex flex-col gap-1.5 text-sm">
              {decisions.map((d) => (
                <li key={d.assessment_id} className="leading-relaxed">
                  <Badge variant="outline" className="mr-2 text-[10px]">
                    #{d.assessment_id}
                  </Badge>
                  <b>{d.assurance_decision}</b>
                  {d.decided_by ? <span> by {d.decided_by}</span> : null}
                  {d.note ? <span className="text-muted-foreground"> — {d.note}</span> : null}
                </li>
              ))}
            </ul>
          </Section>
        )}

        {(record.hypotheses ?? []).map((h) => {
          const an = h.analytics;
          const grounds = an?.grounds ? Object.entries(an.grounds) : [];
          const maxGround = Math.max(0, ...grounds.map(([, n]) => n));
          // Chart data comes straight from the stored claims and the stored
          // coverage matrix: contested flags, confidences, seats and class
          // lists as the review recorded them. Nothing here is estimated.
          const claims = (h.claims ?? []).filter(
            (c): c is NonNullable<typeof c> & { hypothesis_id?: string; id?: string } =>
              c.hypothesis_id != null || c.id != null,
          );
          const cov = (h as { council?: { coverage?: {
            covered?: unknown[]; unexamined?: unknown[]; not_in_corpus?: unknown[];
            coverage_pct?: number | null } } }).council?.coverage;
          const seats = Object.entries(an?.by_seat ?? {})
            .map(([seat, st]) => ({
              seat,
              filed: st?.filed ?? 0,
              reviewing: an?.reviewing?.[seat] ?? 0,
            }))
            .filter((r) => r.filed > 0 || r.reviewing > 0);
          return (
          <Section
            key={h.assessment_id}
            icon={<FlaskConical className="size-4" />}
            title={`Hypotheses — assessment #${h.assessment_id}`}
            hint={
              h.confidence != null
                ? `Confidence ${Math.round(h.confidence)}/100 — about the claims, not the system.`
                : undefined
            }
          >
            <ul className="flex flex-col gap-2.5">
              {(h.claims ?? []).map((c) => {
                const challenges = c.council?.challenges ?? [];
                return (
                  <li
                    key={c.hypothesis_id ?? c.id ?? c.claim}
                    className="rounded-md border-l-2 border-border pl-3 text-sm leading-relaxed"
                  >
                    <div>
                      <b>{c.hypothesis_id ?? c.id}</b> {c.claim}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      confidence {Math.round(c.confidence ?? 0)}/100 · stakes{' '}
                      {c.impact ?? '?'}/5
                      {c.council?.seat ? (
                        <>
                          {' '}
                          · seat <b className="text-foreground">{c.council.seat}</b>
                        </>
                      ) : null}{' '}
                      · refutation test {c.council?.falsifier_audit?.grade ?? 'ungraded'}
                      {c.status && c.status !== 'untested' ? (
                        <>
                          {' '}
                          · status <b className="text-foreground">{c.status}</b>
                        </>
                      ) : null}
                    </div>
                    {c.falsifier ? (
                      <div className="text-xs">Refuted by: {c.falsifier}</div>
                    ) : null}
                    {challenges.length > 0 && (
                      <div className="mt-0.5 text-xs text-muted-foreground">
                        Objected to by{' '}
                        {challenges
                          .map((ch) => `${ch.seat} (${(ch.ground ?? '').replace(/_/g, ' ')})`)
                          .join('; ')}
                        . Silence would be the review&rsquo;s reach, not the claim&rsquo;s safety.
                      </div>
                    )}
                  </li>
                );
              })}
            </ul>
            {an && (
              <div className="mt-3 grid grid-cols-2 gap-2 border-t pt-3 text-xs text-muted-foreground sm:grid-cols-4">
                <span>
                  <b className="tabular text-foreground">{an.n_claims}</b> claims
                </span>
                {an.mean_confidence != null && (
                  <span>
                    mean confidence{' '}
                    <b className="tabular text-foreground">{Math.round(an.mean_confidence)}/100</b>
                  </span>
                )}
                <span>
                  <b className="tabular text-foreground">{an.n_contested ?? 0}</b> contested
                  {an.pct_contested != null ? ` (${an.pct_contested}%)` : ''}
                </span>
                {(an.n_blocking ?? 0) > 0 && (
                  <span>
                    <b className="tabular text-foreground">{an.n_blocking}</b> blocking
                  </span>
                )}
              </div>
            )}
            {(claims.length > 0 || grounds.length > 0 || seats.length > 0) && (
              <div className="mb-1">
                <CouncilCharts
                  claims={claims.map((c) => ({
                    id: c.hypothesis_id ?? c.id ?? '?',
                    confidence: Math.max(0, Math.min(100, c.confidence ?? 0)),
                    contested: c.peer_reviewed === true,
                    seat: c.council?.seat,
                  }))}
                  grounds={Object.fromEntries(grounds)}
                  coverage={{
                    covered: cov?.covered?.length ?? an?.n_covered ?? 0,
                    unexamined: cov?.unexamined?.length ?? an?.n_unexamined ?? 0,
                    silent: cov?.not_in_corpus?.length ?? 0,
                    pct: cov?.coverage_pct ?? an?.coverage_pct ?? null,
                  }}
                  seats={seats}
                />
              </div>
            )}
            {grounds.length > 0 && (
              <div className="mt-2 flex max-w-xl flex-col gap-1">
                {grounds.map(([g, n]) => (
                  <div key={g} className="grid grid-cols-[150px_1fr_24px] items-center gap-2 text-[11px]">
                    <span className="truncate text-muted-foreground">{g.replace(/_/g, ' ')}</span>
                    <span className="block h-2 rounded bg-muted">
                      <span
                        className="block h-2 rounded bg-amber-500"
                        style={{ width: `${maxGround ? Math.round((100 * n) / maxGround) : 0}%` }}
                      />
                    </span>
                    <b className="text-right tabular-nums">{n}</b>
                  </div>
                ))}
              </div>
            )}
          </Section>
          );
        })}
      </CardContent>
    </Card>
  );
}
