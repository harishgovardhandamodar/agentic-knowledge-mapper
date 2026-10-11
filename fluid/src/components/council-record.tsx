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

  const logs = (record.logs ?? []).filter((l) => (l.hops ?? []).length > 0);
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
            title="Logs — the deliberation"
          >
            <ol className="flex list-decimal flex-col gap-2 pl-5 text-sm">
              {logs.flatMap((l) =>
                (l.hops ?? []).map((hop, i) => (
                  <li key={`${l.assessment_id}-${i}`} className="leading-relaxed">
                    <b>{hop.agent}</b>{' '}
                    <code className="text-[11px] text-muted-foreground">{hop.intent}</code>
                    {hop.note ? <span> — {hop.note}</span> : null}
                    <span className="ml-2 text-[11px] text-muted-foreground">
                      #{l.assessment_id} {l.path}
                    </span>
                  </li>
                )),
              )}
            </ol>
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
