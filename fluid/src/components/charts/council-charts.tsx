'use client';

/**
 * Charts for one hypothesis assessment's council review.
 *
 * Four charts, one per analytical question, all derived from the stored
 * claims and the stored coverage matrix (via the endpoint's `analytics`
 * block) — never recomputed, sampled, or estimated:
 *
 *   ConfidenceChart — where does confidence concentrate? Amber contested,
 *     grey uncontested with a dashed mean. An uncontested bar is dimmed,
 *     never hidden: the reader must see what nobody attacked.
 *   GroundsChart    — where did the objections concentrate?
 *   CoverageDonut   — how much of the attack surface was never examined?
 *     Covered / unexamined / corpus-silent as shares of the whole taxonomy.
 *   SeatsChart      — who did the work? Filed beside reviewing per seat; the
 *     gap between the two bars is the seat's reviewing load, so they are
 *     never merged into one number.
 */
import * as React from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  LabelList,
  Legend,
  Pie,
  PieChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { cn } from '@/lib/utils';

const AMBER = 'hsl(var(--warning, 38 92% 50%))';
const MUTED = 'hsl(var(--muted-foreground))';
const TEAL = 'hsl(var(--teal, 174 72% 40%))';
const GRID = 'hsl(var(--border))';

export interface CouncilClaimDatum {
  id: string;
  confidence: number;
  contested: boolean;
  seat?: string;
}

export interface CouncilChartsProps {
  claims: CouncilClaimDatum[];
  grounds: Record<string, number>;
  coverage: { covered: number; unexamined: number; silent: number; pct: number | null };
  seats: { seat: string; filed: number; reviewing: number }[];
  className?: string;
}

function ChartShell({
  title,
  hint,
  height = 150,
  children,
}: {
  title: string;
  hint?: string;
  height?: number;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-md border p-3">
      <h5 className="mb-1 text-xs font-semibold">{title}</h5>
      {hint && <p className="mb-2 text-[11px] text-muted-foreground">{hint}</p>}
      <div
        style={{ height }}
        role="img"
        aria-label={hint ? `${title}. ${hint}` : title}
      >
        <ResponsiveContainer width="100%" height="100%">
          {children}
        </ResponsiveContainer>
      </div>
    </div>
  );
}

function NumTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: { value?: number | string }[];
  label?: string;
}) {
  if (!active || !payload || payload.length === 0) return null;
  const first = payload[0]?.value;
  if (first === undefined) return null;
  return (
    <div className="rounded-md border bg-popover px-2 py-1 text-xs">
      <b>{label}</b>: {first}
    </div>
  );
}

export function CouncilCharts({ claims, grounds, coverage, seats, className }: CouncilChartsProps) {
  const mean =
    claims.length > 0
      ? claims.reduce((a, c) => a + c.confidence, 0) / claims.length
      : null;

  const groundEntries = Object.entries(grounds).sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1));
  const maxGround = Math.max(0, ...groundEntries.map(([, n]) => n));

  const donut = [
    { key: 'covered', label: 'Covered — a seat claimed it', n: coverage.covered, fill: TEAL },
    {
      key: 'unexamined',
      label: 'Unexamined — evidence exists, no seat claimed it',
      n: coverage.unexamined,
      fill: AMBER,
    },
    {
      key: 'silent',
      label: 'Corpus silent — unmeasured, not absent',
      n: coverage.silent,
      fill: MUTED,
    },
  ].filter((d) => d.n > 0);

  return (
    <div className={cn('grid grid-cols-1 gap-2.5 md:grid-cols-2', className)}>
      <ChartShell
        title="Confidence per claim"
        hint="Amber contested, grey unobjected. Dashed line is the mean."
        height={160}
      >
        <BarChart data={claims} margin={{ top: 12, right: 8, left: -18, bottom: 0 }}>
          <CartesianGrid strokeDasharray="2 4" stroke={GRID} vertical={false} />
          <XAxis
            dataKey="id"
            tick={{ fontSize: 10, fill: MUTED }}
            tickLine={false}
            axisLine={false}
            interval={0}
          />
          <YAxis
            domain={[0, 100]}
            tick={{ fontSize: 10, fill: MUTED }}
            tickLine={false}
            axisLine={false}
            width={34}
          />
          <Tooltip content={<NumTooltip />} cursor={{ fill: GRID, opacity: 0.3 }} />
          <Bar dataKey="confidence" radius={[3, 3, 0, 0]}>
            {claims.map((c) => (
              <Cell key={c.id} fill={c.contested ? AMBER : MUTED} opacity={c.contested ? 1 : 0.55} />
            ))}
            <LabelList
              dataKey="confidence"
              position="top"
              formatter={(v: unknown) => `${Math.round(Number(v))}`}
              style={{ fontSize: 10, fill: MUTED }}
            />
          </Bar>
          {mean != null && (
            <ReferenceLine
              y={mean}
              stroke={MUTED}
              strokeDasharray="4 3"
              label={{
                value: `mean ${Math.round(mean)}`,
                position: 'insideTopRight',
                fontSize: 10,
                fill: MUTED,
              }}
            />
          )}
        </BarChart>
      </ChartShell>

      <ChartShell
        title="Attack-class coverage"
        hint={
          coverage.pct != null
            ? `${coverage.pct}% of the classes the corpus speaks to.`
            : undefined
        }
        height={160}
      >
        <PieChart>
          <Pie
            data={donut}
            dataKey="n"
            nameKey="label"
            innerRadius="52%"
            outerRadius="80%"
            strokeWidth={1}
            stroke="hsl(var(--background))"
          >
            {donut.map((d) => (
              <Cell key={d.key} fill={d.fill} />
            ))}
          </Pie>
          <Tooltip content={<NumTooltip />} />
          <Legend
            layout="vertical"
            align="right"
            verticalAlign="middle"
            wrapperStyle={{ fontSize: 10 }}
            formatter={(value: string) => <span style={{ color: MUTED }}>{value}</span>}
          />
        </PieChart>
      </ChartShell>

      {groundEntries.length > 0 && (
        <ChartShell title="Objection grounds" hint="Where the objections concentrated." height={Math.max(90, groundEntries.length * 30 + 20)}>
          <BarChart
            data={groundEntries.map(([g, n]) => ({ ground: g.replace(/_/g, ' '), n }))}
            layout="vertical"
            margin={{ top: 4, right: 30, left: 4, bottom: 4 }}
          >
            <CartesianGrid strokeDasharray="2 4" stroke={GRID} horizontal={false} />
            <XAxis
              type="number"
              domain={[0, Math.max(1, maxGround)]}
              tick={{ fontSize: 10, fill: MUTED }}
              tickLine={false}
              axisLine={false}
              allowDecimals={false}
            />
            <YAxis
              type="category"
              dataKey="ground"
              width={130}
              tick={{ fontSize: 10, fill: MUTED }}
              tickLine={false}
              axisLine={false}
            />
            <Tooltip content={<NumTooltip />} cursor={{ fill: GRID, opacity: 0.3 }} />
            <Bar dataKey="n" fill={AMBER} radius={[0, 3, 3, 0]}>
              <LabelList
                dataKey="n"
                position="right"
                style={{ fontSize: 10, fill: MUTED }}
              />
            </Bar>
          </BarChart>
        </ChartShell>
      )}

      {seats.length > 0 && (
        <ChartShell
          title="Seats — filed vs reviewing"
          hint="Filed beside reviewing for the same seat; the gap is the reviewing load."
          height={Math.max(110, seats.length * 34 + 40)}
        >
          <BarChart
            data={seats}
            layout="vertical"
            margin={{ top: 4, right: 8, left: 4, bottom: 4 }}
          >
            <CartesianGrid strokeDasharray="2 4" stroke={GRID} horizontal={false} />
            <XAxis
              type="number"
              tick={{ fontSize: 10, fill: MUTED }}
              tickLine={false}
              axisLine={false}
              allowDecimals={false}
            />
            <YAxis
              type="category"
              dataKey="seat"
              width={130}
              tick={{ fontSize: 10, fill: MUTED }}
              tickLine={false}
              axisLine={false}
            />
            <Tooltip content={<NumTooltip />} cursor={{ fill: GRID, opacity: 0.3 }} />
            <Legend wrapperStyle={{ fontSize: 10 }} />
            <Bar dataKey="filed" name="Filed" fill={TEAL} radius={[0, 3, 3, 0]} />
            <Bar dataKey="reviewing" name="Reviewing" fill={AMBER} radius={[0, 3, 3, 0]} />
          </BarChart>
        </ChartShell>
      )}
    </div>
  );
}

