import React, { useMemo, useState } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from 'recharts';
import type { Framework } from '../lib/engine';
import { coveragePercent } from '../lib/engine';
import { SUPPORT_MODES } from '../lib/support';
import type { SupportMode } from '../lib/support';
import { supportDistribution } from '../lib/support';
import { useTabNav } from '../lib/tabs';

const MODE_IDS = SUPPORT_MODES.map((m) => m.id);

function SupportCharts({ frameworks, modeId }: { frameworks: Framework[]; modeId: SupportMode }) {
  const mode = SUPPORT_MODES.find((m) => m.id === modeId)!;
  const dist = useMemo(() => supportDistribution(frameworks, mode), [frameworks, mode]);
  const top = useMemo(() => [...frameworks].sort((a, b) => coveragePercent(b) - coveragePercent(a)).slice(0, 6), [frameworks]);

  return (
    <div className="chart-grid">
      <div className="chart-card">
        <h3>{mode.label} — distribution</h3>
        <ResponsiveContainer width="100%" height={240}>
          <BarChart data={dist}>
            <XAxis dataKey="name" tick={{ fill: '#9fb0c0', fontSize: 11 }} interval={0} angle={-14} dy={10} height={60} />
            <YAxis tick={{ fill: '#9fb0c0', fontSize: 11 }} />
            <Tooltip contentStyle={{ background: '#0c1117', border: '1px solid #26303c', borderRadius: 8 }} />
            <Bar dataKey="value" radius={[6, 6, 0, 0]}>
              {dist.map((d, i) => <Cell key={i} fill={d.color} />)}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
        <p className="muted" style={{ fontSize: 12 }}>{mode.description}</p>
      </div>

      <div className="chart-card">
        <h3>Share</h3>
        <ResponsiveContainer width="100%" height={240}>
          <PieChart>
            <Pie data={dist} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={78} label={({ name, percent }: { name?: string; percent?: number }) => `${(name ?? '').slice(0, 10)} ${((percent ?? 0) * 100).toFixed(0)}%`}>
              {dist.map((d, i) => <Cell key={i} fill={d.color} />)}
            </Pie>
            <Tooltip contentStyle={{ background: '#0c1117', border: '1px solid #26303c', borderRadius: 8 }} />
            <Legend wrapperStyle={{ fontSize: 11, color: '#9fb0c0' }} />
          </PieChart>
        </ResponsiveContainer>
      </div>

      <div className="chart-card" style={{ gridColumn: '1 / -1' }}>
        <h3>Frameworks — {mode.short} mapping (top coverage)</h3>
        <div className="matrix-wrap"><table className="matrix" style={{ width: '100%' }}>
          <thead><tr><th>Framework</th><th>{mode.short}</th><th>Coverage</th></tr></thead>
          <tbody>
            {top.map((f) => (
              <tr key={f.id}><th style={{ textAlign: 'left' }}>{f.id.slice(0, 18)}</th>
                <td>{mode.getValues(f).map((v) => <span key={v} className="chip" style={{ borderColor: mode.color, fontSize: 11, marginRight: 4 }}>{v}</span>)}</td>
                <td><span className="muted">{coveragePercent(f)}%</span></td></tr>
            ))}
          </tbody>
        </table></div>
      </div>
    </div>
  );
}

export default function SupportMaterials({ frameworks }: { frameworks: Framework[] }) {
  const [mode, setMode] = useState<SupportMode>('consumption');
  const modeNav = useTabNav('support-mode', MODE_IDS, mode, setMode);
  const [filter, setFilter] = useState('');

  const filtered = useMemo(() => {
    if (!filter.trim()) return frameworks;
    const q = filter.toLowerCase();
    return frameworks.filter((f) => f.name.toLowerCase().includes(q) || f.id.toLowerCase().includes(q) || SUPPORT_MODES.find((m) => m.id === mode)!.getValues(f).join(' ').toLowerCase().includes(q));
  }, [frameworks, filter, mode]);

  return (
    <div className="layout" style={{ padding: 0, gap: 16 }}>
      <section className="card">
        <h2>Support Materials — AI consumption, exposure, data & parties</h2>
        <p className="muted">Seven lenses to operationalize the 34 frameworks. Pick a lens, see distribution, share and per-framework mapping. All lenses are derived from the curated controls/scenarios/riskTiers + coverage — no extra manual data.</p>
        <div className="persona-switch" role={modeNav.listProps.role} onKeyDown={modeNav.listProps.onKeyDown} aria-label="Support modes">
          {SUPPORT_MODES.map((m) => (
            <button key={m.id} {...modeNav.itemProps(m.id)} className={`persona-pill ${mode === m.id ? 'active' : ''}`} style={{ borderColor: m.color, color: mode === m.id ? m.color : undefined }}>{m.icon} {m.short}</button>
          ))}
        </div>
        <div className="row" style={{ marginTop: 8 }}>
          <input aria-label="Filter support" placeholder="Filter frameworks or values…" value={filter} onChange={(e) => setFilter(e.target.value)} />
          <span className="muted">{filtered.length} frameworks</span>
        </div>
      </section>

      <SupportCharts frameworks={filtered} modeId={mode} />

      <section className="card">
        <h3>All lenses — at a glance</h3>
        <div className="chart-grid">
          {SUPPORT_MODES.map((m) => {
            const d = supportDistribution(frameworks, m);
            return (
              <div key={m.id} className="chart-card" style={{ padding: 10 }}>
                <h3 style={{ fontSize: 12, display: 'flex', gap: 6, alignItems: 'center' }}><span style={{ color: m.color }}>{m.icon}</span> {m.short}</h3>
                <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                  {d.slice(0, 5).map((x) => <span key={x.name} className="chip" style={{ fontSize: 11, borderColor: m.color }}>{x.name} · {x.value}</span>)}
                </div>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
}
