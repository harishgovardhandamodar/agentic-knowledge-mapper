import React, { useMemo } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar, PieChart, Pie, Cell, Legend } from 'recharts';
import { coveragePercent } from '../lib/engine';
import type { Framework, Dimension } from '../lib/engine';
import Mermaid from './Mermaid';
import type { Persona } from '../lib/persona';
import { personaFrameworks, personaDimCoverage } from '../lib/persona';

function PillarsSummary({ frameworks, dimensions }: { frameworks: import('../lib/engine').Framework[]; dimensions: import('../lib/engine').Dimension[] }) {
  const pillars = dimensions.map((d) => {
    const avg = frameworks.length ? frameworks.reduce((s, f) => s + ((f.coverage[d.id] ?? 0) / 2), 0) / frameworks.length : 0;
    const pct = Math.round(avg * 100);
    const status = pct >= 70 ? 'Strong' : pct >= 40 ? 'Partial' : 'Gap';
    const color = pct >= 70 ? '#7bd389' : pct >= 40 ? '#f4d35e' : '#e71d36';
    return { dim: d, pct, status, color };
  });
  const [showDefs, setShowDefs] = React.useState(false);
  const [showPillarFw, setShowPillarFw] = React.useState(false);
  const overall = Math.round(pillars.reduce((s, p) => s + p.pct, 0) / pillars.length);
  const definitions: Record<string, { def: string; mermaid: string }> = {
    risk_management: { def: 'Risk tiering, impact assessment, conformity and continuous monitoring per EU AI Act / NIST RMF.', mermaid: 'flowchart LR\n  A[Use Case] --> B{Risk Tier?}\n  B -->|High| C[Conformity + Human Oversight]\n  B -->|Limited| D[Transparency]\n  B -->|Minimal| E[Voluntary Code]' },
    data_governance: { def: 'Training data quality, provenance, bias control and documentation (ISO 42001, EU AI Act Art.10).', mermaid: 'flowchart TD\n  D1[Raw Data] --> D2[Quality Checks]\n  D2 --> D3[Bias Test]\n  D3 --> D4[Provenance Card]\n  D4 --> D5[Approved Dataset]' },
    transparency: { def: 'Model cards, disclosure of AI interaction and synthetic content labeling.', mermaid: 'sequenceDiagram\n  participant U as User\n  participant S as System\n  S->>U: disclose AI use\n  S->>U: label synthetic content' },
    robustness: { def: 'Evals, red-teaming, capability thresholds and safe deployment (UK AISI Inspect).', mermaid: 'flowchart LR\n  T[Test] --> R[Red Team]\n  R --> E[Eval]\n  E -->|pass| D[Deploy]\n  E -->|fail| F[Fix]' },
    security: { def: 'Prompt injection, supply chain, ATLAS/OWASP mitigations and access control.', mermaid: 'flowchart TD\n  I[Input] --> F[Filter]\n  F --> M[LLM]\n  M --> O[Output Filter]\n  O --> U[User]' },
    privacy: { def: 'PII minimization, inference leakage, DLP and data subject rights (NIST, UNESCO).', mermaid: 'flowchart LR\n  P[PII] --> M[Minimize]\n  M --> A[Anonymize]\n  A -->S[Store]' },
    accountability: { def: 'Roles, policies, audit and AIMS (ISO 42001) — who owns what.', mermaid: 'flowchart TD\n  B[Board] --> C[CAIO]\n  C --> T[Team]\n  T --> A[Audit]' },
    human_oversight: { def: 'Human-in-the-loop, override/stop and deployer obligations for high-risk.', mermaid: 'flowchart LR\n  AI[AI] --> H{Human?}\n  H -->|yes| O[Override]\n  H -->|no| A[Auto]' },
    incident_response: { def: 'Logging, serious-incident reporting, post-market monitoring and recall.', mermaid: 'sequenceDiagram\n  participant M as Monitor\n  participant I as Incident\n  M->>I: detect\n  I->>M: report 72h' },
    lifecycle_eval: { def: 'Design→deploy→decommission, change management and third-party diligence.', mermaid: 'flowchart LR\n  D[Design] --> B[Build]\n  B --> V[Verify]\n  V --> O[Operate]\n  O --> R[Retire]' },
  };
  const strengths = [...pillars].sort((a,b)=>b.pct-a.pct).slice(0,3);
  const gaps = [...pillars].sort((a,b)=>a.pct-b.pct).slice(0,3);
  return (
    <div className="card" style={{ borderLeft: '4px solid #4da3ff' }}>
      <h3 style={{ margin: '0 0 8px', fontSize: 14 }}>Pillars of AI Governance — Executive Summary</h3>
      <p className="muted" style={{ fontSize: 12, margin: '0 0 10px' }}>10 pillars averaged across {frameworks.length} frameworks · overall maturity <strong style={{ color: overall>=70?'#7bd389':overall>=40?'#f4d35e':'#e71d36' }}>{overall}%</strong> · strengths in green, gaps in red</p>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 8 }}>
        {pillars.map((p) => (
          <div key={p.dim.id} style={{ background: '#0c1117', border: '1px solid #26303c', borderRadius: 10, padding: '8px 10px', borderLeft: `3px solid ${p.color}` }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: '#e8eef4' }}>{p.dim.label}</div>
            <div style={{ fontSize: 18, fontWeight: 700, color: p.color }}>{p.pct}%</div>
            <div className="muted" style={{ fontSize: 11 }}>{p.status} · {p.dim.description.slice(0, 60)}…</div>
          </div>
        ))}
      </div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 8 }}>
        <button className="chip" onClick={() => setShowDefs((v) => !v)}>{showDefs ? 'Hide definitions' : 'Show definitions & mermaid'}</button>
      </div>
      <div style={{ marginTop: 8, display: showDefs ? 'grid' : 'none', gap: 10 }}>
        {pillars.map((p) => {
          const info = definitions[p.dim.id];
          if (!info) return null;
          return (
            <details key={p.dim.id} open={showDefs} style={{ background: '#0c1117', border: '1px solid #26303c', borderRadius: 10, padding: '8px 10px' }}>
              <summary style={{ cursor: 'pointer', fontSize: 12, fontWeight: 600 }}>{p.dim.label} — {info.def.slice(0, 80)}…</summary>
              <p className="muted" style={{ fontSize: 12, margin: '6px 0' }}>{info.def}</p>
              <Mermaid code={info.mermaid} />
            </details>
          );
        })}
      </div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 8 }}>
        <button className="chip" onClick={() => setShowPillarFw((v) => !v)}>{showPillarFw ? 'Hide frameworks by pillar' : 'View frameworks by pillar — with confidence'}</button>
      </div>
      <div style={{ marginTop: 8, display: showPillarFw ? 'block' : 'none' }}>
        <h4 style={{ margin: '0 0 8px', fontSize: 13 }}>Frameworks by pillar — with confidence</h4>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 10 }}>
          {pillars.map((pp) => {
            const cov = frameworks
              .filter((f) => (f.coverage[pp.dim.id] ?? 0) > 0)
              .sort((a, b) => (b.coverage[pp.dim.id] ?? 0) - (a.coverage[pp.dim.id] ?? 0))
              .slice(0, 6);
            if (cov.length === 0) return null;
            return (
              <div key={pp.dim.id} style={{ background: '#0c1117', border: '1px solid #26303c', borderRadius: 10, padding: '8px 10px', borderLeft: `3px solid ${pp.color}` }}>
                <div style={{ fontSize: 12, fontWeight: 600 }}>{pp.dim.label} — {pp.pct}% avg</div>
                <div className="muted" style={{ fontSize: 11, marginBottom: 6 }}>{pp.dim.description.slice(0, 70)}…</div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {cov.map((f) => {
                    const v = f.coverage[pp.dim.id] ?? 0;
                    const label = v === 2 ? 'direct' : v === 1 ? 'partial' : 'none';
                    const bg = v === 2 ? '#1d5c34' : v === 1 ? '#7a5b17' : '#3a3f45';
                    return (
                      <span key={f.id} className="chip" style={{ fontSize: 11, borderColor: pp.color, background: bg, color: '#e8eef4' }} title={`${f.name} — ${label}`}>
                        {f.id.slice(0, 14)} · {label}
                      </span>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      </div>
      <div className="row" style={{ marginTop: 10, gap: 16, flexWrap: 'wrap' }}>
        <div><span className="muted" style={{ fontSize: 11 }}>Top strengths:</span> {strengths.map((s) => <span key={s.dim.id} className="chip" style={{ borderColor: s.color, fontSize: 11 }}>{s.dim.label} {s.pct}%</span>)}</div>
        <div><span className="muted" style={{ fontSize: 11 }}>Top gaps:</span> {gaps.map((s) => <span key={s.dim.id} className="chip" style={{ borderColor: s.color, fontSize: 11 }}>{s.dim.label} {s.pct}%</span>)}</div>
      </div>
    </div>
  );
}

interface TopFwDatum { name: string; coverage: number; full: string; excerpt: string; issuer: string; jurisdiction: string; kind: string; url: string; }

function TopFwTooltip({ active, payload }: { active?: boolean; payload?: ReadonlyArray<{ payload: TopFwDatum }> }) {
  if (!active || !payload?.[0]) return null;
  const d = payload[0].payload;
  return (
    <div style={{ background: '#0c1117', border: '1px solid #26303c', borderRadius: 10, padding: '10px 12px', maxWidth: 360, boxShadow: '0 8px 24px rgba(0,0,0,0.4)' }}>
      <div style={{ fontWeight: 700, fontSize: 12, color: '#e8eef4' }}>{d.full}</div>
      <div className="muted" style={{ fontSize: 11, margin: '4px 0' }}>{d.issuer} · {d.jurisdiction} · {d.kind} · {d.coverage}% coverage</div>
      <div style={{ fontSize: 12, lineHeight: 1.4, color: '#c8d0d8' }}>{d.excerpt}</div>
      <div className="muted" style={{ fontSize: 11, marginTop: 4 }}><a href={d.url} target="_blank" rel="noreferrer">source ↗</a></div>
    </div>
  );
}

function KPI({ label, value, color }: { label: string; value: string | number; color: string }) {
  return (
    <div className="kpi" style={{ borderColor: color }}>
      <div className="kpi-value" style={{ color }}>{value}</div>
      <div className="kpi-label">{label}</div>
    </div>
  );
}

export default function PersonaDashboard({
  persona, frameworks, dimensions,
}: {
  persona: Persona; frameworks: Framework[]; dimensions: Dimension[];
}) {
  const fws = useMemo(() => personaFrameworks(frameworks, persona), [frameworks, persona]);
  const dimCov = useMemo(() => personaDimCoverage(fws.length ? fws : frameworks, dimensions, persona), [fws, frameworks, dimensions, persona]);

  const topFws = useMemo(() => [...fws].sort((a, b) => coveragePercent(b) - coveragePercent(a)).slice(0, 8), [fws]);
  const topFwData = useMemo(() => topFws.map((f) => ({ name: f.id.slice(0, 14), coverage: coveragePercent(f), full: f.name, excerpt: f.summary.slice(0, 160) + '…', issuer: f.issuer, jurisdiction: f.jurisdiction, kind: f.kind, url: f.url })), [topFws]);
  const jurisdictionData = useMemo(() => {
    const m = new Map<string, number>();
    fws.forEach((f) => m.set(f.jurisdiction, (m.get(f.jurisdiction) ?? 0) + 1));
    return [...m.entries()].map(([name, value]) => ({ name: name.slice(0, 18), value })).sort((a, b) => b.value - a.value).slice(0, 6);
  }, [fws]);

  const radarData = dimCov.map(({ dim, avg }) => ({ dim: dim.label.slice(0, 14), coverage: Math.round(avg * 100) }));

  const COLORS = ['#4da3ff', '#ff9f1c', '#2ec4b6', '#e71d36', '#9d4edd', '#7bd389'];

  return (
    <div className="persona-dash">
      <div className="persona-header" style={{ borderColor: persona.color }}>
        <div>
          <h2 style={{ margin: 0, display: 'flex', gap: 8, alignItems: 'center' }}>
            <span style={{ color: persona.color }}>{persona.icon}</span> {persona.label}
          </h2>
          <p className="muted" style={{ margin: '4px 0 0' }}>{persona.description}</p>
        </div>
        <div className="persona-meta muted">
          {fws.length} of {frameworks.length} frameworks · {persona.dimensions.length} focus dimensions
        </div>
      </div>

      {persona.id === 'csuite' && <PillarsSummary frameworks={frameworks} dimensions={dimensions} />}
      <div className="kpi-row">
        {persona.kpis.map((k) => (
          <KPI key={k.label} label={k.label} value={k.get(fws.length ? fws : frameworks, dimensions)} color={persona.color} />
        ))}
        <KPI label="Relevant Frameworks" value={fws.length} color={persona.color} />
        <KPI label="Avg Coverage (focus)" value={`${Math.round(dimCov.reduce((s, d) => s + d.avg, 0) / dimCov.length * 100) || 0}%`} color={persona.color} />
      </div>

      <div className="chart-grid">
        <div className="chart-card">
          <h3>Focus dimensions — radar</h3>
          <ResponsiveContainer width="100%" height={260}>
            <RadarChart data={radarData}>
              <PolarGrid stroke="#2b3644" />
              <PolarAngleAxis dataKey="dim" tick={{ fill: '#9fb0c0', fontSize: 11 }} />
              <PolarRadiusAxis angle={30} domain={[0, 100]} tick={{ fill: '#6b7a8a', fontSize: 10 }} />
              <Radar dataKey="coverage" stroke={persona.color} fill={persona.color} fillOpacity={0.35} />
              <Tooltip contentStyle={{ background: '#0c1117', border: '1px solid #26303c', borderRadius: 8 }} />
            </RadarChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card">
          <h3>Top frameworks — coverage</h3>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={topFwData} layout="vertical">
              <XAxis type="number" domain={[0, 100]} tick={{ fill: '#9fb0c0', fontSize: 11 }} />
              <YAxis dataKey="name" type="category" width={110} tick={{ fill: '#c8d0d8', fontSize: 11 }} />
              <Tooltip content={<TopFwTooltip />} />
              <Bar dataKey="coverage" fill={persona.color} radius={[0, 6, 6, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card">
          <h3>Jurisdiction mix</h3>
          <ResponsiveContainer width="100%" height={260}>
            <PieChart>
              <Pie data={jurisdictionData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={88} label={({ name, percent }) => `${name} ${((percent ?? 0) * 100).toFixed(0)}%`}>
                {jurisdictionData.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
              </Pie>
              <Tooltip contentStyle={{ background: '#0c1117', border: '1px solid #26303c', borderRadius: 8 }} />
              <Legend wrapperStyle={{ fontSize: 11, color: '#9fb0c0' }} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card">
          <h3>Scenario applicability</h3>
          <div className="chips" style={{ marginBottom: 8 }}>
            {Array.from(new Set(fws.flatMap((f) => f.scenarios))).slice(0, 14).map((s) => (
              <span key={s} className="chip" style={{ borderColor: persona.color, fontSize: 11 }}>{s}</span>
            ))}
          </div>
          <p className="muted" style={{ fontSize: 12 }}>
            {fws.length ? `${fws.length} frameworks filtered for this persona. Toggle the global search to narrow further, or switch persona for a different lens.` : 'No frameworks match this lens — try another persona.'}
          </p>
        </div>
      </div>
    </div>
  );
}
