import React, { useMemo, useState } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar } from 'recharts';
import type { Framework, Dimension } from '../lib/engine';
import { coveragePercent } from '../lib/engine';
import type { GNode, GraphData } from '../lib/graph';
import { SECURITY_TOPICS } from '../lib/security';
import type { SecurityTopic } from '../lib/security';
import { topicFrameworks } from '../lib/security';
import { useTabNav } from '../lib/tabs';

const STREAMS = ['all', 'traditional', 'evolved'] as const;

function TopicCard({ topic, frameworks }: { topic: SecurityTopic; frameworks: Framework[] }) {
  const fws = useMemo(() => topicFrameworks(frameworks, topic), [frameworks, topic]);
  const cov = useMemo(() => {
    // avg coverage for security-relevant dims
    const dims = ['security', 'robustness', 'privacy', 'incident_response'] as const;
    return fws.length ? Math.round(fws.reduce((s, f) => s + dims.reduce((a, d) => a + (f.coverage[d] ?? 0) / 2, 0) / dims.length, 0) / fws.length * 100) : 0;
  }, [fws]);

  return (
    <div className="chart-card" style={{ borderLeft: `3px solid ${topic.color}` }}>
      <h3 style={{ display: 'flex', gap: 6, alignItems: 'center' }}><span style={{ color: topic.color }}>{topic.icon}</span> {topic.label}</h3>
      <p className="muted" style={{ fontSize: 12, margin: '4px 0 8px' }}>{topic.description}</p>
      <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
        <span className="chip" style={{ borderColor: topic.color }}>{fws.length} frameworks</span>
        <span className="chip">avg sec coverage {cov}%</span>
        <span className="chip" style={{ borderColor: topic.color }}>{topic.stream === 'traditional' ? 'Traditional' : 'Evolved'}</span>
      </div>
      {fws.length > 0 && (
        <div className="matrix-wrap" style={{ marginTop: 8 }}>
          <table className="matrix" style={{ width: '100%' }}>
            <thead><tr><th>Framework</th><th>Coverage</th></tr></thead>
            <tbody>
              {fws.slice(0, 6).map((f) => <tr key={f.id}><th style={{ textAlign: 'left' }}>{f.id.slice(0, 18)}</th><td>{coveragePercent(f)}%</td></tr>)}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default function SecurityEvolved({ frameworks, dimensions, graph }: { frameworks: Framework[]; dimensions: Dimension[]; graph: GraphData | null }) {
  const [stream, setStream] = useState<'all' | 'traditional' | 'evolved'>('all');
  const streamNav = useTabNav('sec-stream', STREAMS, stream, setStream);
  const [topicId, setTopicId] = useState<string>(SECURITY_TOPICS.find((t) => t.stream === 'evolved')!.id);

  const topics = useMemo(() => SECURITY_TOPICS.filter((t) => stream === 'all' || t.stream === stream), [stream]);
  const active = SECURITY_TOPICS.find((t) => t.id === topicId) ?? topics[0];

  const radarData = useMemo(() => {
    const dims = ['security', 'robustness', 'privacy', 'incident_response', 'lifecycle_eval', 'data_governance'] as const;
    return dims.map((d) => {
      const dim = dimensions.find((x) => x.id === d);
      const avg = frameworks.length ? frameworks.reduce((s, f) => s + (f.coverage[d] ?? 0) / 2, 0) / frameworks.length : 0;
      return { dim: dim?.label.slice(0, 10) ?? d, value: Math.round(avg * 100) };
    });
  }, [frameworks, dimensions]);

  const barData = useMemo(() => topics.map((t) => ({ name: t.short.slice(0, 10), value: topicFrameworks(frameworks, t).length, color: t.color })).sort((a, b) => b.value - a.value), [topics, frameworks]);

  return (
    <div className="layout" style={{ padding: 0, gap: 16 }}>
      <section className="card">
        <h2>Security & Safety — Traditional vs Evolved</h2>
        <p className="muted">Traditional: IAM, hardening, SecOps, supply chain. Evolved: AI/model hardening, data minimization, fingerprinting, IP protection, adversarial, agent security. Pick a stream, then a topic for deep dive.</p>
        <div className="row persona-switch" role={streamNav.listProps.role} onKeyDown={streamNav.listProps.onKeyDown} aria-label="Security streams">
          {STREAMS.map((s) => (
            <button key={s} {...streamNav.itemProps(s)} className={`persona-pill ${stream === s ? 'active' : ''}`}>{s === 'all' ? 'All' : s === 'traditional' ? 'Traditional' : 'Evolved AI'}</button>
          ))}
        </div>
        <div className="chips" style={{ marginTop: 8 }}>
          {topics.map((t) => (
            <button key={t.id} className={`chip ${topicId === t.id ? 'on' : ''}`} style={{ borderColor: t.color, color: topicId === t.id ? t.color : undefined }} onClick={() => setTopicId(t.id)} title={t.description}>{t.icon} {t.short}</button>
          ))}
        </div>
      </section>

      <div className="chart-grid">
        <div className="chart-card">
          <h3>Topics — framework count</h3>
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={barData}>
              <XAxis dataKey="name" tick={{ fill: '#9fb0c0', fontSize: 11 }} interval={0} angle={-18} dy={10} height={50} />
              <YAxis tick={{ fill: '#9fb0c0', fontSize: 11 }} />
              <Tooltip contentStyle={{ background: '#0c1117', border: '1px solid #26303c', borderRadius: 8 }} />
              <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                {barData.map((d, i) => <Bar key={i} dataKey="value" fill={d.color} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
        <div className="chart-card">
          <h3>Security posture — radar</h3>
          <ResponsiveContainer width="100%" height={240}>
            <RadarChart data={radarData}>
              <PolarGrid stroke="#2b3644" />
              <PolarAngleAxis dataKey="dim" tick={{ fill: '#9fb0c0', fontSize: 11 }} />
              <PolarRadiusAxis angle={30} domain={[0, 100]} tick={{ fill: '#6b7a8a', fontSize: 10 }} />
              <Radar dataKey="value" stroke="#e71d36" fill="#e71d36" fillOpacity={0.3} />
              <Tooltip contentStyle={{ background: '#0c1117', border: '1px solid #26303c', borderRadius: 8 }} />
            </RadarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {active && <TopicCard topic={active} frameworks={frameworks} />}
      {active && (() => {
        const papers = (graph?.nodes ?? []).filter((n: GNode) => n.type === 'paper' && n.topic === active.id);
        if (papers.length === 0) return null;
        return (
          <div className="chart-card">
            <h3>Top arXiv papers — {active.label}</h3>
            <ul className="rel">
              {papers.slice(0, 6).map((pap) => (
                <li key={pap.id}>
                  <a href={pap.url} target="_blank" rel="noreferrer"><strong>{pap.label}</strong></a>
                  <span className="muted"> — {pap.authors} ({pap.year})</span>
                  <div className="muted" style={{ fontSize: 12 }}>{pap.summary?.slice(0, 160)}…</div>
                </li>
              ))}
            </ul>
          </div>
        );
      })()}
    </div>
  );
}
