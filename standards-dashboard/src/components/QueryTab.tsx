import React, { useMemo, useState } from 'react';
import type { Framework } from '../lib/engine';
import { coveragePercent } from '../lib/engine';
import { queryAll } from '../lib/families';
import { mandateSplit } from '../lib/graph';
import type { GraphData } from '../lib/graph';

const KIND_LABEL: Record<string, string> = {
  framework: 'Frameworks', control: 'Controls', topic: 'Topics', exposure: 'Exposures', theme: 'Themes',
};

export default function QueryTab({ frameworks, graph }: { frameworks: Framework[]; graph: GraphData | null }) {
  const [q, setQ] = useState('EU hiring chatbot');
  const hits = useMemo(() => queryAll(frameworks, graph ?? { generated: '', nodes: [], links: [], clusterCount: 0, clusterLabels: [] }, q), [frameworks, graph, q]);
  const fwById = useMemo(() => new Map(frameworks.map((f) => [f.id, f])), [frameworks]);
  const groups = useMemo(() => {
    const g: Record<string, typeof hits> = {};
    for (const h of hits) (g[h.kind] = g[h.kind] ?? []).push(h);
    return g;
  }, [hits]);

  return (
    <section className="card">
      <h2>Query — search &amp; retrieve across everything</h2>
      <div className="row">
        <input aria-label="Query all" placeholder="Ask e.g. hiring in EU, prompt injection mitigations, RAG logging…"
          value={q} onChange={(e) => setQ(e.target.value)} />
        <span className="muted">{hits.length} hits</span>
      </div>
      {q.trim() === '' && <p className="muted">Type to retrieve frameworks, controls, topics, exposures, and themes with evidence.</p>}
      {Object.entries(KIND_LABEL).map(([kind, label]) =>
        groups[kind]?.length ? (
          <div key={kind}>
            <h3>{label} ({groups[kind].length})</h3>
            <ul className="rel">
              {groups[kind].map((h) => (
                <li key={h.id}>
                  <strong>{h.kind === 'framework' ? h.id : h.label}</strong>
                  {h.kind === 'framework' && fwById.get(h.id) && (
                    <span className="muted"> · {coveragePercent(fwById.get(h.id)!)}% ·{' '}
                      <a href={fwById.get(h.id)!.url} target="_blank" rel="noreferrer">source ↗</a></span>
                  )}
                  {h.kind === 'control' && graph && (() => {
                    const s = mandateSplit(graph, h.id);
                    return <span className="muted"> · <span className="badge badge-m">M {s.mandatedBy.length}</span> <span className="badge badge-o">O {s.recommendedBy.length}</span></span>;
                  })()}
                  <br />
                  <span className="muted">{h.detail} · score {h.score}</span>
                </li>
              ))}
            </ul>
          </div>
        ) : null,
      )}
      {q.trim() !== '' && hits.length === 0 && <p className="muted">No hits — try fewer or different keywords.</p>}
    </section>
  );
}
