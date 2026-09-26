import React, { useState } from 'react';
import type { Framework } from '../lib/engine';
import type { Dimension } from '../lib/engine';
import { coveragePercent } from '../lib/engine';
import KnowledgeGraph from './KnowledgeGraph';
import { familyGraph } from '../lib/families';
import type { Family } from '../lib/families';
import type { GraphData } from '../lib/graph';
import { Bar } from './charts';

export default function FamilyTab({
  family, graph, frameworks, dimensions,
}: {
  family: Family; graph: GraphData; frameworks: Framework[]; dimensions: Dimension[];
}) {
  const [selected, setSelected] = useState<string | null>(null);
  const members = family.members
    .map((id) => frameworks.find((f) => f.id === id))
    .filter((f): f is Framework => Boolean(f));
  const sub = familyGraph(graph, family.members);

  return (
    <div className="layout" style={{ padding: 0 }}>
      <section className="card">
        <h2>{family.label} — what it is</h2>
        <p>{family.about}</p>
      </section>
      <section className="card">
        <h2>When it applies</h2>
        <ul>
          {family.applicability.map((a, i) => (
            <li key={i}>{a}</li>
          ))}
        </ul>
      </section>
      <section className="grid2">
        <div className="card">
          <h2>Member instruments ({members.length})</h2>
          <ul className="list" style={{ maxHeight: 320 }}>
            {members.map((f) => (
              <li key={f.id}>
                <button className={`pick ${selected === f.id ? 'active' : ''}`} onClick={() => setSelected(f.id)}>
                  <strong>{f.name}</strong>
                  <span className="muted"> · {f.jurisdiction} · {f.kind} · {coveragePercent(f)}%</span>
                </button>
                {selected === f.id && (
                  <div style={{ marginTop: 6 }}>
                    <p>{f.summary}</p>
                    <p className="muted">{f.version} · {f.status} · <a href={f.url} target="_blank" rel="noreferrer">source ↗</a></p>
                    <Bar value={coveragePercent(f)} />
                  </div>
                )}
              </li>
            ))}
          </ul>
        </div>
        <div className="card">
          <h2>{family.short} knowledge graph</h2>
          <p className="muted">
            Members (circles) with their theme hubs (diamonds), similarity edges, and mandated/optional controls.
            Click any node for the detail overlay. {sub.nodes.length} nodes · {sub.links.length} edges in this view.
          </p>
          <KnowledgeGraph
            graph={sub} frameworks={frameworks} dimensions={dimensions} initialMinSim={0.5} compact
          />
        </div>
      </section>
    </div>
  );
}
