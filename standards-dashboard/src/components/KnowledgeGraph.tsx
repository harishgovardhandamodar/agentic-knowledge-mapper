import React, { useEffect, useMemo, useRef, useState } from 'react';
import { forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY } from 'd3-force';
import type { SimulationLinkDatum, SimulationNodeDatum } from 'd3-force';
import type { Framework } from '../lib/engine';
import type { Dimension } from '../lib/engine';
import { CLUSTER_COLORS, colorFor, cooccurring, isDataControl, mandateSplit, relatedNodes, similarityScope } from '../lib/graph';
import type { GLink, GNode, GraphData } from '../lib/graph';

interface SimNode extends SimulationNodeDatum, GNode {}
interface SimLink extends SimulationLinkDatum<SimNode> {
  relation: GLink['relation'];
  weight: number;
  shared: string[];
}

const W = 1100;
const H = 640;

export default function KnowledgeGraph({
  graph, frameworks, dimensions, initialMinSim = 0.62, compact = false,
}: {
  graph: GraphData; frameworks: Framework[]; dimensions: Dimension[];
  initialMinSim?: number; compact?: boolean;
}) {
  const [minSim, setMinSim] = useState(initialMinSim);
  const [colorBy, setColorBy] = useState<'cluster' | 'jurisdiction' | 'kind'>('cluster');
  const [showThemes, setShowThemes] = useState(true);
  const [showControls, setShowControls] = useState(false);
  const [showTopics, setShowTopics] = useState(false);
  const [showExposures, setShowExposures] = useState(false);
  const [showPartial, setShowPartial] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [zoom, setZoom] = useState(1);
  const [hover, setHover] = useState<{ type: 'node' | 'edge'; id: string; label: string; detail: string; x: number; y: number } | null>(null);
  const [clusterFilter, setClusterFilter] = useState<number | null>(null);
  const [expanded, setExpanded] = useState(false);
  const [, setTick] = useState(0);
  const nodesRef = useRef<SimNode[]>([]);
  const dragRef = useRef<SimNode | null>(null);

  useEffect(() => {
    if (!expanded) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setExpanded(false); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [expanded]);

  const jurisdictions = useMemo(
    () => [...new Set(frameworks.map((f) => f.jurisdiction))].sort(), [frameworks],
  );
  const fwById = useMemo(() => new Map(frameworks.map((f) => [f.id, f])), [frameworks]);
  const dimByLabel = useMemo(() => {
    const m = new Map<string, Dimension>();
    for (const d of dimensions) m.set(d.label, d);
    return m;
  }, [dimensions]);

  const visible = useMemo(() => {
    const nodes = graph.nodes.filter((n) => {
      if (clusterFilter !== null && n.type === 'framework' && n.cluster !== clusterFilter) return false;
      if (n.type === 'framework') return true;
      if (n.type === 'theme') return showThemes;
      if (n.type === 'control') return showControls;
      if (n.type === 'topic') return showTopics;
      return showExposures;
    });
    const ids = new Set(nodes.map((n) => n.id));
    const links = graph.links.filter((l) => {
      if (!ids.has(l.source) || !ids.has(l.target)) return false;
      if (l.relation === 'similar') return l.weight >= minSim;
      if (l.relation === 'partially-covers') return showPartial && showThemes;
      if (l.relation === 'covers') return showThemes;
      if (l.relation === 'mandates' || l.relation === 'recommends') return showControls;
      if (l.relation === 'applies-to') return showTopics;
      if (l.relation === 'flags') return showExposures;
      return true;
    });
    return { nodes, links };
  }, [graph, minSim, clusterFilter, showThemes, showControls, showTopics, showExposures, showPartial]);

  // Cluster anchors on a ring (grouped layout) + force physics (hive theme).
  useEffect(() => {
    const nodes: SimNode[] = visible.nodes.map((n) => {
      const prev = nodesRef.current.find((p) => p.id === n.id);
      return { ...n, x: prev?.x ?? W / 2 + (Math.random() - 0.5) * 300, y: prev?.y ?? H / 2 + (Math.random() - 0.5) * 300 };
    });
    const byId = new Map(nodes.map((n) => [n.id, n]));
    const links: SimLink[] = visible.links
      .map((l) => ({ ...l, source: byId.get(l.source)!, target: byId.get(l.target)! }))
      .filter((l) => l.source && l.target);
    const anchors = Array.from({ length: graph.clusterCount }, (_, k) => ({
      x: W / 2 + Math.cos((2 * Math.PI * k) / graph.clusterCount) * 260,
      y: H / 2 + Math.sin((2 * Math.PI * k) / graph.clusterCount) * 200,
    }));
    const sim = forceSimulation<SimNode>(nodes)
      .force('link', forceLink<SimNode, SimLink>(links)
        .id((d) => d.id)
        .distance((l) => (l.relation === 'similar' ? 150 - l.weight * 90 : 90))
        .strength((l) => (l.relation === 'similar' ? 0.5 : 0.25)))
      .force('charge', forceManyBody<SimNode>().strength(-220))
      .force('collide', forceCollide<SimNode>().radius((d) => nodeR(d) + 7))
      .force('cx', forceX<SimNode>((d) => {
        return d.type === 'theme' ? W / 2 : anchors[Math.max(0, d.cluster)]?.x ?? W / 2;
      }).strength(0.12))
      .force('cy', forceY<SimNode>((d) => {
        return d.type === 'theme' ? H / 2 : anchors[Math.max(0, d.cluster)]?.y ?? H / 2;
      }).strength(0.12))
      .on('tick', () => setTick((t) => t + 1));
    nodesRef.current = nodes;
    return () => { sim.stop(); };
  }, [visible, graph.clusterCount]);

  const sel = selected ? graph.nodes.find((n) => n.id === selected) : undefined;
  const getNodeDetail = (n: GNode) => n.type === 'framework' ? `${n.jurisdiction} · ${n.kind} · ${n.coverage}%` : n.type === 'paper' ? `${n.authors} (${n.year})` : n.type === 'theme' ? 'Theme' : n.type;
  const related = selected ? relatedNodes(graph, selected, minSim) : [];
  const scope = selected ? similarityScope(graph, selected) : null;
  const split = sel && sel.type !== 'framework' && sel.type !== 'theme' ? mandateSplit(graph, sel.id) : null;
  const co = sel && sel.type !== 'framework' && sel.type !== 'theme' ? cooccurring(graph, sel.id) : [];

  const vbW = W / zoom;
  const vbH = H / zoom;

  return (
    <div className="kg">
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 8, marginBottom: 8 }}>
        {graph.clusterLabels.map((label, idx) => {
          const count = graph.nodes.filter((n) => n.type === 'framework' && n.cluster === idx).length;
          const active = clusterFilter === idx;
          return (
            <button
              key={idx}
              className="card"
              style={{ padding: '8px 10px', textAlign: 'left', borderColor: active ? CLUSTER_COLORS[idx % CLUSTER_COLORS.length] : '#26303c', background: active ? '#171e26' : '#0c1117', cursor: 'pointer' }}
              onClick={() => setClusterFilter(active ? null : idx)}
            >
              <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                <span className="dot" style={{ background: CLUSTER_COLORS[idx % CLUSTER_COLORS.length] }} />
                <strong style={{ fontSize: 12 }}>Cluster {idx + 1}</strong>
                <span className="muted" style={{ fontSize: 11 }}>{count} fw</span>
              </div>
              <div style={{ fontSize: 11, color: '#c8d0d8', marginTop: 4, lineHeight: 1.3 }}>{label}</div>
              <div className="muted" style={{ fontSize: 10, marginTop: 4 }}>{active ? 'Click to clear filter' : 'Click to filter'}</div>
            </button>
          );
        })}
      </div>
      <div className="row kg-controls">
        <label>Min similarity <strong>{minSim.toFixed(2)}</strong>
          <input type="range" min={0.5} max={0.75} step={0.01} value={minSim}
            onChange={(e) => setMinSim(parseFloat(e.target.value))} aria-label="Minimum similarity for edges" />
        </label>
        <label>Color by
          <select value={colorBy} onChange={(e) => setColorBy(e.target.value as never)} aria-label="Color nodes by">
            <option value="cluster">theme cluster</option>
            <option value="jurisdiction">jurisdiction</option>
            <option value="kind">type</option>
          </select>
        </label>
        <label><input type="checkbox" checked={showThemes} onChange={(e) => setShowThemes(e.target.checked)} /> themes ({graph.nodes.filter((n) => n.type === 'theme').length})</label>
        <label><input type="checkbox" checked={showControls} onChange={(e) => setShowControls(e.target.checked)} /> controls ({graph.nodes.filter((n) => n.type === 'control').length})</label>
        <label><input type="checkbox" checked={showTopics} onChange={(e) => setShowTopics(e.target.checked)} /> topics ({graph.nodes.filter((n) => n.type === 'topic').length})</label>
        <label><input type="checkbox" checked={showExposures} onChange={(e) => setShowExposures(e.target.checked)} /> exposures ({graph.nodes.filter((n) => n.type === 'exposure').length})</label>
        <label><input type="checkbox" checked={showPartial} onChange={(e) => setShowPartial(e.target.checked)} /> partial coverage</label>
        <span className="muted">{visible.nodes.length} nodes · {visible.links.length} edges</span>
        <span className="kg-zoom">
          <button onClick={() => setExpanded((v) => !v)} aria-label={expanded ? 'Exit expanded view' : 'Expand graph'}>
            {expanded ? '✕ exit' : '⛶ expand'}
          </button>
          <button onClick={() => setZoom((z) => Math.min(2.5, z + 0.25))} aria-label="Zoom in">+</button>
          <button onClick={() => setZoom(1)} aria-label="Reset zoom">reset</button>
          <button onClick={() => setZoom((z) => Math.max(0.5, z - 0.25))} aria-label="Zoom out">−</button>
        </span>
      </div>

      <div className={`kg-body${expanded ? ' expanded' : ''}`}>
        <svg viewBox={`${W / 2 - vbW / 2} ${H / 2 - vbH / 2} ${vbW} ${vbH}`} className={`kg-svg${compact ? ' compact' : ''}`} role="img" aria-label="Knowledge graph of AI frameworks">
          {nodesRef.current
            .flatMap((n) => visible.links
              .filter((l) => l.source === n.id)
              .map((l, i) => ({ l, i, a: n, b: nodesRef.current.find((m) => m.id === l.target)! }))
              .filter((e) => e.b?.x != null))
            .map(({ l, i, a, b }) => (
              <line key={`${l.source}-${l.target}-${i}`} x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                className={`edge edge-${l.relation}`} strokeWidth={l.relation === 'similar' ? 0.5 + l.weight * 2.5 : 1}
                onMouseEnter={(e) => setHover({ type: 'edge', id: `${l.source}→${l.target}`, label: `${l.source} —[${l.relation}]→ ${l.target}`, detail: `${l.relation}${l.relation === 'similar' ? ` ${Math.round(l.weight*100)}%` : ''}${l.shared.length ? ` · ${l.shared.slice(0,3).join(', ')}` : ''}`, x: e.clientX, y: e.clientY })}
                onMouseMove={(e) => setHover((h) => h && h.id === `${l.source}→${l.target}` ? { ...h, x: e.clientX, y: e.clientY } : h)}
                onMouseLeave={() => setHover(null)}>
                <title>{`${l.source} —[${l.relation}${l.relation === 'similar' ? ` ${Math.round(l.weight * 100)}%` : ''}]→ ${l.target}${l.shared.length ? `: ${l.shared.slice(0, 5).join(', ')}` : ''}`}</title>
              </line>
            ))}
          {nodesRef.current.filter((n) => visible.nodes.some((v) => v.id === n.id)).map((n) => (
            <g key={n.id} transform={`translate(${n.x},${n.y})`}
              onMouseEnter={(e) => setHover({ type: 'node', id: n.id, label: n.label, detail: getNodeDetail(n), x: e.clientX, y: e.clientY })}
              onMouseMove={(e) => setHover((h) => h && h.id === n.id ? { ...h, x: e.clientX, y: e.clientY } : h)}
              onMouseLeave={() => setHover(null)}
              onPointerDown={(e) => { (e.target as Element).setPointerCapture(e.pointerId); dragRef.current = n; n.fx = n.x; n.fy = n.y; }}
              onPointerMove={(e) => {
                if (dragRef.current !== n || n.fx == null) return;
                const svg = (e.currentTarget.ownerSVGElement as unknown as SVGSVGElement);
                const pt = new DOMPoint(e.clientX, e.clientY).matrixTransform(svg.getScreenCTM()!.inverse());
                n.fx = pt.x; n.fy = pt.y;
              }}
              onPointerUp={() => { dragRef.current = null; n.fx = null; n.fy = null; }}
              onClick={() => setSelected(n.id)} className="node">
              <title>{n.label}</title>
              {shapeFor(n, selected === n.id, colorFor(n, colorBy, jurisdictions))}
              {(n.type === 'theme' || selected === n.id
                || (n.type === 'framework' && (n.coverage ?? 0) >= 60)
                || (n.count ?? 0) >= 8) && (
                <text y={nodeR(n) + 13} textAnchor="middle" className="node-label">
                  {n.type === 'framework' ? n.id.slice(0, 16) : shortLabel(n.label)}
                </text>
              )}
            </g>
          ))}
        </svg>
        {hover && !selected && (
          <div style={{ position: 'fixed', left: hover.x + 12, top: hover.y + 12, background: '#0c1117', border: '1px solid #26303c', borderRadius: 8, padding: '6px 8px', fontSize: 11, maxWidth: 260, pointerEvents: 'none', zIndex: 50, boxShadow: '0 4px 12px rgba(0,0,0,0.4)' }}>
            <div style={{ fontWeight: 600, color: '#e8eef4' }}>{hover.label}</div>
            <div className="muted" style={{ fontSize: 11 }}>{hover.detail}</div>
            <div className="muted" style={{ fontSize: 10 }}>{hover.type === 'node' ? 'Click for details' : 'Edge — hover'}</div>
          </div>
        )}

        {sel && (
          <aside className="overlay" aria-label={`${sel.label} details`}>
            <button className="overlay-x" onClick={() => setSelected(null)} aria-label="Close details">✕</button>
            <p className="muted">{typeLine(sel)}</p>
            <h3>{sel.label}</h3>
            {sel.type === 'framework' && fwById.get(sel.id) && <p>{fwById.get(sel.id)!.summary}</p>}
            {sel.type === 'theme' && dimByLabel.get(sel.label) && <p>{dimByLabel.get(sel.label)!.description}</p>}
            {sel.type === 'paper' && <><p><strong>{sel.authors} ({sel.year})</strong> — {sel.summary}</p><p><a href={sel.url} target="_blank" rel="noreferrer">arXiv ↗</a> · topic: {sel.topic}</p></>}
            {sel.type === 'security_topic' && <p className="muted">Security topic hub — linked papers and frameworks share this theme.</p>}
            {sel.type === 'control' && split && (
              <p>
                <span className="badge badge-m">MANDATED · {split.mandatedBy.length}</span>{' '}
                <span className="badge badge-o">OPTIONAL · {split.recommendedBy.length}</span>{' '}
                {isDataControl(sel) && <span className="badge badge-d">DATA CONTROL</span>}
              </p>
            )}
            {sel.type === 'control' && split && split.mandatedBy.length > 0 && (
              <p className="muted">Mandated by: {split.mandatedBy.map((f) => f.id).join(', ')}</p>
            )}
            {sel.type === 'control' && split && split.recommendedBy.length > 0 && (
              <p className="muted">Optional in: {split.recommendedBy.map((f) => f.id).join(', ')}</p>
            )}
            {sel.type === 'framework' && (
              <p className="muted">Cluster: {graph.clusterLabels[sel.cluster]} ·{' '}
                <a href={sel.url} target="_blank" rel="noreferrer">source ↗</a></p>
            )}
            {scope && scope.n > 0 && (
              <p className="muted">Similarity scope: {Math.round(scope.min * 100)}–{Math.round(scope.max * 100)}% across {scope.n} peers (blend of coverage cosine + control overlap).</p>
            )}
            {co.length > 0 && (
              <>
                <h4>Frequently combined with</h4>
                <ul className="rel">
                  {co.map(({ node, n }) => (
                    <li key={node.id}>
                      <button className="pick" onClick={() => setSelected(node.id)}>
                        <span className="dot" style={{ background: colorFor(node, colorBy, jurisdictions) }} />
                        <strong>{node.label}</strong>
                        <span className="muted"> · co-occurs in {n}</span>
                      </button>
                    </li>
                  ))}
                </ul>
              </>
            )}
            <h4>Related nodes ({related.length})</h4>
            <ul className="rel">
              {related.slice(0, 14).map((r) => (
                <li key={r.node.id}>
                  <button className="pick" onClick={() => setSelected(r.node.id)}>
                    <span className="dot" style={{ background: colorFor(r.node, colorBy, jurisdictions) }} />
                    <strong>{r.node.type === 'framework' ? r.node.id : shortLabel(r.node.label)}</strong>
                    <span className="muted"> · {r.relation}{r.relation === 'similar' ? ` ${Math.round(r.weight * 100)}%` : ''}</span>
                    {r.shared.length > 0 && <span className="muted"> — {r.shared.slice(0, 3).join(', ')}</span>}
                  </button>
                </li>
              ))}
            </ul>
          </aside>
        )}
      </div>

      <div className="chips">
        {graph.clusterLabels.map((c, k) => (
          <span key={k} className="chip" style={{ borderColor: CLUSTER_COLORS[k % CLUSTER_COLORS.length] }}>
            <span className="dot" style={{ background: CLUSTER_COLORS[k % CLUSTER_COLORS.length] }} />{c}
          </span>
        ))}
      </div>
    </div>
  );
}

function nodeR(n: GNode): number {
  if (n.type === 'theme') return 9;
  if (n.type === 'security_topic') return 8;
  if (n.type === 'paper') return 6;
  if (n.type === 'framework') return 5 + ((n.coverage ?? 50) / 100) * 9;
  return 4 + Math.min(6, (n.count ?? 1) * 0.8);
}

function shortLabel(s: string): string {
  return s.length > 22 ? s.slice(0, 22) + '…' : s;
}

function typeLine(n: GNode): string {
  if (n.type === 'framework') return `${n.jurisdiction} · ${n.kind} · coverage ${n.coverage}%`;
  if (n.type === 'theme') return 'THEME';
  if (n.type === 'control') return `CONTROL · in ${n.count ?? 0} instruments`;
  if (n.type === 'topic') return `TOPIC · in ${n.count ?? 0} instruments`;
  return `EXPOSURE · flagged by ${n.count ?? 0} instruments`;
}

/** Shape per node type: circle=source, diamond=theme, square=control, triangle=topic, hexagon=exposure. */
function shapeFor(n: GNode, active: boolean, fill: string) {
  const common = { fill, opacity: active ? 1 : 0.88, stroke: active ? '#fff' : 'none', strokeWidth: 2 } as const;
  if (n.type === 'theme') {
    return <rect x={-9} y={-9} width={18} height={18} transform="rotate(45)" {...common} />;
  }
  if (n.type === 'security_topic') {
    return <rect x={-8} y={-8} width={16} height={16} transform="rotate(45)" {...common} opacity={active?1:0.9} />;
  }
  if (n.type === 'paper') {
    return <circle r={6} {...common} />;
  }
  if (n.type === 'control') {
    const r = nodeR(n);
    return <rect x={-r} y={-r} width={r * 2} height={r * 2} {...common} />;
  }
  if (n.type === 'topic') {
    const r = nodeR(n) + 2;
    return <polygon points={`0,${-r} ${r},${r * 0.8} ${-r},${r * 0.8}`} {...common} />;
  }
  if (n.type === 'exposure') {
    const r = nodeR(n) + 2;
    const pts = Array.from({ length: 6 }, (_, i) => {
      const a = (Math.PI / 3) * i - Math.PI / 6;
      return `${(r * Math.cos(a)).toFixed(1)},${(r * Math.sin(a)).toFixed(1)}`;
    }).join(' ');
    return <polygon points={pts} {...common} />;
  }
  return <circle r={nodeR(n)} {...common} />;
}
