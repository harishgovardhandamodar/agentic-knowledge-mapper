import React, { lazy, Suspense, useMemo, useState } from 'react';
import type { Framework, IngestedData } from './lib/engine';
import { adviseForScenario, coveragePercent, heatmapRows, provenanceStatus, searchFrameworks, topOverlaps } from './lib/engine';
import { Bar, HeatCell, OverlapMatrix } from './components/charts';
import QueryTab from './components/QueryTab';
import SupportFilterBar from './components/SupportFilterBar';
import { filterBySupport } from './components/SupportFilterBar';
import type { SupportFilters } from './components/SupportFilterBar';
import { useTabNav } from './lib/tabs';
import { chatLink } from './lib/config';
import { FAMILIES } from './lib/families';
import { PERSONAS } from './lib/persona';
import type { PersonaId } from './lib/persona';
import type { GraphData } from './lib/graph';

// Heavy views (graph viz, recharts dashboards) load on demand so the initial
// bundle stays small; each resolves to its component's default export.
const KnowledgeGraph = lazy(() => import('./components/KnowledgeGraph'));
const FamilyTab = lazy(() => import('./components/FamilyTab'));
const BenchmarkTab = lazy(() => import('./components/BenchmarkTab'));
const PersonaDashboard = lazy(() => import('./components/PersonaDashboard'));
const SupportMaterials = lazy(() => import('./components/SupportMaterials'));
const SecurityEvolved = lazy(() => import('./components/SecurityEvolved'));

const SCENARIO_EXAMPLES = [
  'Deploy a RAG customer-support chatbot in the EU (healthcare)',
  'Ship an agentic coding assistant with tool use in the US',
  'Release an open-weights foundation model API globally',
  'Launch text-to-image app in China and California',
  'HR hiring screening tool in Colorado and Brazil',
  'Biometric attendance and emotion detection in EU workplaces',
  'Credit scoring and loan approval AI for EU/US lending (high-risk)',
  'AI triage for emergency healthcare in the EU (high-risk)',
  'Education admissions and exam scoring AI in Brazil and Singapore',
  'Law-enforcement facial recognition in EU public spaces (prohibited/high-risk)',
  'Critical infrastructure predictive maintenance AI in Japan and Korea',
  'Voice cloning and deepfake video generation for marketing in China/EU',
  'Multi-agent autonomous research assistant with web browsing (frontier)',
  'Internal HR chatbot for interview scheduling in the EU (limited-risk)',
  'Public-sector benefits eligibility AI in Canada and US (rights-impacting)',
  'SaaS AI for housing recommendations in US (Colorado) and EU',
  'Synthetic data generation for training in UK and Australia',
  'On-prem embedded AI for manufacturing quality control in Germany',
  'B2B RAG for legal document review with PII (privacy-sensitive)',
  'Customer-facing image generation with watermarking for EU transparency',
];

const SCENARIO_CATEGORIES: Record<string, string[]> = {
  'High-Risk': [
    'HR hiring screening tool in Colorado and Brazil',
    'Biometric attendance and emotion detection in EU workplaces',
    'Credit scoring and loan approval AI for EU/US lending (high-risk)',
    'AI triage for emergency healthcare in the EU (high-risk)',
    'Law-enforcement facial recognition in EU public spaces (prohibited/high-risk)',
  ],
  'Generative': [
    'Deploy a RAG customer-support chatbot in the EU (healthcare)',
    'Launch text-to-image app in China and California',
    'Voice cloning and deepfake video generation for marketing in China/EU',
    'Customer-facing image generation with watermarking for EU transparency',
  ],
  'Agentic': [
    'Ship an agentic coding assistant with tool use in the US',
    'Multi-agent autonomous research assistant with web browsing (frontier)',
  ],
  'Global': [
    'Release an open-weights foundation model API globally',
    'Education admissions and exam scoring AI in Brazil and Singapore',
    'Critical infrastructure predictive maintenance AI in Japan and Korea',
    'Public-sector benefits eligibility AI in Canada and US (rights-impacting)',
  ],
};

export default function App({ data, graph }: { data: IngestedData; graph: GraphData | null }) {
  const { frameworks, dimensions, overlap } = data;
  const [query, setQuery] = useState('');
  const [jurisdiction, setJurisdiction] = useState('all');
  const [kind, setKind] = useState('all');
  const [selected, setSelected] = useState<string | null>(null);
  const [scenario, setScenario] = useState(SCENARIO_EXAMPLES[0]);
  const [showScenarios, setShowScenarios] = useState(false);
  const [pair, setPair] = useState<string | null>(null);
  const [tab, setTab] = useState<'dash' | 'graph' | 'query' | 'bench' | 'support' | 'security' | string>('dash');
  const [persona, setPersona] = useState<PersonaId | 'all'>('all');
  const [supportFilters, setSupportFilters] = useState<SupportFilters>({});
  const filteredFrameworks = React.useMemo(() => filterBySupport(frameworks, supportFilters), [frameworks, supportFilters]);
  const [expandHeat, setExpandHeat] = useState(false);
  const [heatQuery, setHeatQuery] = useState('');
  const [heatDims, setHeatDims] = useState<string[] | null>(null);
  const [heatMin, setHeatMin] = useState<0 | 1 | 2>(0);
  const [heatSort, setHeatSort] = useState<'coverage' | 'name'>('coverage');

  React.useEffect(() => {
    if (!expandHeat) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setExpandHeat(false); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [expandHeat]);

  const jurisdictions = useMemo(
    () => ['all', ...Array.from(new Set(frameworks.map((f) => f.jurisdiction))).sort()],
    [frameworks],
  );

  const results = useMemo(
    () => searchFrameworks(filteredFrameworks, query, { jurisdiction, kind }),
    [filteredFrameworks, query, jurisdiction, kind],
  );

  const advice = useMemo(() => adviseForScenario(frameworks, scenario), [frameworks, scenario]);
  const heatCols = useMemo(
    () => (heatDims ? dimensions.filter((d) => heatDims.includes(d.id)) : dimensions),
    [dimensions, heatDims],
  );
  const heatRows = useMemo(
    () => heatmapRows(filteredFrameworks, heatQuery, heatSort),
    [filteredFrameworks, heatQuery, heatSort],
  );
  const toggleHeatDim = (id: string) =>
    setHeatDims((prev) => {
      const cur = prev ?? dimensions.map((d) => d.id);
      return cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id];
    });

  const names = useMemo(() => Object.fromEntries(frameworks.map((f) => [f.id, f.name])), [frameworks]);
  const overlapLookup = useMemo(() => {
    const m = new Map<string, number>();
    for (const c of overlap) m.set(`${c.a}|${c.b}`, c.jaccard);
    return (a: string, b: string) => {
      if (a === b) return null;
      return m.get(`${a}|${b}`) ?? m.get(`${b}|${a}`) ?? 0;
    };
  }, [overlap]);

  const matrixIds = useMemo(() => frameworks.slice(0, 20).map((f) => f.id), [frameworks]);
  const selectedFw: Framework | undefined = frameworks.find((f) => f.id === selected);

  const personaIds = ['all', ...PERSONAS.map((p) => p.id)] as (PersonaId | 'all')[];
  const viewIds = ['dash', ...FAMILIES.map((f) => f.id), 'graph', 'query', 'bench', 'support', 'security'] as const;
  const personaNav = useTabNav('persona', personaIds, persona, (p) => setPersona(p), 'radio');
  const viewNav = useTabNav('view', viewIds, tab as (typeof viewIds)[number], (t) => setTab(t));

  const heatOverlayRef = React.useRef<HTMLElement | null>(null);
  React.useEffect(() => {
    if (!expandHeat) return;
    const el = heatOverlayRef.current;
    if (!el) return;
    const focusables = () =>
      Array.from(el.querySelectorAll<HTMLElement>('a[href], button, input, select, textarea, [tabindex]:not([tabindex="-1"])'));
    (el.querySelector<HTMLElement>('.expand-btn') ?? focusables()[0])?.focus();
    const trap = (e: KeyboardEvent) => {
      if (e.key !== 'Tab') return;
      const els = focusables();
      if (els.length === 0) return;
      const first = els[0];
      const last = els[els.length - 1];
      const activeEl = document.activeElement as HTMLElement | null;
      const inside = activeEl && el.contains(activeEl);
      if (e.shiftKey && (!inside || activeEl === first)) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && (!inside || activeEl === last)) {
        e.preventDefault();
        first.focus();
      }
    };
    window.addEventListener('keydown', trap);
    return () => window.removeEventListener('keydown', trap);
  }, [expandHeat]);

  return (
    <div className="layout">
      <header className="hero">
        <div>
          <h1>AI Standards &amp; Regulations Dashboard</h1>
          <p>
            {frameworks.length} frameworks · {dimensions.length} control dimensions · refreshed {data.generated} ·
            monthly ingest via <code>npm run ingest</code>
          </p>
        </div>
        <a className="btn" href={chatLink()} target="_blank" rel="noreferrer">
          Chat in Open WebUI
        </a>
      </header>

      <div className="persona-switch" {...personaNav.listProps} aria-label="Persona modes">
        <span className="muted" style={{ fontSize: 12, alignSelf: "center" }}>View as:</span>
        <button className={"persona-pill " + (persona==="all"?"active":"")} {...personaNav.itemProps('all')}>All</button>
        {PERSONAS.map((pp) => (
          <button key={pp.id} className={"persona-pill " + (persona===pp.id?"active":"")} style={{ borderColor: pp.color, color: persona===pp.id?pp.color:undefined }} {...personaNav.itemProps(pp.id)}>{pp.icon} {pp.short}</button>
        ))}
      </div>

      <SupportFilterBar frameworks={frameworks} filters={supportFilters} onChange={setSupportFilters} />

      <nav className="tabs" aria-label="Views" {...viewNav.listProps}>
        <button className={`tab ${tab === 'dash' ? 'active' : ''}`} {...viewNav.itemProps('dash')}>Dashboard</button>
        {FAMILIES.map((f) => (
          <button key={f.id} className={`tab ${tab === f.id ? 'active' : ''}`} {...viewNav.itemProps(f.id)}>{f.short}</button>
        ))}
        <button className={`tab ${tab === 'graph' ? 'active' : ''}`} {...viewNav.itemProps('graph')}>Knowledge Graph</button>
        <button className={`tab ${tab === 'query' ? 'active' : ''}`} {...viewNav.itemProps('query')}>Query</button>
        <button className={`tab ${tab === 'bench' ? 'active' : ''}`} {...viewNav.itemProps('bench')}>Benchmark</button>
        <button className={`tab ${tab === 'support' ? 'active' : ''}`} {...viewNav.itemProps('support')}>Support</button>
        <button className={`tab ${tab === 'security' ? 'active' : ''}`} {...viewNav.itemProps('security')}>Security & Safety</button>
      </nav>

      <div role="tabpanel" id={`view-panel-${tab}`} aria-labelledby={`view-${tab}`}>
      <Suspense fallback={<p className="muted" role="status">Loading view…</p>}>
      {tab === 'security' ? (
        <SecurityEvolved frameworks={filteredFrameworks} dimensions={dimensions} graph={graph} />
      ) : tab === 'support' ? (
        <SupportMaterials frameworks={filteredFrameworks} />
      ) : tab === 'bench' ? (
        <BenchmarkTab />
      ) : tab === 'query' ? (
        <QueryTab frameworks={frameworks} graph={graph} />
      ) : tab === 'graph' ? (
        <section className="card">
          <h2>Knowledge graph — sources, themes &amp; relations</h2>
          {graph
            ? <KnowledgeGraph graph={graph} frameworks={filteredFrameworks} dimensions={dimensions} />
            : <p className="muted">Run <code>npm run ingest</code> to generate <code>public/graph.json</code>.</p>}
        </section>
      ) : FAMILIES.some((f) => f.id === tab) ? (
        graph ? (
          <FamilyTab key={tab} family={FAMILIES.find((f) => f.id === tab)!} graph={graph} frameworks={frameworks} dimensions={dimensions} />
        ) : (
          <section className="card"><p className="muted">Run <code>npm run ingest</code> to generate <code>public/graph.json</code>.</p></section>
        )
      ) : (
      <>

        {persona !== "all" && (
          <PersonaDashboard persona={PERSONAS.find((pp) => pp.id === persona)!} frameworks={filteredFrameworks} dimensions={dimensions} />
        )}

      <section className="grid2">
        <div className="card">
          <h2>Search &amp; filter</h2>
          <div className="row">
            <input
              aria-label="Search frameworks"
              placeholder="Search e.g. prompt injection, RAG, EU, hiring, labeling…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            <select aria-label="Jurisdiction" value={jurisdiction} onChange={(e) => setJurisdiction(e.target.value)}>
              {jurisdictions.map((j) => (
                <option key={j} value={j}>{j}</option>
              ))}
            </select>
            <select aria-label="Type" value={kind} onChange={(e) => setKind(e.target.value)}>
              {['all', 'regulation', 'standard', 'framework', 'guideline'].map((k) => (
                <option key={k} value={k}>{k}</option>
              ))}
            </select>
          </div>
          <p className="muted">{results.length} of {frameworks.length} shown · <span title="Coverage = average over 10 control dimensions (Risk, Data, Transparency, Robustness, Security, Privacy, Accountability, Human Oversight, Incident, Lifecycle) where 0=not covered, 1=partial, 2=direct → %">coverage % = avg of 10 pillars (0 none, 1 partial, 2 direct)</span></p>
          <ul className="list">
            {results.map((f) => (
              <li key={f.id}>
                <button className={`pick ${selected === f.id ? 'active' : ''}`} onClick={() => setSelected(f.id)}>
                  <strong>{f.name}</strong>
                  <span className="muted" title="Coverage = avg of 10 pillars (0 none, 1 partial, 2 direct) → %"> · {f.jurisdiction} · {f.kind} · {coveragePercent(f)}%</span>
                </button>
              </li>
            ))}
          </ul>
        </div>

        <div className="card">
          <h2>{selectedFw ? selectedFw.name : 'Select a framework'}</h2>
          {selectedFw ? (
            <>
              <p>{selectedFw.summary}</p>
              <p className="muted">
                {selectedFw.issuer} · {selectedFw.version} · {selectedFw.status} · checked {selectedFw.lastChecked}{' '}
                {(() => {
                  const prov = provenanceStatus(selectedFw);
                  const color = prov.tier === 'fresh' ? '#7bd389' : prov.tier === 'aging' ? '#f4d35e' : prov.tier === 'stale' ? '#e71d36' : '#9fb0c0';
                  return (
                    <span
                      className="chip"
                      title={`Provenance: source last verified ${selectedFw.lastChecked}. Fresh ≤90d, aging ≤180d, stale beyond.`}
                      style={{ color, borderColor: color, fontSize: 11 }}
                    >
                      {prov.tier === 'unknown' ? 'provenance unknown' : `${prov.tier} · ${prov.label}`}
                    </span>
                  );
                })()}{' '}
                <a href={selectedFw.url} target="_blank" rel="noreferrer">source ↗</a>
              </p>
              <Bar value={coveragePercent(selectedFw)} />
              <table className="cov">
                <tbody>
                  {dimensions.map((d) => (
                    <tr key={d.id}>
                      <th scope="row" title={d.description}>{d.label}</th>
                      <td><HeatCell v={(selectedFw.coverage[d.id] ?? 0) as number} /></td>
                      <td className="muted">{d.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <h3>Closest overlaps (shared controls)</h3>
              <ul>
                {topOverlaps(overlap, selectedFw.id).map((c) => {
                  const other = c.a === selectedFw.id ? c.b : c.a;
                  return (
                    <li key={other}>
                      {names[other]} — {Math.round(c.jaccard * 100)}% ({c.shared.slice(0, 4).join(', ')})
                    </li>
                  );
                })}
              </ul>
              <h3>Controls</h3>
              <p>{selectedFw.controls.join(' · ')}</p>
            </>
          ) : (
            <p className="muted">Click a framework on the left to see per-dimension coverage, overlap, and source.</p>
          )}
        </div>
      </section>

      <section className={`card${expandHeat ? ' expanded' : ''}`}>
        <h2>Coverage heatmap (all frameworks × dimensions){' '}
          <button className="expand-btn" onClick={() => setExpandHeat((v) => !v)}
            aria-label={expandHeat ? 'Exit expanded heatmap' : 'Expand heatmap'}>
            {expandHeat ? '✕ exit' : '⛶ expand'}
          </button>
        </h2>
        <div className="row heat-controls">
          <input aria-label="Query heatmap" placeholder="Filter rows: e.g. EU, chatbot, prompt injection, hiring…"
            value={heatQuery} onChange={(e) => setHeatQuery(e.target.value)} />
          <select aria-label="Minimum cell score" value={heatMin} onChange={(e) => setHeatMin(parseInt(e.target.value) as 0 | 1 | 2)}>
            <option value={0}>all cells</option>
            <option value={1}>partial + direct</option>
            <option value={2}>direct only</option>
          </select>
          <select aria-label="Sort rows" value={heatSort} onChange={(e) => setHeatSort(e.target.value as 'coverage' | 'name')}>
            <option value="coverage">sort: coverage ↓</option>
            <option value="name">sort: name A–Z</option>
          </select>
          <button className="chip" onClick={() => { setHeatQuery(''); setHeatDims(null); setHeatMin(0); }}>reset</button>
          <span className="muted">{heatRows.length} frameworks × {heatCols.length} dimensions</span>
        </div>
        <div className="chips">
          {dimensions.map((d) => {
            const on = !heatDims || heatDims.includes(d.id);
            return (
              <button key={d.id} className={`chip${on ? ' on' : ''}`} title={d.description}
                onClick={() => toggleHeatDim(d.id)} aria-pressed={on}>{d.label}</button>
            );
          })}
        </div>
        <div className="matrix-wrap">
          <table className="matrix">
            <thead>
              <tr>
                <th scope="col">Framework</th>
                {heatCols.map((d) => (
                  <th key={d.id} scope="col" title={d.description}>{d.label.slice(0, 10)}</th>
                ))}
                <th scope="col">Total</th>
              </tr>
            </thead>
            <tbody>
              {heatRows.map((f) => (
                <tr key={f.id}>
                  <th scope="row" title={`${f.name} — ${f.summary}`}>{f.id.slice(0, 18)}</th>
                  {heatCols.map((d) => {
                    const v = (f.coverage[d.id] ?? 0) as number;
                    return <td key={d.id} className={v < heatMin ? 'cell-dim' : ''}><HeatCell v={v} /></td>;
                  })}
                  <td><Bar value={coveragePercent(f)} /></td>
                </tr>
              ))}
            </tbody>
          </table>
          {heatRows.length === 0 && <p className="muted">No frameworks match “{heatQuery}”. Try fewer keywords.</p>}
        </div>
      </section>

      <section className="card">
        <h2>Overlap matrix (Jaccard on control tags, top 20)</h2>
        <OverlapMatrix ids={matrixIds} names={names} get={overlapLookup} onSelect={(a, b) => setPair(`${a}|${b}`)} />
        {pair && (() => {
          const [a, b] = pair.split('|');
          const cell = overlap.find((c) => (c.a === a && c.b === b) || (c.a === b && c.b === a));
          if (!cell) return null;
          return (
            <p className="muted">
              {names[cell.a]} × {names[cell.b]}: {Math.round(cell.jaccard * 100)}% — shared:{' '}
              {cell.shared.join(', ') || 'none'}
            </p>
          );
        })()}
      </section>

      <section className="card">
        <h2>Scenario advisor — what applies to my build?</h2>
        <div className="row" style={{ gap: 8 }}>
          <input aria-label="Scenario" placeholder="Describe your build — e.g. RAG chatbot in EU healthcare with PII" value={scenario} onChange={(e) => setScenario(e.target.value)} style={{ flex: 1, minWidth: 280 }} />
          <button className="chip" onClick={() => setShowScenarios((v) => !v)}>{showScenarios ? 'Hide library' : 'Browse scenarios'}</button>
        </div>
        <div style={{ display: showScenarios ? 'grid' : 'none', gap: 8, marginTop: 8 }}>
          {Object.entries(SCENARIO_CATEGORIES).map(([cat, list]) => (
            <div key={cat}>
              <div className="muted" style={{ fontSize: 11, marginBottom: 4, fontWeight: 600 }}>{cat}</div>
              <div className="chips" style={{ margin: 0 }}>
                {list.map((s) => (
                  <button key={s} className="chip" onClick={() => setScenario(s)}>{s.slice(0, 44)}…</button>
                ))}
              </div>
            </div>
          ))}
          <div>
            <div className="muted" style={{ fontSize: 11, marginBottom: 4, fontWeight: 600 }}>More</div>
            <div className="chips" style={{ margin: 0 }}>
              {SCENARIO_EXAMPLES.filter((s) => !Object.values(SCENARIO_CATEGORIES).flat().includes(s)).map((s) => (
                <button key={s} className="chip" onClick={() => setScenario(s)}>{s.slice(0, 44)}…</button>
              ))}
            </div>
          </div>
        </div>
        {advice.length === 0 ? (
          <p className="muted" style={{ textAlign: 'center', padding: 16 }}>No matches — try a different scenario or fewer keywords.</p>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 12, marginTop: 12 }}>
            {advice.map((a, idx) => (
              <div key={a.framework.id} className="card" style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 8 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8 }}>
                  <strong style={{ fontSize: 13, lineHeight: 1.3 }}>{idx + 1}. {a.framework.name}</strong>
                  <span className="chip" style={{ fontSize: 10, whiteSpace: 'nowrap' }}>{a.framework.jurisdiction} · {a.framework.kind}</span>
                </div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', rowGap: 6, alignContent: 'flex-start' }}>
                  <span className="chip" style={{ fontSize: 11, borderColor: '#4da3ff' }}>{coveragePercent(a.framework)}% coverage</span>
                  <a href={a.framework.url} target="_blank" rel="noreferrer" className="chip" style={{ fontSize: 11 }}>source ↗</a>
                </div>
                <div style={{ fontSize: 12, display: "flex", flexWrap: "wrap", gap: 6, alignItems: "center", rowGap: 6 }}>
                  <span className="muted" style={{ fontWeight: 600 }}>Why:</span> {a.reasons.length ? a.reasons.map((r) => <span key={r} className="chip" style={{ fontSize: 11 }}>{r}</span>) : <span className="muted">keyword match</span>}
                </div>
                <div style={{ fontSize: 12, display: "flex", flexWrap: "wrap", gap: 6, alignItems: "center", rowGap: 6 }}>
                  <span className="muted" style={{ fontWeight: 600 }}>Watch gaps:</span> {a.missing.length ? a.missing.map((m) => <span key={m} className="chip" style={{ fontSize: 11, borderColor: '#e71d36' }}>{m}</span>) : <span className="muted">none</span>}
                </div>
              </div>
            ))}
          </div>
        )}
        <p className="muted">
          Dev support: pair this with <code>npm run export:finetune</code> + the Unsloth chatbot
          (see README) for Q&amp;A grounded in these sources. Rule-based ranking here is the offline fallback.
        </p>
      </section>

      </>
      )}
      </Suspense>
      </div>
      <footer className="muted">        Curated baselines with official source links; coverage scores are approximate and refreshed monthly.
        For legal decisions consult counsel and the linked primary source.
      </footer>
    </div>
  );
}
