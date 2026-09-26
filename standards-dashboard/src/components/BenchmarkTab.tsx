import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { benchApiBase } from '../lib/config';

interface EvalSummary {
  model: string; host?: string; port: number; total: number; passed: number; pass_rate: number;
  queries_total?: number; queries_distinct?: number;
  by_category: Record<string, { total: number; passed: number; pass_rate: number }>;
}
interface EvalScore { hit_count: number; hits: string[]; has_citation: boolean; score: number; }
interface EvalQuery {
  id: number; category: string; query: string; expects: string[];
  response_excerpt: string; evaluation: EvalScore; elapsed_s: number;
}
interface EvalReport { summary: EvalSummary; queries: EvalQuery[]; }
interface RerunResult { response_excerpt: string; evaluation: EvalScore; }
interface RerunResponse { id: number; query: string; results: Record<string, RerunResult>; }

const MODELS = [
  { key: 'qwen7b', label: 'Finetuned Qwen 7B', full: 'ai-standards:latest (finetuned)', file: 'eval-report-qwen7b.json', color: '#4da3ff' },
  { key: 'gemma', label: 'Finetuned Gemma 12B', full: 'ai-standards:gemma-4-12b (finetuned)', file: 'eval-report-gemma.json', color: '#2ec4b6' },
  { key: 'qwen27b', label: 'Vanilla Qwen 27B', full: 'qwen3.8:27b-mlx (no finetune)', file: 'eval-report-qwen27b.json', color: '#ff9f1c' },
] as const;

const API = benchApiBase();

// BENCH_API_TOKEN is a runtime secret — entered in the UI, held only in memory
// for this session — deliberately not baked into the build or the bundle.
let sessionToken = '';

function ScoreBar({ value, color }: { value: number; color: string }) {
  return <div className="bar" style={{ height: 14 }}><div className="bar-fill" style={{ width: `${Math.round(value * 100)}%`, background: color }} /><span className="bar-label" style={{ fontSize: 10 }}>{Math.round(value * 100)}%</span></div>;
}

function CategoryChart({ reports }: { reports: Record<string, EvalReport | null> }) {
  const cats = Array.from(new Set(Object.values(reports).filter(Boolean).flatMap((r) => Object.keys(r!.summary.by_category)))).sort();
  const data = cats.map((cat) => {
    const row: Record<string, string | number> = { category: cat };
    for (const m of MODELS) {
      const r = reports[m.key];
      row[m.key] = r ? (r.summary.by_category[cat]?.pass_rate ?? 0) : 0;
    }
    return row;
  });
  return (
    <ResponsiveContainer width="100%" height={Math.max(260, cats.length * 32)}>
      <BarChart data={data} layout="vertical" margin={{ left: 90, right: 12, top: 4, bottom: 4 }}>
        <XAxis type="number" domain={[0, 1]} tickFormatter={(v) => `${Math.round(v * 100)}%`} tick={{ fill: '#9fb0c0', fontSize: 11 }} />
        <YAxis dataKey="category" type="category" width={90} tick={{ fill: '#c8d0d8', fontSize: 11 }} />
        <Tooltip contentStyle={{ background: '#0c1117', border: '1px solid #26303c', borderRadius: 8 }} formatter={(value) => [`${Math.round(Number(value) * 100)}%`, '']} />
        <Legend wrapperStyle={{ fontSize: 11 }} />
        {MODELS.map((m) => <Bar key={m.key} dataKey={m.key} name={m.label} fill={m.color} radius={[0, 6, 6, 0]} />)}
      </BarChart>
    </ResponsiveContainer>
  );
}

export default function BenchmarkTab() {
  const [reports, setReports] = useState<Record<string, EvalReport | null>>({});
  const [loading, setLoading] = useState(true);
  const [filterCat, setFilterCat] = useState<string>('all');
  const [search, setSearch] = useState('');
  const [tokenOpen, setTokenOpen] = useState(false);
  const [tokenEntry, setTokenEntry] = useState('');
  const [tokenError, setTokenError] = useState<string | null>(null);
  const [pendingAction, setPendingAction] = useState<null | { kind: 'run' } | { kind: 'rerun-model'; key: string }>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [rerunning, setRerunning] = useState<number | null>(null);
  const [benchState, setBenchState] = useState<{ running: boolean; current: string | null } | null>(null);
  const [perModel, setPerModel] = useState<Record<string, { progress: { done: number; total: number } | null; has_report: boolean }>>({});

  const pageSize = 20;

  const loadReports = useCallback(async () => {
    const pairs = await Promise.all(MODELS.map(async (m) => {
      try {
        const r = await fetch(`/${m.file}`, { cache: 'no-store' });
        if (!r.ok) return [m.key, null] as const;
        const j = await r.json() as EvalReport;
        return [m.key, j] as const;
      } catch { return [m.key, null] as const; }
    }));
    const rec: Record<string, EvalReport | null> = {};
    for (const [k, v] of pairs) rec[k] = v;
    setReports(rec);
    setLoading(false);
  }, []);
  useEffect(() => { loadReports(); }, [loadReports]);

  const pollStatus = useCallback(async () => {
    try {
      const r = await fetch(`${API}/api/benchmark/status`, { cache: 'no-store' });
      if (!r.ok) return;
      const j = await r.json();
      setBenchState(j.state);
      setPerModel(j.per_model);
      if ((Object.values(j.per_model) as Array<{ has_report: boolean }>).some((v) => v.has_report)) loadReports();
    } catch { /* backend not running — static reports still work */ }
  }, [loadReports]);
  useEffect(() => {
    pollStatus();
    const id = setInterval(pollStatus, 4000);
    return () => clearInterval(id);
  }, [pollStatus]);

  const saveToken = () => {
    sessionToken = tokenEntry.trim();
    setTokenOpen(false);
    setTokenError(null);
  };

  const authHeaders = (): Record<string, string> => (sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {});

  // Shared mutation path: attaches the session token and surfaces 401s inline.
  const mutate = async (path: string, body?: unknown) => {
    const r = await fetch(`${API}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (r.status === 401) {
      setTokenError('Token required or incorrect — the benchmark API rejected this action.');
      setTokenOpen(true);
    }
    return r;
  };

  const handleRerun = async (q: EvalQuery) => {
    setRerunning(q.id);
    try {
      const r = await mutate(`/api/benchmark/rerun`, { id: q.id, query: q.query, expects: q.expects });
      if (r.status !== 200) return;
      const j = await r.json() as RerunResponse;
      setReports((prev) => {
        const nxt: Record<string, EvalReport | null> = { ...prev };
        for (const m of MODELS) {
          const cur = nxt[m.key];
          if (!cur) continue;
          const upd = (j.results)?.[m.key];
          if (!upd) continue;
          const idx = cur.queries.findIndex((x) => x.id === q.id);
          if (idx !== -1) {
            const copy = { ...cur, queries: [...cur.queries] };
            copy.queries[idx] = { ...copy.queries[idx], response_excerpt: upd.response_excerpt, evaluation: { ...copy.queries[idx].evaluation, ...upd.evaluation } };
            const passed = copy.queries.filter((x) => x.evaluation.score >= 0.5).length;
            copy.summary = { ...copy.summary, passed, pass_rate: passed / copy.queries.length };
            nxt[m.key] = copy;
          }
        }
        return nxt;
      });
    } catch (e) { setActionError(`Re-run failed: ${String(e)}`); }
    setRerunning(null);
  };

  const handleRerunModel = (key: string) => {
    setActionError(null);
    setPendingAction({ kind: 'rerun-model', key });
  };

  const runBenchmark = () => {
    setActionError(null);
    setPendingAction({ kind: 'run' });
  };

  // Long, expensive mutations run only after an explicit inline confirmation.
  const executePending = async () => {
    const action = pendingAction;
    setPendingAction(null);
    if (!action) return;
    try {
      if (action.kind === 'run') {
        await mutate(`/api/benchmark/run`);
        pollStatus();
      } else {
        await mutate(`/api/benchmark/rerun-model`, { key: action.key });
      }
    } catch (e) {
      setActionError(`Benchmark action failed: ${String(e)}`);
    }
  };

  const loaded = MODELS.filter((m) => reports[m.key]);
  const cats = Array.from(new Set(Object.values(reports).filter(Boolean).flatMap((r) => Object.keys(r!.summary.by_category)))).sort();

  // side-by-side data: base queries from first loaded report
  const baseKey = loaded[0]?.key ?? 'qwen7b';
  const filtered = useMemo(() => {
    const base = reports[baseKey]?.queries ?? [];
    return base.filter((q) => {
      if (filterCat !== 'all' && q.category !== filterCat) return false;
      if (search.trim() && !q.query.toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    });
  }, [reports, baseKey, filterCat, search]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const pageQueries = filtered.slice(page * pageSize, (page + 1) * pageSize);
  useEffect(() => { setPage(0); }, [filterCat, search]);

  if (loading) return <section className="card"><p className="muted">Loading benchmark…</p></section>;

  return (
    <div className="layout" style={{ padding: 0, gap: 16 }}>
      <section className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
          <h2 style={{ margin: 0 }}>Benchmark — 3-way comparison</h2>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <button className="btn" onClick={runBenchmark} disabled={!!benchState?.running} style={{ opacity: benchState?.running ? 0.6 : 1, fontSize: 12, padding: '6px 12px' }}>
              {benchState?.running ? `Running ${benchState.current ?? ''}…` : '▶ Run 500×3'}
            </button>
            <button
              className="chip"
              onClick={() => setTokenOpen((v) => !v)}
              aria-expanded={tokenOpen}
              style={{ fontSize: 11 }}
              title="Benchmark mutations are gated by a shared token set as BENCH_API_TOKEN (see README)"
            >
              {sessionToken ? 'Token set' : 'Token'}
            </button>
          </div>
        </div>
        {tokenOpen && (
          <div className="row" style={{ marginTop: 8, gap: 8 }}>
            <input
              aria-label="Benchmark API token"
              type="password"
              placeholder="BENCH_API_TOKEN (only sent to the benchmark API)"
              value={tokenEntry}
              onChange={(e) => setTokenEntry(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') saveToken(); }}
              style={{ flex: 1, minWidth: 240, fontFamily: 'monospace' }}
            />
            <button className="chip" onClick={saveToken}>Save token</button>
            {tokenError && (
              <span className="muted" role="alert" style={{ color: '#e71d36', fontSize: 12 }}>{tokenError}</span>
            )}
          </div>
        )}
        {pendingAction && (
          <div
            role="alertdialog"
            aria-label="Confirm benchmark action"
            aria-describedby="bench-confirm-desc"
            onKeyDown={(e) => { if (e.key === 'Escape') setPendingAction(null); }}
            style={{ marginTop: 8, padding: '8px 12px', border: '1px solid #8a6d1c', borderRadius: 8, background: '#2a230f', display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}
          >
            <span id="bench-confirm-desc" style={{ fontSize: 12 }}>
              {pendingAction.kind === 'run'
                ? 'Run full 500×3 benchmark? ~3–4 h, streams to logs.'
                : `Re-run 500 queries for ${pendingAction.key}? This takes ~60 min and streams to logs.`}
            </span>
            <span style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
              <button className="chip" autoFocus onClick={executePending}>Confirm</button>
              <button className="chip" onClick={() => setPendingAction(null)}>Cancel</button>
            </span>
          </div>
        )}
        {actionError && (
          <div role="alert" style={{ marginTop: 8, display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <span className="muted" style={{ color: '#e71d36', fontSize: 12 }}>{actionError}</span>
            <button className="chip" onClick={() => setActionError(null)}>Dismiss</button>
          </div>
        )}
        <p className="muted" style={{ fontSize: 12, margin: '6px 0 0' }}>
          Scoring: 70% framework hit + 30% citation · Pass ≥0.5 · Yield = pass rate
          {(() => {
            const s = loaded[0] && reports[loaded[0].key]?.summary;
            return s?.queries_distinct ? <> · {s.queries_total ?? s.total} total, {s.queries_distinct} distinct prompts</> : null;
          })()}
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 10, marginTop: 12 }}>
          {MODELS.map((m) => {
            const r = reports[m.key];
            const prog = perModel[m.key]?.progress;
            return (
              <div key={m.key} className="card" style={{ padding: 12, borderLeft: `3px solid ${m.color}` }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}><div style={{ fontWeight: 600, fontSize: 13, color: m.color }}>{m.label}</div><button title={`Refresh ${m.label} (500 queries)`} onClick={() => handleRerunModel(m.key)} style={{ background: 'none', border: '1px solid #26303c', borderRadius: 6, padding: '2px 6px', cursor: 'pointer', fontSize: 11, color: '#4da3ff' }}>↻</button></div>
                <div className="muted" style={{ fontSize: 11 }}>{m.full}</div>
                {r ? (
                  <>
                    <div style={{ marginTop: 8 }}><ScoreBar value={r.summary.pass_rate} color={m.color} /></div>
                    <div className="muted" style={{ fontSize: 11, marginTop: 4 }}>{r.summary.passed}/{r.summary.total} passed · avg {(r.queries.reduce((s, q) => s + q.evaluation.score, 0) / r.queries.length).toFixed(2)}</div>
                  </>
                ) : prog ? <div className="muted" style={{ fontSize: 12, marginTop: 8 }}>{prog.done}/500</div> : <div className="muted" style={{ fontSize: 12, marginTop: 8 }}>pending</div>}
              </div>
            );
          })}
        </div>
      </section>

      {loaded.length > 0 && (
        <section className="card">
          <h3>Scoring per group</h3>
          <CategoryChart reports={reports} />
        </section>
      )}

      <section className="card">
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', marginBottom: 8 }}>
          <h3 style={{ margin: 0 }}>Skim — answers side by side</h3>
          <span className="muted" style={{ fontSize: 12 }}>{filtered.length} queries · page {page + 1}/{totalPages}</span>
          <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
            <button className="chip" disabled={page === 0} onClick={() => setPage((p) => Math.max(0, p - 1))}>‹ Prev</button>
            <button className="chip" disabled={page + 1 >= totalPages} onClick={() => setPage((p) => p + 1)}>Next ›</button>
          </div>
        </div>
        <div className="row" style={{ gap: 8, marginBottom: 8 }}>
          <input aria-label="Search queries" placeholder="Search query text…" value={search} onChange={(e) => setSearch(e.target.value)} style={{ flex: 1, minWidth: 220 }} />
          <select value={filterCat} onChange={(e) => setFilterCat(e.target.value)} aria-label="Category">
            <option value="all">all categories</option>
            {cats.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </div>

        <div style={{ display: 'grid', gap: 12 }}>
          {pageQueries.map((q) => (
            <div key={q.id} className="card" style={{ padding: 0, overflow: 'hidden' }}>
              <div style={{ padding: '10px 12px', background: '#0c1117', borderBottom: '1px solid #26303c', display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                <div><strong style={{ fontSize: 12 }}>#{q.id} [{q.category}]</strong> <span style={{ fontSize: 12 }}>{q.query.slice(0, 140)}</span>
                  <div className="muted" style={{ fontSize: 11 }}>expects: {q.expects.join(', ')}</div>
                </div>
                <div style={{ display: 'flex', gap: 6, alignSelf: 'flex-start' }}><button title="Re-run this prompt for all 3 models" onClick={() => handleRerun(q)} disabled={rerunning === q.id} style={{ background: 'none', border: '1px solid #26303c', borderRadius: 6, padding: '2px 6px', cursor: 'pointer', fontSize: 12, color: rerunning === q.id ? '#6b7a8a' : '#4da3ff' }}>{rerunning === q.id ? '…' : '↻'}</button><button className="chip" style={{ fontSize: 11 }} onClick={() => setExpanded(expanded === q.id ? null : q.id)}>{expanded === q.id ? 'Collapse' : 'Expand'}</button></div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: `repeat(${loaded.length}, 1fr)`, gap: 0 }}>
                {loaded.map((m) => {
                  const hit = reports[m.key]!.queries.find((x) => x.id === q.id);
                  const isExpanded = expanded === q.id;
                  return (
                    <div key={m.key} style={{ padding: 10, borderRight: `1px solid #1e2631`, background: hit && hit.evaluation.score >= 0.5 ? '#0f1a12' : '#1a0f12' }}>
                      <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 6 }}>
                        <span className="dot" style={{ background: m.color }} />
                        <strong style={{ fontSize: 11, color: m.color }}>{m.label}</strong>
                        {hit && <span className={`badge ${hit.evaluation.score >= 0.5 ? 'badge-o' : 'badge-m'}`} style={{ fontSize: 10 }}>{hit.evaluation.score.toFixed(2)}</span>}
                        {hit?.evaluation.has_citation && <span style={{ fontSize: 10 }} title="has citation">⧉</span>}
                      </div>
                      <div style={{ fontSize: 11, color: '#8a9aad' }}>{hit?.evaluation.hits.join(', ') || '—'}</div>
                      <div style={{ fontSize: 12, lineHeight: 1.45, marginTop: 6, maxHeight: isExpanded ? 'none' : 96, overflow: 'hidden', whiteSpace: 'pre-wrap' }}>
                        {hit?.response_excerpt || <span className="muted">no data</span>}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
        {filtered.length === 0 && <p className="muted" style={{ textAlign: 'center', padding: 12 }}>No queries match.</p>}
      </section>
    </div>
  );
}
