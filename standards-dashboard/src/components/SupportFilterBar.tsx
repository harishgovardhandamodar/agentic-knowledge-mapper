import React from 'react';
import type { Framework } from '../lib/engine';
import { SUPPORT_MODES } from '../lib/support';
import type { SupportMode } from '../lib/support';
import { supportDistribution } from '../lib/support';

export type SupportFilters = Partial<Record<SupportMode, string[]>>;

export function filterBySupport(frameworks: Framework[], filters: SupportFilters): Framework[] {
  const active = Object.entries(filters).filter(([, v]) => v && v.length > 0) as [SupportMode, string[]][];
  if (active.length === 0) return frameworks;
  return frameworks.filter((f) =>
    active.every(([modeId, vals]) => {
      const mode = SUPPORT_MODES.find((m) => m.id === modeId)!;
      const fVals = mode.getValues(f);
      return vals.some((v) => fVals.includes(v));
    }),
  );
}

export default function SupportFilterBar({
  frameworks, filters, onChange,
}: {
  frameworks: Framework[]; filters: SupportFilters; onChange: (f: SupportFilters) => void;
}) {
  const toggle = (mode: SupportMode, value: string) => {
    const cur = filters[mode] ?? [];
    const next = cur.includes(value) ? cur.filter((v) => v !== value) : [...cur, value];
    const nxt = { ...filters };
    if (next.length === 0) delete nxt[mode];
    else nxt[mode] = next;
    onChange(nxt);
  };
  const clearAll = () => onChange({});

  const activeCount = Object.values(filters).reduce((s, v) => s + (v?.length ?? 0), 0);

  return (
    <div className="support-filter-bar card" style={{ padding: 12 }}>
      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center' }}>
        <strong style={{ fontSize: 13 }}>Support filters — refine view</strong>
        <span className="muted" style={{ fontSize: 12 }}>{activeCount ? `${activeCount} active` : 'no filters'} · e.g. DPO + Frontier + Customer-Facing</span>
        {activeCount > 0 && <button className="chip" onClick={clearAll}>clear all</button>}
      </div>
      <div style={{ display: 'grid', gap: 10, marginTop: 10 }}>
        {SUPPORT_MODES.map((mode) => {
          const dist = supportDistribution(frameworks, mode);
          const sel = new Set(filters[mode.id] ?? []);
          return (
            <div key={mode.id} style={{ display: 'flex', gap: 8, alignItems: 'flex-start', flexWrap: 'wrap' }}>
              <span style={{ minWidth: 110, fontSize: 12, fontWeight: 600, color: mode.color, display: 'flex', gap: 4, alignItems: 'center' }}>
                <span>{mode.icon}</span> {mode.short}
              </span>
              <div className="chips" style={{ margin: 0, gap: 6 }}>
                {dist.map((d) => (
                  <button
                    key={d.name}
                    className={`chip ${sel.has(d.name) ? 'on' : ''}`}
                    style={{ borderColor: sel.has(d.name) ? mode.color : undefined, color: sel.has(d.name) ? mode.color : undefined, fontSize: 11 }}
                    onClick={() => toggle(mode.id, d.name)}
                    title={`${d.name}: ${d.value} frameworks`}
                  >
                    {d.name} · {d.value}
                  </button>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
