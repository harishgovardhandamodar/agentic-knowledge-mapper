import React from 'react';

export function Bar({ value, max = 100 }: { value: number; max?: number }) {
  return (
    <div className="bar" role="img" aria-label={`coverage ${value} percent`}>
      <div className="bar-fill" style={{ width: `${Math.min(100, (value / max) * 100)}%` }} />
      <span className="bar-label">{value}%</span>
    </div>
  );
}

export function HeatCell({ v }: { v: number }) {
  const cls = v === 2 ? 'h2' : v === 1 ? 'h1' : 'h0';
  const label = v === 2 ? 'direct' : v === 1 ? 'partial' : 'none';
  return (
    <span className={`heat ${cls}`} title={label} aria-label={label}>
      {v}
    </span>
  );
}

export function OverlapMatrix({
  ids,
  names,
  get,
  onSelect,
}: {
  ids: string[];
  names: Record<string, string>;
  get: (a: string, b: string) => number | null;
  onSelect: (a: string, b: string) => void;
}) {
  return (
    <div className="matrix-wrap" role="table" aria-label="Framework overlap matrix">
      <table className="matrix">
        <thead>
          <tr>
            <th scope="col"></th>
            {ids.map((id) => (
              <th key={id} scope="col" title={names[id]}>
                {id.slice(0, 12)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {ids.map((a) => (
            <tr key={a}>
              <th scope="row" title={names[a]}>
                {a.slice(0, 12)}
              </th>
              {ids.map((b) => {
                const v = get(a, b);
                const pct = v == null ? 0 : Math.round(v * 100);
                return (
                  <td key={b}>
                    <button
                      className={`mx ${pct >= 60 ? 'mx-hi' : pct >= 30 ? 'mx-mid' : 'mx-lo'}`}
                      onClick={() => onSelect(a, b)}
                      title={`${names[a]} × ${names[b]}: ${pct}% control overlap`}
                    >
                      {a === b ? '—' : `${pct}`}
                    </button>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
