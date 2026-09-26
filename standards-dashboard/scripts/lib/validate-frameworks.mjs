// Validates data/frameworks.json against data/taxonomy.json invariants.
// Invariants (kept in sync with ingest.mjs):
//   - unique non-empty ids
//   - coverage keys are known dimensions
//   - coverage scores are 0|1|2
//   - every dimension is present on every framework
//   - url is an absolute http(s) link
// Returns an array of error strings (empty => valid).
export function validateFrameworks(fwRaw, taxRaw) {
  const dimIds = new Set(taxRaw.dimensions.map((d) => d.id));
  const errors = [];
  const seen = new Set();
  for (const f of fwRaw.frameworks) {
    if (!f.id || seen.has(f.id)) errors.push(`duplicate/missing id: ${f.id}`);
    seen.add(f.id);
    for (const [k, v] of Object.entries(f.coverage ?? {})) {
      if (!dimIds.has(k)) errors.push(`${f.id}: unknown dimension ${k}`);
      if (![0, 1, 2].includes(v)) errors.push(`${f.id}: bad score ${k}=${v}`);
    }
    for (const d of dimIds) if (!(d in (f.coverage ?? {}))) errors.push(`${f.id}: missing dimension ${d}`);
    if (!f.url?.startsWith('http')) errors.push(`${f.id}: bad url`);
  }
  return errors;
}