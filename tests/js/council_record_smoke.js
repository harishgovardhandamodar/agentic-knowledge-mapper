/* Headless check for the council record in the artifacts view.
 *
 * The artifacts tab shows what an investigation *collected*; the council
 * record above it shows what the council *did* (logs, actions, decisions,
 * hypotheses). Two failure modes this guards against, both silent in the
 * Python suite and both previously shipped:
 *
 *   1. loadCouncilRecord() called from *outside* loadArtifacts' body, so it
 *      runs once at page load with no investigation selected and never again
 *      -- the section never appears no matter what the endpoint returns.
 *   2. councilRecordHtml dropping a section or crashing on a sparse record
 *      (an investigation with logs but no hypotheses, or claims without a
 *      council block, must render the rest, not throw).
 *
 * Usage: node council_record_smoke.js
 */
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..', '..');
const html = fs.readFileSync(path.join(root, 'static', 'index.html'), 'utf8');
const blocks = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
const block = blocks.find((b) => b.includes('function loadArtifacts')) || '';
if (!block) { console.error('FAIL: app script block not found'); process.exit(1); }

function extractFn(name) {
  const re = new RegExp('\\b(async\\s+)?function ' + name + '\\s*\\([^)]*\\)\\s*\\{');
  const m = re.exec(block);
  if (!m) throw new Error('function ' + name + ' not found');
  const start = m.index;
  let i = block.indexOf('{', start);
  let depth = 0;
  for (; i < block.length; i++) {
    if (block[i] === '{') depth++;
    else if (block[i] === '}') { depth--; if (depth === 0) break; }
  }
  return block.slice(start, i + 1);
}

const failed = [];
function assert(cond, msg) { if (!cond) failed.push(msg); }
function show(label, v) { process.stdout.write('    ' + label + ': ' + v + '\n'); }

// A stub record: one full hypothesis assessment plus one standard row with a
// trace but no claims, the shape GET /council-record actually returns.
const RECORD = {
  investigation_id: 7,
  logs: [
    {
      assessment_id: 11, path: 'model_hypothesis', product: 'Widget',
      task_id: 'hyp-x',
      plan: [
        { n: 0, kind: 'plan', phase: 'plan_hypothesis_synthesis', by: 'hypothesis-orchestrator',
          plan: 'analyst → verifier → reporter', started_at: 't0', finished_at: 't0',
          duration_s: 0.0, status: 'planned' },
        { n: 1, kind: 'step', phase: 'draft_hypotheses', by: 'hypothesis-orchestrator',
          worker: 'hypothesis-analyst', input_note: 'claims from priors',
          output_note: '2 claims drafted', started_at: 't0', finished_at: 't1',
          duration_s: 38.0, status: 'done' },
        { n: 2, kind: 'step', phase: 'write_hypothesis_report',
          by: 'hypothesis-orchestrator', input_note: 'write it',
          started_at: 't2', status: 'incomplete' },
      ],
      hops: [
        { agent: 'hypothesis-analyst', intent: 'hypotheses_drafted', at: 't0', note: '2 claims drafted' },
        { agent: 'hypothesis-verifier', intent: 'hypotheses_verified', at: 't1', note: '2 verified, 1 contested' },
      ],
    },
    { assessment_id: 9, path: 'model', product: 'Widget', task_id: 'mod-y', hops: [] },
    // Legacy payload: hops but no plan pairing. Must render the flat list,
    // not nothing.
    { assessment_id: 8, path: 'model', product: 'Widget', task_id: 'mod-z',
      hops: [
        { agent: 'model-orchestrator', intent: 'plan_model_assessment', at: 't0', note: 'profile it' },
      ] },
  ],
  runs: [{ id: 3, status: 'done', trigger: 'security' }],
  actions: [
    { kind: 'assessment_requested', assessment_id: 11, actor: 'op', detail: 'Widget' },
    { kind: 'register_edit', assessment_id: 11, hypothesis_id: 'H01', status: 'supported', falsifiers: ['x'] },
    { kind: 'artifact_reviews', accepted_or_rejected: 0 },
  ],
  decisions: [
    { assessment_id: 11, product: 'Widget', assurance_decision: 'accept', decided_by: 'reviewer', decided_at: 't2', note: null, expires_at: null },
  ],
  hypotheses: [
    {
      assessment_id: 11,
      confidence: 44,
      claims: [
        {
          hypothesis_id: 'H01', claim: 'Outputs reveal training rows',
          falsifier: 'Canary rows never surface', confidence: 62, impact: 4,
          status: 'supported',
          council: {
            seat: 'privacy-cryptography', attack_classes: ['extraction'],
            falsifier_audit: { grade: 'decisive' },
            challenges: [{ seat: 'measurement-science', ground: 'single_flow', why: 'one flow only' }],
          },
        },
        {
          hypothesis_id: 'H02', claim: 'Vendor logs everything',
          falsifier: 'DPA forbids retention', confidence: 41, impact: 3,
          status: 'untested',
          // No council block: legacy-shaped claim. Must render, not throw.
        },
      ],
      council: {
        panel: { n_seats: 6 }, contested: 1,
        coverage: {
          coverage_pct: 50.0,
          covered: [{ class: 'extraction', label: 'Extraction' }],
          unexamined: [{ class: 'poisoning', label: 'Poisoning', stored_rows: 2 }],
          not_in_corpus: [],
        },
      },
      analytics: {
        n_claims: 2, mean_confidence: 51.5, n_contested: 1,
        n_uncontested: 1, n_blocking: 0, pct_contested: 50.0,
        grounds: { single_flow: 1 },
        by_seat: { 'privacy-cryptography': { filed: 1, contested: 1 } },
        reviewing: { 'measurement-science': 1 },
        statuses: {}, impacts: {}, coverage_pct: 50.0,
        n_covered: 1, n_unexamined: 1, n_not_in_corpus: 0,
        unexamined_classes: ['poisoning'], n_seats: 6,
      },
    },
  ],
};

async function main() {
  // 1. The call must live *inside* loadArtifacts' body. A statement after the
  // closing brace runs once at page load (currentInv is null) and never again.
  const loaderSrc = extractFn('loadArtifacts');
  assert(loaderSrc.includes('loadCouncilRecord()'),
    'loadArtifacts does not call loadCouncilRecord at all');
  const bodyOnly = loaderSrc.slice(loaderSrc.indexOf('{'));
  // The call must precede the function's final closing brace, i.e. be part of
  // the body rather than a following statement. Depth-walk to the matching
  // close and require the call before it.
  let depth = 0, end = -1;
  for (let i = 0; i < bodyOnly.length; i++) {
    if (bodyOnly[i] === '{') depth++;
    else if (bodyOnly[i] === '}') { depth--; if (depth === 0) { end = i; break; } }
  }
  assert(end > 0 && bodyOnly.slice(0, end).includes('loadCouncilRecord()'),
    'loadCouncilRecord() is outside loadArtifacts body -- runs once at page load, never per investigation');
  show('call placement', 'inside loadArtifacts');

  // 2. Render the record through the real function.
  const src = 'const LB_W = 640;\n'
    + 'function lbScale(domain, range) { const [d0, d1] = domain, [r0, r1] = range; const span = (d1 - d0) || 1; return (v) => r0 + ((v - d0) / span) * (r1 - r0); }\n'
    + 'function lbNiceMax(v) { if (v <= 0) return 10; const mag = Math.pow(10, Math.floor(Math.log10(v))); return Math.ceil(v / mag) * mag; }\n'
    + 'function lbAxisTicks(max, count) { const out = []; for (let i = 0; i <= count; i++) out.push(Math.round((max / count) * i)); return out; }\n'
    + 'let FOLD_STORE = "akm.folds";\nlet _foldCache = null;\n'
    + 'const CSS = { escape: (s) => s };\n'
    + 'const localStorage = { _s: {}, getItem(k) { return k in this._s ? this._s[k] : null; },'
    + ' setItem(k, v) { this._s[k] = String(v); }, removeItem(k) { delete this._s[k]; } };\n'
    + extractFn('_foldAll') + '\n'
    + extractFn('_foldSet') + '\n'
    + extractFn('foldIsOpen') + '\n'
    + extractFn('foldSection') + '\n'
    + extractFn('loadCouncilRecord') + '\n'
    + extractFn('councilConfBars') + '\n'
    + extractFn('councilDonut') + '\n'
    + extractFn('lbGroupedBars') + '\n'
    + extractFn('councilPlanHtml') + '\n'
    + extractFn('councilRecordHtml') + '\n';
  const escHtml = (v) => String(v === null || v === undefined ? '' : v);
  const els = {};
  const documentStub = {
    getElementById(id) {
      if (!els[id]) els[id] = { innerHTML: '', style: {}, dataset: {} };
      return els[id];
    },
  };
  const fetchStub = async () => ({ ok: true, json: async () => RECORD });
  // eslint-disable-next-line no-new-func
  const fn = new Function('document', 'escHtml', 'fetch', 'API', 'currentInv',
    'foldIsOpen',
    src + '\nreturn { loadCouncilRecord, councilRecordHtml };');
  const F = fn(documentStub, escHtml, fetchStub, '/api', 7,
    () => true);
  await F.loadCouncilRecord();
  const host = els.councilRecord.innerHTML;
  assert(host.includes('Council record'), 'fold header missing');
  assert(host.includes('hypothesis-analyst'), 'log hops not rendered');
  assert(host.includes('council-steps'), 'plan stepper not rendered');
  assert(host.includes('draft_hypotheses'), 'step phase not rendered');
  assert(host.includes('2 claims drafted'), 'step output not rendered');
  assert(host.includes('incomplete'), 'open step status not marked');
  assert(host.includes('profile it'), 'legacy flat-hop fallback not rendered');
  assert(host.includes('Register edit'), 'register-edit action not rendered');
  assert(host.includes('accept'), 'assurance decision not rendered');
  assert(host.includes('Outputs reveal training rows'), 'claim H01 not rendered');
  assert(host.includes('privacy-cryptography'), 'author seat not rendered');
  assert(host.includes('measurement-science'), 'objection not rendered');
  assert(host.includes('Vendor logs everything'), 'council-less claim H02 dropped instead of rendered');
  assert(host.includes('mean confidence'), 'analytics strip missing');
  assert(host.includes('single flow'), 'grounds bars missing');
  assert(host.toLowerCase().includes('poisoning'), 'coverage matrix missing the unexamined class');
  assert(host.includes('Confidence per claim'), 'confidence chart missing');
  assert(host.includes('Attack-class coverage'), 'coverage donut missing');
  assert(host.includes('filed vs reviewing'), 'seats chart missing');
  const svgs = (host.match(/<svg/g) || []).length;
  assert(svgs >= 3, 'expected at least 3 chart SVGs, found ' + svgs);
  show('sections', 'logs + actions + decisions + hypotheses');

  // 3. Sparse record: logs only, no hypotheses, no decisions. Must render the
  // logs and skip the rest without throwing.
  const sparse = { investigation_id: 7, logs: RECORD.logs, runs: [], actions: [], decisions: [], hypotheses: [] };
  const sparseHtml = F.councilRecordHtml(sparse);
  assert(sparseHtml.includes('hypothesis-analyst'), 'sparse record lost its logs');
  assert(!sparseHtml.includes('Hypotheses'), 'empty hypotheses section rendered instead of skipped');
  show('sparse record', 'logs only, rest skipped');

  if (failed.length) {
    console.error('FAIL:');
    for (const f of failed) console.error('  - ' + f);
    process.exit(1);
  }
  console.log('PASS: council record renders logs, actions, decisions, hypotheses');
}

main().catch((e) => { console.error('FAIL: threw: ' + (e && e.stack || e)); process.exit(1); });
