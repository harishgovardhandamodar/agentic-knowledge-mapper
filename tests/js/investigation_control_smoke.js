/* Investigation control sub-tab: parts render from the backend contract.
 *
 * The rows are rendered by icRenderState from `/api/investigations/{id}/control`,
 * so a renamed part key or a dropped field fails here rather than silently in
 * the browser. The behaviours pinned are the ones that would make the panel
 * lie: an unavailable part must be visibly disabled with its reason, and a
 * stale tick must not survive into a trigger.
 *
 * Usage: node investigation_control_smoke.js
 */
const fs = require('fs');
const path = require('path');

const html = fs.readFileSync(
  path.join(__dirname, '..', '..', 'static', 'index.html'), 'utf8');

function grab(name) {
  const at = html.indexOf('function ' + name + '(');
  if (at < 0) throw new Error('missing ' + name);
  // Keep an `async` prefix: slicing from "function name(" would silently
  // drop it and turn an await inside the body into a parse error.
  const start = html.slice(Math.max(0, at - 6), at).endsWith('async ')
    ? at - 6 : at;
  let depth = 0;
  let i = html.indexOf('{', at);
  for (; i < html.length; i++) {
    if (html[i] === '{') depth++;
    if (html[i] === '}') { depth--; if (!depth) break; }
  }
  return html.slice(start, i + 1);
}

const escHtml = eval('(' + grab('escHtml').replace('function escHtml', 'function') + ')');
const lib = ['icInit', 'icTargetId', 'icLoadState', 'icRenderState', 'icPartRow',
             'icTogglePart', 'icSelectAllParts', 'icRenderCheckboxes',
             'icRenderOutcomes', 'icRqPrefill', 'icRqRender', 'icRqSeed',
             'icRqLoadRoles'].map(grab).join('\n');

// Minimal DOM: the panel writes innerHTML and reads a few counters.
function makeDoc() {
  const els = {};
  const el = (id) => {
    if (!els[id]) els[id] = { hidden: false, innerHTML: '', textContent: '', value: '' };
    return els[id];
  };
  return {
    els,
    getElementById: (id) => el(id),
    querySelectorAll: () => [],
    querySelector: () => null,
  };
}

const state = {
  investigation_id: 42,
  counts: { artifacts: 12, assessments: 2, explanations: 1, cve_findings: 3, runs: 7 },
  parts: [
    { key: 'research', label: 'Research collection', blurb: 'Re-plan and collect.', endpoint: 'POST /api/investigations/{id}/run', requires: null, blocking: true, available: true, blocked_reason: null, last: { id: 91, status: 'done', trigger: 'manual', finished_at: '2026-10-14T09:12:00' } },
    { key: 'assess', label: 'Security assessment', blurb: 'Run the security agent.', endpoint: 'POST /api/investigations/{id}/security/assess', requires: null, blocking: false, available: true, blocked_reason: null, last: null },
    { key: 'gaps', label: 'Gap research', blurb: 'Paper-first on open gaps.', endpoint: 'POST /api/investigations/{id}/research-gaps/run', requires: 'research', blocking: true, available: false, blocked_reason: 'nothing collected yet — run research first', last: null },
    { key: 'hypotheses', label: 'Hypothesis evidence', blurb: 'Collect falsifier evidence.', endpoint: 'POST /api/security/assessments/{id}/hypotheses/{hid}/collect-evidence', requires: 'assess', blocking: false, available: false, blocked_reason: 'no stored assessment — run the security assessment first', last: null },
    { key: 'summary', label: 'Summary recompute', blurb: 'Recompute the summary.', endpoint: 'POST /api/investigations/{id}/summary/regenerate', requires: null, blocking: false, available: true, blocked_reason: null, last: null },
  ],
};

let fails = 0;
const check = (name, cond, extra) => {
  console.log((cond ? 'PASS' : 'FAIL') + ' ' + name + (cond ? '' : ' — ' + extra));
  if (!cond) fails++;
};

// The panel's helpers are async, so the harness body has to be too: a plain
// Function rejects the `await` inside icInit/icLoadState at parse time.
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const factory = new AsyncFunction('document', 'escHtml', 'investigations',
  'currentInv', 'API', 'showNotif', 'fetch',
  'const icState = { parts: [], selected: new Set(), busy: false };\n' +
  'const icRq = { draft: null, busy: false, roleLabels: {} };\n' +
  lib + '\nreturn { icRenderState, icPartRow, icTogglePart, icSelectAllParts, icRenderOutcomes, icRqRender, icRqPrefill, icRqLoadRoles, icState, icRq };');

async function main() {
const doc = makeDoc();
const invs = [{ id: 42, title: 'Acme support agent', status: 'ready',
                keywords: 'acme, agent',
                description: 'Drafts replies from ticket text.\n\nPart of manager run #7.' }];
const api = await factory(doc, escHtml, invs, 42, '/api', () => {},
  () => Promise.reject(new Error('no network')));
const { icRenderState, icTogglePart, icSelectAllParts, icRenderOutcomes,
        icRqRender, icRqPrefill, icState, icRq } = api;

// 1: counts and the availability badge.
icRenderState(state);
const counts = doc.getElementById('icCounts').textContent;
check('counts render', counts.includes('12 artifact(s)') && counts.includes('7 run(s)'), counts);
check('availability badge', doc.getElementById('icPartsCount').textContent === '3/5 available',
  doc.getElementById('icPartsCount').textContent);

// 2: every part renders, with its endpoint visible.
let body = doc.getElementById('icParts').innerHTML;
check('all parts rendered', (body.match(/data-ic-part=/g) || []).length === 5,
  'got ' + (body.match(/data-ic-part=/g) || []).length);
check('endpoints shown', body.includes('/api/investigations/{id}/run'));
check('last run shown', body.includes('never run') && body.includes('#91'));

// 3: unavailable parts are disabled AND carry their reason.
check('blocked part is disabled', /data-ic-part="gaps" disabled/.test(body), body);
check('blocked reason shown', body.includes('nothing collected yet — run research first'));
check('blocked reason for hypotheses',
  body.includes('no stored assessment — run the security assessment first'));
check('available part is not disabled',
  !/data-ic-part="research"[^>]*disabled/.test(body));

// 4: a stale tick for a part that is no longer runnable is dropped.
icState.selected = new Set(['research', 'gaps', 'gone']);
icRenderState(state);
check('stale ticks dropped',
  icState.selected.has('research') && !icState.selected.has('gaps') &&
  !icState.selected.has('gone'),
  [...icState.selected].join(','));

// 5: select-all selects only runnable parts.
icState.selected.clear();
icSelectAllParts(true);
check('all selects available only',
  icState.selected.size === 3 && icState.selected.has('research') &&
  !icState.selected.has('gaps'), [...icState.selected].join(','));
icSelectAllParts(false);
check('none clears', icState.selected.size === 0);
icTogglePart('research', true);
check('toggle adds', icState.selected.has('research'));
icTogglePart('research', false);
check('toggle removes', !icState.selected.has('research'));

// 6: outcomes render per part, and a partial failure is reported as partial.
icRenderOutcomes({
  counts: { launched: 2, skipped: 1, failed: 1, nothing_to_do: 0 },
  outcomes: [
    { part: 'research', label: 'Research collection', status: 'launched', detail: '' },
    { part: 'gaps', label: 'Gap research', status: 'skipped', detail: 'nothing collected yet' },
    { part: 'cves', label: 'CVE sweep', status: 'collected', detail: '4 CVE finding(s) stored' },
    { part: 'assess', label: 'Security assessment', status: 'failed', detail: 'already running here', refused: true },
  ],
});
const res = doc.getElementById('icResult').innerHTML;
check('outcome card shown', doc.getElementById('icResultCard').hidden === false);
check('outcome summary counts', res.includes('2 ran') && res.includes('1 skipped') && res.includes('1 failed'), res);
check('partial failure is explained',
  res.includes('one part failing does not stop the others'));
check('each outcome listed', res.includes('CVE sweep') && res.includes('4 CVE finding(s) stored'));

// 7: the panel lives in the AKM pane next to the knowledge graph, and the
// tab is wired into the real switchView rather than its own pane switcher.
const akmTab = /data-view="control"[^>]*>\s*<i[^>]*><\/i>\s*Investigation control/.test(html);
check('AKM tab exists', akmTab);
const graphAt = html.indexOf('data-view="graph"');
const controlAt = html.indexOf('data-view="control"');
check('tab sits next to Knowledge graph',
  controlAt > graphAt && controlAt - graphAt < 220,
  'graph at ' + graphAt + ', control at ' + controlAt);
check('controlView exists inside the AKM pane',
  html.includes('id="controlView"') &&
  controlAt < html.indexOf('id="controlView"') &&
  html.indexOf('id="controlView"') < html.indexOf('/akmPane'));
check('switchView loads the panel',
  html.includes("if (view === 'control' && typeof icInit === 'function') icInit();"));
// No leftover pane switcher from the earlier Manager placement.
check('Manager sub-tab switcher is gone',
  !html.includes('mgrSwitchPane') && !html.includes('id="mgrCtrlPane"') &&
  !html.includes('icRefreshInvOptions') && !html.includes('icSelectAvailable'));

// 8: the risk questionnaire writer is present in the same panel, with the
// form and the filling run reachable from it.
check('questionnaire card in the control view',
  html.includes('Security risk questionnaire') &&
  html.indexOf('Security risk questionnaire') > html.indexOf('id="controlView"'));
check('questionnaire query box and generate wired',
  html.includes('id="icRqQuery"') && html.includes('icRqGenerate(this)'));

const draft = {
  draft: { id: 6, target: 'a customer-support agent', source: 'deterministic' },
  frame: { axes: ['data_privacy', 'autonomy_boundaries'] },
  quality: { questions: 37, sections: 12, ok: true, roles: ['data_protection'] },
  role_slices: { data_protection: [{ key: 'q1' }], product_owner: [{ key: 'q2' }] },
};
icRq.roleLabels = { data_protection: 'Data protection / privacy' };
icRq.draft = draft;
icRqRender();
let rq = doc.getElementById('icRqResult').innerHTML;
check('draft summarised', rq.includes('Draft #6') && rq.includes('37 questions') && rq.includes('12 sections'));
check('fillable form linked',
  rq.includes('/api/risk-questionnaire/drafts/6/report.md') &&
  rq.includes('Open fillable form'));
check('cover note linked', rq.includes('format=brief'));
check('seed button present', rq.includes('icRqSeed(this)'));
check('render uses the loaded role labels',
  rq.includes('Data protection / privacy') && rq.includes('product_owner (1)'),
  rq);

// The labels themselves must be fetched, not carried in JS: the questionnaire
// routes by role, and a stale copy here would tell a team they own questions
// they were never asked. A hardcoded map would render identically and still
// be wrong, so the loader is exercised against a stubbed response.
const loaderApi = await factory(doc, escHtml, invs, 42, '/api', () => {},
  async () => ({ ok: true, json: async () => ({
    roles: [{ key: 'data_protection', title: 'Data protection / privacy' },
            { key: 'platform_engineering', title: 'Platform / engineering' }],
  }) }));
await loaderApi.icRqLoadRoles();
check('role labels load from the API',
  loaderApi.icRq.roleLabels.data_protection === 'Data protection / privacy' &&
  loaderApi.icRq.roleLabels.platform_engineering === 'Platform / engineering',
  JSON.stringify(loaderApi.icRq.roleLabels));
check('no hardcoded role titles in JS',
  !html.includes("roleLabels = { data_protection"));

// Prefill must describe the investigation in focus and strip the manager
// footer, which is bookkeeping rather than what the system does.
icRqPrefill();
const prefill = doc.getElementById('icRqQuery').value;
check('prefill uses the investigation in focus', prefill.includes('Acme support agent'), prefill);
check('prefill keeps keywords', prefill.includes('Keywords: acme, agent'), prefill);
check('prefill keeps the description', prefill.includes('Drafts replies'), prefill);
check('prefill strips the manager footer', !prefill.includes('manager run'), prefill);

// No draft yet -> nothing rendered.
icRq.draft = null;
icRqRender();
check('no draft renders nothing', doc.getElementById('icRqResult').innerHTML === '');

console.log(fails ? 'FAILURES: ' + fails : 'all good');
process.exit(fails ? 1 : 0);
}

main().catch((e) => {
  console.log('FAIL harness error — ' + e.message);
  process.exit(1);
});
