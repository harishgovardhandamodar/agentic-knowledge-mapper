/* Headless render check for the leadership board.
 *
 * The board's render path is ~700 lines of template strings behind a browser.
 * A typo in there is invisible to the Python suite and fatal in the page, so
 * this loads the real leadership slice of static/index.html against a minimal
 * DOM shim and renders a real board payload produced by the API.
 *
 * It asserts two things the eye is bad at:
 *   1. rendering does not throw (undefined function, bad property access);
 *   2. the output contains no "undefined" or "NaN" -- a silently blank figure
 *      is a worse bug than a crash, because a CISO reads past it.
 *
 * Usage: node leadership_render_smoke.js <payload.json>
 * The payload is one /api/leadership/board response.
 */
const fs = require('fs');
const path = require('path');

const payloadPath = process.argv[2];
if (!payloadPath) {
  console.error('usage: node leadership_render_smoke.js <board.json>');
  process.exit(2);
}
const board = JSON.parse(fs.readFileSync(payloadPath, 'utf8'));

// ---- minimal DOM shim -----------------------------------------------------
// Only what the leadership slice touches. Anything it reaches for that is not
// here is a bug worth knowing about, so the proxy throws with the name.
const store = {};
function makeEl(id) {
  const el = {
    id: id || '',
    value: '',
    checked: false,
    hidden: false,
    disabled: false,
    style: {},
    textContent: '',
    innerHTML: '',
    className: '',
    options: [],
    children: [],
    setAttribute() {}, getAttribute() { return null; }, remove() {},
    appendChild(c) { this.children.push(c); return c; },
    addEventListener() {}, removeEventListener() {}, focus() {}, blur() {},
    closest() { return null; }, querySelector() { return null; },
    querySelectorAll() { return []; },
    insertAdjacentHTML() {}, scrollIntoView() {},
    getBoundingClientRect() { return { top: 0, left: 0, width: 100, height: 20 }; },
  };
  return el;
}
const elCache = {};
const document = {
  hidden: false,
  visibilityState: 'visible',
  body: makeEl('body'),
  documentElement: makeEl('html'),
  getElementById(id) {
    if (!elCache[id]) elCache[id] = makeEl(id);
    return elCache[id];
  },
  querySelector() { return null; },
  querySelectorAll() { return []; },
  createElement() { return makeEl('created'); },
  createElementNS() { return makeEl('svg'); },
  addEventListener() {}, removeEventListener() {},
};
const window = {
  innerWidth: 1600, innerHeight: 900,
  open() {}, close() {}, alert() {}, confirm() { return false; },
  prompt() { return ''; }, location: { href: '' }, matchMedia: () => ({ matches: false }),
  addEventListener() {}, removeEventListener() {}, getComputedStyle: () => ({}),
};
// The slice calls these on load paths we do not exercise, but a bare
// setInterval would keep the process alive after the render.
function setInterval() { return 0; }
function clearInterval() {}
const localStorage = { getItem: () => null, setItem() {}, removeItem() {} };
const fetch = async () => ({ ok: true, status: 200, json: async () => ({}) });
const escHtml = (v) => String(v === null || v === undefined ? '' : v);
const secDashInv = () => null;
const secSwitchPaneTab = () => {};
const switchApp = () => {};
const loadSecurityById = () => {};

// ---- load the real slice from static/index.html ----------------------------
const root = path.resolve(__dirname, '..', '..');
const html = fs.readFileSync(path.join(root, 'static', 'index.html'), 'utf8');
const blocks = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
if (blocks.length < 2) {
  console.error('FAIL: could not find the app script block');
  process.exit(1);
}
const block = blocks[1];
const start = block.indexOf('let secLeadCache');
if (start < 0) {
  console.error('FAIL: leadership slice not found in the app script');
  process.exit(1);
}
const slice = block.slice(start);

// Every onclick="fn(...)" in the slice must resolve to a function we defined.
// A handler that does not exist throws only when a reader clicks it.
const handlers = new Set();
for (const m of slice.matchAll(/onclick="([A-Za-z_$][\w$]*)\(/g)) handlers.add(m[1]);
for (const m of slice.matchAll(/onchange="([A-Za-z_$][\w$]*)\(/g)) handlers.add(m[1]);

const problems = [];
let defined = [];
try {
  // eslint-disable-next-line no-new-func
  const fn = new Function(
    'document', 'window', 'setInterval', 'clearInterval', 'localStorage',
    'fetch', 'escHtml', 'secDashInv', 'secSwitchPaneTab', 'switchApp',
    'loadSecurityById', '__payload',
    slice
    + '\n;return {__setCache: (v) => { secLeadCache = v; },'
    + [...handlers, 'secLeadRender', 'secLeadKpis', 'secLeadSorted',
       'lbLineChart', 'lbGroupedBars', 'lbBars', 'lbKpi', 'lbSev',
       'secLeadChartMode', 'secLeadSortBy', 'secLeadQueueHtml',
       'secLeadRiskHtml', 'secLeadAlertsHtml']
      .map(n => `${n}: typeof ${n} !== 'undefined' ? ${n} : undefined`).join(',')
    + '};');
  const api = fn(document, window, setInterval, clearInterval, localStorage,
    fetch, escHtml, secDashInv, secSwitchPaneTab, switchApp, loadSecurityById,
    board);

  for (const name of handlers) {
    if (typeof api[name] !== 'function') {
      problems.push(`handler ${name}() is wired to the UI but not defined`);
    }
  }
  defined = Object.entries(api).filter(([, v]) => typeof v === 'function').map(([k]) => k);

  document.getElementById('secLeadBody').innerHTML = '';
  // The slice keeps secLeadCache in its own scope, so the setter has to live
  // inside that scope rather than on the returned handle.
  api.__setCache(board);
  api.secLeadRender();
  const htmlOut = document.getElementById('secLeadBody').innerHTML;
  if (!htmlOut || htmlOut.length < 200) {
    problems.push(`render produced almost nothing (${(htmlOut || '').length} chars)`);
  }
  // A missing field must not reach the page as the string "undefined": the
  // reader cannot tell that apart from a real value.
  const bad = htmlOut.match(/>(?:undefined|NaN|\[object Object\])</g) || [];
  if (bad.length) {
    problems.push(`rendered ${bad.length} literal undefined/NaN cell(s): ${bad.slice(0, 5).join(' ')}`);
  }
  if (htmlOut.includes('NaN')) {
    const i = htmlOut.indexOf('NaN');
    problems.push(`NaN near: ${htmlOut.slice(Math.max(0, i - 80), i + 40).replace(/\s+/g, ' ')}`);
  }
  // The strip and the charts are the point of the rework. Charts are only
  // required when there is something to plot: with an empty portfolio the
  // honest output is the "no history, direction unknown" panel, and demanding
  // an SVG there would push the renderer toward inventing a zero line.
  const series = ((board.risk_position || {}).portfolio_series) || [];
  const tiers = (board.risk_position || {}).tiers || [];
  // Every lens must still show the residual position and the KPI strip: a lens
  // that dropped them would be reporting something different, not viewing the
  // same thing differently.
  if (!(board.emphasis || []).includes('risk_position')
      && !htmlOut.includes('Risk position')) {
    problems.push(`lens ${board.persona} emphasises ${JSON.stringify(board.emphasis)} `
      + 'and the board rendered no risk position at all');
  }
  if (!htmlOut.includes('Risk position')) problems.push('no risk position card rendered');
  if (!htmlOut.includes('lb-kpis')) problems.push('KPI strip did not render');
  if (series.length && !htmlOut.includes('<svg')) {
    problems.push(`${series.length} chartable point(s) but no SVG rendered; `
      + `emphasis=${JSON.stringify(board.emphasis)}`);
  }
  if (tiers.length && !htmlOut.includes('<svg')) {
    problems.push(`${tiers.length} tier(s) but the grouped bar chart is missing`);
  }
  if (!series.length && !htmlOut.includes('lb-empty')) {
    problems.push('no data to plot and no empty-state panel either');
  }
  if (series.length && !htmlOut.includes('<title>')) {
    problems.push('chart points carry no <title>, so the figures are hover-only');
  }

  // The alternate chart mode and a client sort must not throw either.
  api.secLeadChartMode('confidence');
  const m2 = document.getElementById('secLeadBody').innerHTML;
  if (series.length && !m2.includes('<svg')) {
    problems.push('confidence chart mode rendered no SVG');
  }
  api.secLeadChartMode('residual');
  api.secLeadSortBy('age');
  api.secLeadSortBy('blast');
  api.secLeadSortBy('product');
} catch (e) {
  problems.push(`threw: ${e && e.stack ? e.stack.split('\n').slice(0, 4).join(' | ') : e}`);
}

console.log(`handlers wired: ${handlers.size}; functions loaded: ${defined.length}`);
if (problems.length) {
  console.error('FAIL');
  problems.forEach(p => console.error('  - ' + p));
  process.exit(1);
}
console.log('PASS leadership board renders clean');