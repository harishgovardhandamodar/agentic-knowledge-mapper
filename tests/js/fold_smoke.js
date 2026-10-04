/* Headless check for the collapsible section helpers and the review-queue
 * grouping that uses them.
 *
 * Findings and artifacts are rendered as foldSection() groups with persisted
 * open/closed state. The risks this guards against are the same ones the
 * leadership harness targets: an undefined helper or a bad property read
 * crashes only when a reader clicks, and a lost count or a wrong default
 * state is silent. It asserts, against the *real* functions pulled out of
 * static/index.html:
 *   1. foldSection emits valid markup (state, count, aria-expanded, hidden);
 *   2. foldToggle / foldSetAll flip the tree and persist to localStorage;
 *   3. artifactCardHtml renders every action for the review states;
 *   4. loadArtifacts partitions the queue into the four expected groups with
 *      each card in exactly one group.
 *
 * Usage: node fold_smoke.js
 */
const fs = require('fs');
const path = require('path');

// ---- minimal DOM shim -----------------------------------------------------
// Fold state persistence is core behaviour, so this localStorage is real
// (in-memory) rather than the no-op stub the render harness uses.
const store = {};
function makeFoldEl(key, open) {
  const classes = new Set(open ? ['open'] : []);
  const headAttrs = {};
  const el = {
    tag: 'div',
    getAttribute(a) {
      if (a === 'data-fold') return key;
      if (a === 'aria-expanded') return headAttrs['aria-expanded'];
      return null;
    },
    setAttribute(a, v) { headAttrs[a] = v; },
    classList: {
      contains(c) { return classes.has(c); },
      toggle(c, on) { on ? classes.add(c) : classes.delete(c); },
    },
    querySelector(sel) {
      if (sel === '.fold-body') return { hidden: !classes.has('open') };
      if (sel === '.fold-head') return { setAttribute: (a, v) => { headAttrs[a] = v; } };
      return null;
    },
  };
  return el;
}
const folds = new Map();
const document = {
  querySelector(sel) {
    const m = /^\[data-fold="(.+)"\]$/.exec(sel);
    return m ? (folds.get(m[1]) || null) : null;
  },
  querySelectorAll(sel) {
    if (sel.endsWith(' .fold') || sel === '.fold') return [...folds.values()];
    return [];
  },
};
const localStorage = {
  getItem(k) { return k in store ? store[k] : null; },
  setItem(k, v) { store[k] = String(v); },
  removeItem(k) { delete store[k]; },
};

// ---- load the real helpers out of static/index.html ------------------------
const root = path.resolve(__dirname, '..', '..');
const html = fs.readFileSync(path.join(root, 'static', 'index.html'), 'utf8');
const blocks = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
if (blocks.length < 2) { console.error('FAIL: app script block not found'); process.exit(1); }
const block = blocks[1];

function extractFn(name) {
  // Keep an `async` prefix: loadArtifacts awaits fetch, and dropping the
  // keyword would turn a valid async body into a top-level await error.
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
const names = ['_foldAll', '_foldSet', 'foldIsOpen', 'foldSection', 'foldToggle',
  'foldSetAll', 'artifactCardHtml', 'loadArtifacts'];
let src = '';
for (const n of names) src += extractFn(n) + '\n';
// The helpers read module-level state the extraction does not capture.
src = 'let FOLD_STORE = "akm.folds";\nlet _foldCache = null;\n'
  + 'const CSS = { escape: (s) => s };\n' + src;

const escHtml = (v) => String(v === null || v === undefined ? '' : v);
const API = '/api';
let currentInv = 7, revFilter = 'pending', driftOnly = false;
const els = {};
const document2 = {
  querySelector: document.querySelector.bind(document),
  querySelectorAll: document.querySelectorAll.bind(document),
  getElementById(id) {
    if (!els[id]) {
      els[id] = { id, value: '', innerHTML: '' };
      if (id === 'searchInput') els[id].value = '';
    }
    return els[id];
  },
};
const fetch = async (url) => ({
  ok: true, status: 200, json: async () => ({ items: [] }),
});

const failed = [];
function assert(cond, msg) { if (!cond) failed.push(msg); }
function show(label, v) { process.stdout.write('    ' + label + ': ' + v + '\n'); }

async function main() {
try {
  // eslint-disable-next-line no-new-func
  const fn = new Function('document', 'localStorage', 'escHtml', 'fetch',
    'API', 'currentInv', 'revFilter', 'driftOnly',
    src + '\nreturn { foldSection, foldToggle, foldSetAll, foldIsOpen, '
      + 'artifactCardHtml, loadArtifacts };');
  const F = fn(document2, localStorage, escHtml, fetch, API, 7, 'pending', false);

  show('foldSection', 'generating markup');
  const open = F.foldSection('k:open', 'Open group', 'BODY', { open: true, count: 4, unit: 'rows' });
  const closed = F.foldSection('k:closed', 'Closed group', 'BODY', { count: 3 });
  assert(open.includes('class="fold open"'), 'open fold carries .open class');
  assert(open.includes('aria-expanded="true"'), 'open fold announces expanded');
  assert(!open.includes(' hidden>'), 'open fold body is visible');
  assert(open.includes('<span class="fold-count">4 rows</span>'), 'count+unit rendered');
  assert(closed.includes('class="fold"') && !closed.includes(' class="fold open"'),
    'closed fold has no .open class');
  assert(closed.includes('aria-expanded="false"'), 'closed fold announces collapsed');
  assert(closed.includes(' hidden>'), 'closed fold body is hidden');
  assert(closed.includes('<span class="fold-count">3</span>'), 'closed fold keeps count');
  assert(!open.includes('undefined') && !closed.includes('undefined'),
    'no "undefined" leaked into markup');

  show('foldToggle', 'state flip + persistence');
  folds.set('k:closed', makeFoldEl('k:closed', false));
  F.foldToggle('k:closed');
  assert(folds.get('k:closed').classList.contains('open'), 'toggle opens the tree node');
  assert(F.foldIsOpen('k:closed', false), 'toggle persists open state');
  F.foldToggle('k:closed');
  assert(!folds.get('k:closed').classList.contains('open'), 'toggle re-collapses');
  assert(!F.foldIsOpen('k:closed', true), 'toggle persists closed state');

  show('foldSetAll', 'bulk collapse over a container');
  folds.set('k:a', makeFoldEl('k:a', true));
  folds.set('k:b', makeFoldEl('k:b', true));
  F.foldSetAll('#list', false);
  assert(!folds.get('k:a').classList.contains('open') && !folds.get('k:b').classList.contains('open'),
    'collapse-all closes every fold');
  assert(!F.foldIsOpen('k:a', true) && !F.foldIsOpen('k:b', true), 'bulk state persisted');
  F.foldSetAll('#list', true);
  assert(folds.get('k:a').classList.contains('open'), 'expand-all opens every fold');

  show('artifactCardHtml', 'actions per review state');
  const card = F.artifactCardHtml({ id: 1, title: 'Evidence A', artifact_type: 'report',
    relevance: 0.9, review: 'pending', source: 'web', url: 'http://x', tags: 'a,b' });
  assert(card.includes('90%'), 'relevance ring shows percent');
  assert(card.includes('Accept') && card.includes('Reject') && !card.includes('Unreview'),
    'pending card offers accept/reject, not unreview');
  const drift = F.artifactCardHtml({ id: 2, title: 'D', artifact_type: 'doc', relevance: 0.5, review: 'pending', drift: true });
  assert(drift.includes('drift-pill') && drift.includes('Undrift'), 'drift card flags drift');
  const done = F.artifactCardHtml({ id: 3, title: 'E', artifact_type: 'doc', relevance: 0.5, review: 'accepted' });
  assert(done.includes('Unreview') && !done.includes('Accept'), 'accepted card offers unreview');

  show('loadArtifacts', 'queue partitioned into fold groups');
  const items = [
    { id: 1, title: 'p', artifact_type: 'doc', relevance: 0.9, review: 'pending' },
    { id: 2, title: 'd', artifact_type: 'doc', relevance: 0.8, review: 'pending', drift: true },
    { id: 3, title: 'a', artifact_type: 'doc', relevance: 0.7, review: 'accepted' },
    { id: 4, title: 'r', artifact_type: 'doc', relevance: 0.6, review: 'rejected' },
    { id: 5, title: 'ad', artifact_type: 'doc', relevance: 0.5, review: 'accepted', drift: true },
  ];
  const fetchItems = async () => ({ ok: true, status: 200, json: async () => ({ items }) });
  const F2 = fn(document2, localStorage, escHtml, fetchItems, API, 7, 'pending', false);
  await F2.loadArtifacts();
  const html2 = els.artList.innerHTML;
  assert(html2.includes('Needs review'), 'pending group header present');
  assert(html2.includes('Drift flagged'), 'drift group header present');
  assert(html2.includes('Accepted') && html2.includes('Rejected'), 'decided groups present');
  const counts = [...html2.matchAll(/<span class="fold-count">(\d+)<\/span>/g)].map(m => m[1]);
  assert(counts.join(',') === '1,2,1,1',
    'group sizes are Needs review=1, drift=2, accepted=1, rejected=1 (got ' + counts.join(',') + ')');
  // Every card must land in exactly one group -- drift wins over review state.
  assert(html2.match(/class="art-card"/g).length === 5, 'no card is duplicated or dropped');
  // The two actionable groups are open, the decided ones start folded.
  const groupState = {};
  for (const m of html2.matchAll(/<div class="fold([^"]*)"[^>]*>\s*<button[^>]*>[\s\S]*?<span class="fold-title">([\s\S]*?)<\/span>/g)) {
    const title = m[2].split('<')[0].trim();   // strip the nested hint span
    groupState[title] = m[1].split(' ').includes('open');
  }
  assert(groupState['Needs review'] === true, 'pending group open by default');
  assert(groupState['Drift flagged'] === true, 'drift group open by default');
  assert(groupState['Accepted'] === false, 'accepted group closed by default');
  assert(groupState['Rejected'] === false, 'rejected group closed by default');

  // Empty queue keeps its friendly empty state, no folds.
  const F3 = fn(document2, localStorage, escHtml, async () => ({ ok: true, status: 200, json: async () => ({ items: [] }) }), API, 7, 'pending', false);
  els.artList.innerHTML = '';
  await F3.loadArtifacts();
  assert(els.artList.innerHTML.includes('empty-state'), 'empty queue keeps empty state');

  // The collection pane's section folds also come from the same helper, so
  // confirm its three keys exist with the right defaults via foldIsOpen.
  assert(F.foldIsOpen('collect:table:7', true) === true, 'short table defaults open (def true)');
  assert(F.foldIsOpen('collect:actors:7', true) === true, 'actors fold defaults open');

  if (failed.length) {
    console.error('FAIL: ' + failed.length + ' assertion(s)');
    failed.forEach(m => console.error('  - ' + m));
    process.exit(1);
  }
  console.log('PASS: fold helpers, review grouping, collection folds');
} catch (e) {
  console.error('FAIL: threw: ' + (e && e.stack || e));
  process.exit(1);
}
}

main();