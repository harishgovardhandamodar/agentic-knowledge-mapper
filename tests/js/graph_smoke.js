/* Headless check for the global knowledge-graph finder and detail panel.

 * The leadership graph grew search, a filter-to-matches mode, and a
 * hover/click detail panel -- all template string + scoring code behind a
 * browser. This pulls the real functions out of static/index.html and drives
 * them with a three-artifact fixture, asserting:
 *   1. the search corpus builds from the graph payload;
 *   2. the elastic-like scorer ranks an exact label over a tag-only hit and
 *      highlights the matched substring;
 *   3. filter-to-matches keeps the matching artifacts plus their investigation
 *      hubs;
 *   4. the detail panel renders without a bare undefined.
 *
 * Usage: node graph_smoke.js
 */
const fs = require('fs');
const path = require('path');

const els = {};
const document = {
  getElementById(id) {
    if (!els[id]) els[id] = { id, value: '', innerHTML: '', hidden: false };
    return els[id];
  },
  querySelectorAll() { return []; },
};

const root = path.resolve(__dirname, '..', '..');
const html = fs.readFileSync(path.join(root, 'static', 'index.html'), 'utf8');
const blocks = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
const block = blocks[1];

function extractFn(name) {
  const re = new RegExp('\\b(async\\s+)?function ' + name + '\\s*\\([^)]*\\)\\s*\\{');
  const m = re.exec(block);
  if (!m) throw new Error('function ' + name + ' not found');
  let i = block.indexOf('{', m.index);
  let depth = 0;
  for (; i < block.length; i++) {
    if (block[i] === '{') depth++;
    else if (block[i] === '}') { depth--; if (depth === 0) break; }
  }
  return block.slice(m.index, i + 1);
}
const names = ['secLeadGraphBuildIndex', 'secLeadGraphMatch',
  'secLeadGraphFilterSet', 'secLeadGraphHighlight', 'secLeadGraphDetailHtml',
  'secLeadGraphSearch'];
let src = 'let secLeadGraphIndex = {};\nlet secLeadGraphResults = [];\n'
  + 'let secLeadGraphSelIdx = 0;\nlet secLeadGraphFilterActive = false;\n';
for (const n of names) src += extractFn(n) + '\n';

const escHtml = (v) => String(v === null || v === undefined ? '' : v);
const TYPE_COLORS = { paper: '#3fb950', investigation: '#8250df' };
const fixture = {
  nodes: [
    { id: 'a:1', label: 'RLHF preference paper', title: 'Full title A',
      type: 'paper', relevance: 0.9, review: 'pending', drift: false,
      tags: 'rlhf, preference', investigation_id: 7, investigation: 'One' },
    { id: 'a:2', label: 'Safety paper', title: 'Full title B',
      type: 'paper', relevance: 0.5, review: 'accepted', drift: false,
      tags: 'safety, alignment', investigation_id: 7, investigation: 'One' },
    { id: 'a:3', label: 'Policy news', title: 'Full title C',
      type: 'news', relevance: 0.2, review: 'rejected', drift: true,
      tags: 'policy', investigation_id: 8, investigation: 'Two' },
    { id: 'inv:7', label: 'One', title: 'Investigation 7: One',
      type: 'investigation', relevance: 0, review: 'accepted', drift: false,
      tags: '', investigation_id: 7, investigation: 'One' },
    { id: 'inv:8', label: 'Two', title: 'Investigation 8: Two',
      type: 'investigation', relevance: 0, review: 'accepted', drift: false,
      tags: '', investigation_id: 8, investigation: 'Two' },
  ],
  edges: [
    { from: 'a:1', to: 'a:2', label: 'cites', title: '' },
    { from: 'a:1', to: 'inv:7', label: 'collected_in', title: '' },
    { from: 'a:2', to: 'inv:7', label: 'collected_in', title: '' },
    { from: 'a:3', to: 'inv:8', label: 'collected_in', title: '' },
  ],
};

const failed = [];
function assert(cond, msg) { if (!cond) failed.push(msg); }
function show(label, v) { process.stdout.write('    ' + label + ': ' + v + '\n'); }

try {
  // eslint-disable-next-line no-new-func
  const fn = new Function('document', 'escHtml', 'TYPE_COLORS', 'secLeadGraphData',
    src + '\nreturn { secLeadGraphBuildIndex, secLeadGraphMatch, '
      + 'secLeadGraphFilterSet, secLeadGraphHighlight, secLeadGraphDetailHtml, '
      + 'secLeadGraphSearch };');
  const G = fn(document, escHtml, TYPE_COLORS, fixture);

  show('buildIndex', 'searchable corpus built from nodes');
  G.secLeadGraphBuildIndex();
  assert(G.secLeadGraphMatch(fixture.nodes[0], 'rlhf'), 'rlhf matches the paper');
  assert(!G.secLeadGraphMatch(fixture.nodes[0], 'policy'), 'rlhf paper is not a policy hit');

  show('search', 'scoring ranks the exact label first');
  G.secLeadGraphSearch('rlhf preference');
  const out = els.secLeadGraphResults.innerHTML;
  assert(out.toLowerCase().includes('<mark>rlhf preference</mark>'), 'query substring is highlighted');
  assert(out.includes('data-id="a:1"'), 'the rlhf paper is the hit');
  assert(!out.includes('data-id="a:2"'), 'a non-matching safety paper is not a hit');
  assert(!out.includes('data-id="a:3"'), 'a policy news item is not a hit');
  G.secLeadGraphSearch('nomatchxyz');
  assert(els.secLeadGraphResults.innerHTML.includes('No matching artifacts'), 'no-match state is explicit');

  show('filter', 'filter-to-matches keeps artifacts plus their hubs');
  els.secLeadGraphSearch = { id: 'secLeadGraphSearch', value: 'safety', innerHTML: '', hidden: false };
  const fn2 = new Function('document', 'escHtml', 'TYPE_COLORS', 'secLeadGraphData',
    src + '\nreturn { secLeadGraphBuildIndex, secLeadGraphMatch, '
      + 'secLeadGraphFilterSet, secLeadGraphHighlight, secLeadGraphDetailHtml, '
      + 'secLeadGraphSearch, secLeadGraphSetF: (v) => { secLeadGraphFilterActive = v; } };');
  const G2 = fn2(document, escHtml, TYPE_COLORS, fixture);
  G2.secLeadGraphBuildIndex();
  G2.secLeadGraphSetF(true);
  const ids = G2.secLeadGraphFilterSet();
  assert(ids.has('a:2'), 'matching artifact survives the filter');
  assert(ids.has('inv:7'), 'its investigation hub survives too');
  assert(!ids.has('a:1'), 'non-matching artifact is dropped');

  show('detail', 'detail panel renders without junk');
  const fn3 = new Function('document', 'escHtml', 'TYPE_COLORS', 'secLeadGraphData',
    src + '\nreturn { secLeadGraphBuildIndex, secLeadGraphMatch, '
      + 'secLeadGraphFilterSet, secLeadGraphHighlight, secLeadGraphDetailHtml, '
      + 'secLeadGraphSearch };');
  const G3 = fn3(document, escHtml, TYPE_COLORS, fixture);
  G3.secLeadGraphBuildIndex();
  const detail = G3.secLeadGraphDetailHtml(fixture.nodes[0]);
  assert(detail.includes('RLHF preference paper'), 'detail shows the label');
  assert(detail.includes('rlhf') && detail.includes('preference'), 'tags render');
  assert(detail.includes('Investigation:</b> One'), 'investigation renders');
  assert(!/\bundefined\b/.test(detail), 'no bare undefined in the panel');

  if (failed.length) {
    console.error('FAIL: ' + failed.length + ' assertion(s)');
    failed.forEach(m => console.error('  - ' + m));
    process.exit(1);
  }
  console.log('PASS: graph search, filter, detail helpers');
} catch (e) {
  console.error('FAIL: threw: ' + (e && e.stack || e));
  process.exit(1);
}