/* Headless check for the manager plan card: plugin mix + episode depth.
 *
 * After parsing, the operator must see which investigation-type plugins
 * take part and pick a depth before running. These render from the parse
 * payload (mgrPlan), so a renamed key or a dropped block fails silently
 * in the browser. Asserts, against the *real* functions pulled out of
 * static/index.html:
 *   1. mgrRenderPlan shows all five plugin chips, matched ones flagged;
 *   2. the three depth radios render with blurbs and the suggested one
 *      checked;
 *   3. mgrDepthPreset maps scout -> research-only, deep -> both on;
 *   4. a legacy plan without plugins/depths still renders.
 *
 * Usage: node manager_plan_smoke.js
 */
const fs = require('fs');
const path = require('path');

const html = fs.readFileSync(
  path.join(__dirname, '..', '..', 'static', 'index.html'), 'utf8');

function grab(name) {
  const start = html.indexOf('function ' + name + '(');
  if (start < 0) throw new Error('missing ' + name);
  let depth = 0;
  let i = html.indexOf('{', start);
  const begin = i;
  for (; i < html.length; i++) {
    if (html[i] === '{') depth++;
    if (html[i] === '}') { depth--; if (!depth) break; }
  }
  return html.slice(start, i + 1);
}

const lib = ['escHtml', 'mgrRenderPlan', 'mgrDepthPreset'].map(grab)
  .join('\n');

function makeDoc() {
  const els = {};
  const el = (id) => {
    if (!els[id]) els[id] = { hidden: false, innerHTML: '', checked: true,
                              value: 'scout' };
    return els[id];
  };
  return {
    els,
    getElementById: (id) => el(id),
    querySelector: (sel) => {
      if (sel === 'input[name="mgrDepth"]:checked') return { value: 'scout' };
      return null;
    },
  };
}

const plan = {
  parsed_by: 'llm', truncated: false, domain: 'd', exposure: 'public',
  topics: [{ title: 'T1', description: 'desc', exposure: null }],
  summary: { title: 'S' },
  plugins: [
    { key: 'adoption', title: 'Adoption advice', version: '1', matched: false, via: 'x' },
    { key: 'security', title: 'Security and privacy assessment', version: '1', matched: true, via: 'default lens' },
    { key: 'vulnerability', title: 'Known vulnerability search and landscape', version: '1', matched: false, via: 'x' },
    { key: 'writeup', title: 'Write-up / explainer', version: '1', matched: true, via: 'question form' },
    { key: 'hypothesis', title: 'Hypothesiser: inherent and derived', version: '1', matched: false, via: 'x' },
  ],
  depths: {
    scout: { label: 'Scout', blurb: 'quick', max_items: 8, max_rounds: 1 },
    standard: { label: 'Standard', blurb: 'full', max_items: 25, max_rounds: 2 },
    deep: { label: 'Deep', blurb: 'wide', max_items: 50, max_rounds: 3 },
  },
  suggested_depth: 'standard',
};

let fails = 0;
const check = (name, cond) => {
  console.log((cond ? 'PASS' : 'FAIL') + ' ' + name);
  if (!cond) fails++;
};

const factory = new Function('mgrPlan', 'document', 'escHtml',
  lib + '\nmgrRenderPlan();\nreturn document;');

// 1+2: full plan renders chips, radios, suggested default.
let doc = makeDoc();
factory(plan, doc, eval('(' + grab('escHtml').replace('function escHtml', 'function') + ')'));
const body = doc.els.mgrPlanBody.innerHTML;
check('five plugin chips', (body.match(/mgr-plugin/g) || []).length >= 5);
check('matched flagged', body.includes('mgr-plugin on'));
check('via tooltip', body.includes('default lens'));
check('three depth radios',
  ['Scout', 'Standard', 'Deep'].every((l) => body.includes(l)));
check('suggested checked',
  body.includes('value="standard" checked') ||
  body.includes("value='standard' checked") ||
  /value="standard"[^>]*checked/.test(body));

// 3: presets drive the checkboxes.
const presetFn = new Function('document',
  grab('mgrDepthPreset') + '\nmgrDepthPreset();\nreturn document;');
doc = makeDoc();
doc.querySelector = () => ({ value: 'scout' });
presetFn(doc);
check('scout unchecks assessment', doc.els.mgrOptAssess.checked === false);
doc = makeDoc();
doc.getElementById('mgrOptAssess').checked = false;
doc.querySelector = () => ({ value: 'deep' });
presetFn(doc);
check('deep checks both',
  doc.els.mgrOptAssess.checked === true &&
  doc.els.mgrOptResearch.checked === true);

// 4: legacy plan without the new keys still renders.
doc = makeDoc();
const legacy = { topics: [{ title: 'T', description: 'd' }], summary: {} };
factory(legacy, doc, eval('(' + grab('escHtml').replace('function escHtml', 'function') + ')'));
check('legacy plan renders',
  doc.els.mgrPlanBody.innerHTML.includes('>T<') &&
  !doc.els.mgrPlanBody.innerHTML.includes('undefined'));

process.exit(fails ? 1 : 0);
