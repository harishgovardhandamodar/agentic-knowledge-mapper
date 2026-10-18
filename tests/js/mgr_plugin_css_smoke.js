/* Does the chip checkbox actually render as a checkbox?
 *
 * The chips used to live inside `.std-filters`, whose rule is
 *   .std-filters input { flex: 1; min-width: 160px; }
 *   .std-filters input, .std-filters select { background: var(--bg2);
 *                                            border: 1px solid var(--border);
 *                                            border-radius: 8px;
 *                                            padding: 6px 10px; }
 * Every descendant input inherits that, so each chip's checkbox was
 * stretched to 160px and painted as a field: an empty grey box. It read
 * as a disabled control, so the operator could not pick a plugin at all,
 * while every markup assertion still passed.
 *
 * A rendered string cannot catch that, so this pins the two things that
 * actually decide it: the mix row's position in the DOM, and which rule
 * wins the cascade for the chip's checkbox.
 *
 * Usage: node mgr_plugin_css_smoke.js
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
  for (; i < html.length; i++) {
    if (html[i] === '{') depth++;
    if (html[i] === '}') { depth--; if (!depth) break; }
  }
  return html.slice(start, i + 1);
}

const lib = ['escHtml', 'mgrRenderPlan', 'mgrDepthPreset'].map(grab).join('\n');

const plan = {
  parsed_by: 'llm', truncated: false, domain: 'd', exposure: 'public',
  topics: [{ title: 'T1', description: 'desc', exposure: null }],
  summary: { title: 'S' },
  plugins: [
    { key: 'adoption', title: 'Adoption advice', version: '1', matched: false, via: 'adoption language' },
    { key: 'security', title: 'Security and privacy assessment', version: '1', matched: true, via: 'default lens' },
    { key: 'vulnerability', title: 'Known vulnerability search and landscape', version: '1', matched: true, via: 'CVE/advisory language' },
    { key: 'writeup', title: 'Write-up / explainer', version: '1', matched: false, via: 'question form' },
    { key: 'hypothesis', title: 'Hypothesiser: inherent and derived', version: '1', matched: false, via: 'scenario language' },
  ],
  depths: {
    scout: { label: 'Scout', blurb: 'quick', max_items: 8, max_rounds: 1 },
    standard: { label: 'Standard', blurb: 'full', max_items: 25, max_rounds: 2 },
    deep: { label: 'Deep', blurb: 'wide', max_items: 50, max_rounds: 3 },
  },
  suggested_depth: 'standard',
};

let fails = 0;
const check = (name, cond, extra) => {
  console.log((cond ? 'PASS' : 'FAIL') + ' ' + name + (cond ? '' : ' — ' + extra));
  if (!cond) fails++;
};

// Render the real function against a minimal document.
const fakeDoc = {
  els: {},
  getElementById(id) {
    if (!this.els[id]) this.els[id] = { hidden: false, innerHTML: '' };
    return this.els[id];
  },
  querySelector: () => null,
  querySelectorAll: () => [],
};
const escHtml = eval('(' + grab('escHtml').replace('function escHtml', 'function') + ')');
new Function('mgrPlan', 'document', 'escHtml', lib + '\nmgrRenderPlan();')(
  plan, fakeDoc, escHtml);
const body = fakeDoc.els.mgrPlanBody.innerHTML;

// --- markup ------------------------------------------------------------
check('five chips rendered',
  (body.match(/class="mgr-plugin/g) || []).length === 5,
  'got ' + (body.match(/class="mgr-plugin/g) || []).length);
check('chips are checkboxes',
  (body.match(/type="checkbox" data-mgr-plugin="/g) || []).length === 5,
  'got ' + (body.match(/type="checkbox" data-mgr-plugin="/g) || []).length);
check('matched chips are pre-ticked',
  /data-mgr-plugin="security" checked/.test(body) &&
  /data-mgr-plugin="vulnerability" checked/.test(body));
check('unmatched chips are not ticked',
  /data-mgr-plugin="adoption"(?! checked)/.test(body) &&
  /data-mgr-plugin="hypothesis"(?! checked)/.test(body));
check('no chip is disabled',
  !/data-mgr-plugin="[^"]+"[^>]*\sdisabled/.test(body));

// The mix row must be its own container, not a child of .std-filters: that
// class is what stretches the checkboxes in the first place.
const mixAt = body.indexOf('class="mgr-mix"');
const filtersAt = body.indexOf('class="std-filters"');
const chipsAt = body.indexOf('data-mgr-plugin=');
check('mix row has its own container', mixAt >= 0, '.mgr-mix missing');
check('mix row is outside .std-filters',
  mixAt >= 0 && chipsAt > mixAt && filtersAt > chipsAt,
  'order: mix=' + mixAt + ' chips=' + chipsAt + ' filters=' + filtersAt);

// --- cascade -----------------------------------------------------------
// Resolve which rule wins for the chip checkbox, so re-nesting the chips
// inside .std-filters cannot silently come back. Specificity is the CSS
// one: (id, class+attr+pseudo, type). Only the <style> blocks are read --
// the page is a single file whose template literals are full of `{...}`
// that a naive brace match would swallow as CSS -- and comments come out
// first, since the reset rule is documented in place and a comment
// mentioning a selector would otherwise be counted as part of it.
const css = [...html.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/g)]
  .map((m) => m[1])
  .join('\n')
  .replace(/\/\*[\s\S]*?\*\//g, '');

function specificity(selector) {
  return selector.split(',').map((sel) => {
    sel = sel.trim();
    const ids = (sel.match(/#[\w-]+/g) || []).length;
    const cls = (sel.match(/\.[\w-]+|\[[^\]]*\]|::?[\w-]+/g) || []).length;
    const types = (sel.match(/(^|[\s>+~])[a-z][\w-]*/gi) || []).length;
    return ids * 10000 + cls * 100 + types;
  });
}

function rulesFor(predicate) {
  const out = [];
  // The lookbehind, not a captured `}`: a captured separator is consumed,
  // so the rule right after a match has no left delimiter and is skipped --
  // which silently loses every second rule in the sheet.
  const re = /(?:^|(?<=\}))\s*([^{}@][^{}]*?)\s*\{([^{}]*)\}/g;
  let m;
  while ((m = re.exec(css)) !== null) {
    const selector = m[1].trim();
    const body = m[2];
    if (!selector || !predicate(selector, body)) continue;
    out.push({ selector, body, index: m.index, spec: specificity(selector) });
  }
  return out;
}

const resetRules = rulesFor((sel, body) =>
  /mgr-plugin/.test(sel) && /input/.test(sel) && /min-width/.test(body));
const fieldRules = rulesFor((sel, body) =>
  /\.std-filters/.test(sel) && /(^|\s)input/.test(sel) && /min-width/.test(body));

check('a reset rule exists for the chip checkbox', resetRules.length > 0,
  'no .mgr-plugin ... input rule sets min-width');
check('the offending .std-filters input rule still exists',
  fieldRules.length > 0, 'the rule this guards against is gone; re-check the nesting');

for (const reset of resetRules) {
  const spec = Math.max(...reset.spec);
  for (const field of fieldRules) {
    const fieldSpec = Math.max(...field.spec);
    const later = reset.index > field.index;
    check(`reset beats .std-filters input (${reset.selector})`,
      spec > fieldSpec || (spec === fieldSpec && later),
      `specificity ${spec} vs ${fieldSpec}, reset ` +
      `${later ? 'later' : 'earlier'} in the sheet`);
  }
}

// The reset must undo every field-ish property, not just the width: a
// 13px-wide box still looks disabled if it keeps the field background.
const resetBody = resetRules.map((r) => r.body).join(';');
for (const prop of ['flex', 'min-width', 'width', 'height', 'padding',
                    'background', 'border', 'border-radius']) {
  check(`reset clears ${prop}`, new RegExp('(^|[;\\s])' + prop + '\\s*:').test(resetBody),
    'not reset: ' + prop);
}

console.log(fails ? 'FAILURES: ' + fails : 'all good');
process.exit(fails ? 1 : 0);
