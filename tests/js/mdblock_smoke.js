/* Headless check for explainer markdown fences + the diagram loader.
 *
 * Explainer section bodies flow through mdBlock(), which must turn
 * ```mermaid fences into live .mermaid nodes (with the source in
 * data-src) instead of one paragraph per line, and leave other fences
 * as code blocks. The mermaid library itself must load local-first
 * (static/vendor) with a CDN failover, so diagrams also render when
 * the CDN is unreachable.
 *
 * Usage: node mdblock_smoke.js
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

const lib = ['escHtml', 'mdInline', 'mdBlock'].map(grab).join('\n');
const miniSrc = grab('renderMiniMarkdown');
const asFn = (src) => eval('(' + src.replace(/^function \w+/, 'function') + ')');
const escHtml = asFn(grab('escHtml'));
const mdBlock = new Function('escHtml', 'mdInline',
  lib + '\nreturn mdBlock;')(escHtml, asFn(grab('mdInline')));

let fails = 0;
const check = (name, cond) => {
  console.log((cond ? 'PASS' : 'FAIL') + ' ' + name);
  if (!cond) fails++;
};

const dia = '## T\n\n```mermaid\nsequenceDiagram\n    A->>B: hi\n```\n\n- a';
const h1 = mdBlock(dia);
check('fence -> div.mermaid', h1.includes('<div class="mermaid"'));
check('data-src round-trips', h1.includes('data-src="sequenceDiagram'));
check('heading intact', h1.includes('<h3>T</h3>'));
const unlabeled = mdBlock('```\ngraph TD\n A-->B\n```');
check('unlabeled graph -> diagram', unlabeled.includes('<div class="mermaid"'));
const code = mdBlock('```python\nprint(1)\n```');
check('non-mermaid -> pre, no diagram',
  code.includes('<pre>') && !code.includes('div class="mermaid"'));
const unclosed = mdBlock('text\n```mermaid\nsequenceDiagram\n A->>B: x');
check('unclosed fence at EOF', unclosed.includes('<div class="mermaid"'));
check('loader local-first', html.includes('/static/vendor/mermaid.min.js'));
check('loader CDN failover', html.includes('MM_CDN_SRC'));
check('loader failure note', html.includes('mmNoteUnavailable'));

const renderMiniMarkdown = new Function(miniSrc + '\nreturn renderMiniMarkdown;')();
const causal = 'text\n\n```mermaid causal\nflowchart TD\n    T["a"]\n```\n\ntail';
const mini = renderMiniMarkdown(causal);
check('labeled fence -> div.mermaid (mini)',
  mini.includes('<div class="mermaid"'));
check('no pre-wrapped mermaid (mini)',
  !/<pre>[^<]*flowchart/.test(mini));
const bare = renderMiniMarkdown('```mermaid\ngraph TD\n A-->B\n```');
check('bare fence still works', bare.includes('<div class="mermaid"'));
const py = renderMiniMarkdown('```python\nx = 1\n```');
check('non-mermaid stays code', py.includes('<pre>'));

process.exit(fails ? 1 : 0);
