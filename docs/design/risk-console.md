# Risk Console — Design Note

## Personas and visual tokens

| Persona | Home emphasis | Density |风险 tokens |
|---|---|---|---|
| Researcher | Evidence, attacks, graph, A2A | Compact | severity + cascade (dashed), unknown amber hatched |
| Lead | Attention queue, mitigations, stale | Compact | severity + privacy (purple), stale clock badge |
| Privacy/DPO | Leakage, provider posture, datapoint | Comfortable | privacy purple, retention callouts |
| Legal | Decisions, acceptances, briefs | Comfortable | claim chips: Stated policy / Independent / Unknown |
| Executive | Availability lights, concentration, brief | Comfortable | low chrome, generous spacing, max 70ch line |

Tokens: `--red` critical, `--orange` high, `--purple` privacy, `--orange` stale, hatched unknown (`repeating-linear-gradient 45deg`), cascade dashed, declared-only striped “unevidenced”. WCAG AA contrast on severity/privacy/unknown.

## Search syntax help

Single box: `Search risks, evidence, models…`

- `AND`/`OR` (default AND), `"exact phrase"`, prefix `memoriz*`
- Field filters: `layer:privacy severity:high status:open`
- Persona default: Executive/DPO/Legal → `accepted_only=on` (pending hidden); Researcher toggles off.

## Readability

Report Reader: H1–H3 scale, 70–80ch, narrative first (exec blurb → numbers → tables → appendix), claim chips, risk callouts with severity stripe, collapsible sections, inline mermaid/PNG, glossary tooltips for T01/RM05/ZDR/cascade/inherited, modes Full / Summary / Privacy-only / Risks-only, print CSS (hide chrome, keep severity as text + pattern, repeat headers, cover with date/scope/unknowns).

## Shell

`static/console/index.html` — new bundle, classic remains `static/index.html`. Shared design system, shared REST. Feature flag `RISK_CONSOLE_ENABLED=1` (default on); classic header links to `/console`, console links back to `/`. Persona + scope + filters in URL + localStorage; polling for running assessments (lighter than Classic console).

