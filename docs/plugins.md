# Investigation-type plugins

The five investigation types share one registry (`app/plugins.py`)
so the manager, the API, and the CLI treat them uniformly. Launches
stay in their home modules; plugins route and read back.

| key | home module | manager track | analyze reads |
|---|---|---|---|
| `adoption` | `app/adoption_advice.py` | none (endpoint-driven) | deterministic advice pack |
| `security` | `app/security_agent.py` | none (assessment flag) | latest assessment summary |
| `vulnerability` | `app/cve.py` collectors | `vulnerability_landscape` topic | CVE artifacts + findings |
| `writeup` | `app/explainer.py` | none (endpoint-driven) | latest explanation summary |
| `hypothesis` | `app/hypothesiser.py` | `hypothesis_scenarios` topic | inherent + derived scenarios |

`GET /api/plugins` lists the registry. `POST/GET
/api/investigations/{id}/scenarios` enumerates hypothesis scenarios
(idempotent).

## Episode depth

After parsing, the manager shows the matched plugins and three depth
levels (Scout / Standard / Deep) mapping to research scale
(`max_items` 8/25/50, `max_rounds` 1/2/3, clamped server-side). Depth
presets suggest the research/assessment mix; the checkboxes keep the
final say. Depth and scale persist in the run options so re-runs
reproduce the episode.

## Research council (`app/research_council.py`)

Every investigation plans through the council: source seats (news,
papers, official, CVE, provider, incident) propose query families only
when relevant, the critic dedupes, tops up uncovered specialist seats
within the 6-query cap (news never tops up: generic briefs pass
through untouched), and records gaps. Queries carry a `seat` tag;
`AgentRun.plan` and run stats keep the council record, so any query
traces back to its seat.
