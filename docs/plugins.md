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

## Research council (`app/research_council.py`)

Every investigation plans through the council: source seats (news,
papers, official, CVE, provider, incident) propose query families only
when relevant, the critic dedupes, tops up uncovered specialist seats
within the 6-query cap (news never tops up: generic briefs pass
through untouched), and records gaps. Queries carry a `seat` tag;
`AgentRun.plan` and run stats keep the council record, so any query
traces back to its seat.
