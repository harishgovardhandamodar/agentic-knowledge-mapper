# Agentic-workflows CLI

Terminal interface to the same agentic workflows the web app runs:
research investigations, mermaid diagrams, the agentic manager, and an
ops view (runtime logs, LLM gateway, agent swarm, activity, web-search
history).

## Architecture: shared backend, web-visible by construction

The CLI holds **no state of its own**. It is a thin client of the running
web app's HTTP API (`AKM_API_URL`, default `http://127.0.0.1:8204`), so
every investigation, run, artifact, or manager run created from the CLI
lands in the shared database and is immediately viewable in the web GUI
(and vice versa). Verified end to end: an investigation created with
`research new` reads back through the same endpoint the GUI uses.

Dependencies: stdlib + `httpx` / `rich` / `click` (already installed).
No new requirements.

## Gateway identity: `agentic-knowledge-mapper-tUI`

Every CLI request sends `X-AKM-Client: tui`. The backend carries that
label into its fox-services calls as `X-Service-Name:
agentic-knowledge-mapper-tui` (request scope, inherited by research
threads, re-bound from the job payload by queued security workers), so
the gateway queue, usage history, and project dashboard tell
CLI-driven load apart from web-driven load. The gateway needs no
code change for this: service names are free-form and the dashboard
groups the TUI name under the `agentic-knowledge-mapper` project.

## Scriptable commands (`python -m cli ...`)

| Command | What it does |
|---|---|
| `health` | LLM gateway: preferred/served-by, fallback flag, models |
| `research list` | Investigations (id, title, status, runs, artifacts) |
| `research new --title T [--description D] [--keywords K]` | Create (shows up in the web app) |
| `research launch ID` | Fire-and-forget research run |
| `research show ID` | Summary, web-search shapes, artifact counts |
| `diagrams show investigation ID [-i N] [--save F]` | ASCII render of one mermaid diagram; `--save` writes `.mmd` |
| `diagrams show run ID ...` | Same for a manager synthesis report |
| `manager list` | Manager runs (status/compiled/command) |
| `manager launch "COMMAND"` | Parse + launch (same as the GUI's manager tab) |
| `manager timeline ID` | Flow + recent lane events |
| `manager compile ID` | Compile a finished run (long call) |
| `manager report ID [--save F]` | Compiled markdown |
| `ops swarm` | Agent-run statuses (the swarm) |
| `ops searches ID` | Web-search history shapes (attempts/found/kept/llm_calls) |
| `ops activity [--limit N]` | Ledger tail: actor/kind/verdict |
| `ops logs [--log-file F]` | Audit drops, pending approvals, log-file tail |

## Interactive dashboard (`python -m cli tui [--log-file F]`)

Two tabs, auto-refresh every 8 s, banner shows which gateway serves:

* `1 Research` (main) — investigation list + detail (summary, runs,
  assessments) + selected mermaid diagram as ASCII.
* `2 Ops` — LLM gateway, agent swarm, manager runs (+flow of the
  selected run), activity monitor, web-search history, runtime logs.

Keys: `1`/`2` tabs · `↑`/`↓` select · `j`/`k` scroll ops · `n` new
investigation · `l` launch run · `d` next diagram · `s` save `.mmd` ·
`m` select manager run · `c` compile · `r` refresh · `q` quit.
Needs a TTY.

## Mermaid in the terminal

`cli/mermaid.py` extracts ```` ```mermaid ```` fences and renders
`graph`/`flowchart` (layered boxes, labelled edges, chains unrolled)
and `sequenceDiagram` (participants, numbered messages, notes) as
ASCII. Other kinds (or unparseable sources) fall back to the raw
source, which can be saved with `--save` / `s` and opened in a browser
or rendered to PNG by the existing `app/mermaid_png.py` pipeline.
