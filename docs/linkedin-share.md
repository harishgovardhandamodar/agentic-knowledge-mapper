# Agentic Knowledge Mapper — Share / Write-up (LinkedIn)

> **Diagrams live in [SHARE-DIAGRAMS.md](SHARE-DIAGRAMS.md)** — copy the Mermaid
> source into https://mermaid.live (LinkedIn does not render Mermaid). This file
> is the clean text for your post or article.

---

## LinkedIn post (copy-paste)

**Sharing what I've been building: an agentic security & privacy research platform.**

The Agentic Knowledge Mapper runs structured agent swarms that investigate AI
security, model/provider data posture, RLHF and memorization risks, and
agentic-payments safety — then scores everything deterministically and proves
it on an append-only audit ledger.

A few things I'm proud of:

- A switchable core: the classic agent path, or a Fox Security Research Core of
  4 swarms (knowledge, assessment, risk, portfolio) over MCP tools — same data,
  different orchestration, and the ledger records which core served each run.
- A hash-chained audit ledger that renders the swarm control flow: every
  agent-to-orchestrator handoff, with the model calls under it, provable offline.
- Deterministic risk scoring (idempotent, `inputs_hash`), a unified risk
  register, and human approval gates — the LLM drafts, never decides.
- Deep-research question drafting: a versioned axis library that generates
  seedable evaluation catalogs (payments, data export, AI adoption in the
  enterprise…) with stable keys and severity hints.
- Privacy by construction: trust boundaries, digest-only ledger (prompts never
  stored), PII counted but never kept, sandboxed fetching, and constant-time
  credential verification that returns only the redacted form.
- Run summary reports with all diagrams and artifacts, exportable as Markdown/PDF
  from the Classic GUI, the Risk Console, and the Agentic Manager.

Built as a local-first stack: FastAPI + SQLite WAL, inference on a GPU node via
a fox-services gateway (2x RTX 5080), no external API keys, everything inside
the LAN.

Happy to talk about the architecture, the ledger, or the risk-scoring core.

---

## Full write-up

### What it is

The **Agentic Knowledge Mapper** is a local-first agentic research platform for
security, privacy, and AI-risk investigation. It runs structured agent swarms
to collect evidence, build assessments, score residual risk, and produce
auditable reports — from a single browser tab on a laptop.

Seven applications cooperate; the mapper is the only one that holds research
data, and everything else is a presentation layer or a dependency it calls:

| App | Port | Role |
|---|---|---|
| Agentic Knowledge Mapper | 8204 | investigations, graph, security, manager |
| Risk Console | 8204 `/console` | risk-first alternative GUI (same REST) |
| Executive brief — Security & Privacy | 8204 `#dashboard` | assurance board + coverage, register, fox-services nodes, knowledge graph |
| fox-services | 8210 | LLM gateway + OpenShell broker (GPU node) |
| AI Standards dashboard | 5173 | browsable standards taxonomy |
| OpenShell broker | in fox-services | sandboxed page fetching, egress policy |

### Architecture, in one breath

Every GUI is a projection over one FastAPI backend. All model calls leave the
app only to the fox-services GPU node (local model, no mesh-peer fallback). The
only way to reach the open internet is through the sandboxed broker carrying
queries and URLs. *(Diagram 1 in SHARE-DIAGRAMS.md.)*

### The switchable core

A thin facade picks between the classic agent engine and the **Fox Security
Research Core**: four swarms (knowledge, assessment, risk, portfolio) over MCP
tools (`search, graph, register, score, assess, index, ledger, catalog, brief`).
Below the facade everything converges on the same deterministic spine — so
switching cores never changes the numbers, only how the LLM is orchestrated.
*(Diagram 2.)*

### The audit ledger

Hash-chained and proof-anchored, the ledger records every LLM call (as digests
+ gateway proof), every A2A handoff, and every human decision. A **swarm
control-flow** view renders each delegation chain — orchestrator to specialist,
with the model calls under it — and the whole chain verifies offline.
*(Diagram 3.)*

### Risk management

Agents propose and draft; humans own and decide. `risk_sync/review/decide/enrich`
move findings into a unified register with deterministic, idempotent scoring
(`inputs_hash`). Acceptances and policy changes cross an **approval gate**
(requester ≠ approver) and land on the ledger. *(Diagram 4.)*

### Privacy by construction

Trust boundaries keep prompts out of the ledger (digests only), count PII
without keeping it, and route all internet egress through a sandboxed broker.
Credential checks are constant-time and return only the redacted form.
*(Diagram 5.)*

### Deep-research question drafting & evaluation runs

A versioned axis library drives an LLM workflow (with a deterministic
fallback) that produces **seedable evaluation catalogs** — stable keys,
severity hints, weights — across domains: agentic payments (12 sections, 53
questions), data export, enterprise AI adoption. Draft → seed → run → score →
`report.md`/`report.json`. *(Diagram 6.)*

---

## How to try it

- Start the fox-services gateway (port 8210), then the app (port 8204).
- GUI at `http://localhost:8204`; Risk Console at `/console`; the audit ledger
  tab shows chains, proofs, and the swarm control flow.
- Run the Agentic Manager on a command like *"security investigation of MFA
  bypass in banking payment agents"* and watch one command fan out to
  investigations, assessments, and a compiled summary report (Markdown/PDF).

## Stack

FastAPI + SQLite (WAL) · SQLAlchemy · a hash-chained audit ledger · NVIDIA
OpenShell sandboxed fetching · local LLM via an OpenAI-compatible gateway on a
GPU node · no external API keys · everything stays inside the LAN.