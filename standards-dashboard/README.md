# AI Standards & Regulations Dashboard

TSX dashboard + monthly ingest + Unsloth finetune + Open WebUI chat, covering worldwide AI
regulations, standards, and control frameworks (EU AI Act, GPAI Code, NIST AI RMF/600-1,
ISO/IEC 42001/23894/23053/24029/24028, OWASP LLM/Agentic, MITRE ATLAS, OECD, UNESCO,
G7 Hiroshima, US EO/OMB/CO/CA, UK AISI, CN GenAI/Deep Synthesis, CA AIDA, BR 2338,
SG Model Framework, JP, KR Basic Act, IN NITI, AU guardrails — 34 sources, see `data/frameworks.json`).

## Quickstart (this machine)

```bash
npm install
npm run ingest            # validate + compute overlap -> public/data.json
npm run export:finetune   # -> data/finetune.jsonl (chat-tuning dataset)
npm run dev               # dashboard at http://localhost:5173
npm run build             # typecheck + production build
```

## Benchmark backend

The Benchmark tab reads the committed `public/eval-report-*.json` statically and can also
drive a FastAPI backend (`benchmark-api/`) that triggers long `run`/`rerun` jobs. The tab
talks to the backend **same-origin**: vite proxies `/api/benchmark/*` in dev, and the
dashboard container's nginx proxies it to `benchmark-api` in the compose network — no
cross-origin CORS needed. Cross-origin is still possible via the `VITE_BENCH_API` build
arg for a hosted backend.

Mutations are gated server-side by `BENCH_API_TOKEN`:

- Loopback clients (uvicorn on your own machine) work with no token.
- Remote clients need the token. Set `BENCH_API_TOKEN=<secret>` before `docker compose up`.
- The token is **not baked into the static bundle** (it was before, via `VITE_BENCH_TOKEN`,
  which made the gate cosmetic): enter it in the Benchmark tab after a 401 — it is held in
  memory for the session only, and sent with each mutation.
- CORS is restricted to the dashboard origin (`BENCH_ALLOW_ORIGIN`, default `http://localhost:5173`).
- Backend tests: `python3 -m pip install -r benchmark-api/requirements-dev.txt && python3 -m pytest benchmark-api -q`.

Dashboard gives: full-text search + jurisdiction/type filters, per-regulation coverage heatmap
(10 control dimensions), Jaccard overlap matrix on control tags, and a rule-based scenario
advisor ("deploy RAG chatbot in EU healthcare" → applicable sources + gaps + links).

## Deploy (docker compose)

```bash
docker compose up -d --build
# dashboard http://localhost:5173 · chat http://localhost:8080 · ollama :11434
```

- `dashboard` is built from `Dockerfile` (node build → nginx, SPA fallback).
- All images are pinned by digest (`Dockerfile` + `docker-compose.yml`, frozen
  2026-09-20; refresh commands are commented next to each pin), and every service
  has a healthcheck: `open-webui` waits for `ollama`, `dashboard` waits for
  `benchmark-api` (`depends_on: service_healthy`). Startup grace covers slow
  first boots (model seeding, apt+pip in benchmark-api).
- `ollama` seeds `ai-standards:latest` from `models/*.gguf` on first start only
  (entrypoint is idempotent — restarts skip the seed). Needs the 4.7GB GGUF in
  `models/`; on a fresh host copy it there or re-run `openwebui/import-model.sh`.
- `open-webui` talks to `http://ollama:11434` inside the compose network.
- The model ships a tools-capable Qwen2.5 chat template (`openwebui/Modelfile.base`,
  single source of truth). Without it Ollama reports only `completion` and Open WebUI
  fails with "<model> does not support tools" whenever a tool is attached to the chat.
- On NVIDIA Linux (axiom), uncomment the `deploy.resources` GPU block in
  `docker-compose.yml` for GPU inference.

## Data persistence (deletion protection)

- `ollama-data` (models/blobs) and `open-webui-data` (users/chats/settings) are
  **named volumes**: they survive `docker compose down`, rebuilds, and image/container
  deletion. `restart: unless-stopped` brings the stack back after reboots.
- The ONLY destructive command is `docker compose down -v`. Back up first:
  `bash scripts/backup-volumes.sh` (restores documented in the script output).
- Never `docker volume rm` the two volumes above unless you have a backup.

## Monthly refresh

- `scripts/ingest.mjs` is the single ingest owner: validates scores (0|1|2), recomputes
  overlap, writes `public/data.json`, flags entries stale >45d.
- `.github/workflows/refresh-monthly.yml` runs it on the 1st of each month (`--check-urls`,
  commits refreshed `data/frameworks.json` + `public/data.json`).
- To refresh locally: `node scripts/ingest.mjs --refresh-dates --check-urls && npm run build`.

## Finetune on axiom (2× RTX 5080) + import locally + chat

```bash
# 1. ship dataset to axiom (user fox)
scp data/finetune.jsonl fox@axiom:~/ai-standards/finetune/
ssh fox@axiom  # password supplied separately; prefer ssh key

# 2. on axiom: DDP QLoRA via Unsloth (falls back to single-GPU if needed)
bash finetune/run-axiom.sh ./finetune.jsonl

# 3. import locally (this machine or axiom): GGUF Q4_K_M -> Ollama
bash openwebui/import-model.sh ./outputs/ai-standards-merged

# 4. serve everything (dashboard + model + chat)
docker compose up -d --build
# -> dashboard http://localhost:5173, chat http://localhost:8080 (model: ai-standards:latest)
```

Details: `finetune/train_unsloth.py` (Llama-3.1-8B-Instruct 4-bit QLoRA, seq 4096, torchrun
DDP on 2×5080), `finetune/requirements-axiom.txt` (cu128 nightly for Blackwell),
`docker-compose.yml` (dashboard build + ollama with model seed + Open WebUI;
swap the image to `https://github.com/harishgovardhandamodar/open-webui` when published).

## Design notes

- No backend: static `public/data.json` keeps total complexity minimal; dashboard does
  search/coverage/overlap/scenario ranking client-side (`src/lib/engine.ts`).
- No chart dep: heatmap/bars/overlap matrix are hand-rolled SVG/CSS (`src/components/charts.tsx`).
- Coverage scores are curated approximations with primary-source URLs; for legal use verify
  the linked source and consult counsel.
