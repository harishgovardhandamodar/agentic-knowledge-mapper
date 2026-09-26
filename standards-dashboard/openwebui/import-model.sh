#!/usr/bin/env bash
# Import the finetuned model locally (this machine or axiom) and expose it to Open WebUI.
# Model definition (chat template with tool support, params, system prompt) is the
# single source of truth in openwebui/Modelfile.base — FROM is prepended here.
# Prereqs: ollama installed (https://ollama.com). Run the finetune first (finetune/run-axiom.sh).
# Usage:
#   bash openwebui/import-model.sh ./outputs/ai-standards-merged   # HF merged dir -> GGUF -> ollama
#   bash openwebui/import-model.sh --gguf ./model-Q4_K_M.gguf        # prebuilt GGUF
set -euo pipefail
MODEL_NAME="${MODEL_NAME:-ai-standards:latest}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${1:-}" == "--gguf" ]]; then
  GGUF="$2"
else
  SRC="${1:?usage: import-model.sh ./outputs/ai-standards-merged | --gguf file.gguf}"
  GGUF="${SRC%/}-Q4_K_M.gguf"
  test -d "$SRC" || { echo "missing merged dir $SRC"; exit 1; }
  test -x ./llama.cpp/convert_hf_to_gguf.py || git clone --depth 1 https://github.com/ggerganov/llama.cpp
  cmake -S ./llama.cpp -B ./llama.cpp/build -D LLAMA_CURL=OFF >/dev/null && cmake --build ./llama.cpp/build -j --target llama-quantize >/dev/null
  python3 ./llama.cpp/convert_hf_to_gguf.py "$SRC" --outfile "${SRC%/}-f16.gguf"
  ./llama.cpp/build/bin/llama-quantize "${SRC%/}-f16.gguf" "$GGUF" Q4_K_M
fi

{ echo "FROM $GGUF"; cat "$SCRIPT_DIR/Modelfile.base"; } > /tmp/Modelfile.ai-standards
ollama create "$MODEL_NAME" -f /tmp/Modelfile.ai-standards
ollama run "$MODEL_NAME" "Summarize your governance sources in one line." --verbose || true
echo "OK: ollama model '$MODEL_NAME' ready. Start chat:  docker compose up -d  -> http://localhost:8080"
