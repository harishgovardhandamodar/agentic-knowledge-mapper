#!/bin/sh
# Ollama entrypoint: start server, seed the finetuned model once, then stay up.
# Idempotent: skips `ollama create` when ai-standards:latest already exists in
# the ollama-data volume, so restarts are instant and data is never re-seeded.
# Model definition (incl. tools-capable chat template) comes from /Modelfile.base.
set -e
MODEL="${MODEL_NAME:-ai-standards:latest}"
GGUF="${MODEL_GGUF:-/models/ai-standards-Q4_K_M.gguf}"

ollama serve &
SERVER_PID=$!
for i in $(seq 1 60); do
  if ollama list >/dev/null 2>&1; then break; fi
  sleep 2
done
if ! ollama show "$MODEL" >/dev/null 2>&1; then
  if [ -f "$GGUF" ] && [ -f /Modelfile.base ]; then
    echo "seeding $MODEL from $GGUF ..."
    { echo "FROM $GGUF"; cat /Modelfile.base; } > /tmp/Modelfile.ai-standards
    ollama create "$MODEL" -f /tmp/Modelfile.ai-standards
    echo "seeded $MODEL"
  else
    echo "WARNING: $GGUF or /Modelfile.base missing — start with an empty Ollama, import later via openwebui/import-model.sh"
  fi
else
  echo "$MODEL already present — skipping seed"
fi
wait "$SERVER_PID"
