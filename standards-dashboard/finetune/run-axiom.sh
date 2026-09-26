#!/usr/bin/env bash
# One-shot finetune on axiom (fox@axiom, 2x RTX 5080) + export for local import.
# Usage (on axiom):  bash finetune/run-axiom.sh  [/path/to/finetune.jsonl]
set -euo pipefail
DATA="${1:-./finetune.jsonl}"
test -f "$DATA" || { echo "missing dataset: $DATA (copy data/finetune.jsonl here)"; exit 1; }
nvidia-smi --query-gpu=name,memory.total --format=csv
python3 -c "import torch; print(torch.__version__, torch.cuda.is_available(), [torch.cuda.get_device_name(i) for i in range(torch.cuda.device_count())])"
pip install -q --index-strategy unsafe-best-match -r finetune/requirements-axiom.txt
# 2-GPU DDP; fall back to single GPU if torchrun fails.
export DATA_FILE="$DATA" OUTPUT_DIR=./outputs/ai-standards-lora EPOCHS=2 MAX_SEQ_LEN=2048
export TORCHDYNAMO_DISABLE=1 PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True
if torchrun --nproc_per_node=2 finetune/train_unsloth.py; then
  echo "DDP training ok"
else
  echo "DDP failed — retrying single-GPU (GPU0 train, GPU1 stays free for serving)"
  CUDA_VISIBLE_DEVICES=0 WORLD_SIZE=1 RANK=0 python3 finetune/train_unsloth.py
fi
# GGUF (Q4_K_M) for Ollama / Open WebUI import.
test -x ./llama.cpp/quantize || git clone --depth 1 https://github.com/ggerganov/llama.cpp
python3 - <<'EOF'
from transformers import AutoTokenizer, AutoModelForCausalLM
print("merged model at ./outputs/ai-standards-merged — convert with llama.cpp/convert_hf_to_gguf.py then quantize to Q4_K_M")
EOF
echo "DONE. Next: bash openwebui/import-model.sh ./outputs/ai-standards-merged"
