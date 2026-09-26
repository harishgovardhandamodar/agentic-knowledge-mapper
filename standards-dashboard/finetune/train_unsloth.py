"""Finetune a chat model on data/finetune.jsonl with Unsloth, tuned for 2x RTX 5080 (Blackwell, ~16GB each).

Strategy (fits total-system simplicity + VRAM reality):
- Base: Qwen2.5-7B-Instruct (Apache-2.0, ungated), 4-bit QLoRA, seq 2048,
  batch 1 x accum 8. Fits on ONE 16GB 5080; GPU 2 stays free for serving.
- 2-GPU use: torchrun DDP (2 procs) via run-axiom.sh; effective batch doubles.
  If DDP proves unstable, fall back to single-GPU (WORLD_SIZE=1).
- Blackwell needs torch cu128+ / cu130 and recent unsloth (see requirements-axiom.txt).
  TORCHDYNAMO_DISABLE=1 works around a Triton RMS-norm grid bug on sm_120.

Run on axiom (user fox):
    scp data/finetune.jsonl fox@axiom:~/ai-standards/finetune/
    ssh fox@axiom
    bash finetune/run-axiom.sh

Outputs: ./outputs/ai-standards-lora + ./outputs/ai-standards-merged (16-bit) for GGUF/Ollama import.
"""
import json
import os

from unsloth import FastLanguageModel  # MUST be imported before trl/transformers/peft
import torch
from datasets import load_dataset
from transformers import TrainingArguments
from trl import SFTTrainer, SFTConfig

MODEL_ID = os.environ.get("BASE_MODEL", "unsloth/gemma-4-12b-it")  # Gemma 4 12B IT (ungated); QLoRA 4-bit via bnb on-the-fly
MAX_SEQ = int(os.environ.get("MAX_SEQ_LEN", "4096"))
OUT = os.environ.get("OUTPUT_DIR", "./outputs/ai-standards-lora")
DATA = os.environ.get("DATA_FILE", "./finetune.jsonl")

SYSTEM = (
    "You are an AI governance assistant. Answer about EU AI Act, NIST, ISO/IEC, OWASP, MITRE ATLAS, "
    "and worldwide AI regulations from the curated dataset. Cite the source framework and URL, "
    "state coverage gaps explicitly, and never give legal advice — recommend consulting counsel."
)

model, tokenizer = FastLanguageModel.from_pretrained(
    MODEL_ID,
    max_seq_length=MAX_SEQ,
    dtype=None,          # auto: bf16 on Blackwell
    load_in_4bit=True,
)
# Keep the model's native chat template (Gemma uses <start_of_turn>, Qwen uses <|im_start|>).
# Previous Qwen-only override broke Gemma — rely on tokenizer's default instead.
if "qwen" in MODEL_ID.lower() and not tokenizer.chat_template:
    tokenizer.chat_template = (
        "{% for m in messages %}{{ '<|' + m['role'] + '|>\n' + m['content'] + '\n' }}{% endfor %}"
        "{{ '<|assistant|>\n' }}"
    )

model = FastLanguageModel.get_peft_model(
    model,
    r=32,
    lora_alpha=64,
    lora_dropout=0.0,
    bias="none",
    use_gradient_checkpointing="unsloth",
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    use_rslora=True,
    loftq_config=None,
)


def to_chat(ex):
    user = ex["instruction"] + (f"\n{ex['input']}" if ex.get("input") else "")
    return {
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": user},
            {"role": "assistant", "content": ex["output"]},
        ],
        "source": ex.get("source", ""),
    }


ds = load_dataset("json", data_files=DATA, split="train").map(to_chat)


def fmt(ex):
    return {"text": tokenizer.apply_chat_template(ex["messages"], tokenize=False)}


ds = ds.map(fmt)

world = int(os.environ.get("WORLD_SIZE", "1"))
per_device = int(os.environ.get("PER_DEVICE_BATCH", "1"))  # 16GB RTX 5080: keep 1, scale via accumulation
grad_accum = int(os.environ.get("GRAD_ACCUM", "8"))

trainer = SFTTrainer(
    model=model,
    processing_class=tokenizer,
    train_dataset=ds,
    formatting_func=lambda ex: ex["text"],
    args=SFTConfig(
        output_dir=OUT,
        max_length=MAX_SEQ,
        eos_token=None,  # skip TRL override; tokenizer already carries '<|im_end|>'
        per_device_train_batch_size=per_device,
        gradient_accumulation_steps=grad_accum,
        num_train_epochs=float(os.environ.get("EPOCHS", "2")),
        learning_rate=2e-4,
        lr_scheduler_type="cosine",
        optim="adamw_8bit",
        weight_decay=0.01,
        logging_steps=10,
        save_steps=200,
        save_total_limit=2,
        bf16=True,
        gradient_checkpointing=True,
        ddp_find_unused_parameters=False,
        report_to="none",
        seed=3407,
    ),
)
trainer.train()

# Save LoRA (rank 0 only under DDP) then merge to 16-bit for GGUF/Ollama.
if int(os.environ.get("RANK", "0")) == 0:
    model.save_pretrained(OUT)
    tokenizer.save_pretrained(OUT)
    merged = OUT.replace("ai-standards-lora", "ai-standards-merged")
    model.save_pretrained_merged(merged, tokenizer, save_method="merged_16bit")
    print(f"saved LoRA -> {OUT}; merged -> {merged}")
    with open(os.path.join(OUT, "SOURCES.json"), "w") as fh:
        json.dump({"data": DATA, "base": MODEL_ID, "system": SYSTEM}, fh, indent=2)
