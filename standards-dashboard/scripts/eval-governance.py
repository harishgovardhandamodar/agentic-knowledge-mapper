#!/usr/bin/env python3
"""
500 AI Governance Queries — eval harness.

Generates 500 queries spanning EU AI Act, NIST, OWASP, ISO, worldwide
regulations and runs them against ai-standards Ollama endpoints.

Usage:
  python3 scripts/eval-governance.py --model ai-standards:latest --port 11434 --out data/eval-report.json
  # after gemma export:
  python3 scripts/eval-governance.py --model ai-standards:gemma-4-12b --port 11437 --out data/eval-report-gemma.json
"""
import argparse, json, re, sys, time, urllib.request, urllib.error
from pathlib import Path

# ---------------------------------------------------------------------------
# 500 queries: hand-curated templates expanded to 500 distinct questions.
# Each entry: {id, query, expects: [framework ids or keywords], category}
# ---------------------------------------------------------------------------

def build_queries():
    qs = []
    def add(q, expects, cat): qs.append({"query": q, "expects": expects, "category": cat})
    # EU AI Act family (100)
    eu_templates = [
        ("How does the EU AI Act regulate {use} in {jurisdiction}? Cite articles and GPAI implications.", "{use} in {jurisdiction}"),
        ("What are deployer obligations under EU AI Act for {use}?", "{use} EU deployment"),
        ("List prohibited practices under EU AI Act relevant to {use}.", "EU AI Act prohibited"),
        ("Explain GPAI Code of Practice duties for {use} under EU AI Act Chapter V.", "GPAI Code EU"),
        ("We deploy a {use} in the EU — what conformity, logging, and transparency duties apply per EU AI Act?", "EU AI Act conformity"),
    ]
    eu_uses = ["AI in recruitment and hiring interviews", "biometric identification at work", "generative AI chatbots for customers",
               "AI in credit scoring", "AI in education admissions", "AI in healthcare triage", "RAG assistants for legal advice",
               "open-weights foundation model APIs", "synthetic media generation", "AI for worker management"]
    for i, (tmpl, _) in enumerate(eu_templates):
        for j, use in enumerate(eu_uses):
            add(tmpl.format(use=use, jurisdiction="the EU"), ["eu-ai-act", "eu-gpai-code"], "EU AI Act")
            if len(qs) >= 100: break
        if len(qs) >= 100: break
    while len(qs) < 100:
        add(f"EU AI Act: what are the serious-incident reporting timelines? (variant {len(qs)})", ["eu-ai-act"], "EU AI Act")

    # NIST family (80)
    nist_qs = [
        "Explain NIST AI RMF Govern-Map-Measure-Manage for enterprise adoption.",
        "How does NIST Generative AI Profile 600-1 address confabulation and CBRN risks?",
        "What NIST Adversarial ML taxonomy controls apply to prompt injection?",
        "Compare NIST AI RMF with ISO 23894 for AI risk management.",
        "Apply NIST AI RMF to a RAG pipeline risk assessment — list key subcategories.",
    ]
    for i in range(80):
        base = nist_qs[i % len(nist_qs)]
        add(f"{base} (case {i+1})", ["nist-ai-rmf", "nist-genai-600-1", "nist-adversarial-ml"], "NIST")

    # OWASP family (70)
    owasp_qs = [
        "What OWASP LLM Top 10 controls mitigate prompt injection in a customer chatbot?",
        "How to prevent data leakage per OWASP LLM02 when using RAG with private docs?",
        "OWASP agentic guidance: least-privilege tool use and human-approval gates for coding agents.",
        "Map OWASP LLM risks to MITRE ATLAS techniques for an LLM application threat model.",
        "What excessive agency (LLM06) controls does OWASP recommend for autonomous agents?",
    ]
    for i in range(70):
        add(f"{owasp_qs[i % len(owasp_qs)]} (scenario {i+1})", ["owasp-llm-top10", "owasp-agentic", "mitre-atlas"], "OWASP")

    # ISO family (70)
    iso_qs = [
        "What does ISO/IEC 42001 require for an AI Management System certification?",
        "Explain ISO 23894 AI risk management aligned to ISO 31000 — key process steps.",
        "How does ISO 23053 structure the ML lifecycle from data to decommissioning?",
        "What robustness testing does ISO 24029 prescribe for neural networks?",
        "Compare ISO 24028 trustworthiness characteristics vs OECD AI Principles.",
    ]
    for i in range(70):
        add(f"{iso_qs[i % len(iso_qs)]} (context {i+1})", ["iso-42001", "iso-23894", "iso-23053", "iso-24029"], "ISO")

    # Worldwide regulations (100)
    world = [
        ("US Colorado AI Act SB24-205 for consequential decisions (hiring, lending, housing)", ["us-co-ai-act"]),
        ("California AI Transparency Act and training-data disclosure", ["us-ca-ai-transparency"]),
        ("UK AI Safety Institute Inspect evaluations for frontier models", ["uk-aisi"]),
        ("China Interim Measures for Generative AI plus deep synthesis labeling", ["china-genai-measures", "china-deep-synthesis"]),
        ("Canada AIDA high-impact duties and voluntary code", ["canada-aida"]),
        ("Brazil Bill 2338 GPAI and high-risk algorithmic impact assessments", ["brazil-bill-2338"]),
        ("Singapore Model AI Governance Framework and GenAI sandbox", ["singapore-model-framework"]),
        ("Japan AI Guidelines v1.0 and AI Promotion Act", ["japan-ai-guidelines"]),
        ("Korea AI Basic Act transparency labeling and impact assessment", ["korea-ai-basic-act"]),
        ("EU Product Liability Directive for AI liability and evidence disclosure", ["eu-pld-ai"]),
    ]
    for i in range(100):
        topic, exp = world[i % len(world)]
        add(f"Explain {topic} — scope, obligations, and how it compares to EU AI Act. (query {i+1})", exp, "Worldwide")

    # Cross-cutting + scenario advisor (80)
    cross = [
        "Deploying a RAG customer-support chatbot in EU healthcare — which frameworks apply and what are coverage gaps? Cite EU AI Act, NIST, OWASP.",
        "Interview process AI in the EU: what do we have on using AI in recruitment? Provide cites for EU AI Act, NIST, OWASP.",
        "Release an open-weights foundation model API globally — what applies from EU AI Act, US EOs, G7 Hiroshima?",
        "Launch text-to-image app in China and California — what labeling and disclosure duties?",
        "HR hiring screening tool in Colorado and Brazil — which algorithmic audits and notices?",
        "Agentic coding assistant with tool use — security controls from OWASP and MITRE ATLAS?",
        "High-risk AI in critical infrastructure under EU AI Act + ISO 42001 certification path?",
        "Synthetic media (voice clone) — deepfake consent and labeling per China and EU vs NIST?",
    ]
    for i in range(80):
        add(f"{cross[i % len(cross)]} (variant {i+1})", ["eu-ai-act", "nist-ai-rmf", "owasp-llm-top10", "iso-42001"], "Cross-cutting")

    # Trim/pad to exactly 500
    if len(qs) > 500:
        qs = qs[:500]
    while len(qs) < 500:
        qs.append({"query": f"General AI governance question {len(qs)+1}: summarize trustworthiness per ISO 24028.", "expects": ["iso-24028"], "category": "General"})
    for i, q in enumerate(qs, 1):
        q["id"] = i
    return qs

def ollama_generate(port, model, prompt, timeout=120, host="localhost"):
    url = f"http://{host}:{port}/api/generate"
    body = json.dumps({"model": model, "prompt": prompt, "stream": False, "think": False, "options": {"num_predict": 150, "temperature": 0.3}}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read()).get("response", "")
    except urllib.error.HTTPError as e:
        return f"[HTTPError {e.code} {e.read()[:300]}]"
    except Exception as e:
        return f"[Error {e}]"

# Scoring logic lives in scripts/eval_scoring.py (shared with benchmark-api).
from eval_scoring import distinct_query_count, evaluate_response, load_framework_names

load_framework_names("data/frameworks.json")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="ai-standards:latest")
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=11434)
    ap.add_argument("--limit", type=int, default=500)
    ap.add_argument("--out", default="data/eval-report.json")
    ap.add_argument("--concurrency", type=int, default=1)  # keep sequential for ollama
    args = ap.parse_args()

    queries = build_queries()[:args.limit]
    print(f"Running {len(queries)} queries ({distinct_query_count(queries)} distinct) against {args.model} @ :{args.port}", flush=True)

    results = []
    passed = 0
    for q in queries:
        t0 = time.time()
        resp = ollama_generate(args.port, args.model, q["query"], host=args.host)
        ev = evaluate_response(resp, q["expects"])
        elapsed = round(time.time() - t0, 2)
        if ev["score"] >= 0.5:
            passed += 1
        results.append({
            "id": q["id"], "category": q["category"], "query": q["query"],
            "expects": q["expects"], "response_excerpt": resp[:800],
            "evaluation": ev, "elapsed_s": elapsed
        })
        if q["id"] % 50 == 0:
            print(f"  {q['id']}/{len(queries)}  pass={passed}/{q['id']} ({passed/q['id']:.0%})  t={elapsed}s", flush=True)

    summary = {
        "model": args.model, "host": args.host, "port": args.port, "total": len(results),
        "queries_total": len(queries), "queries_distinct": distinct_query_count(queries),
        "passed": passed, "pass_rate": round(passed / len(results), 3) if results else 0,
        "by_category": {}
    }
    for q in queries:
        cat = q["category"]
        summary["by_category"].setdefault(cat, {"total": 0, "passed": 0})
    for r in results:
        summary["by_category"][r["category"]]["total"] += 1
        if r["evaluation"]["score"] >= 0.5:
            summary["by_category"][r["category"]]["passed"] += 1
    for cat, v in summary["by_category"].items():
        v["pass_rate"] = round(v["passed"] / v["total"], 3) if v["total"] else 0

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps({"summary": summary, "queries": results}, indent=2, ensure_ascii=False))
    # also copy to public for dashboard
    pub = Path("public") / Path(args.out).name
    pub.parent.mkdir(parents=True, exist_ok=True)
    pub.write_text(json.dumps({"summary": summary, "queries": results}, indent=2, ensure_ascii=False))
    print(json.dumps(summary, indent=2))
    print(f"Report -> {args.out} + {pub}")

if __name__ == "__main__":
    main()
