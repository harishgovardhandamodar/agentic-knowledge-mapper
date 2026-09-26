from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
import subprocess, threading, time, json, re, os, signal
from pathlib import Path
from datetime import datetime

app = FastAPI(title="Benchmark API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.environ.get("BENCH_ALLOW_ORIGIN", "http://localhost:5173")],
    allow_methods=["*"],
    allow_headers=["*"],
)

LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}

def _mutation_error(token: str, provided: str, client_host: str) -> str | None:
    """Pure authorization decision: None = allowed, otherwise an error message."""
    if token:
        return None if provided == token else "invalid or missing BENCH_API_TOKEN"
    if client_host in LOOPBACK_HOSTS:
        return None
    return "mutation requires BENCH_API_TOKEN (or run from localhost)"

def require_authorized(request: Request) -> None:
    """Gate mutating endpoints (run/stop/rerun) behind a shared token.

    - BENCH_API_TOKEN set   -> request must send it via `Authorization: Bearer` or `X-Bench-Token`.
    - token unset           -> only loopback clients may mutate (host dev flow).
    Anything else is rejected. Read-only GETs stay open.
    """
    token = os.environ.get("BENCH_API_TOKEN", "")
    provided = request.headers.get("X-Bench-Token") or request.headers.get("Authorization", "")
    if provided.startswith("Bearer "):
        provided = provided[len("Bearer "):]
    client = request.client.host if request.client else ""
    error = _mutation_error(token, provided, client)
    if error:
        raise HTTPException(401 if token else 403, error)

ROOT = Path("/app")
if not (ROOT / "scripts" / "eval-governance.py").exists():
    # fallback when running from host (project root is cwd)
    ROOT = Path.cwd()
    if not (ROOT / "scripts" / "eval-governance.py").exists():
        ROOT = Path(__file__).resolve().parents[1]

# Shared scoring (same heuristic as the offline eval harness): never drift again.
import sys
sys.path.insert(0, str(ROOT / "scripts"))
from eval_scoring import evaluate_response, load_framework_names  # noqa: E402
load_framework_names(str(ROOT / "data" / "frameworks.json"))

# models in order: finetuned qwen, finetuned gemma, vanilla qwen27b
MODELS = [
    {"key": "qwen7b", "model": "ai-standards:latest", "file": "eval-report-qwen7b.json", "log": "eval-qwen.log"},
    {"key": "gemma", "model": "ai-standards:gemma-4-12b", "file": "eval-report-gemma.json", "log": "eval-gemma.log"},
    {"key": "qwen27b", "model": "qwen3.8:27b-mlx", "file": "eval-report-qwen27b.json", "log": "eval-qwen27b.log"},
]

state = {"running": False, "current": None, "started_at": None, "pids": [], "error": None}
lock = threading.Lock()

def _ollama_host():
    # inside Docker, host Ollama is host.docker.internal; on host, it's localhost
    # prefer env, then detect
    env = os.environ.get("OLLAMA_HOST")
    if env:
        return env
    # if /app is mounted and we are inside Docker with host.docker.internal reachable, use it if localhost fails?
    # default to host.docker.internal when running in Docker (exists in /etc/hosts), else localhost
    try:
        import socket
        socket.gethostbyname("host.docker.internal")
        return "host.docker.internal"
    except Exception:
        return "localhost"

def _log_progress(log_path: Path):
    try:
        txt = log_path.read_text()[-4000:]
        # find last "  250/500  pass=..."
        m = re.findall(r"(\d+)/500\s+pass=(\d+)/\d+\s+\((\d+)%\)", txt)
        if m:
            done, passed, pct = m[-1]
            return {"done": int(done), "passed": int(passed), "pct": int(pct), "total": 500}
        # check for "Running 500"
        if "Running 500" in txt:
            return {"done": 0, "passed": 0, "pct": 0, "total": 500}
    except Exception:
        pass
    return None

def _run_sequential():
    global state
    host = _ollama_host()
    for m in MODELS:
        with lock:
            state["current"] = m["key"]
        log = ROOT / m["log"]
        out = ROOT / "data" / m["file"]
        # clean previous log
        try:
            log.unlink()
        except Exception:
            pass
        cmd = ["python3", "scripts/eval-governance.py", "--model", m["model"], "--host", host, "--port", "11434", "--out", str(out)]
        # also handle gemma/min fallback: if gemma not found, try gemma-min?
        proc = subprocess.Popen(cmd, cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        with lock:
            state["pids"] = [proc.pid]
        # stream to log file
        with open(log, "w") as f:
            for line in proc.stdout:  # type: ignore
                f.write(line)
                f.flush()
        proc.wait()
        # copy to public
        try:
            pub = ROOT / "public" / m["file"]
            pub.parent.mkdir(parents=True, exist_ok=True)
            if out.exists():
                pub.write_text(out.read_text())
        except Exception as e:
            print(f"copy to public failed: {e}")
        if proc.returncode != 0:
            with lock:
                state["error"] = f"{m['key']} failed code {proc.returncode}"
            break
    with lock:
        state["running"] = False
        state["current"] = None
        state["pids"] = []

@app.get("/api/benchmark/status")
def status():
    # build per-model progress from logs and reports
    per = {}
    for m in MODELS:
        log = ROOT / m["log"]
        prog = _log_progress(log)
        report = ROOT / "data" / m["file"]
        has_report = report.exists()
        per[m["key"]] = {
            "model": m["model"],
            "log": m["log"],
            "has_report": has_report,
            "progress": prog,
        }
        if has_report:
            try:
                j = json.loads(report.read_text())
                per[m["key"]]["summary"] = j.get("summary")
            except Exception:
                pass
    with lock:
        s = dict(state)
    return {"state": s, "per_model": per, "host": _ollama_host(), "time": datetime.utcnow().isoformat()}

@app.get("/api/benchmark/logs")
def logs(model: str = "qwen7b", tail: int = 120):
    # model key or log name
    m = next((x for x in MODELS if x["key"] == model or x["log"] == model), None)
    if not m:
        return {"error": "unknown model", "available": [x["key"] for x in MODELS]}
    log = ROOT / m["log"]
    try:
        lines = log.read_text().splitlines()[-tail:]
        return {"model": m["key"], "log": m["log"], "lines": lines}
    except FileNotFoundError:
        return {"model": m["key"], "log": m["log"], "lines": [], "note": "no log yet"}

@app.post("/api/benchmark/run")
def run(request: Request):
    require_authorized(request)
    global state
    with lock:
        if state["running"]:
            return {"error": "already running", "state": state}
        state["running"] = True
        state["started_at"] = datetime.utcnow().isoformat()
        state["error"] = None
        state["current"] = MODELS[0]["key"]
    # kill any previous eval processes (best effort)
    try:
        subprocess.run(["pkill", "-f", "eval-governance"], timeout=2)
    except Exception:
        pass
    t = threading.Thread(target=_run_sequential, daemon=True)
    t.start()
    return {"started": True, "state": state}

@app.post("/api/benchmark/stop")
def stop(request: Request):
    require_authorized(request)
    try:
        subprocess.run(["pkill", "-f", "eval-governance"], timeout=2)
    except Exception:
        pass
    with lock:
        state["running"] = False
        state["current"] = None
    return {"stopped": True}

@app.get("/api/benchmark/reports")
def reports():
    out = {}
    for m in MODELS:
        p = ROOT / "data" / m["file"]
        if p.exists():
            try:
                out[m["key"]] = json.loads(p.read_text())
            except Exception as e:
                out[m["key"]] = {"error": str(e)}
    return out

@app.post("/api/benchmark/rerun-model")
def rerun_model(payload: dict, request: Request):
    require_authorized(request)
    # payload: {key: qwen7b|gemma|qwen27b}
    key = payload.get("key")
    m = next((x for x in MODELS if x["key"] == key), None)
    if not m:
        return {"error": "unknown model", "available": [x["key"] for x in MODELS]}
    # run single model in background
    def _run_one():
        import subprocess, pathlib
        host = _ollama_host()
        out = ROOT / "data" / m["file"]
        log = ROOT / m["log"]
        try:
            log.unlink(missing_ok=True)
        except Exception:
            pass
        cmd = ["python3", "scripts/eval-governance.py", "--model", m["model"], "--host", host, "--port", "11434", "--out", str(out)]
        proc = subprocess.Popen(cmd, cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        with open(log, "w") as f:
            for line in proc.stdout:  # type: ignore
                f.write(line); f.flush()
        proc.wait()
        try:
            pub = ROOT / "public" / m["file"]
            pub.parent.mkdir(parents=True, exist_ok=True)
            if out.exists():
                pub.write_text(out.read_text())
        except Exception:
            pass
    import threading
    threading.Thread(target=_run_one, daemon=True).start()
    return {"started": key}

@app.post("/api/benchmark/rerun")
def rerun(payload: dict, request: Request):
    require_authorized(request)
    # payload: {query: str, expects: list, id: int}
    q = payload.get("query", "")
    expects = payload.get("expects", [])
    qid = payload.get("id")
    host = _ollama_host()
    results = {}
    for m in MODELS:
        # reuse eval's ollama_generate logic (simple)
        import urllib.request, json as _json
        url = f"http://{host}:11434/api/generate"
        body = _json.dumps({"model": m["model"], "prompt": q, "stream": False, "think": False, "options": {"num_predict": 150, "temperature": 0.3}}).encode()
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        try:
            import urllib.error
            with urllib.request.urlopen(req, timeout=120) as r:
                resp = _json.loads(r.read()).get("response", "")
        except Exception as e:
            resp = f"[Error {e}]"
        results[m["key"]] = {"response_excerpt": resp[:800], "evaluation": evaluate_response(resp, expects)}
    return {"id": qid, "query": q, "results": results}

@app.get("/health")
def health():
    return {"ok": True}
