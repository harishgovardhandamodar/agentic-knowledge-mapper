#!/bin/bash
# Start the AKM agent console (chat-style TUI).
#
#   ./startup.sh
#
# Uses the project venv (.venv, created with uv). Everything the console
# does goes through the web app's API, so its work is visible in the GUI.
# (The older tabbed dashboard is still available: .venv/bin/python -m cli tui)
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x .venv/bin/python ]; then
  echo "No .venv here -- creating it with uv..." >&2
  uv venv .venv
  uv pip install --python .venv/bin/python \
    -r requirements.txt -r requirements-dev.txt
fi

export AKM_API_URL="${AKM_API_URL:-http://127.0.0.1:8204}"
if ! AKM_API_URL="$AKM_API_URL" .venv/bin/python - <<'EOF'
import os
import sys
import urllib.request
try:
    urllib.request.urlopen(
        os.environ["AKM_API_URL"] + "/api/health", timeout=4)
except Exception as exc:
    print(f"probe failed: {exc}")
    sys.exit(1)
EOF
then
  echo "warning: web app not reachable at $AKM_API_URL -- start it" >&2
  echo "  first (docker compose up -d, or uvicorn app.main:app)" >&2
fi

exec .venv/bin/python -m cli chat "$@"
