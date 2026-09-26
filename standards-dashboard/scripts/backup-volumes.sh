#!/usr/bin/env bash
# Back up persistent volumes (run BEFORE `docker compose down -v`, image prunes, or host moves).
# Usage: bash scripts/backup-volumes.sh [output-dir=./backups]
set -euo pipefail
OUT="${1:-./backups}/ai-standards-volumes-$(date +%F).tar.gz"
mkdir -p "$(dirname "$OUT")"
PROJ="$(basename "$PWD" | tr '[:upper:]' '[:lower:]' | tr -c '[:alnum:]' '-')"
docker run --rm \
  -v "${PROJ}_ollama-data:/vol/ollama:ro" \
  -v "${PROJ}_open-webui-data:/vol/webui:ro" \
  -v "$PWD/$(dirname "$OUT"):/backup" \
  alpine tar czf "/backup/$(basename "$OUT")" -C /vol ollama webui
echo "backup -> $OUT"
echo "restore: docker run --rm -v <volume>:/vol -v \$PWD:/backup alpine tar xzf /backup/$(basename "$OUT") -C /vol --strip-components=1"
