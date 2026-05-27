#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="${1:-ai-soc-grafana}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
INJECTION_FILE="$REPO_ROOT/deploy/observability/grafana/custom-login/ai-soc-grafana-login-branding.html"
TMP_INDEX="$(mktemp)"
TMP_PATCHED="$(mktemp)"

cleanup() {
  rm -f "$TMP_INDEX" "$TMP_PATCHED"
}
trap cleanup EXIT

docker cp "$CONTAINER_NAME:/usr/share/grafana/public/views/index.html" "$TMP_INDEX"

if grep -q "AI SOC Grafana login branding injection" "$TMP_INDEX"; then
  echo "AI SOC Grafana login branding already present."
  exit 0
fi

python3 - "$TMP_INDEX" "$INJECTION_FILE" "$TMP_PATCHED" <<'PY'
from pathlib import Path
import sys

index_path = Path(sys.argv[1])
injection_path = Path(sys.argv[2])
output_path = Path(sys.argv[3])

index = index_path.read_text(encoding="utf-8")
injection = injection_path.read_text(encoding="utf-8")

marker = "</body>"
if marker not in index:
    raise SystemExit("Could not find </body> in Grafana index.html")

patched = index.replace(marker, injection + "\n" + marker, 1)
output_path.write_text(patched, encoding="utf-8")
PY

chmod 0644 "$TMP_PATCHED"

docker cp "$TMP_PATCHED" "$CONTAINER_NAME:/usr/share/grafana/public/views/index.html"

docker exec "$CONTAINER_NAME" sh -lc 'chmod 0644 /usr/share/grafana/public/views/index.html'

echo "AI SOC Grafana login branding applied to $CONTAINER_NAME."
