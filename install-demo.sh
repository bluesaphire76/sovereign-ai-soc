#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

if ! command -v python3 >/dev/null 2>&1; then
  cat >&2 <<'EOF'
Error: Python 3 is required for the Ubuntu guided demo installer.

Manual Ubuntu preparation:
  sudo apt update
  sudo apt install -y python3 python3-venv python3-pip

The installer did not run these commands automatically.
EOF
  exit 1
fi

exec python3 "$REPOSITORY_ROOT/scripts/install_demo_ubuntu.py" "$@"
