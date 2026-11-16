#!/usr/bin/env bash
# RansomWatch demo: harmless attack simulation (random bytes, temp folder only).
# No real malware is compiled or executed, no network connection is made.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "error: $PYTHON_BIN not found (Python 3.8+ required)" >&2
    exit 1
fi

exec "$PYTHON_BIN" "$SCRIPT_DIR/detector/simulate.py" "$@"
