#!/usr/bin/env bash
# Decode a masked token back to plaintext via the running proxy (local audit).
# Usage: reveal.sh <TOKEN>
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_resolve-bins.sh
. "$SCRIPT_DIR/_resolve-bins.sh"
# --no-build: reveal needs a RUNNING proxy; building the binary wouldn't make a
# down proxy answer, so just resolve an existing one and report if absent.
zlauder_resolve_bins --no-build || true

token="${1:-}"
if [ -z "$token" ]; then
  echo "usage: /zlauder:reveal <TOKEN>   (e.g. [EMAIL_ADDRESS_xxxx])" >&2
  exit 2
fi

if ! command -v zlauder-hooks >/dev/null 2>&1; then
  echo "error: zlauder-hooks not available (proxy not built/installed for this project)." >&2
  exit 1
fi

if [ -n "${ZLAUDER_PORT:-}" ]; then
  zlauder-hooks reveal "$token" --port "$ZLAUDER_PORT"
else
  zlauder-hooks reveal "$token"
fi
