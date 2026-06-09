#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_resolve-bins.sh
. "$SCRIPT_DIR/_resolve-bins.sh"

if ! zlauder_resolve_bins --no-build; then
  echo "error: zlauder-hooks is not available for this project yet. Start a Claude Code session in this project, or put the binaries on PATH, then retry." >&2
  exit 1
fi

PORT_ARGS=()
[ -n "${ZLAUDER_PORT:-}" ] && PORT_ARGS=(--port "$ZLAUDER_PORT")

# $1 is the (possibly empty) action: status | list. Empty defaults to status.
ACTION="${1:-}"
exec "$ZLAUDER_HOOKS_BIN" "${PORT_ARGS[@]}" secrets ${ACTION:+$ACTION}
