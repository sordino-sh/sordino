#!/usr/bin/env bash
# Backs /zlauder:zdr. Observer-style: never aborts hard (needs a *running* proxy),
# resolves binaries with --no-build. The hooks binary keys this session's conversation
# off the inherited ANTHROPIC_BASE_URL, so no id needs to be threaded here.
set -uo pipefail
set -f

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_resolve-bins.sh
. "$SCRIPT_DIR/_resolve-bins.sh"

if ! zlauder_resolve_bins --no-build; then
  echo "error: zlauder-hooks is not available for this project yet. Start a Claude Code session in this project, or put the binaries on PATH, then retry." >&2
  exit 1
fi

# Re-split the single argument string into positionals (status / on <config> / off /
# config) under `set -f` so a config name lands as its own arg. (Like the other
# zlauder scripts, this word-splits on whitespace — ZDR config names are TOML target
# identifiers, so keep them shell-simple / single-word.)
# shellcheck disable=SC2086
set -- ${1:-}

PORT_ARGS=()
[ -n "${ZLAUDER_PORT:-}" ] && PORT_ARGS=(--port "$ZLAUDER_PORT")

if [ "$#" -eq 0 ]; then
  exec "$ZLAUDER_HOOKS_BIN" "${PORT_ARGS[@]}" zdr status
fi
exec "$ZLAUDER_HOOKS_BIN" "${PORT_ARGS[@]}" zdr "$@"
