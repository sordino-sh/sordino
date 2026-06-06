#!/usr/bin/env bash
# Codex SessionStart hook: start/reuse this project's zlauder OpenAI proxy.
#
# stdout must stay valid hook JSON. Diagnostics go to stderr.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_resolve-bins.sh
. "$SCRIPT_DIR/_resolve-bins.sh"

warn() { printf '%s\n' "$*" >&2; }

if ! zlauder_resolve_bins; then
  warn "ZlauDeR: proxy not started this session."
  printf '{}\n'
  exit 0
fi

PROJECT_ROOT="${CODEX_PROJECT_DIR:-${PWD:-.}}"
PLUGIN_ROOT="${CODEX_PLUGIN_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"

config_path() {
  if [ -f "$PROJECT_ROOT/zlauder.toml" ]; then
    printf '%s\n' "$PROJECT_ROOT/zlauder.toml"
  elif [ -f "$PLUGIN_ROOT/zlauder.toml" ]; then
    printf '%s\n' "$PLUGIN_ROOT/zlauder.toml"
  fi
}

# zlauder-hooks currently owns per-project port reservation and proxy lifecycle.
# It is Claude-oriented, so provide the project root and route env it expects only
# inside this subprocess. Codex routing itself is the trusted `openai_base_url`
# config documented by this plugin.
export CLAUDE_PROJECT_DIR="$PROJECT_ROOT"

PORT="${ZLAUDER_PORT:-$("$ZLAUDER_HOOKS_BIN" reserve-port)}"
BASE_URL="http://127.0.0.1:${PORT}"
OPENAI_BASE_URL="${BASE_URL}/v1"
export ANTHROPIC_BASE_URL="$BASE_URL"

CFG="$(config_path)"
set +e
if [ -n "$CFG" ]; then
  "$ZLAUDER_HOOKS_BIN" --port "$PORT" session-start --config "$CFG" >/dev/null
else
  "$ZLAUDER_HOOKS_BIN" --port "$PORT" session-start >/dev/null
fi
rc=$?
set -e

if [ "$rc" -ne 0 ]; then
  warn "ZlauDeR: zlauder-hooks session-start exited $rc."
  printf '{}\n'
  exit 0
fi

printf '{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"ZlauDeR OpenAI proxy is listening for this project at %s. Route trusted Codex config with openai_base_url = \"%s\" to mask Chat Completions and Responses create traffic."},"env":{"OPENAI_BASE_URL":"%s","ZLAUDER_PORT":"%s"}}\n' \
  "$BASE_URL" "$OPENAI_BASE_URL" "$OPENAI_BASE_URL" "$PORT"
