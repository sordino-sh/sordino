#!/usr/bin/env bash
# zlauder PreToolUse hook: resolve allow-listed BROKER secrets into the tool input.
#
# Reads the PreToolUse payload (tool_name + tool_input) on stdin and, when an
# allow-listed broker token resolves, emits a `hookSpecificOutput.updatedInput` JSON
# so the tool runs with the real value spliced in at the LAST moment. FAIL-CLOSED and
# silent: any error (no proxy, no binaries, timeout, nothing resolved) emits nothing,
# so the tool simply runs with the broker token unresolved — never a secret leak.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_resolve-bins.sh
. "$SCRIPT_DIR/_resolve-bins.sh"

# Binaries unavailable ⇒ emit nothing (the tool proceeds unmodified).
if ! zlauder_resolve_bins --no-build 2>/dev/null; then
  exit 0
fi

PORT_ARGS=()
[ -n "${ZLAUDER_PORT:-}" ] && PORT_ARGS=(--port "$ZLAUDER_PORT")

# zlauder-hooks reads the PreToolUse payload from stdin and prints the hook JSON (or
# nothing). Never fail the tool: swallow any non-zero exit.
"$ZLAUDER_HOOKS_BIN" "${PORT_ARGS[@]}" pre-tool-use || true
