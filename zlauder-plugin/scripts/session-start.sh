#!/usr/bin/env bash
# zlauder SessionStart hook (plugin entry point).
#
# Resolves the zlauder-proxy/zlauder-hooks binaries, then hands off to the real
# control plane `zlauder-hooks session-start`, which ensures this project's proxy
# is running and prints the SessionStart hook JSON Claude Code consumes.
#
# stdout MUST stay valid hook JSON: it is passed through from zlauder-hooks
# UNCHANGED. All diagnostics go to stderr.
#
# The one thing this plugin cannot do is set ANTHROPIC_BASE_URL (Claude Code
# only honors "agent"/"subagentStatusLine" from a plugin settings.json). Routing
# is wired by `/zlauder:enable` patching this project's .claude/settings.json,
# after which Claude Code must be RESTARTED. The route guard below warns when the
# proxy is up but traffic is not actually pointed at it.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_resolve-bins.sh
. "$SCRIPT_DIR/_resolve-bins.sh"

# Do NOT default the port. zlauder-hooks/zlauder-proxy derive a per-project port
# via derive_port(project_root) (range 18000..20000) whenever neither --port nor
# $ZLAUDER_PORT is set. Forcing a fixed port would collapse every project onto one
# shared proxy and break per-project isolation. We only pass --port when the user
# explicitly set $ZLAUDER_PORT.
PORT_ARGS=()
if [ -n "${ZLAUDER_PORT:-}" ]; then
  PORT_ARGS=(--port "$ZLAUDER_PORT")
fi
PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-}"

warn() { printf '%s\n' "$*" >&2; }

# Resolve the config: project zlauder.toml if present, else the bundled template.
config_path() {
  local proj="${CLAUDE_PROJECT_DIR:-}"
  if [ -n "$proj" ] && [ -f "$proj/zlauder.toml" ]; then
    printf '%s\n' "$proj/zlauder.toml"
  elif [ -n "$PLUGIN_ROOT" ] && [ -f "$PLUGIN_ROOT/zlauder.toml" ]; then
    printf '%s\n' "$PLUGIN_ROOT/zlauder.toml"
  fi
}

# Warn when the proxy is up but ANTHROPIC_BASE_URL does not route through it.
# The port is the one the proxy actually launched on (parsed from the hook JSON),
# not a guessed default.
route_guard() {
  local port="$1"
  if [ -z "$port" ]; then
    # No resolved port to compare against; cannot reliably check routing.
    return 0
  fi
  local want="http://127.0.0.1:${port}"
  local have="${ANTHROPIC_BASE_URL:-}"
  case "$have" in
    "$want"|"$want"/*) return 0 ;;
  esac
  warn "⚠ zlauder proxy is up but ANTHROPIC_BASE_URL is not set to ${want} — traffic is NOT masked. Run /zlauder:enable then restart Claude Code."
}

# Resolve (and, on first run, build) the binaries; this also prepends their dir
# to PATH so the bare `zlauder-hooks` calls below and session-start's default
# --proxy-bin "zlauder-proxy" both resolve.
if ! zlauder_resolve_bins; then
  warn "zlauder: proxy not started this session."
  exit 1
fi

CFG="$(config_path)"

# Hand off to the real control plane. It drains our stdin (the SessionStart
# payload), ensures the proxy is up, and prints the hook JSON. Capture that
# JSON so we can emit it byte-for-byte while still running the route guard
# afterward (the guard writes to stderr only, so it never touches the JSON).
HOOK_OUT="$(mktemp "${TMPDIR:-/tmp}/zlauder-sessionstart.XXXXXX")"
trap 'rm -f "$HOOK_OUT"' EXIT

set +e
if [ -n "$CFG" ]; then
  zlauder-hooks "${PORT_ARGS[@]}" session-start --config "$CFG" >"$HOOK_OUT"
else
  zlauder-hooks "${PORT_ARGS[@]}" session-start >"$HOOK_OUT"
fi
rc=$?
set -e

# Pass the hook JSON through UNCHANGED, regardless of the guard outcome.
cat "$HOOK_OUT"

if [ "$rc" -ne 0 ]; then
  warn "zlauder: zlauder-hooks session-start exited $rc."
  exit "$rc"
fi

# Resolve the port the proxy actually launched on from the hook JSON. session-start
# emits {"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:<port>","ZLAUDER_PORT":"<port>"}};
# this is the derived per-project port, not a guess. Fall back to $ZLAUDER_PORT if
# parsing fails. jq is already a hard dependency (enable.sh/disable.sh).
real_port=""
if command -v jq >/dev/null 2>&1; then
  real_port="$(jq -r '.env.ZLAUDER_PORT // empty' "$HOOK_OUT" 2>/dev/null)"
fi
real_port="${real_port:-${ZLAUDER_PORT:-}}"

# Now that the proxy is up, warn if traffic isn't actually routed through it.
route_guard "$real_port"

exit 0
