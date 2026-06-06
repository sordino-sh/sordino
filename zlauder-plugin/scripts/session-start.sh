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

# Resolve (and, on first run, build) the binaries; this also prepends their dir
# to PATH so the bare `zlauder-hooks` calls below and session-start's default
# --proxy-bin "zlauder-proxy" both resolve.
if ! zlauder_resolve_bins; then
  warn "ZlauDeR: proxy not started this session."
  exit 1
fi

CFG="$(config_path)"

# Hand off to the real control plane and emit its hook JSON byte-for-byte. zlauder-hooks
# owns the routing decision now: it checks whether THIS session's ANTHROPIC_BASE_URL is
# actually pointed at the proxy and, only then, launches/recycles it and announces that
# masking is active — otherwise it stays a silent no-op (and nudges, on stderr, if the
# project is configured but awaiting a restart). Single source of truth, no shell guard.
set +e
if [ -n "$CFG" ]; then
  zlauder-hooks "${PORT_ARGS[@]}" session-start --config "$CFG"
else
  zlauder-hooks "${PORT_ARGS[@]}" session-start
fi
rc=$?
set -e

if [ "$rc" -ne 0 ]; then
  warn "ZlauDeR: zlauder-hooks session-start exited $rc."
  exit "$rc"
fi

exit 0
