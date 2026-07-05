#!/usr/bin/env bash
# Backs /zlauder:disable — turns ZlauDeR MASKING off (NOT routing; routing teardown is
# /zlauder:uninstall). Default: THIS conversation only (session-scoped, in-memory — it
# lifts on the next Claude Code restart). `--project`: the whole project's master switch.
# Registered secrets stay masked in both modes, and the data policy (categories / profile
# / threshold) is never touched. Re-enable with /zlauder:privacy on.
#
# Observer-style: never aborts hard (needs a *running* proxy), resolves binaries with
# --no-build (the SessionStart hook builds/launches the proxy; a control verb can't
# conjure one). `set -f` keeps the argument intact when we re-split it.
set -uo pipefail
set -f

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_resolve-bins.sh
. "$SCRIPT_DIR/_resolve-bins.sh"

if ! zlauder_resolve_bins --no-build; then
  echo "error: zlauder-hooks is not available for this project yet. Start a Claude Code session in this project, or put the binaries on PATH, then retry." >&2
  exit 1
fi

# The command passes the whole user argument string as ONE quoted positional; re-split it
# here under `set -f` so `--project` lands as its own arg (there is no token to protect
# here, but we mirror the other zlauder scripts for consistency).
# shellcheck disable=SC2086
set -- ${1:-}

# Target THIS project's proxy when the port is pinned (post-/zlauder:enable). `--port` is a
# global option, so it leads the subcommand. (The `disable` handler resolves the live proxy
# by project root regardless, so this is belt-and-suspenders.)
PORT_ARGS=()
[ -n "${ZLAUDER_PORT:-}" ] && PORT_ARGS=(--port "$ZLAUDER_PORT")

exec "$ZLAUDER_HOOKS_BIN" "${PORT_ARGS[@]}" disable "$@"
