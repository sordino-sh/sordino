#!/usr/bin/env bash
# Legacy backing for /sordino:disable, now superseded by /sordino:mask off (which routes through
# scripts/mask.sh -> `sordino-hooks disable`). Turns Sordino MASKING off (NOT routing; routing
# teardown is /sordino:uninstall). Default: THIS conversation only — a BOUNDED off that auto-re-arms
# to ON in ~30 min unless extended, and stays off until then or until you re-enable; a Claude Code
# restart does not change that (the proxy daemon outlives it). `--project`: the whole project's
# master switch (shared with any Codex sibling). Registered secrets stay masked while traffic
# transits the proxy in both modes, and the data policy (categories / profile / threshold) is never
# touched. Re-enable with /sordino:mask on.
#
# Observer-style: never aborts hard (needs a *running* proxy), resolves binaries with
# --no-build (the SessionStart hook builds/launches the proxy; a control verb can't
# conjure one). `set -f` keeps the argument intact when we re-split it.
set -uo pipefail
set -f

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_resolve-bins.sh
. "$SCRIPT_DIR/_resolve-bins.sh"

if ! sordino_resolve_bins --no-build; then
  echo "error: sordino-hooks is not available for this project yet. Start a Claude Code session in this project, or put the binaries on PATH, then retry." >&2
  exit 1
fi

# The command passes the whole user argument string as ONE quoted positional; re-split it
# here under `set -f` so `--project` lands as its own arg (there is no token to protect
# here, but we mirror the other sordino scripts for consistency).
# shellcheck disable=SC2086
set -- ${1:-}

# Target THIS project's proxy when the port is pinned (post-/sordino:enable). `--port` is a
# global option, so it leads the subcommand. (The `disable` handler resolves the live proxy
# by project root regardless, so this is belt-and-suspenders.)
PORT_ARGS=()
[ -n "${SORDINO_PORT:-}" ] && PORT_ARGS=(--port "$SORDINO_PORT")

exec "$SORDINO_HOOKS_BIN" "${PORT_ARGS[@]}" disable "$@"
