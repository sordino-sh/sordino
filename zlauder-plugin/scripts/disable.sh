#!/usr/bin/env bash
# Inverse of enable.sh: remove env.ANTHROPIC_BASE_URL (and env.ZLAUDER_PORT) from the
# project's .claude/settings.local.json (and any legacy committed .claude/settings.json)
# so Claude Code stops routing through the zlauder proxy, and undo the status-line takeover. If enable.sh wrapped a pre-existing line,
# its original was saved to .claude/zlauder-statusline.json — we RESTORE that verbatim;
# if the slot was empty, we just drop our line. Every other setting is preserved; the
# file is rewritten atomically. The seeded zlauder.toml is left in place (inert without
# routing).
# No `set -e`: the binary's exit 3 (idempotent "already disabled") is expected, not fatal.
set -uo pipefail

# Routing is written to settings.local.json (gitignored); older installs may have it in the
# committed settings.json. The binary strips both; the manual-fallback text below names both.
settings="${CLAUDE_PROJECT_DIR:-$PWD}/.claude/settings.local.json"

# Resolve the zlauder-hooks binary the same way every other script does, then hand the
# settings.local.json edit to it — no `jq` dependency (a hard blocker on Windows). --no-build:
# teardown should never trigger a heavyweight build. The binary validates JSON, deletes
# env.ANTHROPIC_BASE_URL/ZLAUDER_PORT (and an emptied env), restores the wrapped status
# line from the sidecar (or drops ours), writes atomically, and removes the sidecar.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_resolve-bins.sh
. "$SCRIPT_DIR/_resolve-bins.sh"
zlauder_resolve_bins --no-build || true

if ! command -v "$ZLAUDER_HOOKS_BIN" >/dev/null 2>&1; then
  echo "error: zlauder-hooks is not available, so $settings cannot be edited automatically." >&2
  echo "  Start a Claude Code session in this project (or put the binaries on PATH), then re-run /zlauder:disable." >&2
  echo "  To remove routing by hand instead: in .claude/settings.local.json (and .claude/settings.json if present)," >&2
  echo "  delete env.ANTHROPIC_BASE_URL and env.ZLAUDER_PORT, and if statusLine.command runs 'zlauder-hooks statusline'," >&2
  echo "  restore it from .claude/zlauder-statusline.json (or delete it)." >&2
  exit 1
fi

# Exit code is a contract: 0 = removed wiring, 3 = already disabled (no wiring / no file),
# non-zero = error (reason on stderr).
# `/zlauder:disable --all` sweeps EVERY plumbed project (run this BEFORE uninstalling the
# plugin so no project is left pointing at a dead proxy). Exits 0 on a full or empty sweep,
# non-zero if any project could not be cleaned (forwarded via `exit $?` below) — so a scripted
# pre-uninstall can gate on success.
if [ "${1:-}" = "--all" ]; then
  "$ZLAUDER_HOOKS_BIN" settings disable --all
  exit $?
fi

"$ZLAUDER_HOOKS_BIN" settings disable
rc=$?

case "$rc" in
  0)
    echo "Removed ZlauDeR routing from this project (.claude/settings.local.json; restored your original status line, if any)."
    echo "ZlauDeR routing removed — restart Claude Code once to fully stop routing (it reads the route at startup; this session may keep routing through the proxy until then, which is harmless). This project is now opted out of auto-routing."
    ;;
  3)
    echo "ZlauDeR already disabled: no ZlauDeR wiring in this project."
    ;;
  *)
    exit "$rc"
    ;;
esac
