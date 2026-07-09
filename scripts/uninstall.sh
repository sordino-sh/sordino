#!/usr/bin/env bash
# Backs /sordino:uninstall — REMOVES the Sordino plumbing (the inverse of enable.sh).
# Strips env.ANTHROPIC_BASE_URL (and env.SORDINO_PORT) from the project's
# .claude/settings.local.json (and any legacy committed .claude/settings.json) so Claude
# Code stops routing through the proxy, and undoes the status-line takeover: if enable.sh
# wrapped a pre-existing line, its original is RESTORED verbatim from
# .claude/sordino-statusline.json; if the slot was empty, our line is dropped. Our
# permissions.deny/ask rules and autoMode.environment note are removed too. Every other
# setting is preserved; the file is rewritten atomically. The seeded sordino.toml (your
# masking POLICY) is deliberately LEFT in place — uninstall removes the plumbing, not your
# config. Turning masking off (without removing anything) is /sordino:disable instead.
# No `set -e`: the binary's exit 3 (idempotent "already removed") is expected, not fatal.
set -uo pipefail

# Routing lives in settings.local.json (gitignored); older installs may have it in the
# committed settings.json. The binary strips both; the manual-fallback text below names both.
settings="${CLAUDE_PROJECT_DIR:-$PWD}/.claude/settings.local.json"

# Resolve the sordino-hooks binary like every other script, then hand the settings edit to
# it — no `jq` dependency (a hard blocker on Windows). --no-build: teardown must never
# trigger a heavyweight build. The binary validates JSON, deletes env.ANTHROPIC_BASE_URL/
# SORDINO_PORT (and an emptied env), removes our permissions/autoMode entries, restores the
# wrapped status line from the sidecar (or drops ours), writes atomically, removes the
# sidecar, and records this project as opted out so it won't auto-re-plumb.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_resolve-bins.sh
. "$SCRIPT_DIR/_resolve-bins.sh"
sordino_resolve_bins --no-build || true

if ! command -v "$SORDINO_HOOKS_BIN" >/dev/null 2>&1; then
  echo "error: sordino-hooks is not available, so $settings cannot be edited automatically." >&2
  echo "  Start a Claude Code session in this project (or put the binaries on PATH), then re-run /sordino:uninstall." >&2
  echo "  To remove routing by hand instead: in .claude/settings.local.json (and .claude/settings.json if present)," >&2
  echo "  delete env.ANTHROPIC_BASE_URL and env.SORDINO_PORT, and if statusLine.command runs 'sordino-hooks statusline'," >&2
  echo "  restore it from .claude/sordino-statusline.json (or delete it)." >&2
  exit 1
fi

# Exit code is a contract: 0 = removed wiring, 3 = already removed (no wiring / no file),
# non-zero = error (reason on stderr).
# `/sordino:uninstall --all` sweeps EVERY plumbed project (run this BEFORE removing the
# plugin so no project is left pointing at a dead proxy — a dead ANTHROPIC_BASE_URL makes
# Claude Code hang for minutes and then fail). Exits 0 on a full or empty sweep, non-zero if
# any project could not be cleaned (forwarded via `exit $?`) — so a scripted pre-removal can
# gate on success.
if [ "${1:-}" = "--all" ]; then
  "$SORDINO_HOOKS_BIN" settings disable --all
  exit $?
fi

"$SORDINO_HOOKS_BIN" settings disable
rc=$?

case "$rc" in
  0)
    echo "Removed Sordino routing from this project (.claude/settings.local.json; restored your original status line, if any)."
    echo "Restart Claude Code once to fully stop routing (it reads the route at startup; this session may keep routing through the proxy until then, which is harmless). This project is now opted out of auto-routing."
    echo "Your masking policy (sordino.toml) was left in place. To remove Sordino from EVERY project before deleting the plugin, run /sordino:uninstall --all."
    ;;
  3)
    echo "Sordino already removed: no Sordino wiring in this project."
    ;;
  *)
    exit "$rc"
    ;;
esac
