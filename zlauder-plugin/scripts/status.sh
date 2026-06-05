#!/usr/bin/env bash
# Prints zlauder proxy health + whether this project's traffic is routed through it.
# Informational only — never aborts (no `set -e`); --no-build so a status check
# never triggers a heavyweight cargo build.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_resolve-bins.sh
. "$SCRIPT_DIR/_resolve-bins.sh"
zlauder_resolve_bins --no-build || true

echo "Proxy health:"
if command -v zlauder-hooks >/dev/null 2>&1; then
  if [ -n "${ZLAUDER_PORT:-}" ]; then
    zlauder-hooks statusline --port "$ZLAUDER_PORT" || true
  else
    zlauder-hooks statusline || true
  fi
else
  echo "⚠ zlauder-hooks not available (not built/installed for this project yet)"
fi

echo
echo "Routing (ANTHROPIC_BASE_URL in this project's .claude/settings.json):"
settings="${CLAUDE_PROJECT_DIR:-.}/.claude/settings.json"
if [ -f "$settings" ] && command -v jq >/dev/null 2>&1; then
  jq -r '.env.ANTHROPIC_BASE_URL // "(unset)"' "$settings" 2>/dev/null || echo "(unset)"
else
  echo "(no .claude/settings.json)"
fi
