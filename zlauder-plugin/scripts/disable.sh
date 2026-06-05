#!/usr/bin/env bash
# Inverse of enable.sh: remove env.ANTHROPIC_BASE_URL (and env.ZLAUDER_PORT) from
# the project's .claude/settings.json so Claude Code stops routing through the
# zlauder proxy. Every other setting is preserved; the file is rewritten atomically.
set -euo pipefail

settings="${CLAUDE_PROJECT_DIR:-$PWD}/.claude/settings.json"

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required but not found on PATH" >&2
  exit 1
fi

if [[ ! -f "$settings" ]]; then
  echo "zlauder already disabled: no $settings"
  exit 0
fi

# Trigger on EITHER key so disable is a true inverse even in asymmetric state
# (e.g. ZLAUDER_PORT left behind by a partial edit) — not just when both are set.
if ! jq -e '(.env? // {}) | (has("ANTHROPIC_BASE_URL") or has("ZLAUDER_PORT"))' "$settings" >/dev/null 2>&1; then
  echo "zlauder already disabled: no ANTHROPIC_BASE_URL/ZLAUDER_PORT in $settings"
  exit 0
fi

# Delete the keys enable.sh added, then drop the env object if it ended up empty.
tmp="$(mktemp "${settings}.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
jq '
  del(.env.ANTHROPIC_BASE_URL)
  | del(.env.ZLAUDER_PORT)
  | if (.env | type) == "object" and (.env | length) == 0 then del(.env) else . end
' "$settings" >"$tmp"
mv -f "$tmp" "$settings"
trap - EXIT

echo "Removed ANTHROPIC_BASE_URL and ZLAUDER_PORT from $settings."
echo "zlauder is now disabled. Restart Claude Code for this to take effect."
