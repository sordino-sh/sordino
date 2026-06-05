#!/usr/bin/env bash
# Inverse of enable.sh: remove env.ANTHROPIC_BASE_URL (and env.ZLAUDER_PORT) from the
# project's .claude/settings.json so Claude Code stops routing through the zlauder
# proxy, and remove the zlauder status line it added. A *custom* statusLine and every
# other setting are preserved; the file is rewritten atomically. The seeded
# zlauder.toml is left in place (it is inert without routing).
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

# Trigger on ANY zlauder wiring — either routing env key OR our status line — so
# disable is a true inverse even in asymmetric state (e.g. a key left behind by a
# partial edit), not just when the env keys are present.
if ! jq -e '
  ((.env? // {}) | (has("ANTHROPIC_BASE_URL") or has("ZLAUDER_PORT")))
  or (((.statusLine?.command) // "") | test("zlauder-hooks statusline"))
' "$settings" >/dev/null 2>&1; then
  echo "zlauder already disabled: no zlauder wiring in $settings"
  exit 0
fi

# Delete the keys enable.sh added (and the env object if it ends up empty), plus the
# zlauder status line — but only if statusLine is OURS (a custom one is left alone).
tmp="$(mktemp "${settings}.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
jq '
  del(.env.ANTHROPIC_BASE_URL)
  | del(.env.ZLAUDER_PORT)
  | if (.env | type) == "object" and (.env | length) == 0 then del(.env) else . end
  | if (((.statusLine?.command) // "") | test("zlauder-hooks statusline")) then del(.statusLine) else . end
' "$settings" >"$tmp"
mv -f "$tmp" "$settings"
trap - EXIT

echo "Removed the zlauder routing env (and status line, if it was ours) from $settings."
echo "zlauder is now disabled. Restart Claude Code for this to take effect."
