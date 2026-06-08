#!/usr/bin/env bash
# Inverse of enable.sh: remove env.ANTHROPIC_BASE_URL (and env.ZLAUDER_PORT) from the
# project's .claude/settings.json so Claude Code stops routing through the zlauder
# proxy, and undo the status-line takeover. If enable.sh wrapped a pre-existing line,
# its original was saved to .claude/zlauder-statusline.json — we RESTORE that verbatim;
# if the slot was empty, we just drop our line. Every other setting is preserved; the
# file is rewritten atomically. The seeded zlauder.toml is left in place (inert without
# routing).
set -euo pipefail

settings="${CLAUDE_PROJECT_DIR:-$PWD}/.claude/settings.json"
sidecar="${CLAUDE_PROJECT_DIR:-$PWD}/.claude/zlauder-statusline.json"

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required but not found on PATH" >&2
  exit 1
fi

if [[ ! -f "$settings" ]]; then
  echo "ZlauDeR already disabled: no $settings"
  exit 0
fi

# Trigger on ANY zlauder wiring — either routing env key OR our status line — so
# disable is a true inverse even in asymmetric state (e.g. a key left behind by a
# partial edit), not just when the env keys are present.
if ! jq -e '
  ((.env? // {}) | (has("ANTHROPIC_BASE_URL") or has("ZLAUDER_PORT")))
  or (((.statusLine?.command) // "") | test("zlauder-hooks(\\.exe)? statusline"))
' "$settings" >/dev/null 2>&1; then
  echo "ZlauDeR already disabled: no ZlauDeR wiring in $settings"
  exit 0
fi

# Load the saved original status line (if enable.sh wrapped one). `null` means there
# was nothing to restore, so we just delete our line. We only act on the statusLine if
# it's currently OURS — a line the user set by hand after enabling is left alone.
restore="null"
if [[ -f "$sidecar" ]] && orig="$(cat "$sidecar")" && jq -e . <<<"$orig" >/dev/null 2>&1; then
  restore="$orig"
fi

# Delete the keys enable.sh added (and the env object if it ends up empty), and undo the
# status-line takeover: restore the saved original, or drop our line if there was none.
tmp="$(mktemp "${settings}.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
jq --argjson restore "$restore" '
  del(.env.ANTHROPIC_BASE_URL)
  | del(.env.ZLAUDER_PORT)
  | if (.env | type) == "object" and (.env | length) == 0 then del(.env) else . end
  | if (((.statusLine?.command) // "") | test("zlauder-hooks(\\.exe)? statusline"))
    then (if $restore == null then del(.statusLine) else .statusLine = $restore end)
    else . end
' "$settings" >"$tmp"
mv -f "$tmp" "$settings"
trap - EXIT
rm -f "$sidecar"

echo "Removed the ZlauDeR routing env from $settings (restored your original status line, if any)."
echo "ZlauDeR is now disabled. Restart Claude Code for this to take effect."
