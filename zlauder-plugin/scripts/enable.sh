#!/usr/bin/env bash
set -euo pipefail

# Patch the project's .claude/settings.json so Claude Code routes every request
# through the zlauder proxy by setting env.ANTHROPIC_BASE_URL (and env.ZLAUDER_PORT).
# A plugin cannot set `env` itself, so this is the one piece of wiring the user runs
# explicitly. Idempotent: re-running is a no-op once the value is already present.

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required but not found on PATH. Install jq and re-run /zlauder:enable." >&2
  exit 1
fi

# Resolve the proxy port. The live per-project proxy listens on a port DERIVED from
# the project root (range 18000..20000), NOT the static 8787 config default. The
# authoritative source is zlauder-hooks: `session-start` ensures the proxy is up and
# emits the resolved port in its hook JSON's env block. We parse that, never guess.
#
# Share the SessionStart resolver so the binaries are found the SAME way (PATH ->
# plugin bin/ -> data bin/ -> build) and their dir is exported onto PATH — otherwise
# a session-start that needs to spawn the proxy can't find a non-PATH `zlauder-proxy`.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_resolve-bins.sh
. "$SCRIPT_DIR/_resolve-bins.sh"

port=""
if [ -n "${ZLAUDER_PORT:-}" ]; then
  # User pinned an explicit port; honor it.
  port="$ZLAUDER_PORT"
elif zlauder_resolve_bins; then
  # Ask zlauder-hooks for the real (derived) port. session-start launches the proxy
  # if needed and prints the hook JSON with env.ZLAUDER_PORT = the resolved port.
  hook_json="$(zlauder-hooks session-start 2>/dev/null < /dev/null || true)"
  port="$(printf '%s' "$hook_json" | jq -r '.env.ZLAUDER_PORT // empty' 2>/dev/null || true)"
fi

if [ -z "$port" ]; then
  echo "error: could not resolve the zlauder proxy port. Ensure the zlauder binaries are available (on PATH, shipped in the plugin's bin/, or buildable from the cargo workspace), or set \$ZLAUDER_PORT explicitly, then re-run /zlauder:enable." >&2
  exit 1
fi

base_url="http://127.0.0.1:${port}"

project_dir="${CLAUDE_PROJECT_DIR:-$PWD}"
settings_dir="${project_dir}/.claude"
settings_file="${settings_dir}/settings.json"

mkdir -p "$settings_dir"

if [[ ! -f "$settings_file" ]]; then
  printf '{}\n' >"$settings_file"
fi

if ! jq -e . "$settings_file" >/dev/null 2>&1; then
  echo "error: ${settings_file} is not valid JSON; refusing to overwrite. Fix it and re-run." >&2
  exit 1
fi

current="$(jq -r '.env.ANTHROPIC_BASE_URL // empty' "$settings_file")"
current_port="$(jq -r '.env.ZLAUDER_PORT // empty' "$settings_file")"

tmp="$(mktemp "${settings_dir}/.settings.json.XXXXXX")"
trap 'rm -f "$tmp"' EXIT

jq --arg url "$base_url" --arg port "$port" '
    setpath(["env","ANTHROPIC_BASE_URL"]; $url)
  | setpath(["env","ZLAUDER_PORT"]; $port)
' "$settings_file" >"$tmp"
mv -f "$tmp" "$settings_file"
trap - EXIT

echo "zlauder: set ANTHROPIC_BASE_URL=${base_url} and ZLAUDER_PORT=${port} in ${settings_file}"

if [[ "$current" == "$base_url" && "$current_port" == "$port" ]]; then
  echo "zlauder: already pointed at the proxy; nothing changed."
  exit 0
fi

cat >&2 <<'EOF'

================================================================================
  RESTART CLAUDE CODE NOW.

  ANTHROPIC_BASE_URL is read once at process startup. Your current session is
  still talking to the API directly and is NOT being masked. Fully quit and
  relaunch Claude Code for this project so the proxy takes effect.
================================================================================
EOF
