#!/usr/bin/env bash
set -euo pipefail

# Per-project setup for the zlauder masking proxy. This is the ONE piece of wiring
# the user runs explicitly, because a Claude Code plugin cannot set `env` or the main
# `statusLine` itself (only `agent`/`subagentStatusLine` are honored from a plugin's
# settings.json, and there is no install-time hook). So `/zlauder:enable` patches the
# *project's* .claude/settings.json directly:
#   - env.ANTHROPIC_BASE_URL  (load-bearing: routes Claude Code through the proxy)
#   - env.ZLAUDER_PORT        (so the CLI/status line target this project's proxy)
#   - statusLine              (the 🛡 masking indicator; set only if absent)
# and seeds a starter ./zlauder.toml if the project has none. Idempotent: re-running
# is a no-op once the values are already present.

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required but not found on PATH. Install jq and re-run /zlauder:enable." >&2
  exit 1
fi

# Share the SessionStart resolver so the binaries are found the SAME way (PATH ->
# plugin bin/ -> data bin/ -> build) and their dir is exported onto PATH — otherwise
# a session-start that needs to spawn the proxy can't find a non-PATH `zlauder-proxy`.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_resolve-bins.sh
. "$SCRIPT_DIR/_resolve-bins.sh"

# Resolve (and, on first run, build) the binaries up front. This sets ZLAUDER_BIN_DIR
# and prepends it to PATH, which we need for BOTH the port query below and the
# absolute status-line command we bake into settings.json (the status line is
# evaluated in the user's bare shell, which won't have the plugin data dir on PATH).
bins_ok=0
if zlauder_resolve_bins; then bins_ok=1; fi

# Resolve the proxy port. The live per-project proxy listens on a port DERIVED from
# the project root (range 18000..20000), NOT a static default. The authoritative
# source is zlauder-hooks: `session-start` ensures the proxy is up (atomically
# reserving the derived port on first launch) and emits the resolved port in its hook
# JSON's env block. We parse that, never guess.
port=""
if [ -n "${ZLAUDER_PORT:-}" ]; then
  # User pinned an explicit port; honor it.
  port="$ZLAUDER_PORT"
elif [ "$bins_ok" -eq 1 ]; then
  hook_json="$(zlauder-hooks session-start 2>/dev/null < /dev/null || true)"
  port="$(printf '%s' "$hook_json" | jq -r '.env.ZLAUDER_PORT // empty' 2>/dev/null || true)"
fi

if [ -z "$port" ]; then
  echo "error: could not resolve the zlauder proxy port. Ensure the zlauder binaries are available (on PATH, shipped in the plugin's bin/, or buildable from the cargo workspace), or set \$ZLAUDER_PORT explicitly, then re-run /zlauder:enable." >&2
  exit 1
fi

base_url="http://127.0.0.1:${port}"

# Status-line command. Prefer an absolute path to the resolved binary so it works even
# when zlauder-hooks lives in the plugin data dir (off the user's PATH); fall back to
# a bare name when the binary is already on PATH. We set it only if absent (below), so
# a stale path is refreshed by re-running /zlauder:enable; /zlauder:disable removes it.
if [ -n "${ZLAUDER_BIN_DIR:-}" ]; then
  statusline_cmd="${ZLAUDER_BIN_DIR}/zlauder-hooks statusline"
else
  statusline_cmd="zlauder-hooks statusline"
fi

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

# Set the routing env (always) and the status line (only if absent — don't clobber a
# custom one the user already configured).
jq --arg url "$base_url" --arg port "$port" --arg sl "$statusline_cmd" '
    setpath(["env","ANTHROPIC_BASE_URL"]; $url)
  | setpath(["env","ZLAUDER_PORT"]; $port)
  | if (.statusLine == null)
    then setpath(["statusLine"]; {"type": "command", "command": $sl})
    else . end
' "$settings_file" >"$tmp"
mv -f "$tmp" "$settings_file"
trap - EXIT

echo "zlauder: set ANTHROPIC_BASE_URL=${base_url} and ZLAUDER_PORT=${port} in ${settings_file}"

# Seed a starter zlauder.toml (commented, tunable) if the project has none. Copy the
# bundled template; never clobber a config the user has tuned. Persistent settings are
# edited via `/zlauder:privacy ... --scope project`, which writes this same file.
proj_cfg="${project_dir}/zlauder.toml"
tmpl="${CLAUDE_PLUGIN_ROOT:-}/zlauder.toml"
if [ ! -f "$proj_cfg" ] && [ -n "${CLAUDE_PLUGIN_ROOT:-}" ] && [ -f "$tmpl" ]; then
  if cp "$tmpl" "$proj_cfg" 2>/dev/null; then
    echo "zlauder: seeded ${proj_cfg} from the bundled template."
  fi
fi

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
