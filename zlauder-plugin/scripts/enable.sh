#!/usr/bin/env bash
set -euo pipefail

# Per-project setup for the zlauder masking proxy. This is the ONE piece of wiring
# the user runs explicitly, because a Claude Code plugin cannot set `env` or the main
# `statusLine` itself (only `agent`/`subagentStatusLine` are honored from a plugin's
# settings.json, and there is no install-time hook). So `/zlauder:enable` patches the
# *project's* .claude/settings.json directly:
#   - env.ANTHROPIC_BASE_URL  (load-bearing: routes Claude Code through the proxy)
#   - env.ZLAUDER_PORT        (so the CLI/status line target this project's proxy)
#   - statusLine              (the 🛡 masking indicator; SEAMLESSLY WRAPS an existing
#                              line — see below — instead of refusing to install)
# and seeds a practical starter ./zlauder.toml if the project has none.
#
# Status-line wrapping: a Claude Code project has exactly one `statusLine` slot, so to
# show the masking state alongside a user's existing line we take over the slot and
# prepend our segment. Before doing so we save the user's original `statusLine` object
# verbatim to `.claude/zlauder-statusline.json`; at render time `zlauder-hooks
# statusline` runs that original (forwarding stdin) and prints `🛡 … │ {their line}`,
# and `/zlauder:disable` restores it from the sidecar. If the slot was empty, our
# segment stands alone. Set `env.ZLAUDER_STATUSLINE=off` to hide our segment (the
# wrapped line still shows); `min`/`verbose` change how much it shows.
# Idempotent: re-running is a no-op once the values are already present.

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
# source is zlauder-hooks `reserve-port`, which atomically reserves the derived port
# and prints it — WITHOUT launching the proxy or emitting SessionStart JSON (that hook
# is gated on the session already being routed, which a first-time enable is not). We
# parse that, never guess.
port=""
if [ -n "${ZLAUDER_PORT:-}" ]; then
  # User pinned an explicit port; honor it.
  port="$ZLAUDER_PORT"
elif [ "$bins_ok" -eq 1 ]; then
  port="$("$ZLAUDER_HOOKS_BIN" reserve-port 2>/dev/null < /dev/null || true)"
fi

if [ -z "$port" ]; then
  echo "error: could not resolve the ZlauDeR proxy port. Ensure the zlauder binaries are available (on PATH, shipped in the plugin's bin/, or buildable from the cargo workspace), or set \$ZLAUDER_PORT explicitly, then re-run /zlauder:enable." >&2
  exit 1
fi

base_url="http://127.0.0.1:${port}"

# Status-line command. Prefer an absolute path to the resolved binary so it works even
# when zlauder-hooks lives in the plugin data dir (off the user's PATH); fall back to
# a bare name when the binary is already on PATH. We always own the slot (wrapping any
# existing line — see below); re-running /zlauder:enable refreshes a stale path, and
# /zlauder:disable restores the user's original line from the sidecar.
if [ -n "${ZLAUDER_BIN_DIR:-}" ]; then
  statusline_cmd="${ZLAUDER_BIN_DIR}/${ZLAUDER_HOOKS_BIN} statusline"
else
  statusline_cmd="${ZLAUDER_HOOKS_BIN} statusline"
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

# Preserve the user's existing status line so we can wrap (not clobber) it. If the
# current statusLine isn't already ours, snapshot it to the sidecar that the wrapper
# reads and that /zlauder:disable restores from. We skip this when it's already ours so
# re-running /zlauder:enable can't overwrite the true original with our own wrapper
# (which would lose their line and risk a self-referential status line).
sidecar="${settings_dir}/zlauder-statusline.json"
is_ours="$(jq -r '((.statusLine?.command) // "") | test("zlauder-hooks(\\.exe)? statusline")' "$settings_file")"
if [ "$is_ours" != "true" ]; then
  orig="$(jq -c '.statusLine // null' "$settings_file")"
  if [ "$orig" != "null" ]; then
    printf '%s\n' "$orig" >"$sidecar"
    echo "ZlauDeR: wrapping your existing status line (saved to ${sidecar}; restored on /zlauder:disable)."
  else
    # No prior line to wrap: ensure no stale sidecar lingers from an earlier setup.
    rm -f "$sidecar"
  fi
fi

tmp="$(mktemp "${settings_dir}/.settings.json.XXXXXX")"
trap 'rm -f "$tmp"' EXIT

# Set the routing env (always) and take over the status-line slot (always). The wrapper
# prepends our segment to the saved original line; an empty slot just shows our segment.
jq --arg url "$base_url" --arg port "$port" --arg sl "$statusline_cmd" '
    setpath(["env","ANTHROPIC_BASE_URL"]; $url)
  | setpath(["env","ZLAUDER_PORT"]; $port)
  | setpath(["statusLine"]; {"type": "command", "command": $sl})
' "$settings_file" >"$tmp"
mv -f "$tmp" "$settings_file"
trap - EXIT

echo "ZlauDeR: set ANTHROPIC_BASE_URL=${base_url} and ZLAUDER_PORT=${port} in ${settings_file}"

# Seed a practical starter zlauder.toml if the project has none. Copy the bundled
# default; never clobber a config the user has tuned. The exhaustive reference ships
# as zlauder.toml.example. Persistent settings are edited via
# `/zlauder:privacy ... --scope project`, which writes this same file.
proj_cfg="${project_dir}/zlauder.toml"
tmpl="${CLAUDE_PLUGIN_ROOT:-}/zlauder.toml"
if [ ! -f "$proj_cfg" ] && [ -n "${CLAUDE_PLUGIN_ROOT:-}" ] && [ -f "$tmpl" ]; then
  if cp "$tmpl" "$proj_cfg" 2>/dev/null; then
    echo "ZlauDeR: seeded ${proj_cfg} from the bundled default."
  fi
fi

if [[ "$current" == "$base_url" && "$current_port" == "$port" ]]; then
  echo "ZlauDeR: already pointed at the proxy; nothing changed."
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
