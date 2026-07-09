#!/usr/bin/env bash
set -euo pipefail

# Per-project setup for the sordino masking proxy. Routing is normally AUTO-PLUMBED by the
# SessionStart hook on first sight; this script is the EXPLICIT path (`/sordino:enable`),
# needed because a Claude Code plugin cannot set `env` or the main `statusLine` itself (only
# `agent`/`subagentStatusLine` are honored from a plugin's settings.json, and there is no
# install-time hook). So `/sordino:enable` patches the *project's*
# .claude/settings.local.json (gitignored) directly:
#   - env.ANTHROPIC_BASE_URL  (load-bearing: routes Claude Code through the proxy)
#   - env.SORDINO_PORT        (so the CLI/status line target this project's proxy)
#   - statusLine              (the 🛡 masking indicator; SEAMLESSLY WRAPS an existing
#                              line — see below — instead of refusing to install)
# and seeds a practical starter ./sordino.toml if the project has none.
#
# Status-line wrapping: a Claude Code project has exactly one `statusLine` slot, so to
# show the masking state alongside a user's existing line we take over the slot and
# prepend our segment. Before doing so we save the user's original `statusLine` object
# verbatim to `.claude/sordino-statusline.json`; at render time `sordino-hooks
# statusline` runs that original (forwarding stdin) and prints `🛡 … │ {their line}`,
# and `/sordino:uninstall` restores it from the sidecar. If the slot was empty, our
# segment stands alone. Set `env.SORDINO_STATUSLINE=off` to hide our segment (the
# wrapped line still shows); `shield` shows the 🛡 ONLY when masking is confirmed and
# nothing in any other state; `min`/`verbose` change how much it shows.
# Idempotent: re-running is a no-op once the values are already present.

# Share the SessionStart resolver so the binaries are found the SAME way (PATH ->
# plugin bin/ -> data bin/ -> build) and their dir is exported onto PATH — otherwise
# a session-start that needs to spawn the proxy can't find a non-PATH `sordino-proxy`.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_resolve-bins.sh
. "$SCRIPT_DIR/_resolve-bins.sh"

# Resolve (and, on first run, build) the binaries up front. This sets SORDINO_BIN_DIR
# and prepends it to PATH, which we need for BOTH the port query below and the
# absolute status-line command we bake into settings.local.json (the status line is
# evaluated in the user's bare shell, which won't have the plugin data dir on PATH).
bins_ok=0
if sordino_resolve_bins; then bins_ok=1; fi

# Resolve the proxy port. By default the per-project proxy binds an OS-assigned EPHEMERAL
# port (127.0.0.1:0; or a static `[proxy] port` if pinned). The port isn't derivable, so the
# authoritative source is sordino-hooks `reserve-port`, which LAUNCHES the proxy (so we learn
# the port it actually bound, and it's already running for the next session) and prints that
# bound port. We parse it, never guess.
port=""
if [ "$bins_ok" -eq 1 ]; then
  # Compute the authoritative port with SORDINO_PORT UNSET for this one call: reserve-port
  # honors SORDINO_PORT via its global --port, so an ambient/global value would otherwise
  # pin that exact port and get baked verbatim. Unsetting it forces the real per-project
  # ephemeral bind.
  port="$(env -u SORDINO_PORT "$SORDINO_HOOKS_BIN" reserve-port 2>/dev/null < /dev/null || true)"
fi
# Never bake a stale/global/foreign SORDINO_PORT into this project's routing: that would pin
# the project to ANOTHER project's (or a dead) port. Use the freshly-bound port; honor an
# explicit SORDINO_PORT only as a fallback when reserve-port couldn't run, and warn when a set
# value disagrees. (A routed re-enable has SORDINO_PORT == the live port, so this is a no-op in
# the common case.)
if [ -n "$port" ]; then
  if [ -n "${SORDINO_PORT:-}" ] && [ "$SORDINO_PORT" != "$port" ]; then
    echo "Sordino: ignoring SORDINO_PORT=${SORDINO_PORT}; using this project's freshly-bound proxy port ${port} (a stale or global SORDINO_PORT must not pin a project to a foreign/dead port)." >&2
  fi
elif [ -n "${SORDINO_PORT:-}" ]; then
  port="$SORDINO_PORT"
fi

if [ -z "$port" ]; then
  echo "error: could not resolve the Sordino proxy port. Ensure the sordino binaries are available (on PATH, shipped in the plugin's bin/, or buildable from the cargo workspace), or set \$SORDINO_PORT explicitly, then re-run /sordino:enable." >&2
  exit 1
fi

base_url="http://127.0.0.1:${port}"

# Status-line command. Prefer an absolute path to the resolved binary so it works even
# when sordino-hooks lives in the plugin data dir (off the user's PATH); fall back to
# a bare name when the binary is already on PATH. We always own the slot (wrapping any
# existing line — see below); re-running /sordino:enable refreshes a stale path, and
# /sordino:uninstall restores the user's original line from the sidecar.
if [ -n "${SORDINO_BIN_DIR:-}" ]; then
  # Single-quote ONLY the directory so an install path with spaces survives Claude
  # Code's shell splitting it into argv. The binary name stays outside the quotes so
  # `sordino-hooks statusline` remains contiguous for the ownership regex in this
  # script and uninstall.sh ("sordino-hooks(\.exe)? statusline").
  statusline_cmd="'${SORDINO_BIN_DIR}'/${SORDINO_HOOKS_BIN} statusline"
else
  statusline_cmd="${SORDINO_HOOKS_BIN} statusline"
fi

project_dir="${CLAUDE_PROJECT_DIR:-$PWD}"
# Routing is written to settings.local.json (gitignored), not the committed settings.json,
# so a machine-specific http://127.0.0.1:<port> never lands in version control.
settings_file="${project_dir}/.claude/settings.local.json"

# Patch .claude/settings.local.json via sordino-hooks — no `jq` dependency (a hard blocker on
# Windows). The binary creates the dir/file as needed, ensures a .claude/.gitignore so the
# local route is never committed, validates JSON, wraps any existing status line into the
# sidecar, sets env.ANTHROPIC_BASE_URL + env.SORDINO_PORT + statusLine, and writes atomically. Exit code is a contract: 0 = changed, 3 = already pointed at this
# proxy (idempotent), non-zero = error (it printed the reason to stderr). Guard `set -e`
# so the deliberate 3 doesn't abort us. Needs the binary resolved up front (bins_ok).
if [ "$bins_ok" -ne 1 ]; then
  echo "error: sordino-hooks is unavailable, so ${settings_file} cannot be patched. Ensure the sordino binaries are available (on PATH, shipped in the plugin's bin/, or buildable from the cargo workspace), then re-run /sordino:enable." >&2
  exit 1
fi

set +e
"$SORDINO_HOOKS_BIN" settings enable \
  --url "$base_url" --zport "$port" --statusline "$statusline_cmd"
rc=$?
set -e

if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then
  exit "$rc" # hard error; sordino-hooks already explained on stderr
fi

echo "Sordino: set ANTHROPIC_BASE_URL=${base_url} and SORDINO_PORT=${port} in ${settings_file}"

# Seed a practical starter sordino.toml if the project has none. Copy the bundled
# default; never clobber a config the user has tuned. The exhaustive reference ships
# as sordino.toml.example. Persistent settings are edited via
# `/sordino:privacy ... --scope project`, which writes this same file.
proj_cfg="${project_dir}/sordino.toml"
tmpl="${CLAUDE_PLUGIN_ROOT:-}/sordino.toml"
if [ ! -f "$proj_cfg" ] && [ -n "${CLAUDE_PLUGIN_ROOT:-}" ] && [ -f "$tmpl" ]; then
  if cp "$tmpl" "$proj_cfg" 2>/dev/null; then
    echo "Sordino: seeded ${proj_cfg} from the bundled default."
  fi
fi

if [ "$rc" -eq 3 ]; then
  echo "Sordino: already pointed at the proxy; nothing changed."
  echo "Sordino: masking is PROJECT-SCOPED (this project only). Watch it live with /sordino:monitor." >&2
  exit 0
fi

cat >&2 <<'EOF'

================================================================================
  RESTART Claude Code once to activate masking.

  The route is written to .claude/settings.local.json and the proxy is already
  running, but Claude Code applies a route written mid-session only unreliably —
  every session AFTER a restart reads it at startup, which always works. The
  statusline shows "\u21bb Sordino: restart to mask" until it's live, then the shield.

  This is PROJECT-SCOPED: masking applies only to this project (the routing lives
  in this project's .claude/settings.local.json). Other projects are untouched
  until you run /sordino:enable in each.

  Watch live masking activity with /sordino:monitor (opens a local web view of
  what's being masked for this project). Turn masking off anytime with
  /sordino:disable (this conversation, or --project); remove routing with
  /sordino:uninstall.
================================================================================
EOF
