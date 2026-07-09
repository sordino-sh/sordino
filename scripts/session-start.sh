#!/usr/bin/env bash
# sordino SessionStart hook (plugin entry point).
#
# Resolves the sordino-proxy/sordino-hooks binaries, then hands off to the real
# control plane `sordino-hooks session-start`, which ensures this project's proxy
# is running and prints the SessionStart hook JSON Claude Code consumes.
#
# stdout MUST stay valid hook JSON: it is passed through from sordino-hooks
# UNCHANGED. All diagnostics go to stderr.
#
# The one thing this plugin cannot do is set ANTHROPIC_BASE_URL directly (Claude
# Code only honors "agent"/"subagentStatusLine" from a plugin settings.json). So
# `sordino-hooks session-start` AUTO-ENABLES a never-seen project by writing the
# route into .claude/settings.local.json (gitignored) and launching the proxy; Claude
# Code applies a route written mid-session only unreliably, so masking activates
# reliably after a ONE-TIME RESTART (every session after reads it at startup). The hook
# gates every side effect on whether THIS session is actually routed through the proxy
# (it never announces masking for a session that isn't).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_resolve-bins.sh
. "$SCRIPT_DIR/_resolve-bins.sh"

# Pass --port ONLY when $SORDINO_PORT is set (the per-project EPHEMERAL port baked into
# settings.local.json, which Claude Code exports into this session's env). The hook uses it
# as the session's ROUTED port for the route gate — NOT a bind directive: the proxy binds an
# OS-assigned ephemeral port (or a static [proxy] port) and ignores an inherited SORDINO_PORT.
# When unset (a never-routed first session), the hook resolves the proxy from the project-keyed
# rendezvous.
PORT_ARGS=()
if [ -n "${SORDINO_PORT:-}" ]; then
  PORT_ARGS=(--port "$SORDINO_PORT")
fi
PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-}"

warn() { printf '%s\n' "$*" >&2; }

# Resolve the config: project sordino.toml if present, else the bundled default.
config_path() {
  local proj="${CLAUDE_PROJECT_DIR:-}"
  if [ -n "$proj" ] && [ -f "$proj/sordino.toml" ]; then
    printf '%s\n' "$proj/sordino.toml"
  elif [ -n "$PLUGIN_ROOT" ] && [ -f "$PLUGIN_ROOT/sordino.toml" ]; then
    printf '%s\n' "$PLUGIN_ROOT/sordino.toml"
  fi
}

# Pure-shell detection of OUR baked route (jq-free; jq is a hard Windows blocker). Mirrors
# `project_baked_route`: a route is OURS only when a .claude/settings*.json carries BOTH a loopback
# env.ANTHROPIC_BASE_URL (http://127.0.0.1:<port> or http://localhost:<port>, no path) AND a
# co-keyed env.SORDINO_PORT whose value EQUALS that URL's <port>. A URL-only match is NOT enough —
# it would false-warn on a user's OWN 127.0.0.1 base URL. Bias to FALSE-NEGATIVE: any parse
# ambiguity -> treat as NOT ours -> stay silent (a missed warning just leaves today's behavior; a
# false warning nags an innocent project). Prints nothing; returns 0 iff ours.
sordino_has_baked_route() {
  local proj="${CLAUDE_PROJECT_DIR:-$PWD}"
  local f block url port zport
  for f in "$proj/.claude/settings.local.json" "$proj/.claude/settings.json"; do
    [ -f "$f" ] || continue
    # SCOPE to the TOP-LEVEL "env" object — the only env Claude Code applies as routing, matching
    # Rust project_baked_route's v.get("env"). sordino writes settings via serde pretty-print
    # (2-space indent), so the top-level env spans the lines from `  "env": {` to its `  }`; a nested
    # *.env (e.g. mcpServers.*.env) is indented DEEPER and is excluded, so a co-keyed URL/port outside
    # the top-level env cannot trigger a false warning. Biased to FALSE-NEGATIVE: a compact or
    # hand-reformatted (non-2-space) file yields an EMPTY block -> stay silent (a missed warning just
    # leaves today's behavior; we must never nag an innocent project).
    block="$(sed -n '/^[[:space:]][[:space:]]"env"[[:space:]]*:[[:space:]]*{/,/^[[:space:]][[:space:]]}/p' "$f" 2>/dev/null)" || true
    [ -n "$block" ] || continue
    # First string value of each key WITHIN that env block; tolerant of whitespace around the colon.
    # SORDINO_PORT may be a JSON string ("41234") or a number (41234) — accept both, keep the digits.
    # `|| true`: under `set -euo pipefail` a no-match grep exits 1 and pipefail would abort the hook.
    url="$(printf '%s\n' "$block" | grep -oE '"ANTHROPIC_BASE_URL"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n1 | sed -E 's/.*"([^"]*)"$/\1/')" || true
    zport="$(printf '%s\n' "$block" | grep -oE '"SORDINO_PORT"[[:space:]]*:[[:space:]]*"?[0-9]+"?' | head -n1 | grep -oE '[0-9]+' | head -n1)" || true
    [ -n "$url" ] && [ -n "$zport" ] || continue
    url="${url%/}"
    case "$url" in
      http://127.0.0.1:*|http://localhost:*) ;;
      *) continue ;;
    esac
    port="${url##*:}"
    case "$port" in
      ''|*[!0-9]*) continue ;;   # empty, or a path/query after the port -> not our bare host:port
    esac
    # Match Rust's parse::<u16>(): a port > 65535 is not a real port (NOT ours). `test -le` is decimal.
    [ "$port" -le 65535 ] 2>/dev/null || continue
    [ "$port" = "$zport" ] && return 0
  done
  return 1
}

# Resolve (and, on first run, build) the binaries; this also prepends their dir
# to PATH so the hooks call below and session-start's default --proxy-bin resolve.
if ! sordino_resolve_bins; then
  # Binaries unresolved. If THIS repo nonetheless carries OUR baked route (a cloned repo that
  # committed .claude/settings*.json, or a leftover route on a machine where sordino was removed),
  # Claude Code already applied that route at startup and this session is pointed at a loopback
  # port that will NEVER come up — a silent multi-minute ConnectionRefused hang with no signal that
  # a MISSING BINARY is the cause. Emit a valid SessionStart note (model + human-on-stderr) and
  # exit 0 so CC consumes it instead of logging a hook failure. We do NOT launch/build here — there
  # is no binary to launch.
  if sordino_has_baked_route; then
    warn "Sordino: this repo is configured to route through Sordino, but the sordino binaries are not installed on this machine. Install the plugin (or put sordino-proxy/sordino-hooks on PATH) and restart; until then this session routes to a local proxy port that will not answer, so requests will hang and nothing is masked."
    printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"This repository is configured to route Claude Code through the Sordino PII-masking proxy (a baked ANTHROPIC_BASE_URL + matching SORDINO_PORT in .claude/settings*.json), but the sordino binaries are NOT installed on this machine, so the proxy cannot start. Until the user installs the Sordino plugin (or puts sordino-proxy/sordino-hooks on PATH) and restarts Claude Code, this session is routed to a dead local port: requests will hang with ConnectionRefused and NO masking is active. Tell the user to install Sordino, or to remove the ANTHROPIC_BASE_URL and SORDINO_PORT keys from .claude/settings.local.json to stop routing. Do not claim masking is active in this session."}}'
    exit 0
  fi
  # No sordino route here -> an unconfigured project without the binaries is simply not a sordino
  # project; nothing to warn about. Keep the silent no-op.
  warn "Sordino: proxy not started this session."
  exit 1
fi

CFG="$(config_path)"

# Hand off to the real control plane and emit its hook JSON byte-for-byte. sordino-hooks
# owns the routing decision now: it checks whether THIS session's ANTHROPIC_BASE_URL is
# actually pointed at the proxy and, only then, launches/recycles it and announces that
# masking is active — otherwise it auto-enables a never-seen project, nudges (on stderr)
# a configured-but-not-yet-routed one to restart once to activate masking, or stays a
# silent no-op. (The UserPromptSubmit intake gate blocks that unrouted session's prompts
# until the restart, so nothing sends unmasked.) Single source of truth, no shell guard.
set +e
if [ -n "$CFG" ]; then
  "$SORDINO_HOOKS_BIN" ${PORT_ARGS[@]+"${PORT_ARGS[@]}"} session-start --config "$CFG"
else
  "$SORDINO_HOOKS_BIN" ${PORT_ARGS[@]+"${PORT_ARGS[@]}"} session-start
fi
rc=$?
set -e

if [ "$rc" -ne 0 ]; then
  warn "Sordino: sordino-hooks session-start exited $rc."
  exit "$rc"
fi

exit 0
