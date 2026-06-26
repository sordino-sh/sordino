#!/usr/bin/env bash
# Route Codex's OpenAI traffic through the zlauder masking proxy.
#
# Thin wrapper: (1) auth preflight, (2) learn the live proxy URL, (3) write the
# custom-provider block into $CODEX_HOME/config.toml via `zlauder-hooks codex-config enable`.
# Diagnostics go to stderr; the only stdout is the human instruction at the end.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Put zlauder-hooks (and the proxy) on PATH via the shared resolver, if present.
# shellcheck source=../../../scripts/_resolve-bins.sh
if [ -f "$SCRIPT_DIR/../../../scripts/_resolve-bins.sh" ]; then
  . "$SCRIPT_DIR/../../../scripts/_resolve-bins.sh"
  zlauder_resolve_bins || {
    printf '%s\n' "ZlauDeR: could not resolve zlauder-hooks; routing not enabled." >&2
    exit 1
  }
fi

HOOKS="${ZLAUDER_HOOKS_BIN:-zlauder-hooks}"

# (1) Auth preflight. A non-zero exit means route_ok==false (no usable exported
# OPENAI_API_KEY) — surface its refusal and write NOTHING.
if ! "$HOOKS" codex-auth-check --json; then
  printf '%s\n' "ZlauDeR: Codex auth preflight failed — no config written. Export a usable OPENAI_API_KEY (sk-...) and retry." >&2
  exit 1
fi

# (2) Learn the live proxy URL (do NOT guess a port). ensure-up prints the base URL
# (e.g. http://127.0.0.1:PORT); Codex's provider wants the /v1 root.
BASE_URL="$("$HOOKS" ensure-up --print-url)"
if [ -z "${BASE_URL:-}" ]; then
  printf '%s\n' "ZlauDeR: could not bring the masking proxy up — no config written." >&2
  exit 1
fi
URL="${BASE_URL%/}/v1"

# Resolve the plugin's scripts/ dir (the hook wrappers live there) so codex-config
# installs the $CODEX_HOME [hooks] entries alongside the routing block. Prefer the
# canonical CODEX_PLUGIN_ROOT the resolver normalizes; fall back to this script's path.
PLUGIN_ROOT="${CODEX_PLUGIN_ROOT:-$(cd "$SCRIPT_DIR/../../.." && pwd)}"
HOOKS_DIR="$PLUGIN_ROOT/scripts"

# (3) Write/replace the custom-provider block AND install the [hooks] entries.
# Exit 0 = changed (provider and/or hooks), 3 = already fully enabled.
set +e
"$HOOKS" codex-config enable --url "$URL" --hooks-dir "$HOOKS_DIR"
rc=$?
set -e
if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then
  exit "$rc"
fi

if [ "$rc" -eq 3 ]; then
  printf '%s\n' "ZlauDeR: Codex routing already enabled (proxy at $URL)."
else
  printf '%s\n' "ZlauDeR: Codex routing enabled — masking proxy at $URL."
fi
printf '%s\n' "Routing + the SessionStart/UserPromptSubmit masking hooks were written to \$CODEX_HOME/config.toml."
printf '%s\n' "Next: REVIEW and TRUST this plugin's hooks, then RESTART codex so the new config.toml route + hooks take effect (codex > 0.140 required)."
printf '%s\n' "A usable OPENAI_API_KEY (sk-...) must be exported in the environment codex runs in, or requests will fail at provider construction."
