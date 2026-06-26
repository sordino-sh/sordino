#!/usr/bin/env bash
# Codex SessionStart hook wrapper.
#
# Thin delegate: source the shared resolver to put zlauder-hooks on PATH, then
# exec `zlauder-hooks codex-session-start`, passing the SessionStart payload on
# stdin straight through and letting the subcommand emit the hook-output JSON on
# stdout. The subcommand verifies the route + auth + /healthz identity and emits
# ONLY a schema-valid `hookSpecificOutput.additionalContext` (a neutral
# token-handling onboarding when verified, a warn-only note otherwise) — NEVER a
# top-level `env` key and NEVER an unqualified active-masking claim.
#
# Degrade-to-noop: if the binary can't be resolved at all, print `{}` and exit 0
# so a missing install never breaks the codex session. Diagnostics go to stderr;
# stdout must stay valid hook JSON.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_resolve-bins.sh
# Guard the source itself: if _resolve-bins.sh is missing/unreadable or errors at
# its own top-level under set -e, degrade-to-noop with valid hook JSON rather than
# exiting non-zero having printed nothing.
if ! { [ -r "$SCRIPT_DIR/_resolve-bins.sh" ] && . "$SCRIPT_DIR/_resolve-bins.sh"; }; then
  printf '%s\n' "ZlauDeR: could not source resolver; SessionStart onboarding skipped." >&2
  printf '{}\n'
  exit 0
fi

if ! zlauder_resolve_bins; then
  printf '%s\n' "ZlauDeR: could not resolve zlauder-hooks; SessionStart onboarding skipped." >&2
  printf '{}\n'
  exit 0
fi

exec "${ZLAUDER_HOOKS_BIN:-zlauder-hooks}" codex-session-start
