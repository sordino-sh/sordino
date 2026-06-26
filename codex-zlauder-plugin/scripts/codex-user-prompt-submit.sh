#!/usr/bin/env bash
# Codex UserPromptSubmit hook wrapper.
#
# Thin delegate: source the shared resolver to put zlauder-hooks on PATH, then
# exec `zlauder-hooks codex-user-prompt-submit`, passing the UserPromptSubmit
# payload on stdin straight through. The subcommand owns the FAIL-CLOSED intake
# gate: it BLOCKs an unrouted prompt and ALLOWs (optionally with a non-blocking
# override-warn) a confirmed-routed one.
#
# DEGRADE-TO-ALLOW (documented limitation): the fail-closed gate lives in the
# SUBCOMMAND, which needs the binary to run. When zlauder-hooks cannot be
# resolved AT ALL, this wrapper cannot compute the gate, so it prints `{}` (ALLOW)
# and exits 0 rather than wedging the session. The fail-closed BLOCK only applies
# when the binary IS available; a session with no zlauder install therefore
# degrades to ALLOW. Diagnostics go to stderr; stdout must stay valid hook JSON.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_resolve-bins.sh
# Guard the source itself: if _resolve-bins.sh is missing/unreadable or errors at
# its own top-level under set -e, degrade-to-ALLOW with valid hook JSON rather than
# exiting non-zero having printed nothing (same degrade-to-ALLOW limitation as a
# fully-unresolvable binary).
if ! { [ -r "$SCRIPT_DIR/_resolve-bins.sh" ] && . "$SCRIPT_DIR/_resolve-bins.sh"; }; then
  printf '%s\n' "ZlauDeR: could not source resolver; intake gate degraded to ALLOW." >&2
  printf '{}\n'
  exit 0
fi

if ! zlauder_resolve_bins; then
  printf '%s\n' "ZlauDeR: could not resolve zlauder-hooks; intake gate degraded to ALLOW." >&2
  printf '{}\n'
  exit 0
fi

exec "${ZLAUDER_HOOKS_BIN:-zlauder-hooks}" codex-user-prompt-submit
