#!/usr/bin/env bash
# Verify the Codex masking path: run the proxy/route verifier, then report whether
# any inbound from THIS session has reached the proxy (A8 per-session override
# detection). A REPORT only — never blocks anything.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../../scripts/_resolve-bins.sh
if [ -f "$SCRIPT_DIR/../../../scripts/_resolve-bins.sh" ]; then
  . "$SCRIPT_DIR/../../../scripts/_resolve-bins.sh"
  zlauder_resolve_bins || {
    printf '%s\n' "ZlauDeR: could not resolve zlauder-hooks; cannot verify." >&2
    exit 1
  }
fi

HOOKS="${ZLAUDER_HOOKS_BIN:-zlauder-hooks}"

# (1) Route + engine + identity probes. `verify` reports its own findings; do not
# let a non-zero verdict abort the override report below.
set +e
"$HOOKS" verify
set -e

# (2) Per-session override detection (A8). The authenticated per-session inbound
# read needs the live codex session id, which is present in the env only while
# codex is driving the hook — not in this standalone skill invocation. When the
# session id (CODEX_SESSION_ID / CODEX_THREAD_ID) is available we query A8; absent
# it, or on an older codex build with no A8 endpoint, we report it as unavailable.
SESSION_ID="${CODEX_SESSION_ID:-${CODEX_THREAD_ID:-}}"
if [ -z "$SESSION_ID" ]; then
  printf '%s\n' "override detection unavailable on this Codex build (no session id in env; the real-time check runs from the UserPromptSubmit hook)."
  exit 0
fi

# The A8 read is KEY-GATED (x-zlauder-key). The skill holds no admin key, so a bare curl would
# always 403; we delegate to the key-bearing `codex-session-routed` subcommand, which resolves the
# proxy port + admin key internally (via the nonce-verified proxy identity) and prints a one-word
# verdict. Report-only: a non-zero exit (binary missing) degrades to "unavailable".
ROUTED="$("$HOOKS" codex-session-routed "$SESSION_ID" 2>/dev/null || true)"
case "$ROUTED" in
  routed)
    printf '%s\n' "inbound seen for this session: yes (traffic from this session has reached the proxy)." ;;
  not-routed)
    printf '%s\n' "no inbound from this session has reached the proxy — possible -c/-p override or not-yet-routed." ;;
  *)
    printf '%s\n' "override detection unavailable on this Codex build." ;;
esac
