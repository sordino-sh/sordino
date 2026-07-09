#!/usr/bin/env bash
# sordino UserPromptSubmit hook: the fail-CLOSED first-session INTAKE GATE.
#
# Claude Code applies a freshly-written settings.local.json route to the CURRENT session only
# unreliably, so the common first session after auto-plumb/enable is PLUMBED but NOT routed —
# its prompt would reach the API provider UNMASKED. This hook reads the UserPromptSubmit
# payload on stdin and, in exactly that state, emits {"decision":"block","reason":...} so the
# would-be-unmasked prompt never egresses (the user is told to restart once). Every other
# state — not plumbed, already routed, opted out, or SORDINO_NO_INTAKE_GATE set — emits nothing
# (the prompt proceeds).
#
# The whole decision lives in `sordino-hooks user-prompt-submit` (fast LOCAL reads only — no
# network, nothing that can hang/panic) because a UserPromptSubmit hook that times out or
# crashes FAILS OPEN by Claude Code's contract; only an explicit block decision is fail-closed.
# Binaries unavailable ⇒ no sordino installed ⇒ no masking promise ⇒ allow (emit nothing).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_resolve-bins.sh
. "$SCRIPT_DIR/_resolve-bins.sh"

# Binaries unavailable ⇒ emit nothing (the prompt proceeds; no sordino = nothing to gate).
if ! sordino_resolve_bins --no-build 2>/dev/null; then
  exit 0
fi

# The gate reads its state from the baked route + $ANTHROPIC_BASE_URL (not a --port arg). It
# prints the block JSON or nothing. A non-block exit is an ALLOW either way, so never surface a
# hiccup as a scary error — swallow a non-zero exit (CC treats non-2 exits as non-blocking).
"$SORDINO_HOOKS_BIN" user-prompt-submit || true
