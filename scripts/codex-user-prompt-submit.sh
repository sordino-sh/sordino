#!/usr/bin/env bash
# Codex UserPromptSubmit hook wrapper.
#
# Thin delegate: source the shared resolver to put sordino-hooks on PATH, then
# exec `sordino-hooks codex-user-prompt-submit`, passing the UserPromptSubmit
# payload on stdin straight through. The subcommand owns the FAIL-CLOSED intake
# gate: it BLOCKs an unrouted prompt and ALLOWs (optionally with a non-blocking
# override-warn) a confirmed-routed one.
#
# FAIL-CLOSED (security boundary): the gate proper lives in the SUBCOMMAND, but the
# SECURITY DEFAULT does NOT depend on it. When sordino-hooks cannot be resolved AT
# ALL, this wrapper cannot confirm the prompt is routed through the masking proxy,
# so it emits a hard BLOCK ({"decision":"block","reason":...}) — it must NOT degrade
# to ALLOW, or an unconfigured session would egress PII unmasked. The block reason
# tells the user how to recover (restore the plugin/binary, or remove the sordino
# [hooks] from $CODEX_HOME/config.toml to opt out). stdout stays valid hook JSON.
set -euo pipefail

# The fail-closed block payload (non-empty reason — codex drops a block with an empty reason).
ZL_BLOCK='{"decision":"block","reason":"Sordino intake gate unavailable (the plugin binary could not be resolved) — this Codex prompt cannot be confirmed routed through the masking proxy, so it is blocked to avoid egressing PII unmasked. Restore the sordino plugin/binary on PATH, or remove the sordino [hooks] from $CODEX_HOME/config.toml to opt out."}'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_resolve-bins.sh
# Guard the source itself: if _resolve-bins.sh is missing/unreadable or errors at its
# own top-level under set -e, FAIL CLOSED (block) with valid hook JSON rather than
# exiting non-zero having printed nothing (or, worse, allowing).
if ! { [ -r "$SCRIPT_DIR/_resolve-bins.sh" ] && . "$SCRIPT_DIR/_resolve-bins.sh"; }; then
  printf '%s\n' "Sordino: could not source resolver; FAIL-CLOSED (blocking this prompt)." >&2
  printf '%s\n' "$ZL_BLOCK"
  exit 0
fi

if ! sordino_resolve_bins; then
  printf '%s\n' "Sordino: could not resolve sordino-hooks; FAIL-CLOSED (blocking this prompt)." >&2
  printf '%s\n' "$ZL_BLOCK"
  exit 0
fi

exec "${SORDINO_HOOKS_BIN:-sordino-hooks}" codex-user-prompt-submit
