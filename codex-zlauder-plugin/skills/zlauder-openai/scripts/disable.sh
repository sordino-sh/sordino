#!/usr/bin/env bash
# Stop routing Codex's OpenAI traffic through the zlauder masking proxy.
#
# Thin wrapper around `zlauder-hooks codex-config disable`, which removes ONLY the
# zlauder-managed [model_providers.<id>] block and restores the prior model_provider.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../../scripts/_resolve-bins.sh
if [ -f "$SCRIPT_DIR/../../../scripts/_resolve-bins.sh" ]; then
  . "$SCRIPT_DIR/../../../scripts/_resolve-bins.sh"
  zlauder_resolve_bins || {
    printf '%s\n' "ZlauDeR: could not resolve zlauder-hooks; nothing changed." >&2
    exit 1
  }
fi

HOOKS="${ZLAUDER_HOOKS_BIN:-zlauder-hooks}"

set +e
"$HOOKS" codex-config disable
rc=$?
set -e
if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then
  exit "$rc"
fi

if [ "$rc" -eq 3 ]; then
  printf '%s\n' "ZlauDeR: Codex routing was not enabled — nothing to disable."
else
  printf '%s\n' "ZlauDeR: Codex routing disabled — restored your prior provider."
fi
printf '%s\n' "RESTART codex for the change to take effect."
