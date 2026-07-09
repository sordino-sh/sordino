#!/usr/bin/env bash
# Report the current Codex routing state from $CODEX_HOME/config.toml.
#
# Thin wrapper around `sordino-hooks codex-config show`, which prints the effective
# top-level model_provider and the sordino provider's base_url. A REPORT only —
# never blocks or mutates anything.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../../scripts/_resolve-bins.sh
if [ -f "$SCRIPT_DIR/../../../scripts/_resolve-bins.sh" ]; then
  . "$SCRIPT_DIR/../../../scripts/_resolve-bins.sh"
  sordino_resolve_bins || {
    printf '%s\n' "Sordino: could not resolve sordino-hooks; cannot report status." >&2
    exit 1
  }
fi

HOOKS="${SORDINO_HOOKS_BIN:-sordino-hooks}"

"$HOOKS" codex-config show
