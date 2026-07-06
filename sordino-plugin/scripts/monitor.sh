#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_resolve-bins.sh
. "$SCRIPT_DIR/_resolve-bins.sh"

if ! sordino_resolve_bins --no-build; then
  echo "error: sordino-hooks is not available for this project yet. Start a Claude Code session in this project, or put the binaries on PATH, then retry." >&2
  exit 1
fi

PORT_ARGS=()
[ -n "${SORDINO_PORT:-}" ] && PORT_ARGS=(--port "$SORDINO_PORT")

# The hooks binary prints the keyed monitor URL. This output is injected into the
# MODEL's context (slash-command !bash is not shown directly to the user), so the
# model relays it — the admin key is a `Local` token that the proxy reveals on the
# display path, so the relayed URL works.
URL="$("$SORDINO_HOOKS_BIN" "${PORT_ARGS[@]}" monitor)"
printf '%s\n' "$URL"

# Belt-and-suspenders: also open the monitor in the user's browser directly, so they
# reach it even if the model's summary mangles the URL. Best-effort and non-fatal —
# silently skipped on headless/SSH (no opener / no display) or when SORDINO_NO_OPEN is set.
if [ -z "${SORDINO_NO_OPEN:-}" ]; then
  for _opener in xdg-open open; do
    if command -v "$_opener" >/dev/null 2>&1; then
      "$_opener" "$URL" >/dev/null 2>&1 &
      break
    fi
  done
fi
