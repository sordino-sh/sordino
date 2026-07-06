#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_resolve-bins.sh
. "$SCRIPT_DIR/_resolve-bins.sh"

if ! sordino_resolve_bins --no-build; then
  echo "error: sordino-hooks is not available for this project yet. Start a Claude Code session in this project, or put the binaries on PATH, then retry." >&2
  exit 1
fi

# Run the doctor. Exit codes are a contract: 0 = all probes passed, 1 = it RAN and reported
# one or more FAILs (the table on stdout is the deliverable — relay it). ANY other code (a
# panic, a missing/incompatible binary, a signal) is a failure to RUN, which we must NOT hide
# behind a bare `|| true` — surface it instead.
rc=0
"$SORDINO_HOOKS_BIN" doctor || rc=$?
if [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
  echo "error: \`sordino-hooks doctor\` failed to run (exit $rc)." >&2
  exit "$rc"
fi
# A completed run propagates its own verdict so the contract above is observable:
# 0 = all probes passed, 1 = it ran and one or more probes FAILed. (Without this the
# script would fall off at 0 and a real FAIL would masquerade as success.)
exit "$rc"
