#!/usr/bin/env bash
# Backs /sordino:mask — the unified masking VERB. It wraps the existing hooks subcommands so the
# mental model is one word ("mask on / mask off") instead of three commands:
#
#   mask on            re-enable masking — UNCONDITIONAL: clears any per-conversation off at ANY
#                      scope AND flips the master switch back on  (hooks `config on`)
#   mask off           turn masking off for THIS conversation only (the per-conversation path;
#                      bounded — auto-re-arms in ~30 min unless you extend it)  (hooks `disable`)
#   mask off --for 2h  bounded timed off (clamped to 24h)                       (hooks `disable --for`)
#   mask off --sticky  explicit indefinite off (24h ceiling, then auto-re-arm)  (hooks `disable --sticky`)
#   mask off --project the whole-project master switch (shared with a Codex sibling)  (hooks `disable --project`)
#   mask off --scope project|user|local  persist the master-switch OFF to a config layer (hooks `config off --scope`)
#   mask on  --scope project|user|local   persist the re-enable to a config layer (hooks `config on --scope`)
#
# Every OTHER verb (status / profile / category / threshold / model / reveal / scrub) is delegated
# UNCHANGED to privacy.sh, so /sordino:mask is a lossless superset of the old control plane and the
# deprecated /sordino:disable and /sordino:privacy aliases can forward straight through here.
#
# Observer-style like its siblings: never aborts hard (needs a *running* proxy, which a control
# verb can't conjure), resolves binaries with --no-build. `set -f` keeps a reveal token like
# [EMAIL_ADDRESS_xxxx] intact when we re-split the single quoted argument string.
set -uo pipefail
set -f

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_resolve-bins.sh
. "$SCRIPT_DIR/_resolve-bins.sh"

if ! sordino_resolve_bins --no-build; then
  echo "error: sordino-hooks is not available for this project yet. Start a Claude Code session in this project, or put the binaries on PATH, then retry." >&2
  exit 1
fi

# The command passes the whole user argument string as ONE quoted positional; re-split it here
# under `set -f` so `on`/`off` and their flags land as separate positionals while a token stays
# a single intact word.
# shellcheck disable=SC2086
set -- ${1:-}

# Target THIS project's proxy explicitly when the port is pinned (post-/sordino:enable). `--port`
# is a global option, so it leads the subcommand.
PORT_ARGS=()
[ -n "${SORDINO_PORT:-}" ] && PORT_ARGS=(--port "$SORDINO_PORT")

sub="${1:-status}"
case "$sub" in
  on)
    # Re-enable: `config on` is the unconditional path — it clears any per-conversation off at any
    # scope AND turns the master switch back on. Extra args (e.g. --scope project) pass through.
    shift || true
    exec "$SORDINO_HOOKS_BIN" "${PORT_ARGS[@]}" config on "$@"
    ;;
  off)
    # Turn off: the per-conversation `disable` path (bounded, server-side ~30m TTL by default).
    # --for/--sticky/--project pass through to the CLI. But `--scope` is the symmetric-with-`on`
    # form that persists the MASTER SWITCH off to a config layer — `disable` has no `--scope`, so
    # route those to `config off` (mirroring the `on` -> `config on` path) instead.
    shift || true
    route_config_off=0
    for a in "$@"; do
      case "$a" in --scope | --scope=*) route_config_off=1 ;; esac
    done
    if [ "$route_config_off" -eq 1 ]; then
      exec "$SORDINO_HOOKS_BIN" "${PORT_ARGS[@]}" config off "$@"
    else
      exec "$SORDINO_HOOKS_BIN" "${PORT_ARGS[@]}" disable "$@"
    fi
    ;;
  *)
    # Every other verb (status / profile / category / threshold / model / reveal / scrub) is the
    # existing privacy control plane — delegate unchanged so /sordino:mask loses nothing.
    exec bash "$SCRIPT_DIR/privacy.sh" "$*"
    ;;
esac
