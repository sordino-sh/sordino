#!/usr/bin/env bash
# Unified sordino privacy control plane — backs /sordino:privacy. Subsumes the old
# status / reveal commands and the on/off/profile/category/entity/threshold verbs.
#
# Observer-style: never aborts hard (no `set -e`), and resolves binaries with
# --no-build — config/status/reveal all need a *running* proxy, which a build can't
# conjure (the SessionStart hook builds/launches it). `set -f` keeps masked tokens
# like [EMAIL_ADDRESS_xxxx] intact when we re-split the argument string.
set -uo pipefail
set -f

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_resolve-bins.sh
. "$SCRIPT_DIR/_resolve-bins.sh"
sordino_resolve_bins --no-build || true

if ! command -v "$SORDINO_HOOKS_BIN" >/dev/null 2>&1; then
  echo "error: sordino-hooks is not available for this project yet (the Sordino proxy is built and launched on session start). Start a Claude Code session in this project — or put the binaries on PATH — then retry." >&2
  exit 1
fi

# The command passes the whole user argument string as ONE quoted positional, so the
# outer shell never word-splits or globs it (a reveal token has '[' ']'). Re-split it
# here under `set -f` so on/off/profile/category/threshold + their --scope flags land
# as separate positionals, while a token stays a single intact word.
# shellcheck disable=SC2086
set -- ${1:-}

# Target THIS project's proxy explicitly when the port is pinned (post-/sordino:enable).
# --port is a global option, so it leads the subcommand to avoid any parse ambiguity.
PORT_ARGS=()
[ -n "${SORDINO_PORT:-}" ] && PORT_ARGS=(--port "$SORDINO_PORT")

sub="${1:-status}"
case "$sub" in
  reveal)
    shift || true
    tok="${1:-}"
    if [ -z "$tok" ]; then
      echo "usage: /sordino:privacy reveal <TOKEN>   (e.g. [EMAIL_ADDRESS_xxxx])" >&2
      exit 2
    fi
    exec "$SORDINO_HOOKS_BIN" "${PORT_ARGS[@]}" reveal "$tok"
    ;;
  status | "")
    # One unified "where do I stand": proxy health, then routing, then masking config.
    echo "Proxy health:"
    "$SORDINO_HOOKS_BIN" "${PORT_ARGS[@]}" statusline || true
    echo
    echo "Routing (ANTHROPIC_BASE_URL in this project's .claude/settings.local.json):"
    # sordino-hooks reads settings.local.json first (then legacy settings.json) — no jq needed.
    "$SORDINO_HOOKS_BIN" settings route-url || echo "(unset)"
    echo
    echo "Masking:"
    "$SORDINO_HOOKS_BIN" "${PORT_ARGS[@]}" config || true
    ;;
  on | off | profile | category | threshold | entity)
    # Masking verbs (and any --scope flag) pass straight through to the CLI.
    exec "$SORDINO_HOOKS_BIN" "${PORT_ARGS[@]}" config "$@"
    ;;
  scrub)
    shift || true
    exec "$SORDINO_HOOKS_BIN" "${PORT_ARGS[@]}" scrub "$@"
    ;;
  model)
    # ML recognizer (openai/privacy-filter, CPU): download | status | on | off.
    shift || true
    msub="${1:-status}"
    case "$msub" in
      download)
        # Download needs the sordino-proxy binary (built with the ml backend).
        # Unlike status/reveal, this path MAY build — re-resolve allowing it.
        shift || true
        sordino_resolve_bins || {
          echo "error: could not resolve/build sordino-proxy for the model download." >&2
          exit 1
        }
        if ! command -v "$SORDINO_PROXY_BIN" >/dev/null 2>&1; then
          echo "error: sordino-proxy is not available for this project yet." >&2
          exit 1
        fi
        CFG_ARGS=()
        proj_cfg="${CLAUDE_PROJECT_DIR:-.}/sordino.toml"
        [ -f "$proj_cfg" ] && CFG_ARGS=(--config "$proj_cfg")
        MODEL_ARGS=()
        [ -n "${1:-}" ] && MODEL_ARGS=(--model "$1")
        exec "$SORDINO_PROXY_BIN" "${CFG_ARGS[@]}" --download-model "${MODEL_ARGS[@]}"
        ;;
      on | off | status | "")
        # status / on / off go through the lean control CLI (no ml deps needed).
        exec "$SORDINO_HOOKS_BIN" "${PORT_ARGS[@]}" config ml "$@"
        ;;
      *)
        echo "usage: /sordino:privacy model [status | download [<repo>] | on | off] [--scope session|project|user|local]" >&2
        exit 2
        ;;
    esac
    ;;
  *)
    echo "unknown subcommand '$sub'. usage: /sordino:privacy [status | on | off | profile <name> | category <name> on|off | entity <TYPE> <on|off|token|redact|hash|keep|mask|clear> | threshold <0-1> | model <download|on|off|status> | reveal <token> | scrub --transcript <jsonl> (--value <text> | --values-file <file>)] [--scope session|project|user|local]" >&2
    exit 2
    ;;
esac
