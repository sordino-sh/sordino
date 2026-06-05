#!/usr/bin/env bash
# Shared zlauder binary resolver. SOURCE this file (do not execute it).
#
# Defines zlauder_resolve_bins, which makes zlauder-proxy/zlauder-hooks invocable
# by name, following the locked precedence:
#   PATH  ->  ${CLAUDE_PLUGIN_ROOT}/bin  ->  ${CLAUDE_PLUGIN_DATA}/bin
#         ->  build from the cargo workspace into ${CLAUDE_PLUGIN_DATA}/bin
# On success it prepends the resolved dir (if any) to PATH and exports it, so a
# bare `zlauder-proxy` (e.g. zlauder-hooks session-start's default --proxy-bin)
# resolves too. Pass --no-build to skip the lazy build step (status/reveal want
# this: building never makes a down proxy answer, so just report "unavailable").
#
# All diagnostics go to stderr so a caller that emits hook JSON keeps stdout clean.
# ZLAUDER_BIN_DIR is set to the resolved dir (empty string when already on PATH).

zlauder__warn() { printf '%s\n' "$*" >&2; }

# True if both binaries are invocable from $1 (or from PATH when $1 is empty).
zlauder__has_both() {
  local dir="$1"
  if [ -n "$dir" ]; then
    [ -x "$dir/zlauder-proxy" ] && [ -x "$dir/zlauder-hooks" ]
  else
    command -v zlauder-proxy >/dev/null 2>&1 && command -v zlauder-hooks >/dev/null 2>&1
  fi
}

# Build both binaries from the cargo workspace into ${CLAUDE_PLUGIN_DATA}/bin.
zlauder__build_bins() {
  local plugin_root="${CLAUDE_PLUGIN_ROOT:-}"
  local data_dir="${CLAUDE_PLUGIN_DATA:-}"
  local workspace="${ZLAUDER_WORKSPACE:-}"
  if [ -z "$workspace" ] && [ -n "$plugin_root" ]; then
    workspace="$plugin_root/.."
  fi
  if [ -z "$workspace" ] || [ ! -f "$workspace/Cargo.toml" ]; then
    zlauder__warn "zlauder: cannot resolve binaries — not on PATH, no prebuilt bin/, and no cargo workspace at \"${workspace:-<unset>}\"."
    zlauder__warn "zlauder: set \$ZLAUDER_WORKSPACE to the zlauder checkout, or ship prebuilt binaries in ${plugin_root:-<plugin>}/bin/."
    return 1
  fi
  if ! command -v cargo >/dev/null 2>&1; then
    zlauder__warn "zlauder: cargo not found; cannot build zlauder-proxy/zlauder-hooks. Install Rust or ship prebuilt binaries in ${plugin_root:-<plugin>}/bin/."
    return 1
  fi
  if [ -z "$data_dir" ]; then
    zlauder__warn "zlauder: CLAUDE_PLUGIN_DATA is unset; cannot cache a build."
    return 1
  fi

  zlauder__warn "zlauder: building proxy/hooks from $workspace (first run; cached afterward)…"
  # cargo's own output goes to stderr to keep stdout clean for any hook JSON.
  if ! ( cd "$workspace" && cargo build --release --bin zlauder-proxy --bin zlauder-hooks ) >&2; then
    zlauder__warn "zlauder: cargo build failed."
    return 1
  fi

  local rel="$workspace/target/release"
  if [ ! -x "$rel/zlauder-proxy" ] || [ ! -x "$rel/zlauder-hooks" ]; then
    zlauder__warn "zlauder: build reported success but binaries are missing under $rel."
    return 1
  fi
  mkdir -p "$data_dir/bin"
  install -m 0755 "$rel/zlauder-proxy" "$rel/zlauder-hooks" "$data_dir/bin/"
  ZLAUDER_BIN_DIR="$data_dir/bin"
}

# Resolve both binaries and prepend their dir to PATH (exported). Idempotent.
# Returns non-zero (with a stderr explanation) if they can't be resolved.
zlauder_resolve_bins() {
  local allow_build=1
  if [ "${1:-}" = "--no-build" ]; then allow_build=0; fi
  local plugin_root="${CLAUDE_PLUGIN_ROOT:-}"
  local data_dir="${CLAUDE_PLUGIN_DATA:-}"
  ZLAUDER_BIN_DIR=""

  if zlauder__has_both ""; then
    :                                                   # already on PATH
  elif [ -n "$plugin_root" ] && zlauder__has_both "$plugin_root/bin"; then
    ZLAUDER_BIN_DIR="$plugin_root/bin"                  # shipped prebuilt
  elif [ -n "$data_dir" ] && zlauder__has_both "$data_dir/bin"; then
    ZLAUDER_BIN_DIR="$data_dir/bin"                     # cached from a build
  elif [ "$allow_build" -eq 1 ]; then
    zlauder__build_bins || return 1                     # build into data bin/
  else
    return 1
  fi

  if [ -n "${ZLAUDER_BIN_DIR:-}" ]; then
    case ":$PATH:" in
      *":$ZLAUDER_BIN_DIR:"*) ;;                        # already present
      *) PATH="$ZLAUDER_BIN_DIR:$PATH"; export PATH ;;
    esac
  fi
  return 0
}
