#!/usr/bin/env bash
# Shared zlauder binary resolver for the Codex plugin. Source this file.
set -euo pipefail

zlauder__warn() { printf '%s\n' "$*" >&2; }

zlauder__is_windows_bash() {
  case "$(uname -s 2>/dev/null || true)" in
    MINGW*|MSYS*|CYGWIN*) return 0 ;;
    *) return 1 ;;
  esac
}

# Normalize the plugin root by re-deriving it from THIS file's own path ONLY when the
# inherited value is missing or in native-Windows form (a `DRIVE:` prefix or a backslash):
# a `!bash` block doesn't export it (empty), and on Windows a hook exports it as a native
# C:\... path whose drive-colon splits PATH when prepended below. `cd ... && pwd` always
# emits MSYS form (/c/...), which prepends cleanly. A value already in MSYS/POSIX form is
# correct and is left untouched (so we don't override a good host root with a resolved variant).
#
# Source: Codex's hook engine injects CLAUDE_PLUGIN_ROOT / PLUGIN_ROOT (NOT the CODEX_ name),
# so accept the fallback chain CODEX_PLUGIN_ROOT -> CLAUDE_PLUGIN_ROOT -> PLUGIN_ROOT, and
# fall back to the BASH_SOURCE re-derivation last when none are set. The normalized value is
# written into CODEX_PLUGIN_ROOT, the canonical var the rest of this file reads.
export CODEX_PLUGIN_ROOT="${CODEX_PLUGIN_ROOT:-${CLAUDE_PLUGIN_ROOT:-${PLUGIN_ROOT:-}}}"
case "${CODEX_PLUGIN_ROOT:-}" in
  '' | *'\'* | [A-Za-z]:*)
    _zl_pr="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd || true)"
    [ -n "$_zl_pr" ] && export CODEX_PLUGIN_ROOT="$_zl_pr"
    unset _zl_pr
    ;;
esac

zlauder__host_triple() {
  local os arch
  os="$(uname -s 2>/dev/null || true)"
  arch="$(uname -m 2>/dev/null || true)"
  case "$os" in
    MINGW*|MSYS*|CYGWIN*)
      case "$arch" in
        x86_64|amd64) printf '%s\n' "x86_64-pc-windows-msvc" ;;
      esac ;;
    Linux)
      case "$arch" in
        x86_64|amd64)  printf '%s\n' "x86_64-unknown-linux-gnu" ;;
        aarch64|arm64) printf '%s\n' "aarch64-unknown-linux-gnu" ;;
      esac ;;
    Darwin)
      case "$arch" in
        x86_64)        printf '%s\n' "x86_64-apple-darwin" ;;
        arm64|aarch64) printf '%s\n' "aarch64-apple-darwin" ;;
      esac ;;
  esac
}

zlauder__exe_suffix() {
  if zlauder__is_windows_bash; then
    printf '%s\n' ".exe"
  fi
}

export ZLAUDER_EXE_SUFFIX="${ZLAUDER_EXE_SUFFIX:-$(zlauder__exe_suffix)}"
export ZLAUDER_PROXY_BIN="zlauder-proxy${ZLAUDER_EXE_SUFFIX}"
export ZLAUDER_HOOKS_BIN="zlauder-hooks${ZLAUDER_EXE_SUFFIX}"

zlauder__workspace() {
  if [ -n "${ZLAUDER_WORKSPACE:-}" ]; then
    printf '%s\n' "$ZLAUDER_WORKSPACE"
  elif [ -n "${CODEX_PLUGIN_ROOT:-${CLAUDE_PLUGIN_ROOT:-${PLUGIN_ROOT:-}}}" ]; then
    printf '%s\n' "${CODEX_PLUGIN_ROOT:-${CLAUDE_PLUGIN_ROOT:-${PLUGIN_ROOT:-}}}/.."
  fi
}

zlauder__has_both() {
  local dir="$1"
  if [ -n "$dir" ]; then
    [ -x "$dir/$ZLAUDER_PROXY_BIN" ] && [ -x "$dir/$ZLAUDER_HOOKS_BIN" ]
  else
    command -v "$ZLAUDER_PROXY_BIN" >/dev/null 2>&1 && command -v "$ZLAUDER_HOOKS_BIN" >/dev/null 2>&1
  fi
}

zlauder__build_bins() {
  local data_dir="${CODEX_PLUGIN_DATA:-${CLAUDE_PLUGIN_DATA:-${PLUGIN_DATA:-}}}"
  local workspace; workspace="$(zlauder__workspace)"
  if [ -z "$workspace" ] || [ ! -f "$workspace/Cargo.toml" ]; then
    zlauder__warn "ZlauDeR: no prebuilt binary for this platform and no cargo workspace at \"${workspace:-<unset>}\"."
    zlauder__warn "ZlauDeR: install a release onto PATH, or set \$ZLAUDER_WORKSPACE to a zlauder checkout."
    return 1
  fi
  if ! command -v cargo >/dev/null 2>&1; then
    zlauder__warn "ZlauDeR: no prebuilt binary for this platform and cargo not found; cannot build. Install a release onto PATH."
    return 1
  fi
  if [ -z "$data_dir" ]; then
    zlauder__warn "ZlauDeR: CODEX_PLUGIN_DATA is unset; cannot cache a build."
    return 1
  fi

  zlauder__warn "ZlauDeR: building proxy/hooks from $workspace (first run; cached afterward)."
  if ! ( cd "$workspace" && cargo build --release --bin zlauder-proxy --bin zlauder-hooks ) >&2; then
    zlauder__warn "ZlauDeR: cargo build failed."
    return 1
  fi

  local rel="$workspace/target/release"
  if [ ! -x "$rel/$ZLAUDER_PROXY_BIN" ] || [ ! -x "$rel/$ZLAUDER_HOOKS_BIN" ]; then
    zlauder__warn "ZlauDeR: build reported success but binaries are missing under $rel."
    return 1
  fi
  mkdir -p "$data_dir/bin"
  # cp + chmod rather than `install`: coreutils `install` isn't guaranteed in a minimal
  # Git Bash, while cp/chmod are. chmod is harmless on Windows (the .exe is already runnable).
  # Check cp explicitly: this helper is called via `... || return 1`, which DISABLES errexit
  # inside the function, so a failed copy would otherwise fall through to a success return and
  # prepend an incomplete bin dir to PATH.
  if ! cp -f "$rel/$ZLAUDER_PROXY_BIN" "$rel/$ZLAUDER_HOOKS_BIN" "$data_dir/bin/"; then
    zlauder__warn "ZlauDeR: failed to copy the built binaries into $data_dir/bin."
    return 1
  fi
  chmod 0755 "$data_dir/bin/$ZLAUDER_PROXY_BIN" "$data_dir/bin/$ZLAUDER_HOOKS_BIN" 2>/dev/null || true
  ZLAUDER_BIN_DIR="$data_dir/bin"
}

zlauder_resolve_bins() {
  local allow_build=1
  if [ "${1:-}" = "--no-build" ]; then allow_build=0; fi
  local plugin_root="${CODEX_PLUGIN_ROOT:-${CLAUDE_PLUGIN_ROOT:-${PLUGIN_ROOT:-}}}"
  local data_dir="${CODEX_PLUGIN_DATA:-${CLAUDE_PLUGIN_DATA:-${PLUGIN_DATA:-}}}"
  local triple; triple="$(zlauder__host_triple)"
  local workspace; workspace="$(zlauder__workspace)"
  ZLAUDER_BIN_DIR=""

  if zlauder__has_both ""; then
    :
  elif [ -n "$plugin_root" ] && [ -n "$triple" ] && zlauder__has_both "$plugin_root/bin/$triple"; then
    ZLAUDER_BIN_DIR="$plugin_root/bin/$triple"
  elif [ -n "$plugin_root" ] && zlauder__has_both "$plugin_root/bin"; then
    ZLAUDER_BIN_DIR="$plugin_root/bin"
  elif [ -n "$data_dir" ] && zlauder__has_both "$data_dir/bin"; then
    ZLAUDER_BIN_DIR="$data_dir/bin"
  elif [ -n "$workspace" ] && zlauder__has_both "$workspace/target/release"; then
    ZLAUDER_BIN_DIR="$workspace/target/release"
  elif [ "$allow_build" -eq 1 ]; then
    zlauder__build_bins || return 1
  else
    return 1
  fi

  if [ -n "${ZLAUDER_BIN_DIR:-}" ]; then
    case ":$PATH:" in
      *":$ZLAUDER_BIN_DIR:"*) ;;
      *) PATH="$ZLAUDER_BIN_DIR:$PATH"; export PATH ;;
    esac
  fi
  return 0
}
