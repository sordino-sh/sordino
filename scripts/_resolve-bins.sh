#!/usr/bin/env bash
# Shared sordino binary resolver for the Codex plugin. Source this file.
set -euo pipefail

sordino__warn() { printf '%s\n' "$*" >&2; }

sordino__is_windows_bash() {
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
# so the INJECTED vars must WIN: chain CLAUDE_PLUGIN_ROOT -> PLUGIN_ROOT -> CODEX_PLUGIN_ROOT,
# then fall back to the BASH_SOURCE re-derivation last when none are set. CODEX_PLUGIN_ROOT is
# accepted only as a last-resort/explicit override, never ahead of the var Codex actually set
# this launch — otherwise a STALE/foreign CODEX_PLUGIN_ROOT inherited from a prior context would
# shadow the fresh injected root and wire the wrong plugin copy (incl. the hook paths enable.sh
# writes into config.toml). The normalized value is written into CODEX_PLUGIN_ROOT, the canonical
# var the rest of this file reads.
export CODEX_PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-${PLUGIN_ROOT:-${CODEX_PLUGIN_ROOT:-}}}"
case "${CODEX_PLUGIN_ROOT:-}" in
  '' | *'\'* | [A-Za-z]:*)
    _zl_pr="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd || true)"
    [ -n "$_zl_pr" ] && export CODEX_PLUGIN_ROOT="$_zl_pr"
    unset _zl_pr
    ;;
esac

sordino__host_triple() {
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

sordino__exe_suffix() {
  if sordino__is_windows_bash; then
    printf '%s\n' ".exe"
  fi
}

export SORDINO_EXE_SUFFIX="${SORDINO_EXE_SUFFIX:-$(sordino__exe_suffix)}"
export SORDINO_PROXY_BIN="sordino-proxy${SORDINO_EXE_SUFFIX}"
export SORDINO_HOOKS_BIN="sordino-hooks${SORDINO_EXE_SUFFIX}"

sordino__workspace() {
  if [ -n "${SORDINO_WORKSPACE:-}" ]; then
    printf '%s\n' "$SORDINO_WORKSPACE"
  elif [ -n "${CODEX_PLUGIN_ROOT:-${CLAUDE_PLUGIN_ROOT:-${PLUGIN_ROOT:-}}}" ]; then
    printf '%s\n' "${CODEX_PLUGIN_ROOT:-${CLAUDE_PLUGIN_ROOT:-${PLUGIN_ROOT:-}}}/.."
  fi
}

sordino__has_both() {
  local dir="$1"
  if [ -n "$dir" ]; then
    [ -x "$dir/$SORDINO_PROXY_BIN" ] && [ -x "$dir/$SORDINO_HOOKS_BIN" ]
  else
    command -v "$SORDINO_PROXY_BIN" >/dev/null 2>&1 && command -v "$SORDINO_HOOKS_BIN" >/dev/null 2>&1
  fi
}

sordino__build_bins() {
  local data_dir="${CLAUDE_PLUGIN_DATA:-${PLUGIN_DATA:-${CODEX_PLUGIN_DATA:-}}}"
  local workspace; workspace="$(sordino__workspace)"
  if [ -z "$workspace" ] || [ ! -f "$workspace/Cargo.toml" ]; then
    sordino__warn "Sordino: no prebuilt binary for this platform and no cargo workspace at \"${workspace:-<unset>}\"."
    sordino__warn "Sordino: install a release onto PATH, or set \$SORDINO_WORKSPACE to a sordino checkout."
    return 1
  fi
  if ! command -v cargo >/dev/null 2>&1; then
    sordino__warn "Sordino: no prebuilt binary for this platform and cargo not found; cannot build. Install a release onto PATH."
    return 1
  fi
  if [ -z "$data_dir" ]; then
    sordino__warn "Sordino: CODEX_PLUGIN_DATA is unset; cannot cache a build."
    return 1
  fi

  sordino__warn "Sordino: building proxy/hooks from $workspace (first run; cached afterward)."
  if ! ( cd "$workspace" && cargo build --release --bin sordino-proxy --bin sordino-hooks ) >&2; then
    sordino__warn "Sordino: cargo build failed."
    return 1
  fi

  local rel="$workspace/target/release"
  if [ ! -x "$rel/$SORDINO_PROXY_BIN" ] || [ ! -x "$rel/$SORDINO_HOOKS_BIN" ]; then
    sordino__warn "Sordino: build reported success but binaries are missing under $rel."
    return 1
  fi
  mkdir -p "$data_dir/bin"
  # cp + chmod rather than `install`: coreutils `install` isn't guaranteed in a minimal
  # Git Bash, while cp/chmod are. chmod is harmless on Windows (the .exe is already runnable).
  # Check cp explicitly: this helper is called via `... || return 1`, which DISABLES errexit
  # inside the function, so a failed copy would otherwise fall through to a success return and
  # prepend an incomplete bin dir to PATH.
  if ! cp -f "$rel/$SORDINO_PROXY_BIN" "$rel/$SORDINO_HOOKS_BIN" "$data_dir/bin/"; then
    sordino__warn "Sordino: failed to copy the built binaries into $data_dir/bin."
    return 1
  fi
  chmod 0755 "$data_dir/bin/$SORDINO_PROXY_BIN" "$data_dir/bin/$SORDINO_HOOKS_BIN" 2>/dev/null || true
  SORDINO_BIN_DIR="$data_dir/bin"
}

sordino_resolve_bins() {
  local allow_build=1
  if [ "${1:-}" = "--no-build" ]; then allow_build=0; fi
  local plugin_root="${CODEX_PLUGIN_ROOT:-${CLAUDE_PLUGIN_ROOT:-${PLUGIN_ROOT:-}}}"
  local data_dir="${CLAUDE_PLUGIN_DATA:-${PLUGIN_DATA:-${CODEX_PLUGIN_DATA:-}}}"
  local triple; triple="$(sordino__host_triple)"
  local workspace; workspace="$(sordino__workspace)"
  SORDINO_BIN_DIR=""

  if sordino__has_both ""; then
    :
  elif [ -n "$plugin_root" ] && [ -n "$triple" ] && sordino__has_both "$plugin_root/bin/$triple"; then
    SORDINO_BIN_DIR="$plugin_root/bin/$triple"
  elif [ -n "$plugin_root" ] && sordino__has_both "$plugin_root/bin"; then
    SORDINO_BIN_DIR="$plugin_root/bin"
  elif [ -n "$data_dir" ] && sordino__has_both "$data_dir/bin"; then
    SORDINO_BIN_DIR="$data_dir/bin"
  elif [ -n "$workspace" ] && sordino__has_both "$workspace/target/release"; then
    SORDINO_BIN_DIR="$workspace/target/release"
  elif [ "$allow_build" -eq 1 ]; then
    sordino__build_bins || return 1
  else
    return 1
  fi

  if [ -n "${SORDINO_BIN_DIR:-}" ]; then
    case ":$PATH:" in
      *":$SORDINO_BIN_DIR:"*) ;;
      *) PATH="$SORDINO_BIN_DIR:$PATH"; export PATH ;;
    esac
  fi
  return 0
}
