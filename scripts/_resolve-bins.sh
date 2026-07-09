#!/usr/bin/env bash
# Shared sordino binary resolver. SOURCE this file (do not execute it).
#
# Makes sordino-proxy/sordino-hooks invocable by name, then prepends the resolved
# dir to PATH (exported) so bare `sordino-proxy` / `sordino-hooks` calls — including
# `sordino-hooks session-start`'s default --proxy-bin "sordino-proxy" — resolve.
#
# Locked precedence (first hit wins):
#   1. PATH                                already installed (e.g. ~/.local/bin)
#   2. ${CLAUDE_PLUGIN_ROOT}/bin/<triple>  prebuilt, shipped per-platform by CI on
#                                          the plugin-dist branch — the NORMAL path
#                                          for a marketplace install (no build, no
#                                          download; binary rides /plugin install)
#   3. ${CLAUDE_PLUGIN_ROOT}/bin           prebuilt, flat (a hand-dropped binary)
#   4. ${CLAUDE_PLUGIN_DATA}/bin           cached from a prior in-repo build
#   5. <workspace>/target/release          an in-repo `cargo build --release`
#   6. cargo build -> ${CLAUDE_PLUGIN_DATA}/bin   last resort (in-repo dev only;
#                                          fetches the pinned git deps, so it needs
#                                          network + access to the dep repos)
#
# <triple> is this host's Rust target triple (uname-derived), matching the per-
# platform dirs CI ships and the sordino-<triple>.tar.gz/.zip release assets. Pass
# --no-build to stop before step 6 (a heavyweight build never makes a down proxy
# answer, so read-only callers just report "unavailable").
#
# All diagnostics go to stderr so a caller that emits hook JSON keeps stdout clean.
# SORDINO_BIN_DIR is set to the resolved dir (empty string when already on PATH).

sordino__warn() { printf '%s\n' "$*" >&2; }

sordino__is_windows_bash() {
  case "$(uname -s 2>/dev/null || true)" in
    MINGW*|MSYS*|CYGWIN*) return 0 ;;
    *) return 1 ;;
  esac
}

# Normalize CLAUDE_PLUGIN_ROOT by re-deriving it from THIS file's own path
# (<plugin_root>/scripts/_resolve-bins.sh) ONLY when the inherited value is missing or in
# native-Windows form. The two cases that break:
#   - UNSET: a slash-command `!bash` block only substitutes ${CLAUDE_PLUGIN_ROOT} into the
#     command STRING; it does NOT export the var, so a sourced script sees it empty and the
#     resolver can't find bin/<triple> ("no prebuilt binary ... no cargo workspace at ''").
#   - NATIVE-WINDOWS form (`C:\Users\...`, i.e. a drive-letter colon or a backslash): under
#     a SessionStart hook on Windows, Claude Code exports it that way, and prepending it to
#     PATH below splits on the drive colon (`C:\...` -> a bogus `C` entry), so
#     `sordino-hooks.exe` isn't found and the proxy never launches.
# `cd ... && pwd` always emits MSYS form (/c/Users/...), which has no colon and prepends
# cleanly. A value already in MSYS/POSIX form (Unix hooks, or Git Bash's /c/...) is correct
# and is LEFT UNTOUCHED, so we never override a good host-provided root with a
# symlink-resolved variant.
case "${CLAUDE_PLUGIN_ROOT:-}" in
  '' | *'\'* | [A-Za-z]:*)
    _zl_pr="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd || true)"
    [ -n "$_zl_pr" ] && export CLAUDE_PLUGIN_ROOT="$_zl_pr"
    unset _zl_pr
    ;;
esac

# This host's Rust target triple, or "" if unsupported (-> falls through to a
# source build). Must match the bin/<triple> dirs CI publishes on plugin-dist and
# the sordino-<triple>.tar.gz/.zip release assets (see .github/workflows/release.yml).
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

# The cargo workspace root for the in-repo dev paths (steps 5-6): $SORDINO_WORKSPACE
# if set, else ${CLAUDE_PLUGIN_ROOT}/.. (in-repo the plugin lives in the workspace).
# For a marketplace install this points into the plugin cache and has no Cargo.toml,
# so the build/target probes simply no-op.
sordino__workspace() {
  if [ -n "${SORDINO_WORKSPACE:-}" ]; then
    printf '%s\n' "$SORDINO_WORKSPACE"
  elif [ -n "${CLAUDE_PLUGIN_ROOT:-}" ]; then
    printf '%s\n' "${CLAUDE_PLUGIN_ROOT}/.."
  fi
}

# True if both binaries are invocable from $1 (or from PATH when $1 is empty).
sordino__has_both() {
  local dir="$1"
  if [ -n "$dir" ]; then
    [ -x "$dir/$SORDINO_PROXY_BIN" ] && [ -x "$dir/$SORDINO_HOOKS_BIN" ]
  else
    command -v "$SORDINO_PROXY_BIN" >/dev/null 2>&1 && command -v "$SORDINO_HOOKS_BIN" >/dev/null 2>&1
  fi
}

# Build both binaries from the cargo workspace into ${CLAUDE_PLUGIN_DATA}/bin.
# In-repo dev fallback only: end users get the prebuilt binaries shipped on the
# plugin-dist branch (steps 2-3) and never reach here.
sordino__build_bins() {
  local data_dir="${CLAUDE_PLUGIN_DATA:-}"
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
    sordino__warn "Sordino: CLAUDE_PLUGIN_DATA is unset; cannot cache a build."
    return 1
  fi

  sordino__warn "Sordino: building proxy/hooks from $workspace (first run; fetches pinned git deps, cached afterward)…"
  # cargo's own output goes to stderr to keep stdout clean for any hook JSON.
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

# Resolve both binaries and prepend their dir to PATH (exported). Idempotent.
# Returns non-zero (with a stderr explanation) if they can't be resolved.
sordino_resolve_bins() {
  local allow_build=1
  if [ "${1:-}" = "--no-build" ]; then allow_build=0; fi
  local plugin_root="${CLAUDE_PLUGIN_ROOT:-}"
  local data_dir="${CLAUDE_PLUGIN_DATA:-}"
  local triple; triple="$(sordino__host_triple)"
  local workspace; workspace="$(sordino__workspace)"
  SORDINO_BIN_DIR=""

  if sordino__has_both ""; then
    :                                                                 # 1. PATH
  elif [ -n "$plugin_root" ] && [ -n "$triple" ] \
       && sordino__has_both "$plugin_root/bin/$triple"; then
    SORDINO_BIN_DIR="$plugin_root/bin/$triple"                        # 2. shipped, per-platform
  elif [ -n "$plugin_root" ] && sordino__has_both "$plugin_root/bin"; then
    SORDINO_BIN_DIR="$plugin_root/bin"                                # 3. shipped, flat
  elif [ -n "$data_dir" ] && sordino__has_both "$data_dir/bin"; then
    SORDINO_BIN_DIR="$data_dir/bin"                                   # 4. cached build
  elif [ -n "$workspace" ] && sordino__has_both "$workspace/target/release"; then
    SORDINO_BIN_DIR="$workspace/target/release"                      # 5. in-repo dev build
  elif [ "$allow_build" -eq 1 ]; then
    sordino__build_bins || return 1                                  # 6. build (dev last resort)
  else
    return 1
  fi

  if [ -n "${SORDINO_BIN_DIR:-}" ]; then
    case ":$PATH:" in
      *":$SORDINO_BIN_DIR:"*) ;;                                     # already present
      *) PATH="$SORDINO_BIN_DIR:$PATH"; export PATH ;;
    esac
  fi
  return 0
}
