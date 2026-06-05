#!/usr/bin/env bash
# Shared zlauder binary resolver. SOURCE this file (do not execute it).
#
# Makes zlauder-proxy/zlauder-hooks invocable by name, then prepends the resolved
# dir to PATH (exported) so bare `zlauder-proxy` / `zlauder-hooks` calls — including
# `zlauder-hooks session-start`'s default --proxy-bin "zlauder-proxy" — resolve.
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
# platform dirs CI ships and the zlauder-<triple>.tar.gz release assets. Pass
# --no-build to stop before step 6 (a heavyweight build never makes a down proxy
# answer, so read-only callers just report "unavailable").
#
# All diagnostics go to stderr so a caller that emits hook JSON keeps stdout clean.
# ZLAUDER_BIN_DIR is set to the resolved dir (empty string when already on PATH).

zlauder__warn() { printf '%s\n' "$*" >&2; }

# Repair CLAUDE_PLUGIN_ROOT when it isn't in the environment. Claude Code exports
# it to SessionStart *hook* processes, but a slash-command `!bash` block only
# substitutes ${CLAUDE_PLUGIN_ROOT} into the command STRING — it does NOT export the
# var to that subprocess. A sourced script reading the env var would then see it
# empty, so the resolver can't find bin/<triple> and the workspace probe is blank
# (observed: `/zlauder:enable` -> "no prebuilt binary ... no cargo workspace at ''").
# Derive it from THIS file's path (<plugin_root>/scripts/_resolve-bins.sh) and export
# it, so every consumer in the sourcing script (binary resolution AND e.g. enable.sh's
# zlauder.toml seeding) sees a consistent value. No-op under a hook, where it's set.
if [ -z "${CLAUDE_PLUGIN_ROOT:-}" ]; then
  _zl_pr="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd || true)"
  [ -n "$_zl_pr" ] && export CLAUDE_PLUGIN_ROOT="$_zl_pr"
  unset _zl_pr
fi

# This host's Rust target triple, or "" if unsupported (-> falls through to a
# source build). Must match the bin/<triple> dirs CI publishes on plugin-dist and
# the zlauder-<triple>.tar.gz release assets (see .github/workflows/release.yml).
zlauder__host_triple() {
  local os arch
  os="$(uname -s 2>/dev/null || true)"
  arch="$(uname -m 2>/dev/null || true)"
  case "$os" in
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

# The cargo workspace root for the in-repo dev paths (steps 5-6): $ZLAUDER_WORKSPACE
# if set, else ${CLAUDE_PLUGIN_ROOT}/.. (in-repo the plugin lives in the workspace).
# For a marketplace install this points into the plugin cache and has no Cargo.toml,
# so the build/target probes simply no-op.
zlauder__workspace() {
  if [ -n "${ZLAUDER_WORKSPACE:-}" ]; then
    printf '%s\n' "$ZLAUDER_WORKSPACE"
  elif [ -n "${CLAUDE_PLUGIN_ROOT:-}" ]; then
    printf '%s\n' "${CLAUDE_PLUGIN_ROOT}/.."
  fi
}

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
# In-repo dev fallback only: end users get the prebuilt binaries shipped on the
# plugin-dist branch (steps 2-3) and never reach here.
zlauder__build_bins() {
  local data_dir="${CLAUDE_PLUGIN_DATA:-}"
  local workspace; workspace="$(zlauder__workspace)"
  if [ -z "$workspace" ] || [ ! -f "$workspace/Cargo.toml" ]; then
    zlauder__warn "zlauder: no prebuilt binary for this platform and no cargo workspace at \"${workspace:-<unset>}\"."
    zlauder__warn "zlauder: install a release onto PATH, or set \$ZLAUDER_WORKSPACE to a zlauder checkout."
    return 1
  fi
  if ! command -v cargo >/dev/null 2>&1; then
    zlauder__warn "zlauder: no prebuilt binary for this platform and cargo not found; cannot build. Install a release onto PATH."
    return 1
  fi
  if [ -z "$data_dir" ]; then
    zlauder__warn "zlauder: CLAUDE_PLUGIN_DATA is unset; cannot cache a build."
    return 1
  fi

  zlauder__warn "zlauder: building proxy/hooks from $workspace (first run; fetches pinned git deps, cached afterward)…"
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
  local triple; triple="$(zlauder__host_triple)"
  local workspace; workspace="$(zlauder__workspace)"
  ZLAUDER_BIN_DIR=""

  if zlauder__has_both ""; then
    :                                                                 # 1. PATH
  elif [ -n "$plugin_root" ] && [ -n "$triple" ] \
       && zlauder__has_both "$plugin_root/bin/$triple"; then
    ZLAUDER_BIN_DIR="$plugin_root/bin/$triple"                        # 2. shipped, per-platform
  elif [ -n "$plugin_root" ] && zlauder__has_both "$plugin_root/bin"; then
    ZLAUDER_BIN_DIR="$plugin_root/bin"                                # 3. shipped, flat
  elif [ -n "$data_dir" ] && zlauder__has_both "$data_dir/bin"; then
    ZLAUDER_BIN_DIR="$data_dir/bin"                                   # 4. cached build
  elif [ -n "$workspace" ] && zlauder__has_both "$workspace/target/release"; then
    ZLAUDER_BIN_DIR="$workspace/target/release"                      # 5. in-repo dev build
  elif [ "$allow_build" -eq 1 ]; then
    zlauder__build_bins || return 1                                  # 6. build (dev last resort)
  else
    return 1
  fi

  if [ -n "${ZLAUDER_BIN_DIR:-}" ]; then
    case ":$PATH:" in
      *":$ZLAUDER_BIN_DIR:"*) ;;                                     # already present
      *) PATH="$ZLAUDER_BIN_DIR:$PATH"; export PATH ;;
    esac
  fi
  return 0
}
