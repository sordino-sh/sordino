#!/usr/bin/env bash
# Self-contained test for _resolve-bins.sh's plugin-root/-data env-var resolution.
# Proves the A4 fix: the resolver keys on the env vars Codex actually injects
# (CLAUDE_PLUGIN_ROOT / PLUGIN_ROOT, CLAUDE_PLUGIN_DATA / PLUGIN_DATA) and NOT only
# the CODEX_ names, while the no-env BASH_SOURCE fallback still works.
#
# Each case runs in a subshell so env mutations (PATH, exported vars) don't leak.
# POSIX-bash, coreutils only.

set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/_resolve-bins.sh"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# Host triple computed exactly as the script does (uname -s / -m).
host_triple() {
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

exe_suffix() {
  case "$(uname -s 2>/dev/null || true)" in
    MINGW*|MSYS*|CYGWIN*) printf '%s\n' ".exe" ;;
  esac
}

TRIPLE="$(host_triple)"
[ -n "$TRIPLE" ] || fail "could not compute host triple for $(uname -s)/$(uname -m); update the test's triple map"
SUF="$(exe_suffix)"

# A PATH that still resolves coreutils (uname etc. — the script calls them) but contains NO
# real sordino-proxy/sordino-hooks, so the on-PATH `command -v` branch can't shadow the
# plugin-root resolution we want to assert. Build it from the dir(s) that hold the coreutils
# the script needs, plus a guaranteed-empty prefix; deliberately EXCLUDE the inherited PATH so
# an installed/built sordino release on it can't win the `command -v` branch first.
CLEAN_PATH="/nonexistent-sordino-test-path"
for _tool in uname dirname cd pwd; do
  _p="$(command -v "$_tool" 2>/dev/null || true)"
  case "$_p" in
    /*) _d="$(dirname "$_p")"; case ":$CLEAN_PATH:" in *":$_d:"*) : ;; *) CLEAN_PATH="$CLEAN_PATH:$_d" ;; esac ;;
  esac
done
unset _tool _p _d
# Fallback if the probe came up empty (e.g. cd is a builtin with no path): add the usual dirs.
case ":$CLEAN_PATH:" in
  *:/bin:*|*:/usr/bin:*) : ;;
  *) CLEAN_PATH="$CLEAN_PATH:/usr/bin:/bin" ;;
esac
# Sanity: the script's coreutils must be reachable on CLEAN_PATH, and sordino bins must NOT be.
if ! PATH="$CLEAN_PATH" command -v uname >/dev/null 2>&1; then
  fail "test setup: uname not reachable on CLEAN_PATH ($CLEAN_PATH)"
fi
if PATH="$CLEAN_PATH" command -v "sordino-proxy${SUF}" >/dev/null 2>&1; then
  fail "test setup: a real sordino-proxy is on CLEAN_PATH and would shadow plugin-root resolution"
fi

# Build a fake plugin-root dir with executable proxy/hooks stubs under bin/<triple>/.
D="$(mktemp -d)"
trap 'rm -rf "$D"' EXIT
mkdir -p "$D/bin/$TRIPLE"
for b in "sordino-proxy${SUF}" "sordino-hooks${SUF}"; do
  printf '#!/bin/sh\nexit 0\n' > "$D/bin/$TRIPLE/$b"
  chmod +x "$D/bin/$TRIPLE/$b"
done

# CASE 1 (core fix): ONLY CLAUDE_PLUGIN_ROOT set; CODEX_PLUGIN_ROOT and PLUGIN_ROOT unset.
(
  unset CODEX_PLUGIN_ROOT PLUGIN_ROOT CLAUDE_PLUGIN_ROOT \
        CODEX_PLUGIN_DATA PLUGIN_DATA CLAUDE_PLUGIN_DATA \
        SORDINO_WORKSPACE SORDINO_BIN_DIR 2>/dev/null || true
  export CLAUDE_PLUGIN_ROOT="$D"
  # Ensure no on-PATH bins shadow the plugin-root resolution we want to assert.
  export PATH="$CLEAN_PATH"
  # shellcheck disable=SC1090
  . "$SCRIPT"
  if ! sordino_resolve_bins --no-build; then
    fail "CASE 1: sordino_resolve_bins --no-build returned non-zero with CLAUDE_PLUGIN_ROOT set"
  fi
  [ "${SORDINO_BIN_DIR:-}" = "$D/bin/$TRIPLE" ] \
    || fail "CASE 1: SORDINO_BIN_DIR='${SORDINO_BIN_DIR:-}' != expected '$D/bin/$TRIPLE'"
  case ":$PATH:" in
    *":$D/bin/$TRIPLE:"*) : ;;
    *) fail "CASE 1: $D/bin/$TRIPLE not prepended to PATH ($PATH)" ;;
  esac
) || exit 1

# CASE 2 (PLUGIN_ROOT alias): ONLY PLUGIN_ROOT set.
(
  unset CODEX_PLUGIN_ROOT PLUGIN_ROOT CLAUDE_PLUGIN_ROOT \
        CODEX_PLUGIN_DATA PLUGIN_DATA CLAUDE_PLUGIN_DATA \
        SORDINO_WORKSPACE SORDINO_BIN_DIR 2>/dev/null || true
  export PLUGIN_ROOT="$D"
  export PATH="$CLEAN_PATH"
  # shellcheck disable=SC1090
  . "$SCRIPT"
  if ! sordino_resolve_bins --no-build; then
    fail "CASE 2: sordino_resolve_bins --no-build returned non-zero with PLUGIN_ROOT set"
  fi
  [ "${SORDINO_BIN_DIR:-}" = "$D/bin/$TRIPLE" ] \
    || fail "CASE 2: SORDINO_BIN_DIR='${SORDINO_BIN_DIR:-}' != expected '$D/bin/$TRIPLE'"
) || exit 1

# CASE 3 (fallback intact): no plugin-root env vars; sourced from within the plugin tree.
# Must not crash under `set -u`; must either resolve via the BASH_SOURCE-derived root if bins
# happen to live there, or return non-zero CLEANLY (no syntax / unbound-variable error).
(
  unset CODEX_PLUGIN_ROOT PLUGIN_ROOT CLAUDE_PLUGIN_ROOT \
        CODEX_PLUGIN_DATA PLUGIN_DATA CLAUDE_PLUGIN_DATA \
        SORDINO_WORKSPACE SORDINO_BIN_DIR 2>/dev/null || true
  export PATH="$CLEAN_PATH"
  # shellcheck disable=SC1090
  . "$SCRIPT"
  # The source itself runs the BASH_SOURCE re-derivation case under set -u; reaching here
  # already proves no unbound-variable abort at source time. Now exercise the resolver.
  rc=0
  sordino_resolve_bins --no-build || rc=$?
  # rc is 0 (resolved from a real workspace/plugin-tree bin) or non-zero (clean no-resolve).
  # Either is acceptable; the assertion is that we got HERE without an errexit/set -u abort.
  case "$rc" in
    ''|*[!0-9]*) fail "CASE 3: unexpected return code '$rc'" ;;
  esac
) || exit 1

# CASE 4 (precedence under conflict): a STALE/foreign CODEX_PLUGIN_ROOT pointing at a dir with
# NO bins, plus the FRESH injected CLAUDE_PLUGIN_ROOT pointing at the real fake-plugin root. The
# injected var must WIN — otherwise the stale CODEX_PLUGIN_ROOT shadows it and the resolver (and
# enable.sh, which writes CODEX_PLUGIN_ROOT/scripts into config.toml) wires the wrong plugin copy.
(
  STALE="$(mktemp -d)"            # deliberately empty: no bin/<triple>/ under it
  unset PLUGIN_ROOT CLAUDE_PLUGIN_ROOT \
        CODEX_PLUGIN_DATA PLUGIN_DATA CLAUDE_PLUGIN_DATA \
        SORDINO_WORKSPACE SORDINO_BIN_DIR 2>/dev/null || true
  export CODEX_PLUGIN_ROOT="$STALE"     # stale/foreign, inherited from a prior context
  export CLAUDE_PLUGIN_ROOT="$D"        # fresh, injected by Codex this launch
  export PATH="$CLEAN_PATH"
  # shellcheck disable=SC1090
  . "$SCRIPT"
  if ! sordino_resolve_bins --no-build; then
    rm -rf "$STALE"
    fail "CASE 4: resolver returned non-zero — injected CLAUDE_PLUGIN_ROOT should have resolved"
  fi
  if [ "${SORDINO_BIN_DIR:-}" != "$D/bin/$TRIPLE" ]; then
    rm -rf "$STALE"
    fail "CASE 4: stale CODEX_PLUGIN_ROOT shadowed injected CLAUDE_PLUGIN_ROOT — SORDINO_BIN_DIR='${SORDINO_BIN_DIR:-}' != '$D/bin/$TRIPLE'"
  fi
  # The normalized canonical var must also hold the injected root, not the stale one.
  if [ "${CODEX_PLUGIN_ROOT:-}" != "$D" ]; then
    rm -rf "$STALE"
    fail "CASE 4: CODEX_PLUGIN_ROOT normalized to '${CODEX_PLUGIN_ROOT:-}' != injected '$D'"
  fi
  rm -rf "$STALE"
) || exit 1

printf 'OK: all _resolve-bins.sh resolver cases passed (triple=%s)\n' "$TRIPLE"
exit 0
