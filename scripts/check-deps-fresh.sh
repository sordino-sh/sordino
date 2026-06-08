#!/usr/bin/env bash
#
# Freshness gate for branch-tracked git dependencies.
#
# WHY THIS EXISTS
#   v0.6.1 shipped a UTF-8 panic because presidio-rs was declared
#   `branch = "main"` in Cargo.toml but Cargo.lock froze a commit ~36h behind
#   the fix that had already landed on presidio's main. `--locked` CI then
#   faithfully reproduced the stale pin into the release binaries. `branch =`
#   in Cargo.toml does NOT mean "always latest" — cargo resolves it to a SHA
#   once, writes the lock, and never re-checks until something runs
#   `cargo update`. Nothing did before the tag.
#
# WHAT THIS DOES
#   For every git dependency in Cargo.lock that TRACKS A BRANCH
#   (source = "...?branch=<b>#<sha>"), compare the locked <sha> to the live tip
#   of <b>. If the lock is behind, list the commits it is missing.
#   `rev =`-pinned deps are deliberate freezes and are skipped.
#
# MODES
#   --strict (default)  exit 1 if any branch-tracked dep is behind, OR if a tip
#                       cannot be resolved (fail closed). Use as a release gate.
#   --warn              annotate and always exit 0. Use as a CI drift signal.
#
# AUTH
#   Set DEPS_TOKEN to read private dep repos. The script token-injects the
#   fetch URL itself, so it also works under a global `insteadOf` rewrite or
#   with a developer's own git credentials when run locally.
#
# USAGE
#   scripts/check-deps-fresh.sh [--strict|--warn] [path/to/Cargo.lock]
set -euo pipefail

mode="strict"
lockfile="Cargo.lock"
for arg in "$@"; do
  case "$arg" in
    --strict) mode="strict" ;;
    --warn)   mode="warn" ;;
    -*)       echo "usage: $0 [--strict|--warn] [Cargo.lock]" >&2; exit 2 ;;
    *)        lockfile="$arg" ;;
  esac
done

[ -f "$lockfile" ] || { echo "::error::$lockfile not found (run from repo root)"; exit 2; }

# error in strict mode, warning in warn mode — drives the GitHub annotation level
lvl="error"; [ "$mode" = "warn" ] && lvl="warning"

# Inject DEPS_TOKEN into a github.com https URL for private-repo reads. No-op if
# the token is unset (anonymous fetch — fine once the dep repos are public, or
# when a developer's own credentials / a global insteadOf rewrite already apply).
authed() {
  local url="$1"
  if [ -n "${DEPS_TOKEN:-}" ]; then
    printf '%s' "${url/https:\/\/github.com\//https://x-access-token:${DEPS_TOKEN}@github.com/}"
  else
    printf '%s' "$url"
  fi
}

# Unique "url<TAB>branch<TAB>sha" for every branch-tracked git dep.
deps="$(
  grep -oE 'git\+https://[^"]+\?branch=[^#"]+#[0-9a-f]{40}' "$lockfile" \
    | sed -E 's|^git\+(https://[^?]+)\?branch=([^#]+)#([0-9a-f]+)$|\1\t\2\t\3|' \
    | sort -u
)"

if [ -z "$deps" ]; then
  echo "no branch-tracked git dependencies in $lockfile — nothing to check."
  exit 0
fi

behind=0
unresolved=0

while IFS=$'\t' read -r url branch sha; do
  [ -n "$url" ] || continue
  name="${url##*/}"; name="${name%.git}"

  tip="$(git ls-remote "$(authed "$url")" "refs/heads/$branch" 2>/dev/null | cut -f1)" || true

  if [ -z "$tip" ]; then
    unresolved=1
    echo "::${lvl}::${name}: cannot resolve ${branch} tip (auth/network?) — locked ${sha:0:12}"
    continue
  fi

  if [ "$sha" = "$tip" ]; then
    echo "ok: ${name} @ ${branch} tip (${sha:0:12})"
    continue
  fi

  behind=1
  echo "::${lvl}::${name} is BEHIND ${branch} — locked ${sha:0:12}, ${branch} tip ${tip:0:12}"

  # Best-effort: enumerate the commits the lock is missing, so reviewers see
  # exactly what a release would ship without (this is what surfaced the
  # UTF-8 fix in the post-mortem). Failure here never changes the verdict.
  tmp="$(mktemp -d)"
  if git -C "$tmp" init -q \
     && git -C "$tmp" fetch -q --depth=100 "$(authed "$url")" "$branch" 2>/dev/null \
     && git -C "$tmp" cat-file -e "${sha}^{commit}" 2>/dev/null; then
    echo "    commits on ${branch} not in the locked pin:"
    git -C "$tmp" log --no-merges --format='      %h %ci %s' "${sha}..FETCH_HEAD" 2>/dev/null | head -40 || true
  else
    echo "    (locked commit not within last 100 of ${branch}; lock is far behind or diverged)"
  fi
  rm -rf "$tmp"
done <<< "$deps"

echo
if [ "$behind" -eq 0 ] && [ "$unresolved" -eq 0 ]; then
  echo "All branch-tracked git deps are at their branch tip."
  exit 0
fi

if [ "$mode" = "warn" ]; then
  echo "drift detected (warn mode) — not failing the build."
  exit 0
fi

cat >&2 <<'EOF'

A branch-tracked git dependency is behind its upstream branch (or unverifiable).
A release cut now would ship the stale pin — exactly the v0.6.1 failure.

To fix, pull the latest into the lockfile and re-commit:

    cargo update -p <crate> [-p <crate> ...]
    git add Cargo.lock && git commit -m "deps: pull latest branch-tracked git deps"

If a pin is INTENTIONAL (you do not want the branch tip), make the freeze
explicit so this gate skips it: switch that dep from
    { git = "...", branch = "main", ... }
to
    { git = "...", rev = "<sha>", ... }
in Cargo.toml. An explicit rev is a deliberate, reviewable freeze; a branch
pin that silently lags is the footgun.
EOF
exit 1
