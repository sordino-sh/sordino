#!/usr/bin/env bash
# Regression guard for GH #2: macOS ships /bin/bash 3.2, where expanding an EMPTY
# array with `set -u` — `"${ARR[@]}"` — is a fatal "unbound variable" error (bash
# 4.4+ treats it as legal and expands to nothing). Every plugin hook/command script
# runs `set -u` and several build an argv array (PORT_ARGS, CFG_ARGS, MODEL_ARGS)
# that is empty in an unrouted first session, so a bare expansion crashes the whole
# hook on macOS before the proxy ever launches.
#
# The fix — and the ONLY form allowed in a shipped script — is the guarded idiom
#     ${ARR[@]+"${ARR[@]}"}
# which is a no-op on bash 4.4+ and expands to nothing (NOT a spurious empty arg,
# unlike "${ARR[@]:-}") on bash 3.2.
#
# This test is static: it greps the shipped scripts for any TRULY-bare "${name[@]}"
# / "${name[*]}" (i.e. not the inner half of the guarded form) and fails listing
# every offender with file:line. It needs no bash 3.2 and no built binary, so it
# runs on the cheap Linux CI job and catches the whole bug class at author time.
#
# POSIX-bash; GNU- and BSD-portable (sed -E / grep -E only, no grep -P).

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# Shipped hook/command scripts to guard. Test files (*.test.sh) are excluded — they
# are not run as hooks and may carry pattern literals for matching.
SCRIPT_DIRS=(
  "$REPO_ROOT/sordino-plugin/scripts"
  "$REPO_ROOT/codex-sordino-plugin/scripts"
  "$REPO_ROOT/codex-sordino-plugin/skills/sordino-openai/scripts"
)

# The guarded idiom, as an ERE, so we can delete it before hunting for bare forms.
# Matches ${NAME[@]+"${NAME[@]}"} (and the [*] variant).
GUARDED='\$\{[A-Za-z_][A-Za-z0-9_]*\[[@*]\]\+"\$\{[A-Za-z_][A-Za-z0-9_]*\[[@*]\]\}"\}'
# A truly-bare array expansion: "${NAME[@]}" / "${NAME[*]}" with no +/:-/- modifier.
BARE='"\$\{[A-Za-z_][A-Za-z0-9_]*\[[@*]\]\}"'

scanned=0
offenders=0
for dir in "${SCRIPT_DIRS[@]}"; do
  [ -d "$dir" ] || continue
  for f in "$dir"/*.sh; do
    [ -e "$f" ] || continue
    case "$f" in *.test.sh) continue ;; esac
    scanned=$((scanned + 1))
    rel="${f#"$REPO_ROOT"/}"
    # Delete every guarded occurrence first, THEN look for any surviving bare one.
    # sed keeps line count intact, so grep -n reports the real source line.
    hits="$(sed -E "s/$GUARDED//g" "$f" | grep -nE "$BARE" || true)"
    if [ -n "$hits" ]; then
      while IFS= read -r line; do
        [ -n "$line" ] || continue
        printf '  %s:%s\n' "$rel" "$line" >&2
        offenders=$((offenders + 1))
      done <<EOF
$hits
EOF
    fi
  done
done

[ "$scanned" -gt 0 ] || fail "no shipped scripts found under ${SCRIPT_DIRS[*]} — path drift?"

if [ "$offenders" -gt 0 ]; then
  fail "$offenders bare array expansion(s) found (see above). Use \${NAME[@]+\"\${NAME[@]}\"} — bash 3.2 aborts on a bare \"\${NAME[@]}\" under set -u (GH #2)."
fi

printf 'OK: no bare array expansions in %d shipped plugin scripts (bash-3.2-safe, GH #2)\n' "$scanned"
exit 0
