# shellcheck shell=bash
# codex-e2e-lib.sh — shared setup/teardown for the A6 phase-gating Codex assertions.
#
# Sourced by run-codex-assertions.sh. Provides: binary/codex resolution, a per-case
# sandbox builder (isolated $CODEX_HOME + $SORDINO_STATE_DIR + project root + fake
# upstream + masking proxy), the WRITTEN-config plumbing (via the plugin's
# `sordino-hooks codex-config enable`), a real `codex exec` driver, and capture helpers.
#
# Design notes that make these assertions NON-STUBBABLE against a real codex:
#   * The masking proxy is launched DIRECTLY (fixed loopback port) with --project-root,
#     SORDINO_LAUNCH_NONCE and SORDINO_STATE_DIR, so it publishes the project-keyed
#     rendezvous record (port + nonce + admin_key) the REAL hooks read to identity-verify
#     it (verified_proxy_rec / intake_identity_ok / the A8 authed read). No stub stands in
#     for the proxy identity.
#   * Routing config is written by the PLUGIN's `codex-config enable --url ... --hooks-dir`
#     (NOT inline `-c`), which also installs the [hooks] entries. That is the surface A6 locks.
#   * `codex exec` HANGS on stdin unless `</dev/null` is given; the fake upstream MUST return
#     a well-formed Responses SSE `response.completed` or the turn aborts BEFORE the hook step
#     fires — both honored here.
#   * Launch-generation guard: the SessionStart/UserPromptSubmit gate ALLOWs only when the
#     config was present at launch (config mtime <= the rollout's session-start second). codex
#     names the rollout with the current LOCAL second, so a config written milliseconds earlier
#     can lose the comparison. cle_backdate_config backdates config.toml so a freshly-launched
#     routed session passes the guard (models "enabled, THEN restarted codex"). To force the
#     OPPOSITE (U4 mid-session: config newer than launch), cle_forwarddate_config sets a future
#     mtime so launch_generation_ok is false and the gate BLOCKs.

set -uo pipefail

# --- resolved once -----------------------------------------------------------------------
# The proxy/hooks binaries live in the SHARED target the buildCmd populates (the worktree's
# own ./target is empty). Reference them by ABSOLUTE path.
CLE_BIN_DIR="${SORDINO_BIN_DIR:-/home/failspy/Projects/sordino/target/debug}"
CLE_PROXY_BIN="$CLE_BIN_DIR/sordino-proxy"
CLE_HOOKS_BIN="$CLE_BIN_DIR/sordino-hooks"

# The plugin under test (its scripts/ dir holds the hook wrappers; codex-config installs them).
CLE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
CLE_PLUGIN_ROOT="$(cd "$CLE_LIB_DIR/../../codex-sordino-plugin" 2>/dev/null && pwd || true)"

# The HOOK-FIRING codex. Installed /usr/bin/codex (0.140) does NOT fire SessionStart/
# UserPromptSubmit hooks (the turn-loop hook wiring landed after the 0.140 cut), so the
# hook-dependent assertions need codex > 0.140 — the source-built codex-exec.
CLE_CODEX_EXEC="${CODEX_EXEC:-/tmp/codex-build-target/debug/codex-exec}"

# A codex usable for the NON-hook routing/masking assertion. Prefer the hook-firing codex; else fall
# back to a system `codex` (0.140 routes + masks fine, it just doesn't fire hooks). Resolved to an
# absolute path; empty if no codex at all (then even the non-hook assertion skips).
if [ -x "$CLE_CODEX_EXEC" ]; then
  CLE_ANY_CODEX="$CLE_CODEX_EXEC"
elif command -v codex >/dev/null 2>&1; then
  CLE_ANY_CODEX="$(command -v codex)"
else
  CLE_ANY_CODEX=""
fi

# Canary PII.
CLE_EMAIL="zoe.quine@example.com"
CLE_IP="10.55.66.77"

# Per-run port base (each case bumps off this to avoid collisions inside one run).
CLE_PORT_BASE="${SORDINO_E2E_PORT_BASE:-18960}"
CLE_PORT_CURSOR="$CLE_PORT_BASE"

# A run-wide scratch root (cleaned at exit).
CLE_RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/a6-codex-e2e.XXXXXX")"

# Tracked pids to reap on teardown (run-wide) and per-case.
CLE_PIDS=()
CASE_PIDS=()

cle__log()  { printf '%s\n' "$*" >&2; }
cle__die()  { printf 'FATAL: %s\n' "$*" >&2; exit 9; }

# Allocate the next free loopback port (best-effort; kills any squatter first). The cursor MUST
# survive `$(cle_next_port)` command-substitution subshells (a subshell-local `CLE_PORT_CURSOR++`
# would reset every call to base+1, colliding the fake and the proxy on ONE port). So the cursor is
# persisted to a file and incremented there — the file mutation is visible to the parent regardless
# of the subshell the increment runs in.
CLE_PORT_FILE="$CLE_RUN_DIR/.port-cursor"
printf '%s' "$CLE_PORT_CURSOR" > "$CLE_PORT_FILE"
cle_next_port() {
  local cur next
  cur="$(cat "$CLE_PORT_FILE" 2>/dev/null || printf '%s' "$CLE_PORT_BASE")"
  next=$((cur + 1))
  printf '%s' "$next" > "$CLE_PORT_FILE"
  CLE_PORT_CURSOR="$next"   # keep the in-memory cursor advanced too (for teardown's port window)
  fuser -k "${next}/tcp" >/dev/null 2>&1
  printf '%s\n' "$next"
}

# True iff a hook-firing codex (> 0.140) is available. The 0.140 system codex compiles+runs
# but never fires the hooks, so it is NOT sufficient for the hook-dependent assertions.
cle_have_hook_codex() {
  [ -x "$CLE_CODEX_EXEC" ]
}

cle_have_bins() {
  [ -x "$CLE_PROXY_BIN" ] && [ -x "$CLE_HOOKS_BIN" ]
}

# --- a per-case sandbox ------------------------------------------------------------------
# cle_new_case <name>  ->  exports CASE_DIR, CASE_CODEX_HOME, CASE_STATE, CASE_ROOT,
# CASE_CONFIG (the codex config.toml path). Does NOT start anything.
cle_new_case() {
  # Reap the PREVIOUS case's long-lived procs (fake/proxy) so they don't linger or hold ports
  # until script exit — keeps the run quiet and frees ports for later cases.
  local p
  for p in "${CASE_PIDS[@]:-}"; do
    [ -n "$p" ] && kill "$p" >/dev/null 2>&1
  done
  wait "${CASE_PIDS[@]:-}" 2>/dev/null
  CASE_PIDS=()

  local name="$1"
  CASE_DIR="$CLE_RUN_DIR/$name"
  CASE_CODEX_HOME="$CASE_DIR/codex-home"
  CASE_STATE="$CASE_DIR/state"
  CASE_ROOT="$CASE_DIR/proj"
  mkdir -p "$CASE_CODEX_HOME" "$CASE_STATE" "$CASE_ROOT"
  CASE_ROOT="$(cd "$CASE_ROOT" && pwd)"
  CASE_CONFIG="$CASE_CODEX_HOME/config.toml"
  : > "$CASE_DIR/cap.txt"
  CASE_CAP="$CASE_DIR/cap.txt"
}

# Write a sordino.toml for this case's proxy (balanced masking, fake upstream).
cle__write_proxy_config() {
  local proxy_port="$1" fake_port="$2" out="$3"
  cat > "$out" <<EOF
# A6 e2e proxy config: proxy on $proxy_port, upstream is the local fake on $fake_port.
[proxy]
port = $proxy_port
bind = "127.0.0.1"
upstream_base_url = "http://127.0.0.1:$fake_port"

[engine]
profile = "balanced"
score_threshold = 0.5
language = "en"
default_operator = { kind = "token" }
enabled_categories = ["secrets", "financial", "identity", "contact"]
fail_closed = true

[engine.allow_list]
exact = ["OpenAI", "Codex", "127.0.0.1"]
exact_ci = ["localhost"]
patterns = ['^\d{4}$']
EOF
}

# Start the fake OpenAI upstream for this case, capturing to CASE_CAP. Sets CASE_FAKE_PORT.
cle_start_fake() {
  local extra_capfile="${1:-}"
  CASE_FAKE_PORT="$(cle_next_port)"
  # The fake takes (port, capture[, capture2]) — capture2 lets the override-target case use a
  # SECOND fake writing its own capture file.
  if [ -n "$extra_capfile" ]; then
    python3 "$CLE_LIB_DIR/fake_openai.py" "$CASE_FAKE_PORT" "$extra_capfile" \
      > "$CASE_DIR/fake.log" 2>&1 &
  else
    python3 "$CLE_LIB_DIR/fake_openai.py" "$CASE_FAKE_PORT" "$CASE_CAP" \
      > "$CASE_DIR/fake.log" 2>&1 &
  fi
  local pid=$!
  CLE_PIDS+=("$pid"); CASE_PIDS+=("$pid")
  CASE_FAKE_PID="$pid"
  sleep 1
}

# Start a second fake upstream (the override target) capturing to <file>. Echoes the port.
cle_start_second_fake() {
  local capfile="$1"
  local port; port="$(cle_next_port)"
  python3 "$CLE_LIB_DIR/fake_openai.py" "$port" "$capfile" > "$CASE_DIR/fake2.log" 2>&1 &
  local pid=$!
  CLE_PIDS+=("$pid"); CASE_PIDS+=("$pid")
  printf '%s\n' "$port"
}

# Launch THIS case's masking proxy directly (fixed port) against CASE_ROOT. The launch nonce +
# --project-root + SORDINO_STATE_DIR make it publish the project-keyed rendezvous the REAL hooks
# read to identity-verify it. Sets CASE_PROXY_PORT. Waits for /healthz to echo the nonce.
cle_start_proxy() {
  CASE_PROXY_PORT="$(cle_next_port)"
  local cfg="$CASE_DIR/sordino.toml"
  cle__write_proxy_config "$CASE_PROXY_PORT" "$CASE_FAKE_PORT" "$cfg"
  local nonce; nonce="$(printf '%016x' "$RANDOM$RANDOM")"
  SORDINO_STATE_DIR="$CASE_STATE" \
  SORDINO_LAUNCH_NONCE="$nonce" \
  SORDINO_SESSION_SALT="$(printf '%032x' 7)" \
    "$CLE_PROXY_BIN" --project-root "$CASE_ROOT" --config "$cfg" \
    > "$CASE_DIR/proxy.log" 2>&1 &
  local pid=$!
  CLE_PIDS+=("$pid"); CASE_PIDS+=("$pid")
  CASE_PROXY_PID="$pid"
  # Wait (bounded) for the nonce to be echoed on /healthz — proof the rendezvous is published.
  local i nonce_hdr=""
  for i in $(seq 1 30); do
    nonce_hdr="$(curl -sS -m 2 -D - "http://127.0.0.1:$CASE_PROXY_PORT/healthz" -o /dev/null 2>/dev/null \
      | tr -d '\r' | awk -F': ' 'tolower($1)=="x-sordino-nonce"{print $2}')"
    [ -n "$nonce_hdr" ] && break
    sleep 0.2
  done
  if [ "$nonce_hdr" != "$nonce" ]; then
    cle__log "WARN: proxy /healthz nonce mismatch (got '$nonce_hdr', want '$nonce') on :$CASE_PROXY_PORT"
    return 1
  fi
  return 0
}

# Write the routing config + [hooks] via the PLUGIN's codex-config enable. Returns enable's rc
# (0 changed / 3 no-op / non-zero error). url defaults to this case's proxy /v1 root.
cle_enable_routing() {
  local url="${1:-http://127.0.0.1:$CASE_PROXY_PORT/v1}"
  CODEX_HOME="$CASE_CODEX_HOME" SORDINO_STATE_DIR="$CASE_STATE" PATH="$CLE_BIN_DIR:$PATH" \
    "$CLE_HOOKS_BIN" codex-config enable --url "$url" --hooks-dir "$CLE_PLUGIN_ROOT/scripts" \
    > "$CASE_DIR/enable.out" 2> "$CASE_DIR/enable.err"
}

# Write ONLY the [hooks] entries (no routing provider) into config.toml, pointing each hook at the
# given scripts dir. Used for the unrouted U1 fail-closed case and the env-bug regression lock.
# Args: <hooks_dir> [<extra config head text>]
cle_write_hooks_only() {
  local hooks_dir="$1" head="${2:-}"
  {
    [ -n "$head" ] && printf '%s\n\n' "$head"
    cat <<EOF
[[hooks.SessionStart]]
matcher = "*"
hooks = [{ type = "command", command = "$hooks_dir/codex-session-start.sh" }]

[[hooks.UserPromptSubmit]]
matcher = "*"
hooks = [{ type = "command", command = "$hooks_dir/codex-user-prompt-submit.sh" }]
EOF
  } > "$CASE_CONFIG"
}

# Backdate config.toml so a freshly-launched routed session passes the launch-generation guard
# (config present at launch). Default 30s in the past.
cle_backdate_config() {
  local secs="${1:-30}"
  touch -d "$secs seconds ago" "$CASE_CONFIG"
}

# Forward-date config.toml so launch_generation_ok is FALSE (config written AFTER the session
# launched) — the U4 mid-session-enable case. The gate must BLOCK.
cle_forwarddate_config() {
  local secs="${1:-120}"
  touch -d "$secs seconds" "$CASE_CONFIG"
}

# Drive a REAL hook-firing `codex exec` for this case. Routes via the WRITTEN config in
# $CODEX_HOME (NOT inline -c). Extra `-c` overrides may be appended for the override case.
# Args: <prompt> [extra codex args...]
# Honors </dev/null and --dangerously-bypass-hook-trust (automation: the hook sources are vetted —
# they are this repo's own plugin). Captures stdout->CASE_OUT, stderr->CASE_ERR.
cle_run_codex() {
  local prompt="$1"; shift
  CASE_OUT="$CASE_DIR/codex-out.txt"
  CASE_ERR="$CASE_DIR/codex-err.txt"
  # Pick the codex binary: the hook-firing one if present, else any system codex (route-applied is
  # the only assertion that runs without hooks). A `codex-exec` binary is the exec entrypoint
  # directly; a plain `codex` needs the `exec` subcommand prepended.
  local codex_bin="${CLE_CODEX_EXEC}"
  [ -x "$codex_bin" ] || codex_bin="${CLE_ANY_CODEX}"
  local -a subcmd=()
  case "$(basename "$codex_bin")" in
    codex-exec) : ;;            # direct exec entrypoint
    *)          subcmd=(exec) ;; # `codex exec ...`
  esac
  CODEX_HOME="$CASE_CODEX_HOME" \
  SORDINO_STATE_DIR="$CASE_STATE" \
  CODEX_PLUGIN_ROOT="$CLE_PLUGIN_ROOT" \
  OPENAI_API_KEY="${CASE_OPENAI_API_KEY:-sk-sordino-a6-e2e}" \
  PATH="$CLE_BIN_DIR:$PATH" \
    timeout 120 "$codex_bin" "${subcmd[@]}" \
      -c model="gpt-5.5" \
      --dangerously-bypass-hook-trust \
      --skip-git-repo-check -s read-only -C "$CASE_ROOT" \
      "$@" \
      "$prompt" </dev/null > "$CASE_OUT" 2> "$CASE_ERR"
  CASE_CODEX_RC=$?
  return 0
}

# Count plaintext occurrences of <needle> in <file> (0 if file missing). A single clean integer —
# `grep -c` exits 1 on zero matches, so we MUST NOT `|| printf 0` (that would emit a second line);
# instead count matching lines via grep -o + wc, which always exits 0 and prints one number.
cle_count() {
  local needle="$1" file="$2"
  [ -f "$file" ] || { printf '0'; return; }
  local n
  n="$(grep -o -- "$needle" "$file" 2>/dev/null | wc -l | tr -d ' ')"
  printf '%s' "${n:-0}"
}

# Count fixed-string occurrences (for needles with regex metachars). Same single-integer guarantee.
cle_count_f() {
  local needle="$1" file="$2"
  [ -f "$file" ] || { printf '0'; return; }
  local n
  n="$(grep -o -F -- "$needle" "$file" 2>/dev/null | wc -l | tr -d ' ')"
  printf '%s' "${n:-0}"
}

# Seed A8's per-session `last_seen` for <session_id> on THIS case's proxy by routing one real
# masked request through the proxy's session-scoped URL (/sordino/session/<sid>/v1/responses). After
# this, A8's GET /sordino/session/<sid>/routed reports routed_recently=true — the exact "this session
# reached the proxy" signal the override-warn first-turn discriminator keys off. Use an alnum sid so
# the proxy's id-binding is a no-op (the seeded key == the A8 lookup key). Returns curl's rc.
cle_seed_a8_session() {
  local sid="$1"
  curl -sS -m 5 -X POST \
    "http://127.0.0.1:$CASE_PROXY_PORT/sordino/session/$sid/v1/responses" \
    -H 'content-type: application/json' \
    -d '{"model":"gpt-5.5","input":"seed","stream":true}' \
    -o /dev/null 2>/dev/null
}

# Run the REAL codex-user-prompt-submit subcommand once with a synthesized payload. Echoes its stdout
# (the hook JSON). Args: <session_id> <transcript_path> <prompt>
cle_run_ups_subcmd() {
  local sid="$1" roll="$2" prompt="$3"
  CODEX_HOME="$CASE_CODEX_HOME" SORDINO_STATE_DIR="$CASE_STATE" PATH="$CLE_BIN_DIR:$PATH" \
    OPENAI_API_KEY="sk-sordino-a6-e2e" "$CLE_HOOKS_BIN" codex-user-prompt-submit \
    <<<"{\"prompt\":\"$prompt\",\"session_id\":\"$sid\",\"transcript_path\":\"$roll\",\"cwd\":\"$CASE_ROOT\"}" \
    2>/dev/null
}

# Did codex's stderr show the hook reach Completed (not Failed/Blocked) for <event>?
cle_hook_completed() {
  local event="$1" errf="$2"
  grep -qE "hook: $event Completed" "$errf" 2>/dev/null
}

cle_hook_blocked() {
  local event="$1" errf="$2"
  grep -qE "hook: $event Blocked" "$errf" 2>/dev/null
}

# Reap every tracked pid + any port squatters; remove the run dir.
cle_teardown() {
  local p
  for p in "${CLE_PIDS[@]:-}"; do
    [ -n "$p" ] && kill "$p" >/dev/null 2>&1
  done
  # Best-effort: free the whole port window we used this run. Read the upper bound from the cursor
  # FILE (subshell increments don't reach the in-memory CLE_PORT_CURSOR).
  local hi port
  hi="$(cat "$CLE_PORT_FILE" 2>/dev/null || printf '%s' "$CLE_PORT_CURSOR")"
  for port in $(seq "$CLE_PORT_BASE" "$hi"); do
    fuser -k "${port}/tcp" >/dev/null 2>&1
  done
  rm -rf "$CLE_RUN_DIR" 2>/dev/null
}
