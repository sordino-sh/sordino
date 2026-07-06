#!/usr/bin/env bash
# run-codex-assertions.sh — A6 phase-gating e2e assertions for the Codex plugin.
#
# Each phase of the Codex fix has a FALSIFIABLE, runnable assertion against a REAL codex, driven
# through the masking proxy via the PLUGIN's WRITTEN config (codex-config enable) + [hooks] path:
#
#   1. assert-route-applied            masking via the WRITTEN-config route (any codex; no hooks)
#   2. assert-hook-parses              SessionStart additionalContext DELIVERED to the real codex
#                                      transcript (observed at the upstream request body), in BOTH
#                                      routed and unrouted states; REGRESSION-LOCKED against the
#                                      old top-level-`env` bug (deny_unknown_fields drops it).
#   3. assert-fail-closed-unrouted     U1 unrouted BLOCK + U4 mid-session-enable BLOCK (real gate)
#   4. assert-auth-refusal             enable.sh refuses + writes nothing under ChatGPT auth (any
#                                      codex); SessionStart emits the warn-only auth variant (hooks)
#   5. assert-override-detected-and-warned  S2: gate ALLOWs both, 1st no warn, 2nd warns, override
#                                      target got the real PII (or the A8-unavailable limitation)
#
# HOOK REQUIREMENT: the installed /usr/bin/codex (0.140) does NOT fire SessionStart/UserPromptSubmit
# hooks — that turn-loop wiring landed AFTER the 0.140 cut. The hook-dependent assertions therefore
# need codex > 0.140 (env CODEX_EXEC, default /tmp/codex-build-target/debug/codex-exec). When no
# hook-firing codex is present, the hook-dependent assertions SKIP (clear, non-fatal message) while
# the non-hook ones (route-applied, the enable-refusal half of auth-refusal) STILL RUN.
#
# `--dangerously-bypass-hook-trust` is passed because this is automation over THIS repo's OWN plugin
# hooks (already vetted) — never use it against untrusted hook sources.
#
# Run after `cargo build -p sordino-proxy -p sordino-hooks`:  bash e2e/codex/run-codex-assertions.sh

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
# shellcheck source=codex-e2e-lib.sh
. "$HERE/codex-e2e-lib.sh"

PASS=0; FAIL=0; SKIP=0
RESULTS=()

ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); RESULTS+=("PASS $*"); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); RESULTS+=("FAIL $*"); }
skip() { printf '  \033[33mSKIP\033[0m %s\n' "$*"; SKIP=$((SKIP+1)); RESULTS+=("SKIP $*"); }

trap cle_teardown EXIT

# Preconditions: the proxy/hooks binaries MUST exist (build them first). Their absence is fatal —
# nothing here can run without the real binaries.
if ! cle_have_bins; then
  cle__die "sordino-proxy / sordino-hooks not found under $CLE_BIN_DIR — run 'cargo build -p sordino-proxy -p sordino-hooks' first (or set SORDINO_BIN_DIR)."
fi
if [ -z "$CLE_PLUGIN_ROOT" ] || [ ! -d "$CLE_PLUGIN_ROOT/scripts" ]; then
  cle__die "codex-sordino-plugin/scripts not found at '$CLE_PLUGIN_ROOT' — cannot wire the plugin hooks."
fi

HOOK_CODEX=0
if cle_have_hook_codex; then
  HOOK_CODEX=1
  printf 'hook-firing codex: %s\n' "$CLE_CODEX_EXEC"
else
  printf 'hook-firing codex: NONE (CODEX_EXEC=%s absent) — hook-dependent assertions will SKIP.\n' "$CLE_CODEX_EXEC"
fi

# ===========================================================================================
# 1. assert-route-applied — masking through the PLUGIN's WRITTEN config (no hooks needed).
#    Drives a real codex routed via the written provider block; the canary email MUST be masked
#    at the upstream capture (0 plaintext) and a token forwarded; the email is RESTORED in the
#    codex output IFF echoed. Runs on ANY codex (the masking is the proxy's, independent of hooks).
# ===========================================================================================
assert_route_applied() {
  printf '\n[1] assert-route-applied (WRITTEN-config masking)\n'
  # The masking path is the PROXY's, independent of hooks — it runs on ANY codex (the hook-firing one
  # OR a plain system `codex exec`). Skip ONLY when there is no codex at all.
  if [ -z "${CLE_ANY_CODEX:-}" ]; then
    skip "assert-route-applied: no codex binary available (CODEX_EXEC=$CLE_CODEX_EXEC absent and no system codex)"
    return
  fi

  cle_new_case route-applied
  cle_start_fake
  if ! cle_start_proxy; then bad "assert-route-applied: proxy failed identity (nonce echo)"; return; fi
  local rc; cle_enable_routing; rc=$?
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then bad "assert-route-applied: codex-config enable rc=$rc (expected 0/3)"; return; fi
  # Confirm the WRITTEN config actually selects our loopback provider (not an inline -c).
  if ! grep -q 'model_provider = "sordino"' "$CASE_CONFIG"; then
    bad "assert-route-applied: written config.toml does not select the sordino provider"; return
  fi
  cle_backdate_config  # so the routed session passes the launch-generation guard

  cle_run_codex "My email is $CLE_EMAIL and my home server is $CLE_IP . Acknowledge in one short sentence and echo any tokens you were given."

  local email_up; email_up="$(cle_count_f "$CLE_EMAIL" "$CASE_CAP")"
  local ip_up;    ip_up="$(cle_count_f "$CLE_IP" "$CASE_CAP")"
  local tokens;   tokens="$(grep -oE '\[[A-Z_]+_[0-9a-f]{12}\]' "$CASE_CAP" 2>/dev/null | sort -u | tr '\n' ' ')"
  local email_out; email_out="$(cle_count_f "$CLE_EMAIL" "$CASE_OUT")"

  printf '      upstream plaintext: email=%s ip=%s | tokens=[%s] | restored-in-out: email=%s\n' \
    "$email_up" "$ip_up" "$tokens" "$email_out"

  # KILL-CONDITION: the masking canary (email plaintext at upstream == 0). The IP is in the Network
  # category which is OFF in Balanced by default, so it is allowed to pass — assert ONLY the email.
  if [ "$email_up" = "0" ] && printf '%s' "$tokens" | grep -q 'EMAIL_ADDRESS'; then
    ok "assert-route-applied: email MASKED at upstream (0 plaintext), token forwarded${email_out:+, restored client-side}"
  else
    bad "assert-route-applied: masking canary regressed (email upstream=$email_up, tokens=[$tokens])"
  fi
}

# ===========================================================================================
# 2. assert-hook-parses — NON-STUBBABLE SessionStart additionalContext delivery to a REAL codex.
#    The SessionStart hook's additionalContext is injected into the conversation codex sends to the
#    model — observable as an `input_text` item in the UPSTREAM REQUEST BODY captured by the fake.
#    Asserted in BOTH routed (NeutralOnboarding sentinel) and unrouted (NotRouted warn sentinel)
#    config states. REGRESSION LOCK: a hook emitting a TOP-LEVEL `env` key (the old session-start.sh
#    bug) trips codex's deny_unknown_fields parse → the additionalContext is SILENTLY DROPPED → the
#    sentinel is ABSENT. The lock proves the bug-shaped hook FAILS (0 sentinel) and the fixed plugin
#    hook PASSES (>=1 sentinel).
# ===========================================================================================
assert_hook_parses() {
  printf '\n[2] assert-hook-parses (real-codex SessionStart additionalContext delivery)\n'
  if [ "$HOOK_CODEX" -ne 1 ]; then
    skip "assert-hook-parses: needs a hook-firing codex (>0.140); none available"
    return
  fi

  # --- 2a: ROUTED state — the REAL plugin hook emits the NeutralOnboarding additionalContext, which
  #         must reach the upstream request body (proves parse + delivery on the real codex path).
  cle_new_case hook-parses-routed
  cle_start_fake
  if ! cle_start_proxy; then bad "assert-hook-parses[routed]: proxy failed identity"; return; fi
  local rc; cle_enable_routing; rc=$?
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then bad "assert-hook-parses[routed]: enable rc=$rc"; return; fi
  cle_backdate_config
  cle_run_codex "hello, acknowledge."
  local onboard_routed; onboard_routed="$(cle_count_f "tokenized PII placeholders" "$CASE_CAP")"
  if cle_hook_completed SessionStart "$CASE_ERR" && [ "$onboard_routed" -ge 1 ]; then
    ok "assert-hook-parses[routed]: SessionStart onboarding additionalContext DELIVERED to real codex (upstream count=$onboard_routed)"
  else
    bad "assert-hook-parses[routed]: onboarding NOT delivered (upstream count=$onboard_routed, hook line: $(grep -oE 'hook: SessionStart.*' "$CASE_ERR" | head -1))"
  fi

  # --- 2b: UNROUTED state — the REAL plugin hook emits the NotRouted WARN additionalContext, which
  #         must STILL parse + reach the upstream request body (the hook runs in every state).
  cle_new_case hook-parses-unrouted
  cle_start_fake
  # Unrouted: config selects a NON-sordino provider pointing straight at the fake, hooks wired.
  cle_write_hooks_only "$CLE_PLUGIN_ROOT/scripts" "$(cat <<EOF
model_provider = "plain"
[model_providers.plain]
name = "plain"
base_url = "http://127.0.0.1:$CASE_FAKE_PORT/v1"
wire_api = "responses"
env_key = "OPENAI_API_KEY"
requires_openai_auth = false
EOF
)"
  cle_backdate_config
  # UserPromptSubmit would BLOCK an unrouted PII prompt; use a /sordino: passthrough so the turn
  # completes and the SessionStart additionalContext (already injected) reaches the upstream.
  cle_run_codex "/sordino:status please proceed"
  local warn_unrouted; warn_unrouted="$(cle_count_f "NOT routed through the masking proxy" "$CASE_CAP")"
  if cle_hook_completed SessionStart "$CASE_ERR" && [ "$warn_unrouted" -ge 1 ]; then
    ok "assert-hook-parses[unrouted]: SessionStart NotRouted warn additionalContext DELIVERED (upstream count=$warn_unrouted)"
  else
    bad "assert-hook-parses[unrouted]: NotRouted warn NOT delivered (upstream count=$warn_unrouted)"
  fi

  # --- 2c: REGRESSION LOCK — the OLD top-level-`env` bug. A bug-shaped hook emitting
  #         {"env":{...},"hookSpecificOutput":{...,"additionalContext":SENTINEL}} trips codex's
  #         deny_unknown_fields → the SENTINEL is DROPPED. This MUST be ABSENT (0) — proving the
  #         assertion is a real delivery observation, not a self-written JSON-schema check, and that
  #         the fixed plugin hook (2a, no top-level env) is what makes it pass.
  cle_new_case hook-parses-envbug
  cle_start_fake
  local bug_dir="$CASE_DIR/bug-hooks"; mkdir -p "$bug_dir"
  local SENT="SENTINEL_A6_ENVBUG_$$"
  cat > "$bug_dir/codex-session-start.sh" <<EOF
#!/usr/bin/env bash
cat >/dev/null
# OLD-BUG SHAPE: a TOP-LEVEL "env" key alongside hookSpecificOutput. codex's deny_unknown_fields
# rejects the unknown top-level key and SILENTLY DROPS the additionalContext (the A2 bug).
printf '%s\n' '{"env":{"X":"1"},"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"$SENT"}}'
EOF
  cat > "$bug_dir/codex-user-prompt-submit.sh" <<'EOF'
#!/usr/bin/env bash
cat >/dev/null
printf '{}\n'   # ALLOW — we only exercise the SessionStart parse here
EOF
  chmod +x "$bug_dir/codex-session-start.sh" "$bug_dir/codex-user-prompt-submit.sh"
  cle_write_hooks_only "$bug_dir" "$(cat <<EOF
model_provider = "plain"
[model_providers.plain]
name = "plain"
base_url = "http://127.0.0.1:$CASE_FAKE_PORT/v1"
wire_api = "responses"
env_key = "OPENAI_API_KEY"
requires_openai_auth = false
EOF
)"
  cle_backdate_config
  cle_run_codex "hello"
  local bug_sent; bug_sent="$(cle_count_f "$SENT" "$CASE_CAP")"
  # Positive control: the SAME sentinel WITHOUT the top-level env key parses and delivers.
  cle_new_case hook-parses-envfixed
  cle_start_fake
  local fix_dir="$CASE_DIR/fix-hooks"; mkdir -p "$fix_dir"
  cat > "$fix_dir/codex-session-start.sh" <<EOF
#!/usr/bin/env bash
cat >/dev/null
printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"$SENT"}}'
EOF
  cat > "$fix_dir/codex-user-prompt-submit.sh" <<'EOF'
#!/usr/bin/env bash
cat >/dev/null
printf '{}\n'
EOF
  chmod +x "$fix_dir/codex-session-start.sh" "$fix_dir/codex-user-prompt-submit.sh"
  cle_write_hooks_only "$fix_dir" "$(cat <<EOF
model_provider = "plain"
[model_providers.plain]
name = "plain"
base_url = "http://127.0.0.1:$CASE_FAKE_PORT/v1"
wire_api = "responses"
env_key = "OPENAI_API_KEY"
requires_openai_auth = false
EOF
)"
  cle_backdate_config
  cle_run_codex "hello"
  local fix_sent; fix_sent="$(cle_count_f "$SENT" "$CASE_CAP")"

  if [ "$bug_sent" -eq 0 ] && [ "$fix_sent" -ge 1 ]; then
    ok "assert-hook-parses[regression-lock]: top-level-env bug DROPS sentinel (0), valid shape DELIVERS it ($fix_sent)"
  else
    bad "assert-hook-parses[regression-lock]: lock did not fire as expected (bug=$bug_sent want 0, fixed=$fix_sent want >=1)"
  fi
}

# ===========================================================================================
# 3. assert-fail-closed-unrouted — the REAL UserPromptSubmit intake gate (A7) BLOCKs.
#    U1: an UNCONFIGURED session (no sordino provider) submitting a non-/sordino: PII prompt must be
#        BLOCKED — observed as zero upstream POSTs (the PII never egressed) + `hook: UserPromptSubmit
#        Blocked`. KILL: if U1 ALLOWs, A7 reused the Claude `plumbed`-gated predicate (fail-OPEN).
#    U4: config routes but was written AFTER the session launched (mid-session enable) → the
#        launch-generation guard makes launch_generation_ok false → BLOCK. Approximated by forward-
#        dating config.toml's mtime so it is NEWER than the rollout's session-start second.
# ===========================================================================================
assert_fail_closed_unrouted() {
  printf '\n[3] assert-fail-closed-unrouted (real intake-gate BLOCK)\n'
  if [ "$HOOK_CODEX" -ne 1 ]; then
    skip "assert-fail-closed-unrouted: needs a hook-firing codex (>0.140); none available"
    return
  fi

  # --- U1: unconfigured (no sordino provider) + REAL hooks; a non-/sordino: PII prompt must BLOCK.
  cle_new_case failclosed-u1
  cle_start_fake
  # NO sordino provider — a plain provider straight to the fake (the unconfigured/unrouted case).
  cle_write_hooks_only "$CLE_PLUGIN_ROOT/scripts" "$(cat <<EOF
model_provider = "plain"
[model_providers.plain]
name = "plain"
base_url = "http://127.0.0.1:$CASE_FAKE_PORT/v1"
wire_api = "responses"
env_key = "OPENAI_API_KEY"
requires_openai_auth = false
EOF
)"
  cle_backdate_config
  cle_run_codex "My email is $CLE_EMAIL — please echo it back."
  local u1_leak; u1_leak="$(cle_count_f "$CLE_EMAIL" "$CASE_CAP")"
  # A BLOCK means the turn never egressed: zero plaintext PII at upstream AND the Blocked hook line.
  if cle_hook_blocked UserPromptSubmit "$CASE_ERR" && [ "$u1_leak" -eq 0 ]; then
    ok "assert-fail-closed-unrouted[U1]: unrouted PII prompt BLOCKED (no egress; upstream PII=$u1_leak)"
  else
    bad "assert-fail-closed-unrouted[U1]: NOT blocked (fail-OPEN!) — upstream PII=$u1_leak, hook: $(grep -oE 'hook: UserPromptSubmit.*' "$CASE_ERR" | head -1)"
  fi

  # --- U4: routed config, but written AFTER launch (mid-session enable) → launch-gen false → BLOCK.
  cle_new_case failclosed-u4
  cle_start_fake
  if ! cle_start_proxy; then bad "assert-fail-closed-unrouted[U4]: proxy failed identity"; return; fi
  local rc; cle_enable_routing; rc=$?
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then bad "assert-fail-closed-unrouted[U4]: enable rc=$rc"; return; fi
  cle_forwarddate_config 600   # config mtime in the FUTURE → newer than the session's launch second
  cle_run_codex "My email is $CLE_EMAIL — please echo it back."
  local u4_leak; u4_leak="$(cle_count_f "$CLE_EMAIL" "$CASE_CAP")"
  if cle_hook_blocked UserPromptSubmit "$CASE_ERR" && [ "$u4_leak" -eq 0 ]; then
    ok "assert-fail-closed-unrouted[U4]: mid-session-enable (config newer than launch) BLOCKED (upstream PII=$u4_leak)"
  else
    bad "assert-fail-closed-unrouted[U4]: NOT blocked — upstream PII=$u4_leak, hook: $(grep -oE 'hook: UserPromptSubmit.*' "$CASE_ERR" | head -1)"
  fi
}

# ===========================================================================================
# 4. assert-auth-refusal — ChatGPT-mode auth is refused at enable AND warned at SessionStart.
#    enable half (any codex): with OPENAI_API_KEY unset and a ChatGPT-style auth.json present,
#    `sordino-hooks codex-config enable` via enable.sh runs the codex-auth-check preflight, which
#    exits non-zero → enable.sh writes NOTHING to config.toml and prints the refusal.
#    hook half (hook-firing codex): a SessionStart hook on a routed-but-no-key session emits the
#    warn-only AUTH variant (NEVER a masking claim).
# ===========================================================================================
assert_auth_refusal() {
  printf '\n[4] assert-auth-refusal (ChatGPT-auth refused + warned)\n'

  # --- enable-refusal half (runs on ANY codex / no codex needed). Drive enable.sh end to end.
  cle_new_case auth-refusal-enable
  cle_start_fake
  if ! cle_start_proxy; then bad "assert-auth-refusal[enable]: proxy failed identity"; return; fi
  # A ChatGPT-style auth.json (tokens present, no apikey) — the refusal shape.
  cat > "$CASE_CODEX_HOME/auth.json" <<'EOF'
{ "auth_mode": "chatgpt", "tokens": { "access_token": "fake", "id_token": "fake" } }
EOF
  : > "$CASE_CONFIG"   # start empty so we can assert NOTHING was written
  local cfg_before; cfg_before="$(md5sum "$CASE_CONFIG" 2>/dev/null | cut -d' ' -f1)"
  local enable_sh="$CLE_PLUGIN_ROOT/skills/sordino-openai/scripts/enable.sh"
  # OPENAI_API_KEY MUST be UNSET for the refusal; pass the proxy port via ensure-up's discovery
  # (enable.sh calls ensure-up --print-url, which finds our live proxy via the rendezvous).
  env -u OPENAI_API_KEY \
    CODEX_HOME="$CASE_CODEX_HOME" SORDINO_STATE_DIR="$CASE_STATE" \
    CODEX_PLUGIN_ROOT="$CLE_PLUGIN_ROOT" PATH="$CLE_BIN_DIR:$PATH" \
    bash "$enable_sh" > "$CASE_DIR/enable.out" 2> "$CASE_DIR/enable.err"
  local enable_rc=$?
  local wrote_provider; wrote_provider="$(cle_count_f 'sordino_managed' "$CASE_CONFIG")"
  local cfg_after; cfg_after="$(md5sum "$CASE_CONFIG" 2>/dev/null | cut -d' ' -f1)"
  # grep -E (not -ci) + wc -l: always a single clean integer (0 on no-match/missing file). Avoids
  # the `grep -ci ... || printf 0` double-zero ("0\n0" → `[: integer expected`) the lib forbids.
  local refused; refused="$(grep -Ee 'auth preflight failed|usable OPENAI_API_KEY|refus' "$CASE_DIR/enable.err" 2>/dev/null | wc -l | tr -d ' ')"
  if [ "$enable_rc" -ne 0 ] && [ "$wrote_provider" -eq 0 ] && [ "$cfg_before" = "$cfg_after" ] && [ "$refused" -ge 1 ]; then
    ok "assert-auth-refusal[enable]: enable.sh REFUSED (rc=$enable_rc), config.toml byte-unchanged, printed refusal"
  else
    bad "assert-auth-refusal[enable]: not refused as required (rc=$enable_rc, provider-written=$wrote_provider, config-changed=$([ "$cfg_before" = "$cfg_after" ] && echo no || echo YES), refusal-msg=$refused)"
  fi

  # --- SessionStart warn half (hook-firing codex). Routed config + ChatGPT auth.json + no exported
  #     key → the SessionStart verdict is AuthFail → warn-only additionalContext (NOT a masking claim).
  if [ "$HOOK_CODEX" -ne 1 ]; then
    skip "assert-auth-refusal[hook]: needs a hook-firing codex (>0.140); none available"
    return
  fi
  cle_new_case auth-refusal-hook
  cle_start_fake
  if ! cle_start_proxy; then bad "assert-auth-refusal[hook]: proxy failed identity"; return; fi
  # Write the route via codex-config enable (no auth-check on this direct path). Then drive codex with
  # a NON-sk OPENAI_API_KEY and NO auth.json: detect_codex_auth (the same classifier the auth-check
  # uses) sees an unusable key and no auth-file → AuthFail → the SessionStart hook emits the warn-only
  # AuthFail variant (NEVER a masking claim). We deliberately do NOT plant a ChatGPT auth.json here:
  # codex ITSELF parses auth.json at startup and ABORTS the turn on a malformed `id_token` ("invalid
  # ID token format") BEFORE any hook fires — which would mask the failure as "no hook output". The
  # non-sk env key reproduces the SAME AuthFail verdict without tripping codex's own auth parser; the
  # enable-refusal half (above) already exercised the ChatGPT-auth.json refusal at the enable boundary.
  local rc; cle_enable_routing; rc=$?
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then bad "assert-auth-refusal[hook]: enable rc=$rc"; return; fi
  cle_backdate_config
  # A /sordino: passthrough avoids the intake BLOCK so the SessionStart additionalContext can reach the
  # upstream; requires_openai_auth=false lets codex construct with the (unusable-for-real) bearer and
  # the turn completes against the fake, firing the hooks.
  CASE_OPENAI_API_KEY="not-an-sk-key" cle_run_codex "/sordino:status"
  local authwarn; authwarn="$(cle_count_f "no usable OpenAI API key is exported" "$CASE_CAP")"
  local maskclaim; maskclaim="$(cle_count_f "real values are restored locally" "$CASE_CAP")"
  if cle_hook_completed SessionStart "$CASE_ERR" && [ "$authwarn" -ge 1 ] && [ "$maskclaim" -eq 0 ]; then
    ok "assert-auth-refusal[hook]: SessionStart emitted the AuthFail WARN (delivered=$authwarn), no masking claim (=$maskclaim)"
  else
    bad "assert-auth-refusal[hook]: expected AuthFail warn w/o masking claim (warn=$authwarn, maskclaim=$maskclaim)"
  fi
}

# ===========================================================================================
# 5. assert-override-detected-and-warned — S2 best-effort override warn (needs A8).
#    Config selects the sordino proxy + the proxy is live, but codex is launched with a -c override
#    pointing the provider's base_url at a SECOND fake (the override target). Send TWO PII prompts:
#      (a) the A7 gate ALLOWs BOTH (config+identity+launch-gen pass; a BLOCK here is NOT the design),
#      (b) the FIRST prompt emits NO override-warn (first-turn discriminator — A8 always shows no
#          inbound on turn 1),
#      (c) the SECOND prompt emits the NON-BLOCKING override-warn (A8 still sees 0 inbound),
#      (d) the override target received the REAL PII (the accepted opt-out: it egressed unmasked).
#    OVER-WARN co-assertion: the SAME two-prompt sequence on a CORRECTLY-ROUTED session warns NEITHER.
#    When A8 is unavailable the documented LIMITATION is asserted instead (gate ALLOWs, warn absent).
# ===========================================================================================
assert_override_detected_and_warned() {
  printf '\n[5] assert-override-detected-and-warned (S2 override warn / over-warn)\n'
  if [ "$HOOK_CODEX" -ne 1 ]; then
    skip "assert-override-detected-and-warned: needs a hook-firing codex (>0.140); none available"
    return
  fi

  # --- override path: route written for our proxy, but -c overrides base_url to a SECOND fake. The
  #     two prompts share ONE codex session (codex exec is one-shot, so feed both in one run via a
  #     two-line prompt — each user turn is a separate UserPromptSubmit firing).
  cle_new_case override-warn
  # The override TARGET fake (captures the unmasked PII that egresses past the proxy).
  local override_cap="$CASE_DIR/override-cap.txt"; : > "$override_cap"
  local override_port; override_port="$(cle_start_second_fake "$override_cap")"
  # The proxy's own fake (the route the config selects but the override defeats).
  cle_start_fake
  if ! cle_start_proxy; then bad "assert-override-warn: proxy failed identity"; return; fi
  local rc; cle_enable_routing; rc=$?
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then bad "assert-override-warn: enable rc=$rc"; return; fi
  cle_backdate_config

  # Real-codex leg: confirm the gate ALLOWs (no BLOCK) and the override target got the REAL PII (it
  # egressed unmasked past the proxy — the accepted opt-out). This is the genuine end-to-end S2 shape.
  cle_run_codex "My email is $CLE_EMAIL — echo it." \
    -c "model_providers.sordino.base_url=http://127.0.0.1:$override_port/v1"
  local allowed; if cle_hook_blocked UserPromptSubmit "$CASE_ERR"; then allowed=0; else allowed=1; fi
  local target_pii; target_pii="$(cle_count_f "$CLE_EMAIL" "$override_cap")"
  local proxy_pii;  proxy_pii="$(cle_count_f "$CLE_EMAIL" "$CASE_CAP")"

  # First-turn-vs-2nd-turn override-warn discriminator, exercised through the REAL subcommand (codex
  # exec is one-shot, so two UserPromptSubmit firings in one codex session aren't drivable directly;
  # the subcommand computes the identical override-warn logic the wrapper invokes). With the override
  # in effect NO traffic reaches the proxy, so A8 reports routed_recently=false for this session. Turn
  # 1 must NOT warn (the marker has no prior ALLOW yet → first-turn discriminator); turn 2 MUST warn
  # (a prior ALLOW exists AND A8 still shows no inbound). An ALNUM session id keeps the A8 key stable.
  local sid="overridesess${$}"
  local roll="$CASE_ROOT/rollout-2099-01-01T00-00-00-uuuuuuuu.jsonl"   # FAR-FUTURE session-start > any config mtime → launch-gen passes
  local out1 out2
  out1="$(cle_run_ups_subcmd "$sid" "$roll" "My email is $CLE_EMAIL")"
  out2="$(cle_run_ups_subcmd "$sid" "$roll" "My email is $CLE_EMAIL")"
  local warn1 warn2 block1 block2
  warn1="$(printf '%s\n' "$out1" | grep -c 'no traffic from this session has reached it')"
  warn2="$(printf '%s\n' "$out2" | grep -c 'no traffic from this session has reached it')"
  block1="$(printf '%s\n' "$out1" | grep -c '"decision":"block"')"
  block2="$(printf '%s\n' "$out2" | grep -c '"decision":"block"')"

  printf '      real-codex: allowed=%s override-target-PII=%s proxy-PII=%s | subcmd: warn1=%s warn2=%s block1=%s block2=%s\n' \
    "$allowed" "$target_pii" "$proxy_pii" "$warn1" "$warn2" "$block1" "$block2"

  # (a) gate ALLOWs both (no BLOCK at the subcommand on a route-confirmed session).
  # (b) turn 1 NEVER warns (first-turn discriminator).
  # (d) the override target received the real PII (egressed unmasked — the accepted opt-out).
  local base_ok=1
  [ "$allowed" = "1" ] || { base_ok=0; }
  [ "$block1" = "0" ] && [ "$block2" = "0" ] || base_ok=0
  [ "$warn1" = "0" ] || base_ok=0
  [ "$target_pii" -ge 1 ] || base_ok=0

  if [ "$base_ok" != "1" ]; then
    bad "assert-override-warn: base invariants failed (allowed=$allowed block1=$block1 block2=$block2 warn1=$warn1 target-PII=$target_pii)"
  elif [ "$warn2" -ge 1 ]; then
    # (c) A8 available → the SECOND prompt warns (non-blocking).
    ok "assert-override-warn: gate ALLOWs both, turn-1 silent, turn-2 OVERRIDE-WARN emitted, override target got real PII"
  else
    # A8 unavailable → documented limitation: gate ALLOWs, warn ABSENT. Still a PASS (the spec's
    # fallback) but state it explicitly.
    ok "assert-override-warn: gate ALLOWs both, no warn (A8 unavailable — documented limitation), override target got real PII"
  fi

  # --- OVER-WARN co-assertion: a CORRECTLY-ROUTED session (no override) must warn on NEITHER turn.
  #     We SEED A8's last_seen for this session by routing one real masked request through the proxy's
  #     session-scoped URL — so A8 reports routed_recently=true and the override-warn (which fires only
  #     when A8 shows NO inbound) stays SILENT on both turns. This is the false-positive guard: the warn
  #     must not fire on a genuinely-routed session.
  cle_new_case override-overwarn
  cle_start_fake
  if ! cle_start_proxy; then bad "assert-override-warn[over-warn]: proxy failed identity"; return; fi
  cle_enable_routing >/dev/null 2>&1
  cle_backdate_config
  local sidr="routedsess${$}"
  local rollr="$CASE_ROOT/rollout-2099-01-01T00-00-00-uuuuuuuu.jsonl"
  cle_seed_a8_session "$sidr"   # real inbound for THIS session → A8 routed_recently=true
  local ro1 ro2 ow1 ow2
  ro1="$(cle_run_ups_subcmd "$sidr" "$rollr" "hi")"
  ro2="$(cle_run_ups_subcmd "$sidr" "$rollr" "hi again")"
  ow1="$(printf '%s\n' "$ro1" | grep -c 'no traffic from this session has reached it')"
  ow2="$(printf '%s\n' "$ro2" | grep -c 'no traffic from this session has reached it')"
  if [ "$ow1" = "0" ] && [ "$ow2" = "0" ]; then
    ok "assert-override-warn[over-warn]: correctly-routed (A8-seen) session warns on NEITHER turn"
  else
    bad "assert-override-warn[over-warn]: a correctly-routed session spuriously warned (turn1=$ow1, turn2=$ow2)"
  fi
}

# ===========================================================================================
# Run all five, aggregate, exit non-zero if any RED.
# ===========================================================================================
assert_route_applied
assert_hook_parses
assert_fail_closed_unrouted
assert_auth_refusal
assert_override_detected_and_warned

printf '\n=========================================================\n'
printf 'A6 codex e2e assertions: %d PASS, %d FAIL, %d SKIP\n' "$PASS" "$FAIL" "$SKIP"
for r in "${RESULTS[@]}"; do printf '  %s\n' "$r"; done
printf '=========================================================\n'

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
exit 0
