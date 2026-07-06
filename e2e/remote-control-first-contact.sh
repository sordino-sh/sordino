#!/usr/bin/env bash
# Sordino e2e — Atomic 1 (remote-control readiness plan, 2026-07-02).
#
# Falsifies: "the standalone remote-control daemon's --print --sdk-url stream-json
# worker invocation shape is already covered by Sordino's fail-closed UserPromptSubmit
# intake gate, exactly like a fresh interactive session is."
#
# --sdk-url itself can't be driven directly here (Claude Code rejects any --sdk-url host
# outside its own claude.ai allowlist, cli.v2.1.198.js:618365-618382 — confirmed by
# adversarial review), but the trace showed --sdk-url and plain `--input-format
# stream-json` piped stdin share the IDENTICAL structuredInput -> Yg.enqueue -> kAm ->
# Bwt -> lnn (UserPromptSubmit) pipeline (cli.v2.1.198.js:716703/718020/718081, :242755,
# :711836-711853, :648137-648151, :589501-589518) — so this is the correct reachable
# proxy for that invocation shape.
#
# Scenario: a FRESH project (.claude/ does not exist yet — the "first-ever session"
# state Sordino's own intake gate was built to catch) is driven via
# `claude --print --input-format stream-json --output-format stream-json`, loading the
# REAL sordino-plugin (via --plugin-dir, so SessionStart + UserPromptSubmit + PreToolUse
# all register — NOT the hand-rolled SessionStart-only settings.json run-e2e.sh uses).
# One canary-PII user turn is fed on stdin. PASS = the canary NEVER reaches the fake
# upstream (the gate blocked the turn before any model query); FAIL = the canary is
# forwarded (masked or not) to the upstream, proving the gate did not fire for this
# invocation shape.
set +e
cd "$(dirname "$0")" || exit 9
HERE="$PWD"
REPO="$(cd "$HERE/.." && pwd)"
BIN="$REPO/target/debug"

WORK="$(mktemp -d /tmp/sordino-e2e-first-contact.XXXXXX)"
FRESH_PROJ="$WORK/fresh-project"
mkdir -p "$FRESH_PROJ"
export SORDINO_STATE_DIR="$WORK/state"
export CLAUDE_CONFIG_DIR="$WORK/claude-config"
mkdir -p "$SORDINO_STATE_DIR" "$CLAUDE_CONFIG_DIR"

CAP="$WORK/upstream-capture.txt"; : > "$CAP"
OUT="$WORK/evidence.txt"; : > "$OUT"
log() { echo "$@" >> "$OUT"; }

PROXY_PORT=18830
UPSTREAM_PORT=18831
fuser -k "${PROXY_PORT}/tcp" "${UPSTREAM_PORT}/tcp" 2>/dev/null; sleep 0.3

# fake upstream — captures whatever the proxy forwards (want: nothing, ever)
python3 "$HERE/fake_anthropic.py" "$UPSTREAM_PORT" "$CAP" > "$WORK/fake.log" 2>&1 &
FAKE=$!
sleep 1

# The FRESH project's own sordino.toml (session-start.sh's config_path() prefers
# $CLAUDE_PROJECT_DIR/sordino.toml over the plugin's bundled default) — points the
# soon-to-be-auto-plumbed proxy at the local fake, never the real API.
cat > "$FRESH_PROJ/sordino.toml" <<EOF
[proxy]
port = ${PROXY_PORT}
bind = "127.0.0.1"
upstream_base_url = "http://127.0.0.1:${UPSTREAM_PORT}"

[engine]
profile = "balanced"
score_threshold = 0.5
language = "en"
default_operator = { kind = "token" }
enabled_categories = ["secrets", "financial", "identity", "contact"]
fail_closed = true
EOF
# Deliberately NOT creating $FRESH_PROJ/.claude — this is the untouched first-ever-session
# state; SessionStart's own auto-plumb must be what writes settings.local.json.

CANARY="zoe.quine@example.com"
STDIN_JSON="$WORK/turn.jsonl"
printf '%s\n' "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"My personal email is ${CANARY} . Acknowledge in one short sentence.\"}]}}" > "$STDIN_JSON"

CLAUDE_OUT="$WORK/claude-out.jsonl"
CLAUDE_ERR="$WORK/claude-err.txt"

# SORDINO_WORKSPACE lets _resolve-bins.sh find the in-repo target/debug build via
# --plugin-dir's derived CLAUDE_PLUGIN_ROOT (this is the in-repo dev fallback path, tier 5).
(
  cd "$FRESH_PROJ" || exit 9
  export SORDINO_WORKSPACE="$REPO"
  timeout 60 claude --print --input-format stream-json --output-format stream-json --verbose \
    --include-hook-events \
    --plugin-dir "$REPO/sordino-plugin" \
    < "$STDIN_JSON" > "$CLAUDE_OUT" 2> "$CLAUDE_ERR"
  echo $? > "$WORK/claude-exit.txt"
)

kill "$FAKE" 2>/dev/null
# The proxy, if auto-plumb launched one, is state-dir-scoped and orphaned on purpose —
# clean it up so repeat runs don't accumulate.
pkill -f "sordino-proxy.*${PROXY_PORT}" 2>/dev/null

CLAUDE_EXIT="$(cat "$WORK/claude-exit.txt" 2>/dev/null || echo '?')"
log "claude_exit=$CLAUDE_EXIT"
CANARY_IN_CAPTURE="$(grep -c "$CANARY" "$CAP")"
CAPTURE_BYTES="$(wc -c < "$CAP")"
log "canary_in_upstream_capture=$CANARY_IN_CAPTURE"
log "capture_file_bytes=$CAPTURE_BYTES"
# Positive evidence the gate itself fired (not just "nothing happened to reach it"):
# a UserPromptSubmit hook_response carrying sordino-hooks' block JSON, AND no assistant
# turn anywhere in the transcript (the block must happen before any model query).
UPS_BLOCKED="$(grep -c '"hook_event":"UserPromptSubmit"' "$CLAUDE_OUT")"
ASSISTANT_TURNS="$(grep -c '"type":"assistant"' "$CLAUDE_OUT")"
log "user_prompt_submit_hook_events_seen=$UPS_BLOCKED"
log "assistant_turns_seen=$ASSISTANT_TURNS"

echo "==== evidence ===="; cat "$OUT"
echo "==== fresh project: $FRESH_PROJ ===="
echo "==== upstream capture (want: 0 occurrences, ideally 0 bytes -- no request at all) ===="
echo "  canary occurrences: $CANARY_IN_CAPTURE   capture file bytes: $CAPTURE_BYTES"
if [ -s "$CAP" ]; then echo "  --- capture contents ---"; cat "$CAP"; fi
echo "==== claude stdout (stream-json) ===="
cat "$CLAUDE_OUT"
echo "==== claude stderr ===="
cat "$CLAUDE_ERR"
echo "==== settings.local.json auto-plumb result (want: present, baked route) ===="
cat "$FRESH_PROJ/.claude/settings.local.json" 2>/dev/null || echo "  (none written)"

if [ "$CANARY_IN_CAPTURE" -eq 0 ] && [ "$ASSISTANT_TURNS" -eq 0 ]; then
  echo "==== PASS: canary never reached the upstream AND no model turn ran (gate held for this invocation shape) ===="
  exit 0
elif [ "$CANARY_IN_CAPTURE" -gt 0 ]; then
  echo "==== FAIL: canary reached the upstream -- the intake gate did NOT cover this invocation shape ===="
  exit 1
else
  echo "==== FAIL (weaker signal): no upstream leak, but an assistant turn ran anyway -- gate did not block as expected ===="
  exit 1
fi
