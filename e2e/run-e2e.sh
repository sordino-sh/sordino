#!/usr/bin/env bash
# End-to-end test: a real `claude` CLI, spawned from this folder, routes through
# zlauder (via .claude/settings.json -> ANTHROPIC_BASE_URL) to a local fake
# Anthropic upstream that captures what the proxy forwarded. Verifies that PII is
# masked on egress and unmasked on the way back.
#
# Run from the repo after `cargo build`:  bash e2e/run-e2e.sh
set +e
cd "$(dirname "$0")" || exit 9
HERE="$PWD"
BIN="$HERE/../target/debug"
export ZLAUDER_STATE_DIR="$HERE/state"
rm -rf state; mkdir -p state
CAP="$HERE/state/upstream-capture.txt"; : > "$CAP"
OUT="$HERE/state/evidence.txt"; : > "$OUT"
log() { echo "$@" >> "$OUT"; }

fuser -k 18820/tcp 18821/tcp 2>/dev/null; sleep 0.5

# 1) local fake Anthropic upstream (captures the masked request, returns valid SSE)
python3 "$HERE/fake_anthropic.py" 18821 "$CAP" > state/fake.log 2>&1 &
FAKE=$!
sleep 1

# 2) the proxy (deterministic session key/salt so tokens are reproducible).
#    In production the SessionStart hook launches this; here we launch it directly
#    so the test is deterministic. Claude's own hook reuses it if already healthy.
ZLAUDER_SESSION_KEY=$(printf '%064x' 1) ZLAUDER_SESSION_SALT=$(printf '%032x' 2) \
  "$BIN/zlauder-proxy" --port 18820 --config "$HERE/zlauder.toml" > state/proxy.log 2>&1 &
PROX=$!
sleep 1.2
log "proxy_healthz=$(curl -sS -m 3 http://127.0.0.1:18820/healthz)"

# 3) REAL claude, spawned here; routing comes entirely from .claude/settings.json
timeout 110 claude -p "My personal email is zoe.quine@example.com and my home server is 10.55.66.77 . Acknowledge in one short sentence." \
  > state/claude-out.txt 2> state/claude-err.txt
log "claude_exit=$?"

kill "$PROX" "$FAKE" 2>/dev/null
log "DONE"

echo "==== evidence ===="; cat "$OUT"
echo "==== egress: canary plaintext upstream (want 0/0) ===="
echo "  email: $(grep -c 'zoe.quine@example.com' "$CAP")  ip: $(grep -c '10.55.66.77' "$CAP")"
echo "  tokens forwarded:"; grep -oE '\[[A-Z_]+_[0-9a-f]{12}\]' "$CAP" | sed -E 's/_[0-9a-f]{12}\]/]/' | sort | uniq -c
echo "==== ingress: canary restored to claude ===="
grep -oE 'zoe\.quine@example\.com|10\.55\.66\.77' state/claude-out.txt | sort | uniq -c
