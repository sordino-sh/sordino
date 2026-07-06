# Sordino plugin — end-to-end test plan

Drives a **real `claude` CLI** through the **hook-launched** proxy (not a manually-started
one) against a **stub upstream we can read**, so every masking/leak claim is *falsifiable* by
inspecting the bytes the upstream actually received. Worst case we are hunting:
**(1)** anything that *looks* masked/active but isn't (a leak, a false shield, adoption of a
foreign server); **(2)** ConnectionRefused / hangs on fresh sessions.

## Harness invariants (every scenario)
- **Isolated config:** `CLAUDE_CONFIG_DIR=<tmp copy of ~/.claude>` — never touch the real one.
- **Isolated state:** `SORDINO_STATE_DIR=<tmp>` per scenario — so the hook's build-recycle /
  port logic can NEVER kill or adopt a real proxy. (Default is `$XDG_RUNTIME_DIR/sordino`,
  shared — using it would be the footgun.)
- **Known binaries:** the plugin MUST resolve `…/sordino/target/release/{sordino-proxy,
  sordino-hooks}` of the CURRENT build. Verify: no other `sordino-proxy` on `PATH`
  (`command -v`), and the launched proxy's `/healthz` body == `git rev-parse --short=12 HEAD`
  (the embedded `SORDINO_BUILD`). FALSIFIES "I tested the wrong binary."
- **Visible upstream:** a stub (`fake_anthropic.py`) that appends every request body to a
  capture file and echoes the tokens it saw; the project's `sordino.toml`
  `upstream_base_url` points at it. Auth is a dummy `ANTHROPIC_API_KEY` (the real token never
  leaves the box).
- **No `--bare`** (it skips hooks/plugins); load via `--plugin-dir …/sordino-plugin`.

## A. Egress masking — NO LEAK (falsifiable on the capture file)
- **A1** Prompt with email + IPv4 + an API-key-shaped secret. On a *routed* session the
  capture file MUST contain `0` occurrences of each plaintext canary and ≥1 `[EMAIL_ADDRESS_…]`
  / `[IP_ADDRESS_…]` / `[API_KEY_…]` token. **FALSIFIES masking-on-egress.**
- **A2** `count_tokens` path (if Claude calls it) is also masked (it's a separate handler).
- **A3** Multi-turn: turn 2 resends turn-1 transcript; the masked bytes for a repeated value
  are BYTE-IDENTICAL across turns (prompt-cache prefix) AND still no plaintext.

## B. Ingress unmask — value restored locally
- **B1** Claude's visible output restores the exact plaintext canary (email/IP), and contains
  NO `[…_<12hex>]` token. **FALSIFIES unmask-on-response.**

## C. "Looks active but isn't" — the worst class
- **C1 First-ever session (auto-plumb):** masking is NOT claimed active; the hook's
  `additionalContext` says NOT-active + restart; statusline shows `⟳ restart to mask`, never
  🛡. The capture file MAY contain plaintext here (unrouted) — and that's the HONEST state, so
  the test asserts the *messaging* matches the *reality* (no false shield). **FALSIFIES a
  false "active".**
- **C2 Foreign-server adoption (the nonce leak):** put a non-sordino 200-on-`/healthz` server
  on the port a stale rendezvous names (simulate PID-reuse+port-steal); the hook MUST NOT
  adopt it (no route through it). Assert ensure_up relaunches a real proxy on a fresh port.
  **FALSIFIES the Codex-found MED leak.**
- **C3 Masking OFF:** with `/sordino:privacy off`, a routed session passes plaintext upstream
  (expected) AND the statusline shows OFF, never 🛡.

## D. ConnectionRefused / hangs on fresh sessions
- **D1 Eager launch:** after auto-plumb writes the route, the proxy is ALREADY listening
  (rendezvous shows a healthy pid), so a restart/next session does NOT hit ConnectionRefused.
  Measure: the routed session's wall-clock is bounded (no ~2.5-min hang). **FALSIFIES the
  fresh-install hang.**
- **D2 Established project, proxy dead on launch:** kill the proxy, start a session; the hook
  relaunches (sticky port) and the request succeeds within seconds — no hang. 
- **D3 Reconcile (port stolen):** occupy the sticky port with a foreign listener, start a
  session; the hook binds a NEW ephemeral port, rewrites settings, and surfaces restart — the
  session does not hang (fail-closed), and the NEXT session masks on the new port.

## E. Lifecycle / footguns
- **E1 Single-launch race:** two concurrent sessions in one project → exactly ONE proxy
  (one rendezvous, one pid). No double-bind.
- **E2 Sticky stability:** restart the proxy (build unchanged) → same port → settings.local.json
  unchanged → no restart needed.
- **E3 Static pin:** `[proxy] port = N` → binds N; a second project pinned to N exits with a
  clear conflict error and publishes nothing (no misleading record).
- **E4 Cross-project isolation:** project A and B simultaneously → distinct ports, distinct
  rendezvous; A's capture never shows B's canary and vice-versa.
- **E5 Non-loopback guard:** `SORDINO_BIND=0.0.0.0` without ack → proxy refuses to start
  (no LAN-exposed control plane); with `SORDINO_ALLOW_NON_LOOPBACK_BIND=1` → starts + warns.
- **E6 Binary identity:** `/healthz` build id == current `SORDINO_BUILD`; a stale-build proxy
  on the rendezvous is recycled (and ONLY because nonce+build confirm it's ours).
- **E7 Doctor (Phase 4):** `/sordino:doctor` all-PASS on a healthy host; FAILs loud on a
  blocked loopback / busy static port.

## F. Secrets / broker (if configured)
- **F1** A registered `broker` secret resolves only into the allow-listed tool param at the
  PreToolUse boundary; the upstream LLM sees only the token; the resolved value never appears
  in the capture file.

## Pass bar
Every scenario asserts on **observable artifacts** (capture file, claude stdout, rendezvous
JSON, statusline output, proxy log, exit code + wall-clock). A scenario that cannot be
falsified by one of those is not a real test and must be rewritten.
