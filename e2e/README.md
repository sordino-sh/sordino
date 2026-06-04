# zlauder end-to-end test

A self-contained subfolder with its own `.claude/` config that drives a **real
`claude` CLI** through zlauder and verifies masking/unmasking on actual Claude
Code traffic.

## Layout

- `.claude/settings.json` — points Claude Code at the proxy
  (`ANTHROPIC_BASE_URL=http://127.0.0.1:18820`), wires the `SessionStart` hook
  that launches the proxy, and a status line.
- `zlauder.toml` — proxy config; upstream is the local fake (`127.0.0.1:18821`).
- `fake_anthropic.py` — a stand-in Anthropic endpoint that **captures** the
  (masked) request the proxy forwards and returns a valid SSE response that
  echoes back the tokens it saw (so the proxy can unmask them).
- `run-e2e.sh` — the harness.

## Run

```sh
cargo build --workspace          # from the repo root
bash e2e/run-e2e.sh
```

## What it proves (observed result)

With the prompt *"My personal email is zoe.quine@example.com and my home server
is 10.55.66.77 …"*:

- **Egress masking — 0 leaks.** The fake upstream received **no** plaintext
  `zoe.quine@example.com` / `10.55.66.77`; it received `[EMAIL_ADDRESS_…]` and
  `[IP_ADDRESS_…]` tokens instead. (Other real PII from the loaded context — the
  user's email, an API-key-shaped sha256 — is masked too.)
- **Ingress unmasking — round-trip works.** The fake echoes the tokens; the proxy
  unmasks them, so Claude's printed output shows the real
  `zoe.quine@example.com` and `10.55.66.77` again.
- **Routing** comes entirely from `.claude/settings.json` — Claude Code talks to
  the proxy, not directly to Anthropic.
- **`/privacy` control plane.** The harness also drives the same key-gated config
  endpoints the `/privacy` slash command uses: an *unauthenticated* `disable` is
  refused (`403`), and an authenticated `off`→`on` round-trip flips the live
  `enabled` flag. See the "control plane" block in the output.

### Notes

- The proxy is launched directly by the harness for determinism; in production
  the `SessionStart` hook launches it (and reuses a healthy one).
- This test surfaced two fixes now in the codebase: Claude Code sends some
  messages with bare-string `content` (fixed in `anthropic-wire`), and the proxy
  now **fails safe** (value-walk masking) instead of forwarding an unparsed body.
- Recognizer precision: `URL`/`DOMAIN` are off by default because presidio
  matches every `identifier.ext` (filenames, code) as a domain. See
  `docs/IMPLEMENTATION-NOTES.md`.
