# ZlauDeR

A local **PII masking proxy for Claude Code**. It sits between Claude Code and
the Anthropic Messages API, masks personal data on the way *out*, and unmasks it
on the way *back* — so the model provider only ever sees deterministic tokens
like `[EMAIL_ADDRESS_a47n1d8s9c0f]`, while you keep seeing real values locally.

Detection is done by [`presidio-rs`](../jcc/presidio-rs) (offline regex
recognizers — email, phone, credit card, IP, API keys, IBAN, SSN, …). The
mask/unmask design is ported from the orchestr8 Privacy Engine: deterministic
session-salted tokens (blake3) backed by a reversible AES-256-GCM session store.

## How it works

zlauder is a **hybrid**: a reverse proxy is the data plane, and thin Claude Code
hooks are the control plane.

```
Claude Code  ──ANTHROPIC_BASE_URL=http://127.0.0.1:8787──►  zlauder-proxy  ──TLS──►  api.anthropic.com
   (sees plaintext)                                          (masks/unmasks)        (sees only tokens)
```

This is **not** a TLS-intercepting MITM — Claude Code natively supports
`ANTHROPIC_BASE_URL`, so you simply point it at the local proxy, which
re-originates a fresh TLS connection to Anthropic. No certificates to install.

### Why a proxy and not pure hooks?

Claude Code hooks can't actually mask the traffic: `UserPromptSubmit` can't
rewrite the prompt the model sees, `PostToolUse` can't modify tool output, the
system prompt is unreachable, and assistant text can only be changed
display-only. Mapped onto the privacy "four arrows", hooks cleanly cover only
*one* of them. The proxy is the only place with a real egress guarantee, so it
owns the masking; the hooks just launch it and surface status.

### The four arrows

```
Arrow 1: user / system  → LLM        = MASK   (request)
Arrow 4: tool output    → LLM        = MASK   (request)
Arrow 2: LLM → display               = UNMASK (response)
Arrow 3: LLM → tool input            = UNMASK (response)
```

Because this build **unmasks on the wire**, Claude Code's transcript stores
plaintext — which means assistant-authored history comes back as plaintext on
the next turn and is re-masked outbound. Deterministic tokens make that
round-trip reproduce the *exact* original token form, so nothing leaks and
prompt-cache prefixes stay byte-stable. `thinking` blocks and their signatures
are kept tokenized end-to-end (never unmasked), so signatures stay valid.

## Workspace

| crate | role |
|---|---|
| `zlauder-engine` | masking engine: detection (presidio) + deterministic tokens + AES-GCM reversible store + config (profiles/categories/operators/allow-list/custom rules). Runtime-free. |
| `zlauder-proxy` | axum reverse proxy: request mask walk, per-call manifest, upstream relay, JSON + streaming-SSE unmask. |
| `zlauder-hooks` | Claude Code control plane: `session-start` (launch proxy), `statusline`, `reveal`. |

## Build

```sh
cargo build --release --workspace
# binaries: target/release/zlauder-proxy, target/release/zlauder-hooks
```

Requires Rust ≥ 1.91 (the `anthropic-wire` dependency is edition 2024).

## Install into Claude Code

1. Put `zlauder-proxy` and `zlauder-hooks` on your `PATH`
   (e.g. `cp target/release/zlauder-{proxy,hooks} ~/.local/bin/`).
2. Drop a [`zlauder.toml`](./zlauder.toml) in your project (or point the hook at
   one with `--config`).
3. Merge [`examples/settings.json`](./examples/settings.json) into your project's
   `.claude/settings.json`. This sets `ANTHROPIC_BASE_URL`, runs the
   `SessionStart` hook (which launches the proxy on first use), and adds a status
   line.

The proxy can also be run standalone:

```sh
zlauder-proxy --port 8787 --config zlauder.toml
ANTHROPIC_BASE_URL=http://127.0.0.1:8787 claude   # any client honoring the base URL
```

## Configuration

See [`zlauder.toml`](./zlauder.toml). Highlights:

- `profile` / `score_threshold` / `enabled_categories` — what to detect.
- `default_operator` and per-type `entity_operators`: `token` (reversible),
  `redact`, `mask` (keep last N), `hash`, `keep`.
- `allow_list` (exact / case-insensitive / regex) — never tokenize these.
- `custom_replacements` — your own literal or regex rules (e.g. project
  codenames, employee IDs).

## Audit / reveal

Normally you never see a token (responses are unmasked). To decode one seen in a
`thinking` block:

```sh
zlauder-hooks reveal '[EMAIL_ADDRESS_a47n1d8s9c0f]'
```

The reveal endpoint on the proxy is gated by the session key (`x-zlauder-key`),
so it isn't a trivial deanonymization oracle for a tool-driven `curl`.

## Threat model & limitations

- **Guarantee:** masked PII (per the configured categories) does not reach the
  Anthropic API over the wire. The proxy masks the actual request bytes.
- **Out of scope:** a model with local shell access is a different threat tier —
  it can read local files (including the session key file) just like you can.
  zlauder protects the *egress to the provider*, not against a local jailbreak.
- **Not masked:** base64 image/document bytes (masking would corrupt them);
  `model` id and `stop_sequences` (tokenizing them breaks the API). Payloads of
  *novel* content-block types ride through via `extra` sinks but aren't scanned.
- **Detection is presidio's:** recall depends on its recognizers. `personal`
  entities (PERSON/LOCATION/ORG) need an NLP model and are off by default.
  `URL` masking uses presidio's strict recognizer (keeps real URLs, ignores
  `file.ext`/code); `DOMAIN` is off by default — re-enable via `entity_operators`.
- **Deterministic placeholders / prompt caching:** within a session the same
  plaintext always maps to the same token (`blake3(salt+type+value)`, fixed
  per-session salt), so masked content is byte-stable across turns and
  Anthropic's prompt-cache prefix is preserved. Verified: two identical requests
  produce byte-identical masked output. The salt is reused across proxy restarts
  on a port, so cross-turn consistency survives a crash.
- **Multi-session:** verified concurrency-safe — simultaneous sessions don't
  corrupt each other or cross-contaminate responses. But with the single fixed
  port they share one proxy + one store/salt, so identical plaintext maps to the
  same token across sessions (correlation). Fine for single-user local use; true
  per-session isolation would need per-session ports.
- **Subscription (OAuth) auth:** verified working through the proxy against the
  real `api.anthropic.com` (the `Authorization` header is forwarded verbatim).

## Tests

```sh
cargo test --workspace
```

Notable coverage: engine mask→unmask round-trip, token determinism / cache
stability, every-byte-boundary SSE token splitting, unknown-field round-trip,
Arrow-4 tool-result masking, and an end-to-end proxy test (masked upstream body
+ header passthrough + unmasked client response).
