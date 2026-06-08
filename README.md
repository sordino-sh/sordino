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
Claude Code  ──ANTHROPIC_BASE_URL=http://127.0.0.1:<project-port>──►  zlauder-proxy  ──TLS──►  api.anthropic.com
   (sees plaintext)                                                   (masks/unmasks)        (sees only tokens)
```

**One proxy per project.** Each project gets its own proxy on a port derived from
its path, so its key, token store, and config are fully isolated — concurrent
`claude` sessions in *different* projects never interfere or correlate, while two
windows in the *same* project share one proxy. The Claude Code plugin's
`/zlauder:enable` assigns the port and writes it into the project's
`.claude/settings.json`.

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
| `zlauder-engine` | masking engine: detection (presidio) + deterministic tokens + AES-GCM reversible store + hot-swappable config (profiles/categories/operators/allow-list/custom rules). Runtime-free. |
| `zlauder-proxy` | axum reverse proxy: request mask walk, per-call manifest, upstream relay, JSON + streaming-SSE unmask, and a key-gated privacy control plane (live enable/disable/profile/reload) that backs `/zlauder:privacy`. |
| `zlauder-hooks` | Claude Code control plane: `session-start` (launch proxy, reserve port), `statusline`, `config` (backs `/zlauder:privacy`), `reveal`. Per-project setup is done by the plugin's `/zlauder:enable`. |
| `zlauder-state` | shared on-disk session state (port/key/salt/pid) + project→port derivation; the single source of truth both binaries read. |

## Build

```sh
cargo build --release --workspace
# binaries: target/release/zlauder-proxy, target/release/zlauder-hooks
```

Requires Rust ≥ 1.91 (the `anthropic-wire` dependency is edition 2024).

## License

ZlauDeR is licensed under the Business Source License 1.1
(`BUSL-1.1`). See [LICENSE](LICENSE).

## Install into Claude Code

zlauder installs as a **Claude Code plugin** — that is the only supported
interface. Add the marketplace and enable the plugin:

```
/plugin marketplace add FailSpy/zlauder
/plugin install zlauder
```

Then, per project:

1. **`/zlauder:enable`** — picks a free per-project port and writes
   `.claude/settings.json` (`ANTHROPIC_BASE_URL` + `ZLAUDER_PORT` + a status line)
   plus a practical starter `zlauder.toml`. The plugin's `SessionStart` hook resolves the
   binaries and launches the proxy automatically. `zlauder-proxy` / `zlauder-hooks`
   are **shipped prebuilt per-platform** with the plugin (precedence: PATH →
   shipped `bin/<triple>` → cached/in-repo build), so a marketplace install needs
   **no compile and no download** — see [docs/RELEASING.md](./docs/RELEASING.md).
   Shipped targets are `x86_64-unknown-linux-gnu`,
   `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`,
   `aarch64-apple-darwin`, and `x86_64-pc-windows-msvc`.
   Release assets use `zlauder-<triple>.tar.gz` for Linux/macOS and
   `zlauder-x86_64-pc-windows-msvc.zip` for Windows.
2. **Restart Claude Code** — `ANTHROPIC_BASE_URL` is read once at startup.
3. **`/zlauder:privacy`** — confirm routing + masking.

A plugin cannot set `ANTHROPIC_BASE_URL` itself (only `agent`/`subagentStatusLine`
are honored from a plugin's settings.json, and there is no install-time hook), so
the one-time `/zlauder:enable` patch and the restart are required. See
[`zlauder-plugin/`](./zlauder-plugin/) for the full rationale and command reference.
On Windows, plugin runtime support assumes Claude Code can run the plugin's existing
bash scripts; native PowerShell/cmd wrappers are not included.

The proxy can also be run standalone (no Claude Code, no per-project derivation):

```sh
zlauder-proxy --port 8787 --config zlauder.toml
ANTHROPIC_BASE_URL=http://127.0.0.1:8787 claude   # any client honoring the base URL
```

### Local plugin development

Two acquisition paths run **in tandem** off the same source tree, so a maintainer
can iterate locally while end users keep the zero-build GitHub flow:

| | end users | local dev |
|---|---|---|
| marketplace | `/plugin marketplace add FailSpy/zlauder` → the plugin's `source` is the orphan **`plugin-dist`** branch | not used (see below) |
| plugin files | shipped on `plugin-dist` | this repo's [`zlauder-plugin/`](./zlauder-plugin/), live |
| binaries | prebuilt `bin/<triple>/`, picked by host triple — **no compile, no download** | your `cargo build --release --workspace` output |

Both paths share one resolver ([`_resolve-bins.sh`](./zlauder-plugin/scripts/_resolve-bins.sh),
precedence: PATH → shipped `bin/<triple>` → cached build → **`<workspace>/target/release`** →
in-repo `cargo build`). The published marketplace is deliberately left pointing at
`plugin-dist`; **do not** repoint it at `./zlauder-plugin` — a marketplace install
*caches a copy* of the plugin detached from the cargo workspace, so the resolver
could not find your built binaries, and a GitHub fetch of a relative source carries
no `bin/`.

Instead, load the in-repo plugin directly so `${CLAUDE_PLUGIN_ROOT}` stays inside
the workspace and the resolver finds `target/release`:

```sh
cargo build --release --workspace            # build proxy + hooks once
claude --plugin-dir ./zlauder-plugin         # load the live plugin from this folder
```

For an already-installed (cached) plugin or for the **Codex** plugin, point the
resolver at your checkout instead — it then uses that tree's `target/release`
(building it on first run if needed):

```sh
export ZLAUDER_WORKSPACE=/abs/path/to/zlauder
cargo build --release --workspace
```

Rebuild after editing engine/proxy/hooks code; restart the session (or re-run
`/zlauder:enable`) to pick up new binaries. Plugin command/hook/script edits under
`zlauder-plugin/` are live under `--plugin-dir`. Release packaging
(`cargo build --release --workspace` per target → `plugin-dist` + `codex-plugin-dist`
+ Release assets) is driven by [`.github/workflows/release.yml`](./.github/workflows/release.yml).

## Configuration

### The `/zlauder:privacy` command

Inside a `claude` session, change masking settings live with the slash command
(or `zlauder-hooks config …` from a shell). It affects **only this project's**
proxy. This is the **masking** layer; `/zlauder:enable` / `/zlauder:disable` are
the separate **routing** layer.

```
/zlauder:privacy                        # status: health, routing, on/off, profile, categories
/zlauder:privacy off                    # transparent passthrough (this session, live)
/zlauder:privacy on
/zlauder:privacy profile strict         # threshold + categories + default operator preset
/zlauder:privacy category contact off   # toggle one category
/zlauder:privacy threshold 0.3
/zlauder:privacy model download         # fetch the openai/privacy-filter model (once)
/zlauder:privacy model on               # turn the ML recognizer on (loads in background)
/zlauder:privacy model status           # disabled | loading | ready | failed
/zlauder:privacy reveal '[EMAIL_ADDRESS_a47n1d8s9c0f]'   # decode one token (local debug/audit)
```

Each change takes a `--scope` (default `session`):

| scope | persists to | applies |
|---|---|---|
| `session` | nothing (live only) | this project's running proxy; lost on restart |
| `project` | `./zlauder.toml` (committed) | now (reload) + every future session |
| `local` | `./zlauder.local.toml` (gitignored) | now + future sessions, just for you |
| `user` | `~/.config/zlauder/config.toml` | now + every project you own |

At startup the proxy merges these layers (user < project < local). Because each
project has its own proxy, a live change here is isolated — it never affects a
`claude` running in another project.

> The control endpoints are gated by the session key (`x-zlauder-key`, from the
> `0600` state file), so a blind tool-driven `curl …/zlauder/disable` (e.g. via
> prompt injection) can't silently turn masking off.
>
> `reveal <token>` is mainly a local debug/audit escape hatch for tokens found in
> logs, captured masked payloads, or test output. Normal assistant responses are
> un-masked automatically.

### `zlauder.toml`

[`zlauder.toml`](./zlauder.toml) is the practical default config. For an
annotated reference that enumerates optional and advanced fields, see
[`zlauder.toml.example`](./zlauder.toml.example). Highlights:

- `enabled` — master switch (`/zlauder:privacy on`/`off`).
- `profile` / `score_threshold` / `enabled_categories` — what to detect. The
  presets are `strict` (0.4, all 5 categories), `balanced` (0.5, secrets +
  financial + identity + contact — the default), `minimal` (0.6, secrets +
  financial), and `secrets_only` (0.6, secrets only; the old `development_safe`
  name still loads as an alias). Setting `profile` SEEDS threshold / categories /
  operator; an explicit field overrides the seed.

  > **Upgrade note (load-bearing profile):** a bare `profile = "minimal"` /
  > `"secrets_only"` (no explicit `enabled_categories`) now applies that profile's
  > **narrower** categories/threshold directly. Earlier builds silently fell back to
  > `balanced` behavior for these, so on upgrade such configs **stop masking
  > Identity (SSN/passport) and Contact (email/phone)**. The proxy prints a one-time
  > NOTE on load. To keep the old behavior, add explicit `enabled_categories` /
  > `score_threshold`. (`strict` only adds a category, so it is unaffected.)
- `default_operator` and per-type `entity_operators`: `token` (reversible),
  `redact`, `mask` (keep last N), `hash`, `keep`.
- `allow_list` (exact / case-insensitive / regex) — never tokenize these.
- `custom_replacements` — your own literal or regex rules (e.g. project
  codenames, employee IDs).
- `[engine.ml]` — the optional ML recognizer (below).
- `[engine.reveal_marker]` — highlight un-masked values in the assistant's
  replies (below).

### Optional: `openai/privacy-filter` on CPU

The regex recognizers can't find free-text PII — **names, locations,
organizations** (the `personal` category, off by default). For that, zlauder can
run the [`openai/privacy-filter`](https://huggingface.co/openai/privacy-filter)
token classifier in-process via `presidio-classifier`'s native-Rust **Candle CPU**
backend (no Python, no network at inference time). It is **always compiled in**,
but **off by default** and runs only after you download the model:

```
/zlauder:privacy model download     # cache the weights (large/slow on the first run)
/zlauder:privacy model on           # turn it on
/zlauder:privacy category personal on   # so PERSON/LOCATION actually mask
```

- **Hot-load.** `model on` loads the model in the **background**; the status goes
  `loading → ready`. While loading, masking keeps running **regex-only** — your
  text is *not* filtered through the ML model yet, so you can keep working or wait.
  The status line shows `⏳ml` (loading) → `🧠` (ready). `model off` is instant.
- **CPU.** Inference runs on CPU (`prefer_gpu = false`); the `cuda`/`metal` Candle
  features are out of scope here. Request masking is offloaded to a blocking pool
  and capped so concurrent requests don't oversubscribe the CPU.
- **Model.** Defaults to `openai/privacy-filter`; override with `[engine.ml].model`
  or `model download <repo>` for a privacy-filter–compatible checkpoint. Weights
  cache under the standard HuggingFace location (`HF_HOME` / `~/.cache/huggingface`;
  set `HF_TOKEN` for gated repos).

> Note: because the Candle stack is always compiled in, the build is heavier and
> the binaries are larger than a regex-only build — a deliberate trade-off.

### Optional: highlight un-masked values (`[engine.reveal_marker]`)

Normally an un-masked value is restored silently into the assistant's reply, so
you can't tell which spans came back from a token. Turn on `reveal_marker` to wrap
each restored value with a configurable `prefix`/`suffix` for display:

```toml
[engine.reveal_marker]
enabled = true
prefix = "$"   # or any string — the repo default is an ANSI colour escape
suffix = "$"   #   (see zlauder.toml; written with the TOML \uXXXX escape)
```

- **Assistant prose only.** The decoration is applied **only** to `Surface::AssistantText`
  (Arrow 2). Tool inputs, tool results, citations, and compaction are un-masked
  byte-for-byte — so a value the model writes into a file or passes to a tool is
  never altered.
- **Zero upstream noise.** Claude Code stores the (decorated) reply in the transcript
  and re-sends it as assistant history next turn. The mask path strips the exact
  marker literals **before** detection, so upstream receives the bare token —
  byte-identical to a no-marker round-trip, with a stable prompt-cache prefix. The
  marker is purely a local display aid; it never reaches the model.
- **ANSI vs. printable.** The default `prefix`/`suffix` are ANSI escapes — out-of-band,
  so the model can't emit or override them (unlike `**bold**`). Whether they render
  as color depends on the harness (Claude Code renders model text as markdown, so
  confirm empirically); if you see literal escape junk, switch to a printable pair
  like `prefix = suffix = "$"`. Pick markers that don't occur in ordinary prose —
  the strip removes the **exact** literal from re-sent history (the ANSI escapes
  never collide; a backtick or `*` would over-strip code/emphasis).

## Threat model & limitations

- **Guarantee:** masked PII (per the configured categories) does not reach the
  Anthropic API over the wire. The proxy masks the actual request bytes.
- **Out of scope:** a model with local shell access is a different threat tier —
  it can read local files and run the trusted CLI just like you can. zlauder
  protects the *egress to the provider*, not against a local jailbreak. (The state
  file holds a control token + salt, not the AES key, so it isn't an offline
  decryption oracle — but a shell can still drive the CLI.)
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
  on a port, so cross-turn consistency survives a crash. A live `/zlauder:privacy` config
  change keeps the store (and salt), so determinism survives reconfiguration too.
- **Multi-session / multi-project:** each project runs its **own** proxy on a
  project-derived port — separate key, salt, store, and config. Concurrent
  sessions in different projects can't corrupt each other, cross-contaminate
  responses, or correlate tokens (a value masked in project A is a *different*
  token in project B, and isn't resolvable by B's store). Two windows in the same
  project correctly share one proxy. The bound proxy is the sole writer of its
  state file (after it binds), so even two sessions racing to launch the same
  project's proxy can't desync the key the `reveal`/`config` CLI reads.
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
