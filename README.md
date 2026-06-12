# ZlauDeR

A local **PII masking proxy for Claude Code**. It sits between Claude Code and
the Anthropic Messages API, masks personal data on the way *out*, and unmasks it
on the way *back* — so the model provider only ever sees deterministic tokens
like `[EMAIL_ADDRESS_a47n1d8s9c0f]`, while you keep seeing real values locally.

## Quick start (Claude Code)

Run these **inside a `claude` session** — they are Claude Code slash commands, not
shell commands:

```
/plugin marketplace add FailSpy/zlauder
/plugin install zlauder
[restart Claude Code]
```

That's it. The plugin ships prebuilt binaries (no compile, no download) and
auto-routes each project the first time it sees it. After the one-time restart,
masking is live — run `/zlauder:status` to confirm. Details, scoping options, and
the standalone proxy are below.

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

**One proxy per project.** Each project gets its own proxy on an **OS-assigned
ephemeral port** (`127.0.0.1:0`), synchronized through a per-project **rendezvous file**
keyed by the project's path — so its key, token store, and config are fully isolated, and
two projects can never collide on a port (the birthday problem). Concurrent `claude`
sessions in *different* projects never interfere or correlate; two windows in the *same*
project share one proxy. The plugin writes the bound port into the project's gitignored
`.claude/settings.local.json` on the first session (or explicitly via `/zlauder:enable`).
The port is **sticky** (reused across proxy restarts when free), so it rarely changes; set
`[proxy] port = N` in `zlauder.toml` to pin a static port instead.

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
| `zlauder-hooks` | Claude Code control plane: `session-start` (auto-plumb routing on first sight, launch/recycle the proxy, learn its bound port), `statusline`, `config` (backs `/zlauder:privacy`), `reveal`, `settings` (backs `/zlauder:enable` / `/zlauder:disable`). Per-project routing is auto-plumbed by `session-start`; `/zlauder:enable` is the explicit redo. |
| `zlauder-state` | shared on-disk session state — the project-keyed **rendezvous** record (bound port/key/salt/pid/nonce) + the launch-lock and bind-error primitives; the single source of truth both binaries read. |

## Build

```sh
cargo build --release --workspace
# binaries: target/release/zlauder-proxy, target/release/zlauder-hooks

# HTTP-only ML (thin client; skips the local Candle backend entirely):
cargo build --release -p zlauder-proxy -p zlauder-hooks --no-default-features --features ml-http
```

The thin-client build compiles no Candle stack and downloads no model weights —
it only ever calls a remote endpoint (pair it with `backend = "http"` below).

Requires Rust ≥ 1.91 (the `anthropic-wire` dependency is edition 2024).

## License

ZlauDeR is licensed under the Business Source License 1.1
(`BUSL-1.1`). See [LICENSE](LICENSE).

## Install into Claude Code

zlauder installs as a **Claude Code plugin** — that is the only supported
interface. The [Quick start](#quick-start-claude-code) above is the entire
install; this section explains what those three lines actually do.

**Installed = routed.** The plugin's `SessionStart` hook
auto-plumbs each project the first time it sees it: it resolves the binaries (shipped
prebuilt, below), launches a proxy on an OS-assigned ephemeral port, and writes
`.claude/settings.local.json` (`ANTHROPIC_BASE_URL` + `ZLAUDER_PORT` + a `🛡` status
line that wraps any existing one as `🛡 … │ {your line}`; `ZLAUDER_STATUSLINE=off|shield|min|verbose`
tunes or hides the `🛡` segment — `shield` shows it ONLY when masking is confirmed and
nothing otherwise). The plugin also writes a `.claude/.gitignore` for that
file, so the machine-specific `http://127.0.0.1:<port>` can't be committed.

By default `/plugin install` lands the plugin at **user scope**, so its `/zlauder:*`
commands and `SessionStart` hook are available in *every* project — and the hook then
auto-plumbs each project the first time it sees it.

> **Thin-slice to a single project.** Prefer to scope the *whole plugin* to one
> repo instead of every project? Claude Code asks the install scope
> (`user` / `project` / `local`) during `/plugin install` — choose `project` and
> only that repo ever loads zlauder (and only it is auto-plumbed).

After install, masking activates with a **one-time restart**:

1. **Restart Claude Code once** in this project. The first session writes the route into
   `settings.local.json` and launches the proxy eagerly, but Claude Code applies a route
   written *during* SessionStart to the current session only unreliably (~1 in 5) — every
   session *after* the first reads it at startup, which always works. The statusline shows
   `⟳ ZlauDeR: restart to mask` until it's live, then `🛡`. Until this session is
   routed, ZlauDeR's intake gate **blocks** its messages so nothing sends unmasked
   first (set `ZLAUDER_NO_INTAKE_GATE=1` to send anyway without masking).
2. **`/zlauder:privacy`** — confirm routing + masking, or flip masking on/off live.
3. **`/zlauder:doctor`** — if masking won't come on, this preflight catches the usual causes
   (a local firewall/AV intercepting `127.0.0.1`, a busy static port).

> **Stale-port edge.** If the proxy dies *and* another process grabs its exact port before a
> new session relaunches (rare — a normal relaunch reuses the sticky port), that session is
> routed to the wrong port: it hangs or, if a foreign process answers, leaks unmasked to it.
> The hook detects this and tells you to **Ctrl-C + restart**; it never silently claims
> masking is active. Restarting re-routes to the fresh port.

You rarely run anything by hand. `/zlauder:enable` does the same write explicitly (and
seeds a starter `zlauder.toml`) — useful to re-enable after `/zlauder:disable`.

> **⚠ Before removing zlauder, run `/zlauder:disable --all` first.** The routing patch
> lives in each project's `.claude/settings.local.json`, not in the plugin, so removing
> the plugin does not remove it. Uninstall (or switch it off in the `/plugin` UI)
> *without* disabling first and that project's `ANTHROPIC_BASE_URL` keeps pointing at a
> proxy that no longer launches → **every request in that project fails** (Claude Code
> hangs for minutes, then errors) until you hand-edit `.claude/settings.local.json`. The
> `--all` sweep reverts the routing patch (and restores your status line) across every
> plumbed project; once the plugin is gone there is no hook left to self-heal it.

`zlauder-proxy` / `zlauder-hooks` are **shipped prebuilt per-platform** with the plugin
(precedence: PATH → shipped `bin/<triple>` → cached/in-repo build), so a marketplace
install needs **no compile and no download** — see [docs/RELEASING.md](./docs/RELEASING.md).
Shipped targets are `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
`x86_64-apple-darwin`, `aarch64-apple-darwin`, and `x86_64-pc-windows-msvc`. Release
assets use `zlauder-<triple>.tar.gz` for Linux/macOS and
`zlauder-x86_64-pc-windows-msvc.zip` for Windows.

A plugin cannot set `ANTHROPIC_BASE_URL` itself (only `agent`/`subagentStatusLine` are
honored from a plugin's settings.json, and there is no install-time hook), which is why
routing goes through a real settings source — written to the gitignored
`settings.local.json` and read at startup — the first install needs a one-time restart to
activate (every session after reads it reliably). See
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

#### Remote inference (`backend = "http"`)

Instead of loading the model in-process on every machine, the ML pass can call a
remote HF-compatible token-classification endpoint. This is useful for thin
clients sharing one model host or for HF Inference Providers.

```toml
[engine.ml]
enabled = true
backend = "http"
required = true   # strict: refuse requests whenever the endpoint isn't ready
# a self-hosted privacy-filter wrapper on your own infrastructure…
endpoint = "http://10.0.0.5:3007/detect"
# …or Hugging Face Inference Providers (zero infra, cloud):
# endpoint = "https://router.huggingface.co/hf-inference/models/openai/privacy-filter"
# auth_token_env = "HF_TOKEN"     # name of the env var holding the bearer token
```

- **Same detections.** Spans come back with the same labels the local backend
  emits and flow through the identical category gates / operators; the only
  difference is where the forward pass runs.
- **Fail-closed at request time.** Once `ready`, endpoint failures refuse the
  request instead of sending text with only regex coverage. User-text response
  bodies from the endpoint are not copied into logs, status, or errors.
- **Load failures follow hot-load semantics by default**: a dead endpoint at
  enable time shows `failed` and masking continues regex-only. Set
  `required = true` to refuse maskable requests whenever enabled ML is not
  `ready`; this is recommended for `backend = "http"`.
- **Flipping `required` applies live.** It is refusal policy, not recognizer
  identity.
- **Privacy trade-off.** Every un-cached piece of text is sent to that endpoint.
  Use only infrastructure you trust with that plaintext; the local backend
  remains the most private option.
- `model download` with `backend = "http"` just validates + probes the endpoint
  (there is nothing to download).
- **Slim thin-client build.** Because this path never loads a local model, you can
  compile the proxy + hooks with `--no-default-features --features ml-http` (see
  [Build](#build)) — no model weights, no Candle compile — and point `endpoint` at
  a shared model host.

### Highlighting un-masked values (`[engine.reveal_marker]`)

When an un-masked value is restored into the assistant's reply, ZlauDeR wraps it with
a marker so you can see locally which spans came back from a token. It is **on by
default** with the printable brackets `⟦`/`⟧`; tune or disable it via
`[engine.reveal_marker]`:

```toml
[engine.reveal_marker]
enabled = true       # on by default; set false to restore silently
prefix = "⟦"         # the default printable brackets — render in terminal, file, and web UI
suffix = "⟧"
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
- **Printable by default; ANSI optional.** The default `prefix`/`suffix` are the printable
  brackets `⟦`/`⟧` (U+27E6/U+27E7): they render in every sink (terminal, file, Claude Code
  web UI) and never occur in ordinary code or prose. Prefer terminal colour? Set them to
  ANSI escapes (out-of-band, so the model can't emit or override them) — but they show as
  literal escape bytes anywhere that doesn't interpret them. Whatever you pick, choose
  markers that don't occur in ordinary prose: the strip removes the **exact** literal from
  re-sent history (a backtick or `*` would over-strip code/emphasis).

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
  for a project (keyed by the rendezvous, stable even if the port changes), so cross-turn
  consistency survives a crash. A live `/zlauder:privacy` config
  change keeps the store (and salt), so determinism survives reconfiguration too.
- **Multi-session / multi-project:** each project runs its **own** proxy on a
  project-keyed ephemeral port — separate key, salt, store, and config. Concurrent
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
