# zlauder (Claude Code plugin)

Control plane for **ZlauDeR**, a local PII mask/unmask reverse-proxy for Claude
Code. The proxy sits between Claude Code and the Anthropic Messages API, masks
personal data on the way *out* (email, phone, credit card, IP, API keys, IBAN,
SSN, …), and unmasks it on the way *back* — so the provider only ever sees
deterministic tokens like `[EMAIL_ADDRESS_a47n1d8s9c0f]`, while you keep seeing
real values locally. This plugin launches and supervises that proxy per project
(a `SessionStart` hook), surfaces its status, lets you flip masking on/off, and
reveals a token for audit. The masking itself lives in the `zlauder-proxy` /
`zlauder-engine` binaries; see the [main repo README](../README.md) for the full
design.

## CRITICAL: what this plugin cannot do for you

A Claude Code plugin **cannot set `ANTHROPIC_BASE_URL`** and **cannot set the
main `statusLine`**. Those are exactly the two things needed to *route* Claude
Code through the proxy and to show live status. A plugin's shipped
`settings.json` only honors the `agent` and `subagentStatusLine` keys — `env`
and `statusLine` are ignored. There is also no install/build lifecycle hook.

So enabling the plugin alone does **not** route your traffic through the proxy.
The `SessionStart` hook will launch the proxy and inject an informational
context message, but until `ANTHROPIC_BASE_URL` points at the proxy, requests
still go straight to `api.anthropic.com`. The `/zlauder:enable` command patches
this project's `.claude/settings.json` (`${CLAUDE_PROJECT_DIR}/.claude/settings.json`)
to set that variable — routing is **per-project**, not global — and Claude Code reads
`env` only at startup, so **you must restart Claude Code afterward.**

## Activation flow (do these in order)

1. **Enable the plugin** (see Install below). The `SessionStart` hook now runs
   each session; on first run it resolves the prebuilt per-platform binary that
   shipped with the plugin (**no compile, no download**) and launches the proxy
   on a **per-project port derived in `18000..20000`** from the project root
   (override with `ZLAUDER_PORT`). Routing is **not** active yet.
2. **Run `/zlauder:enable`.** This is the per-project setup step. It patches this
   project's `.claude/settings.json` with `env.ANTHROPIC_BASE_URL=http://127.0.0.1:<derived-port>`
   (and `env.ZLAUDER_PORT`), adds a `🛡` status line, and seeds a starter
   `zlauder.toml` if the project has none.
3. **Restart Claude Code.** `env` is read only at startup; without a restart the
   new base URL is not picked up and traffic still bypasses the proxy.
4. **Run `/zlauder:privacy`** to confirm the session is actually routed through
   the proxy and masking is on.

To stop routing: `/zlauder:disable` reverts the `settings.json` change; restart
Claude Code again for it to take effect.

## Install

Add the marketplace and enable the plugin:

```
/plugin marketplace add FailSpy/zlauder
/plugin install zlauder
```

(Or add this directory as a local marketplace if you are working in-repo.)
Enabling the plugin only wires up the `SessionStart` hook and the
`/zlauder:*` commands — it does **not** route traffic. Continue with the
activation flow above. **This plugin is the only supported install interface** —
there is no separate CLI setup step.

## Commands

Two layers, deliberately separated: `enable`/`disable` control **routing** (whether
traffic goes through the proxy at all — a `settings.json` patch that needs a
restart), while `privacy` controls **masking** (what the running proxy does — live,
no restart).

| Command | What it does |
|---|---|
| `/zlauder:enable` | Per-project setup: patch this project's `.claude/settings.json` to set `ANTHROPIC_BASE_URL` (and `ZLAUDER_PORT`) at the proxy's per-project derived port, add a status line, and seed a starter `zlauder.toml`. **Requires a Claude Code restart to take effect.** |
| `/zlauder:disable` | Revert the routing change (and the zlauder status line) so traffic goes straight to Anthropic again. Also requires a restart. |
| `/zlauder:privacy [args]` | Unified masking control. With no args (or `status`): show proxy health, whether this session is routed, and the masking state (on/off, profile, categories, ML model). Also: `on` / `off`, `profile <name>`, `category <name> on\|off`, `threshold <0-1>` (each takes `--scope session\|project\|user\|local`), and `reveal <token>` to decode one masked token (e.g. `[EMAIL_ADDRESS_a47n1d8s9c0f]`) via the key-gated proxy. |
| `/zlauder:privacy model …` | The optional `openai/privacy-filter` ML recognizer (CPU) for free-text PII (names, locations). `model download [<repo>]` caches the weights (large/slow first run); `model on`/`off` toggles it (on **loads in the background** — text is not filtered through the model until `model status` shows `ready`, so masking stays regex-only meanwhile); `model status` reports `disabled\|loading\|ready\|failed`. Pair with `category personal on`. |

> **Changed in 0.2.0:** `/zlauder:status` and `/zlauder:reveal` were folded into
> `/zlauder:privacy` (`/zlauder:privacy status` and `/zlauder:privacy reveal <token>`).
> The standalone `zlauder-hooks init` CLI setup path was removed — the plugin is now
> the sole install interface.

## How the binaries are resolved

`zlauder-proxy` and `zlauder-hooks` ship **prebuilt, per-platform** with the
plugin. CI (`.github/workflows/release.yml`) builds them for every supported
target and publishes them on the `plugin-dist` branch under
`bin/<target-triple>/`; the marketplace entry installs from that branch, so
`/plugin install zlauder` lands a ready-to-run binary for your OS/arch with **no
compile and no runtime download**. (See [docs/RELEASING.md](../docs/RELEASING.md).)

The `SessionStart` hook (`scripts/session-start.sh`) resolves them lazily each
session and no-ops once a working binary is found. Precedence:

1. **On `PATH`** — an already-installed `zlauder-proxy` / `zlauder-hooks`.
2. **`${CLAUDE_PLUGIN_ROOT}/bin/<triple>/`** — the prebuilt binary shipped for
   *your* platform (the normal marketplace path). `<triple>` is your Rust target
   triple, e.g. `x86_64-unknown-linux-gnu` or `aarch64-apple-darwin`.
3. **`${CLAUDE_PLUGIN_ROOT}/bin/`** — a flat, hand-dropped binary.
4. **`${CLAUDE_PLUGIN_DATA}/bin/`** — a binary this hook built on a prior session.
5. **`<workspace>/target/release/`** — an in-repo `cargo build --release`.
6. **Build from source** (in-repo dev only) — `cargo build --release` from
   `$ZLAUDER_WORKSPACE` or `${CLAUDE_PLUGIN_ROOT}/..`, cached into
   `${CLAUDE_PLUGIN_DATA}/bin/`. Needs a Rust toolchain and network (it fetches
   the pinned git deps). Steps 1–5 satisfy a normal install, so this only runs
   for someone hacking on zlauder itself.

If none can produce a binary, the hook prints a clear error and exits non-zero.

**Supported platforms (shipped binaries):** `x86_64` / `aarch64` Linux
(glibc ≥ 2.35) and `x86_64` / `aarch64` macOS. On any other platform there is no
shipped binary, so the hook falls through to the source build (which needs the
cargo workspace + toolchain). In that case, put the binaries on your `PATH` —
e.g. grab a tarball from the [GitHub Release](https://github.com/FailSpy/zlauder/releases)
and drop them in `~/.local/bin` — or set `$ZLAUDER_WORKSPACE` to a checkout.

## Security and limitations

The guarantee is narrow and worth stating plainly: masked PII (per the
configured categories) does not reach the Anthropic API over the wire — the
proxy masks the actual request bytes. It is **not** a TLS-intercepting MITM
(Claude Code natively honors `ANTHROPIC_BASE_URL`, so no certificates are
installed), and it does **not** protect against a model with local shell access,
which can read local files — including the session-key state file — just like
you can. Detection recall is presidio's; `personal` entities (PERSON/LOCATION/
ORG) need an NLP model and are off by default. The control endpoints
(`reveal`, enable/disable masking, config) are gated by a session key stored in
a `0600` file, so a tool-driven `curl` cannot reveal tokens or flip masking off.
For the full threat model, the "four arrows" design, what is and isn't masked,
and the prompt-cache/determinism notes, see the [main repo README](../README.md).
