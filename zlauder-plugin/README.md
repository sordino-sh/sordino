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

## How routing works (you usually don't lift a finger)

A Claude Code plugin **cannot set `ANTHROPIC_BASE_URL`** and **cannot set the
main `statusLine`** directly — a plugin's shipped `settings.json` only honors the
`agent` and `subagentStatusLine` keys; `env` and `statusLine` are ignored, and
there is no install/build lifecycle hook. Those are exactly the two things needed
to *route* Claude Code through the proxy and show live status.

So the plugin does it the one way it can: its `SessionStart` hook **auto-plumbs**
routing the first time it sees a project. It writes `env.ANTHROPIC_BASE_URL` (and
`ZLAUDER_PORT` + a `🛡` status line) into this project's
**`.claude/settings.local.json`** —
`${CLAUDE_PROJECT_DIR}/.claude/settings.local.json`. The plugin also writes a
`.claude/.gitignore` for that file, so the machine-specific `http://127.0.0.1:<port>`
can't be committed and strand a teammate on a dead pointer. Routing
is **per-project**, not global. Claude Code reads that route reliably only at
**startup**, so masking goes live after a **one-time restart** (every session after
the first reads it at startup and routes reliably) — and until this session is routed,
ZlauDeR's intake gate blocks its messages so nothing sends unmasked first. (Web
`claude.ai/code` can't reach a localhost proxy and is out of scope.)

## Activation flow

Installing the plugin is, in the common case, all you do — **installed = routed**:

1. **Install the plugin** (see Install below). Its `SessionStart` hook runs each
   session. The first time it sees a project it resolves the prebuilt per-platform
   binary that shipped with the plugin (**no compile, no download**), launches a
   **per-project proxy on an OS-assigned ephemeral port**, and publishes that port to a
   per-project *rendezvous* the hooks/CLI look up by project root (pin one with
   `[proxy] port` if you need it fixed; no fixed or derived port to collide). It bakes
   that route into `.claude/settings.local.json`. Because Claude Code snapshots settings
   at startup, the route written now applies reliably only from the *next* session.
2. **Restart Claude Code once.** A freshly-written route is only read reliably at
   startup, so masking goes live after a one-time restart (the statusline shows
   `⟳ ZlauDeR: restart to mask` until then). Until this session is routed, ZlauDeR
   blocks outbound messages so nothing sends unmasked first — and every session after
   the first is masked automatically. (`/zlauder:enable` does the same write explicitly
   — handy to re-enable after `/zlauder:disable`, or to also seed a starter
   `zlauder.toml` — but you rarely need it. The full annotated config reference is
   shipped as `zlauder.toml.example`.)
3. **Run `/zlauder:privacy`** anytime to confirm routing + masking, or to flip
   masking on/off live.

Set `env.ZLAUDER_STATUSLINE=off` to hide the `🛡` segment (your own status line still
shows), `shield` to show the `🛡` ONLY when masking is confirmed (nothing in any other
state), or `min`/`verbose` to change how much it shows.

To stop routing: `/zlauder:disable` (this project; stops routing reliably after a one-time
restart, and opts the project out of auto-routing). **Before uninstalling the plugin, run `/zlauder:disable --all`** to sweep
every project the plugin plumbed, so none is left pointing at a proxy that's about to
disappear — a dead `ANTHROPIC_BASE_URL` makes Claude Code hang for minutes then fail,
and once the plugin is gone there's no hook left to self-heal it. (The patch lives in
the project's `.claude/settings.local.json`, not in the plugin, so it persists until you
disable it — there is no uninstall lifecycle hook to undo it for you.)

## Install

Run these **inside a `claude` session** (they are slash commands, not shell
commands), then reload so the freshly installed plugin activates without
restarting Claude Code:

```
/plugin marketplace add FailSpy/zlauder
/plugin install zlauder
/reload-plugins
```

By default `/plugin install` lands the plugin at **user scope** (commands and the
`SessionStart` hook available in every project); Claude Code asks the scope, so
pick `project` if you'd rather load zlauder in only one repo.
(Or add this directory as a local marketplace if you are working in-repo.)
Installing the plugin wires up the `SessionStart` hook and the `/zlauder:*`
commands, and the hook auto-plumbs routing on the first session it sees in each
project (see the activation flow above). **This plugin is the only supported
install interface** — there is no separate CLI setup step.

### Troubleshooting: `git@github.com: Permission denied (publickey)`

If `/plugin marketplace add` or `/plugin install` fails with

```
Failed to clone repository: Cloning into '…/plugins/cache/temp_github_…'
git@github.com: Permission denied (publickey).
```

it is **not** this plugin. Claude Code clones marketplace plugins over **HTTPS**, but a
global git rule on your machine is rewriting that HTTPS URL to SSH:

```
git config --global --get-regexp 'url\..*\.insteadof'
# e.g.  url.git@github.com:.insteadof https://github.com/
```

That `insteadOf` rewrites **every** `https://github.com/…` clone to `git@github.com:…`. The repo
being **public is irrelevant**: public visibility only grants *anonymous HTTPS* access — GitHub's
SSH transport is **never anonymous**, it always authenticates the *account* behind the key, not the
repo. So the rule turns a clone that needed **no** auth (public HTTPS) into one that **requires** a
usable SSH key, and the install fails (`Permission denied (publickey)`) when Claude Code's git
subprocess has no key/agent available. There is no Claude Code setting to force HTTPS, so the fix is
in your git config. The clean option keeps
SSH for your **pushes** while letting HTTPS clones (including this install) through — swap
`insteadOf` for `pushInsteadOf`:

```
git config --global --unset url.git@github.com:.insteadof
git config --global url."git@github.com:".pushInsteadOf "https://github.com/"
```

(Or just drop the rule with the `--unset` line alone, or make `ssh -T git@github.com` authenticate.)

## Commands

Two layers, deliberately separated. **Routing** (whether traffic goes through the proxy
at all) is plumbing: auto-set once into `settings.local.json` on the first session, then
effectively permanent — `/zlauder:enable` / `/zlauder:disable` set it explicitly (each
takes effect reliably after a one-time restart of Claude Code). **Masking** (what the running proxy does to your
text) is policy: the everyday on/off, controlled live by `/zlauder:privacy`. Masking sits
*on top of* routing, so turning it off is transparent pass-through and never strands a
session.

**Who can run what.** The model can drive only the read-and-tighten commands —
`/zlauder:status`, `/zlauder:secrets`, `/zlauder:doctor`, `/zlauder:enable` — through its
SlashCommand tool. The commands that can *loosen* masking or open a browser
(`/zlauder:privacy`, `/zlauder:disable`, `/zlauder:monitor`) are **user-only**: the model
surfaces the exact command and you run it. This is enforced by `disable-model-invocation` on
those commands plus the `permissions.deny`/`ask` rules the plugin writes into
`.claude/settings.local.json` (deny the model's Bash on the `zlauder-*` CLIs; force an `ask`
prompt on its edits of `zlauder.toml` / `zlauder.local.toml`).

> **Defense-in-depth, not a sandbox.** These rules block the casual and prompt-injection
> paths (the model running `/zlauder:privacy off`, the `zlauder-*` CLIs, or editing the config
> via the Edit tool all hit a deny/ask; Claude Code also prompts on shell redirection by
> default). A model with full shell access could still reach the proxy another way — but that
> is bounded: the proxy re-reads config only on a key-gated reload or a restart (the model
> can't trigger a reload), and the status line shows `⚠ OFF` the moment masking is off, so a
> silent disable isn't possible.

| Command | What it does |
|---|---|
| `/zlauder:enable` | Explicit per-project routing setup (usually automatic — the `SessionStart` hook does this on first sight). Writes this project's gitignored `.claude/settings.local.json` to set `ANTHROPIC_BASE_URL` (and `ZLAUDER_PORT`) at the proxy's per-project OS-assigned ephemeral port, takes over the status-line slot (wrapping any existing line as `🛡 … │ {your line}`, original saved for restore), and seeds a practical starter `zlauder.toml`. **Masking activates after a one-time restart of Claude Code** (ZlauDeR blocks the first unrouted message until then, so nothing sends unmasked). |
| `/zlauder:disable` | Revert the routing change for this project and restore your original status line (saved at enable time; if you had none, the zlauder line is just removed) so traffic goes straight to Anthropic again — effective after a one-time restart, and it opts the project out of auto-routing. **`/zlauder:disable --all`** sweeps every plumbed project (found via its registry and a scan of Claude Code's session logs); run it **before uninstalling** so no project strands on a dead proxy. |
| `/zlauder:status` | **Read-only** (model-invocable): proxy health, whether this session is routed, and the masking state (on/off, profile, categories, ML model). Changes nothing — the model uses this to report status; to *change* anything it surfaces the `/zlauder:privacy` command for you to run. |
| `/zlauder:privacy [args]` | **User-only.** Unified masking control. With no args (or `status`): show proxy health, whether this session is routed, and the masking state. Also: `on` / `off`, `profile <name>`, `category <name> on\|off`, `threshold <0-1>` (each takes `--scope session\|project\|user\|local`), and `reveal <token>` to decode one masked token (e.g. `[EMAIL_ADDRESS_a47n1d8s9c0f]`) via the key-gated proxy. |
| `/zlauder:privacy model …` | The optional `openai/privacy-filter` ML recognizer (CPU) for free-text PII (names, locations). `model download [<repo>]` caches the weights (large/slow first run); `model on`/`off` toggles it (on **loads in the background** — text is not filtered through the model until `model status` shows `ready`, so masking stays regex-only meanwhile); `model status` reports `disabled\|loading\|ready\|failed`. Pair with `category personal on`. |
| `/zlauder:verify` | **Read-only** (model-invocable): proves THIS session is fully active in two distinct legs — the engine **masks** (a key-gated canary comes back tokenized) AND this session is **routed** (`ANTHROPIC_BASE_URL` points at the proxy). A green engine with an unrouted session reads ✗ — the case to catch (masking is on, but this session bypasses it and sends unmasked). |
| `/zlauder:doctor` | **Read-only** (model-invocable): preflight self-check for the loopback / firewall / port footguns that would make masking requests hang. |

> **Changed in 0.2.0:** `/zlauder:status` and `/zlauder:reveal` were folded into
> `/zlauder:privacy` (`/zlauder:privacy status` and `/zlauder:privacy reveal <token>`).
> The standalone `zlauder-hooks init` CLI setup path was removed — the plugin is now
> the sole install interface.
>
> **Changed in 1.0:** `/zlauder:status` is back as a standalone **read-only** command so the
> model can check masking state without being able to change it; `/zlauder:privacy` (which
> can *loosen* masking) is now user-only. `reveal` / `scrub` stay inside the user-only
> `/zlauder:privacy`.

## Troubleshooting

- **"Is masking actually on?"** Run `/zlauder:verify`. It checks two independent things — the
  engine **masks** (a key-gated canary) AND this session **routes** through the proxy; both must
  pass. `/zlauder:status` shows the same at a glance via the status line.
- **A message was blocked, or the status line shows `⟳ ZlauDeR: restart to mask`.** Routing was
  just written, but Claude Code applies a new route reliably only at startup — so until you
  restart, ZlauDeR's **intake gate blocks this session's messages** (it would otherwise send
  them UNMASKED before masking is live). **Restart Claude Code once**, then `/zlauder:verify`.
  To send a message this session WITHOUT masking — skipping the gate — set
  `ZLAUDER_NO_INTAKE_GATE=1` in your environment before launching Claude Code.
  (`/zlauder:enable` re-writes the route if it went missing.)
- **Requests hang for ~3 minutes, or the status line shows `⚠ ZlauDeR routed, proxy down`.** A
  local security/AV product or a hardened loopback firewall is intercepting `127.0.0.1`. Run
  `/zlauder:doctor` — it pinpoints the loopback / firewall / port problem and prints the fix.
- **A token won't decode with `/zlauder:privacy reveal`.** "unknown token" means no such handle
  in this session's store (it may be from another session, or expired). "token is a broker
  secret … never revealable here" means the value is a registered secret resolved only at the
  tool boundary — by design; use `/zlauder:monitor` to inspect it locally.
- **Every request fails right after uninstalling.** A project's `settings.local.json` still
  points at a now-dead proxy. Run **`/zlauder:disable --all` BEFORE uninstalling** to sweep every
  plumbed project; if you already uninstalled, run `/zlauder:disable` in the affected project (or
  delete the `ANTHROPIC_BASE_URL` / `ZLAUDER_PORT` lines from its `.claude/settings.local.json`).
- **See what's being masked.** `/zlauder:monitor` prints a local, key-gated URL to inspect this
  project's masked traffic; `/zlauder:secrets` shows which registered `[[secrets]]` resolved.

## Updating the plugin

A `/plugin update` (or marketplace re-install) is **staged**, not live: the running
session keeps the old hooks and binaries until you start a **new** session. On that
next start the `SessionStart` hook notices the proxy is an older build — it compares
the proxy's reported build id against its own — and **recycles** it, stopping the old
proxy and relaunching the new one on the same port, reusing the token salt so masking
stays prompt-cache-stable. The new plugin code and a matching proxy thus come up
together at the next start; you never manage the proxy by hand. (An old session left
open keeps using the old proxy until it too is restarted — harmless, since port and
salt are stable across the recycle.)

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
   triple, e.g. `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, or
   `x86_64-pc-windows-msvc`.
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
(glibc ≥ 2.35), `x86_64` / `aarch64` macOS, and `x86_64` Windows
(`x86_64-pc-windows-msvc`). Release assets are named `zlauder-<triple>.tar.gz`
for Linux/macOS and `zlauder-x86_64-pc-windows-msvc.zip` for Windows. On Windows,
runtime support assumes Claude Code can run this plugin's existing bash scripts;
native PowerShell/cmd wrappers are not shipped.

On any other platform there is no shipped binary, so the hook falls through to the
source build (which needs the cargo workspace + toolchain). In that case, put the
binaries on your `PATH` — e.g. grab an archive from the
[GitHub Release](https://github.com/FailSpy/zlauder/releases) and drop them in
`~/.local/bin` — or set `$ZLAUDER_WORKSPACE` to a checkout.

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

### Invocation shapes ZlauDeR's hooks cannot see

ZlauDeR ships entirely as this plugin's `SessionStart` / `UserPromptSubmit` /
`PreToolUse` hooks — there is no other lever available to a Claude Code plugin.
Three real Claude Code invocation shapes bypass that hook layer, verified
against the shipped `cli.js` (v2.1.198) control flow rather than assumed:

- **`claude --bare` / `--safe-mode`** (env `CLAUDE_CODE_SIMPLE=1` /
  `CLAUDE_CODE_SAFE_MODE=1`) skip plugin-hook loading entirely — Claude Code's
  own flag description says as much ("skip hooks/plugins"), and it's not a
  partial skip: `loadPluginHooks()` simply never runs, so ZlauDeR's fail-closed
  UserPromptSubmit intake gate never fires for that session. Unlike the two
  items below, a `--bare`/`--safe-mode` session **does** make real model API
  calls — if this project's route hasn't already been baked by a prior normal
  session, real PII can reach the API provider unmasked with **no warning at
  all**, because the mechanism that would warn is exactly what's disabled.
  `zlauder:doctor` can only detect this from *within* a normal session
  (reading its own `CLAUDE_CODE_SIMPLE`/`CLAUDE_CODE_SAFE_MODE` env) — it
  cannot self-detect from inside a `--bare` session, since ZlauDeR's own hook
  wouldn't be invoked there either. Avoid `--bare`/`--safe-mode` on projects
  where you're relying on ZlauDeR, and check your shell/CI environment isn't
  setting either variable for you.
- **`claude mcp serve`** (Claude Code exposing its own Bash/Read/Edit/etc. tool
  surface as an MCP server to any connecting client) never calls the
  SessionStart or PreToolUse hook-dispatch machinery at all — tool calls
  execute directly with zero permission decision and zero ZlauDeR
  involvement. This mode makes no outbound LLM calls of its own, so there's no
  PII-to-model risk from it specifically, but any connecting MCP client gets
  ungated local tool access with none of ZlauDeR's protections in effect.
- **Remote Control's `bash_command` message** (the transport behind
  `claude remote-control` / `claude daemon remote-control add`) executes a
  one-shot shell command directly, the same way the local `!cmd` TUI shortcut
  does — no model turn, no tool executor, no hooks. Same shape as the
  `mcp serve` gap above: no PII-to-model risk, but arbitrary local shell exec
  with zero ZlauDeR involvement, reachable from wherever Remote Control is
  paired.

Everything else in Claude Code's remote-control/remote-drive surface — the
in-session `/remote-control` toggle, the standalone remote-control daemon's
spawned `--print --sdk-url` worker processes, background-agent socket attach,
the IDE bridge, MCP "channel" push, and the generic `--sdk-url` SDK transport
teammates/sub-agents also use — funnels genuine chat turns through the same
`UserPromptSubmit` dispatch a locally-typed prompt uses, so the fail-closed
intake gate above covers it identically; this was verified end-to-end against
the shipped bundle, not just assumed from the invocation's shape. See
`e2e/remote-control-first-contact.sh` for the regression test.
