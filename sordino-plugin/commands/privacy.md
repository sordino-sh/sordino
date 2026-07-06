---
description: View or change Sordino PII-masking for this project — status, on/off, profile, category, threshold, ML model, token reveal, and transcript scrub
argument-hint: "[status | on | off | profile <name> | category <name> on|off | threshold <0-1> | model <download|on|off|status> | reveal <token> | scrub --transcript <jsonl> (--value <text> | --values-file <file>)] [--scope session|project|user|local]"
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/scripts/privacy.sh":*)
# User-only: this panel can LOOSEN masking (off / category off / profile minimal / model off /
# reveal / scrub), so the model must not invoke it via the SlashCommand tool. The model
# surfaces the exact command and the USER runs it. Read-only status moved to /sordino:status.
disable-model-invocation: true
---

Privacy control output:

!`bash "${CLAUDE_PLUGIN_ROOT}/scripts/privacy.sh" "$ARGUMENTS"`

The block above is the result of the unified Sordino privacy control plane for the
request "$ARGUMENTS" (empty means "show status"). Everything here affects **only
this project's** proxy — other projects/sessions are unaffected.

When you explain any of this to the user, keep the model of masking right: the
**user sees their real values locally** at all times — masking only changes what
the **model and the API provider** see (deterministic `[TOKEN]` stand-ins). It
protects data from the provider, not from the user. Never tell the user their own
data is hidden, redacted, or unavailable to them; a token always corresponds to a
real value they can see, and `reveal` just decodes one for convenience/audit.

This command controls **masking** (what the running proxy does to your text) — the
everyday on/off, live and with no restart. It is the real "is Sordino being used?"
control. Do not confuse it with **routing** (whether traffic goes through the proxy at
all): routing is plumbed AUTOMATICALLY the first time the plugin sees a project (written
to `.claude/settings.local.json`, gitignored) and is then effectively permanent;
`/sordino:enable` sets it explicitly and `/sordino:uninstall` removes it (each takes effect
reliably after a one-time restart of Claude Code — a freshly-written route is only read at
startup). Because
masking is policy *on top of* routing,
flipping it off (transparent pass-through) can never strand the session. The `status`
view shows both — proxy health, whether `ANTHROPIC_BASE_URL` is routed, and the masking
config.

Report the result concisely:

- For `status` (or no args): read the status-line's distinct states — `🛡` = proxy up
  **and** masking on **and** this session routed (fully active); `⟳ Sordino: restart to mask`
  = plumbed but this session isn't routed yet, so restart Claude Code once to activate it;
  `✗ Sordino not masking` = routing is off for this project (opted out); `⚠ Sordino OFF :<port>`
  = proxy up but masking is off (transparent pass-through); `⚠ Sordino routed, proxy down
  :<port>` = routed but the proxy isn't answering; `❔ Sordino :<port> (unverified)` = up but the
  state couldn't be confirmed. Don't conflate "OFF" (up, not masking) with "proxy down"
  (unreachable) or "not masking" (routing off). Also report whether this session is **routed**
  (`ANTHROPIC_BASE_URL` = `http://127.0.0.1:<port>` vs `(unset)`/the Anthropic API) and the
  masking state (ON/OFF, profile, categories). If the proxy is up but this session isn't routed,
  tell the user a just-written route takes effect after a **one-time restart** of Claude Code
  (or to run `/sordino:enable`); suggest `/sordino:verify` to confirm both legs.
- For a change (`on`/`off`/`profile`/`category`/`threshold`): confirm what changed
  and at which `--scope` (default `session`, i.e. live-only and lost on restart;
  `project`/`local`/`user` persist to a TOML layer).
- For `model …` (the optional `openai/privacy-filter` ML recognizer, CPU): this adds
  free-text detection (names, locations) on top of the regex recognizers.
  - `model download [<repo>]`: fetches + caches the model (can be large/slow on the
    first run). Relay success or the error verbatim.
  - `model on [--scope …]`: turns the recognizer on. **It loads in the background** —
    the model status goes `loading → ready`, and **text is NOT filtered through the
    ML model until it reports `ready`** (regex masking keeps working meanwhile, so the
    user can continue or wait). Remind them that names/locations also need
    `/sordino:privacy category personal on`.
  - `model off`: turns it off live. `model status`: shows the model + lifecycle
    (`disabled`/`loading`/`ready`/`failed`). Surface the loading/failed state plainly.
- For `reveal <token>`: present the decoded plaintext. If it failed (unknown token,
  proxy down, binary unavailable), relay the error verbatim and explain the likely
  cause.
- For `scrub --transcript <jsonl> (--value <text> | --values-file <file>)`: report
  the redaction count, removed thinking records, relinked parent pointers, and
  backup path. For values containing spaces, prefer `--values-file`; the slash
  wrapper splits arguments conservatively.

Never print or echo the session/control key.
