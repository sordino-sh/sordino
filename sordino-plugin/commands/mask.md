---
description: Turn Sordino PII-masking on or off for this project — the everyday masking verb. `on` re-enables (clears any off at any scope); `off` turns masking off for THIS conversation (bounded, auto-re-arms). Read-only status is /sordino:status; routing is /sordino:enable / /sordino:uninstall.
argument-hint: "[on|off]"
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/scripts/mask.sh":*)
# User-only: `mask off` LOOSENS masking (plaintext PII can then egress upstream), so the model
# must never invoke it via the SlashCommand tool — a prompt-injection must not be able to turn
# masking off. The model SURFACES the exact command and the USER runs it. Read-only status lives
# in the un-gated /sordino:status.
disable-model-invocation: true
---

Masking control output:

!`bash "${CLAUDE_PLUGIN_ROOT}/scripts/mask.sh" "$ARGUMENTS"`

The block above is the result of `/sordino:mask $ARGUMENTS` (empty means "show status").
Everything here affects **only this project's** proxy — other projects/sessions are unaffected.

The two headline verbs:

- **`on`** — turn masking back **on**. This is unconditional: it clears any masking-off at **any**
  scope (this conversation, or the project master switch) **and** re-arms the master switch, so a
  single `on` always ends masked. Routing is untouched.
- **`off`** — turn masking **off for THIS conversation only**. Other conversations in this project
  keep masking. This is a **bounded** window: masking **auto-re-arms to ON in ~30 minutes** unless
  you extend it, and it stays off until then or until you run `/sordino:mask on`. Turning Claude
  Code off and on again does **not** re-mask and does **not** cancel the off — the proxy is a
  background daemon that outlives a Claude Code restart, and the off (and its ~30-min timer) live
  in that daemon.

Advanced forms of `off` (state them to the user; they run it):

- **`off --for <dur>`** — a custom bounded window, e.g. `off --for 10m`, `off --for 2h`,
  `off --for 1h30m`. Clamped to a 24h maximum, then it auto-re-arms.
- **`off --sticky`** — the explicit **indefinite** off: it stays off until you run `/sordino:mask
  on` (up to a 24h ceiling, then it auto-re-arms — nothing is ever truly unbounded). Warn the user:
  **this stays off until you re-enable it; there is no short timer to save you.**
- **`off --project`** — flip the whole-project **master switch** off instead of just this
  conversation. Warn the user that this master switch is **shared with any Codex sibling** running
  in this project, so it turns masking off for that too.

What masking off does and does **not** change:

- The **floor still holds while traffic transits the proxy**: registered **secrets stay masked**
  even with masking off (that floor can't be turned off here), and your **data policy is untouched**
  — categories, profile, threshold, ML and custom masks are exactly as you left them, nothing is
  written to disk.
- The one door **outside** these controls: setting `SORDINO_NO_INTAKE_GATE=1` removes the proxy
  from the request path entirely — with no proxy in the path there is **no floor at all** (secrets
  included). That is the only way past the "secrets always masked" guarantee, and it is a
  deliberate, explicit escape hatch, not something `/sordino:mask off` does.

Advanced verbs beyond on/off pass straight through to the privacy control plane: `status`,
`profile <name>`, `category <name> on|off`, `threshold <0-1>`, `model <download|on|off|status>`,
`reveal <token>`, `scrub …`, each accepting `--scope session|project|user|local`. (`on`/`off`
also take `--scope` to persist the master switch to a config layer.)

Report the result concisely, and keep the masking model right: the **user sees their real values
locally** at all times — masking only changes what the **model and the API provider** see
(deterministic `[TOKEN]` stand-ins). Never tell the user their own data is hidden from them.

- If it turned masking **off for this conversation**, confirm only this conversation is now
  unmasked, that registered secrets stay masked while traffic transits the proxy, and that it
  auto-re-arms in ~30 min (or your `--for` window) or immediately via `/sordino:mask on`.
- If it turned masking **on**, confirm masking is back on and that any prior off was cleared.
- If it reported that **routing isn't active for this session yet**, relay that this session needs
  to be routed through the proxy first: restart Claude Code once to activate routing, then
  `/sordino:mask off` works here. Do **not** suggest `--project` as a shortcut — it needs the same
  live proxy and would fail the same way pre-restart.

Do not run any other commands. If the script exited non-zero, surface its error message verbatim
and do not claim masking changed. Never print or echo the session/control key.

Advanced: `/sordino:mask off --for <dur>` / `off --sticky` / `off --project` — see the notes above.
