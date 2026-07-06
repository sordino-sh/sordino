---
description: Explicitly route this project's Claude Code through the Sordino masking proxy (writes .claude/settings.local.json, seeds practical sordino.toml). Usually automatic; masking activates after a one-time restart of Claude Code (Sordino blocks the first unrouted message until then, so nothing sends unmasked).
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/scripts/enable.sh":*)
---

Script output:

!`bash "${CLAUDE_PLUGIN_ROOT}/scripts/enable.sh"`

This is the per-project **routing** setup, and in most cases you don't need to run it:
the plugin AUTO-ENABLES routing the first time it sees a project (it writes the route on
the first session; masking activates after a one-time restart of Claude Code, which only
reliably picks up a freshly-written route at startup). Run `/sordino:enable` to do
that explicitly — e.g. to turn routing back on after `/sordino:uninstall`, or to refresh a
stale status-line path. It writes this project's **`.claude/settings.local.json`**
(which the plugin keeps out of git via a `.claude/.gitignore`, so the machine-specific
`http://127.0.0.1:<port>` is never committed) with `ANTHROPIC_BASE_URL` + `SORDINO_PORT`
and a `🛡` status line — wrapping any
line you already had as `🛡 … │ {your line}` (the original is saved and restored on
`/sordino:uninstall`) — and seeds a practical starter `sordino.toml` if absent. The
exhaustive reference is `sordino.toml.example`. Hide the `🛡` segment with
`env.SORDINO_STATUSLINE=off`, or show it ONLY when masking is confirmed with
`env.SORDINO_STATUSLINE=shield`.

Report the result above, then make the activation model clear: a freshly-written route
takes effect reliably only after a **one-time restart** of Claude Code (it reads
`ANTHROPIC_BASE_URL` from `settings.local.json` at startup; a mid-session pickup happens
only occasionally and can't be relied on). So tell the user to restart Claude Code once —
the statusline shows `⟳ Sordino: restart to mask` until it's live, then `🛡`. Until this
session is routed, Sordino **blocks** outbound messages so nothing reaches the API unmasked
(to send anyway without masking this session, set `SORDINO_NO_INTAKE_GATE=1`). Every session
after the first is masked automatically.

This command controls **routing** (whether traffic goes through the proxy at all, set once
and then effectively permanent). The everyday control is **masking** — on/off, profile,
categories — which is live and managed with `/sordino:privacy`; flipping masking off leaves
routing in place (transparent pass-through) and can never strand the session. Confirm both
with `/sordino:privacy` (or `/sordino:privacy status`). Before UNINSTALLING the plugin, the
user should run `/sordino:uninstall --all` so no project is left pointing at a proxy that's gone.

After reporting the result, give the user a **brief onboarding** (a few lines, not a wall of
text) so they know what just happened and how to use it. Cover, in your own words:
- **It's project-scoped** — masking is enabled for THIS project only; other projects are
  untouched until they run `/sordino:enable` there.
- **Watch it live** — `/sordino:monitor` opens a local web view of what's being masked for
  this project.
- **The everyday controls** — `/sordino:privacy` to change what's masked, `/sordino:disable`
  to quickly turn masking off (this conversation, or `--project`), `/sordino:verify` to
  confirm the live state, `/sordino:uninstall` to remove routing entirely.
- **Restart once** to activate (per the activation note above).
Keep it short and practical — an orientation, not documentation.
