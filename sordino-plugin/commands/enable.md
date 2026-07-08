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
categories — which is live and flipped with `/sordino:mask on|off`; flipping masking off leaves
routing in place and can never strand the session. Confirm both
with `/sordino:status`. Before UNINSTALLING the plugin, the
user should run `/sordino:uninstall --all` so no project is left pointing at a proxy that's gone.

After reporting the result, give the user a **brief onboarding** (a few lines, not a wall of
text) so they know what just happened and how to use it. Cover, in your own words:
- **Two axes, kept separate.** **Routing** is whether traffic goes through the proxy at all
  (set once by `/sordino:enable`, effectively permanent; removed by `/sordino:uninstall`).
  **Masking** is whether that routed traffic gets tokenized — live, flipped with
  `/sordino:mask on|off`. Routing-off is not the same as masking-off, and masking-off leaves
  routing in place (transparent pass-through), so it can never strand the session.
- **One honest "am I masked?" read.** `/sordino:status` is the single read-only answer — it
  reports the project master switch **and** whether THIS conversation is off. Trust it over any
  assumption that "the proxy is up, so I'm masked."
- **`/sordino:mask off` is per-conversation and bounded.** Its default scope is **THIS
  conversation only** (not the whole project), and it **auto-re-arms to ON in ~30 minutes**
  unless extended; `/sordino:mask on` resumes immediately. `off --project` instead flips the
  whole-project master switch (shared with any Codex sibling here) and stays off until re-enabled.
- **It's project-scoped** — masking is enabled for THIS project only; other projects are
  untouched until they run `/sordino:enable` there.
- **Watch it live** — `/sordino:monitor` opens a local web view of what's being masked.
- **The one bypass door.** Setting `SORDINO_NO_INTAKE_GATE=1` removes the intake floor — the
  block that stops an unrouted session from sending — so outbound text can egress **un-masked**.
  Leave it unset unless you specifically intend that. Only two paths send text un-masked: an
  announced `/sordino:mask off` (routing stays, PII passes un-tokenized) and this env var (which
  removes the proxy floor entirely) — nothing else drops the floor.
- **Restart once** to activate (per the activation note above).
Keep it short and practical — an orientation, not documentation.
