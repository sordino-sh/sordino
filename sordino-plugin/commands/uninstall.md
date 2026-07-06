---
description: Remove Sordino's plumbing from this project — reverts .claude/settings.local.json routing + status line so Claude Code stops routing through the proxy. `--all` sweeps every plumbed project; run it before deleting the plugin. Your sordino.toml policy is left in place. (To just turn masking off, use /sordino:disable.)
argument-hint: "[--all]"
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/scripts/uninstall.sh":*)
# User-only: tearing down routing is a loosen action; the model surfaces it, the user runs it.
disable-model-invocation: true
---

Removing the Sordino routing for this project. The script below removes the
`env.ANTHROPIC_BASE_URL` and `env.SORDINO_PORT` keys that enabling added to this project's
`.claude/settings.local.json` (and drops the `env` object if it becomes empty; older installs
that wrote the committed `.claude/settings.json` are cleaned up there too), removes the
`permissions` and `autoMode` entries enabling added, and undoes the status-line takeover: if
enabling wrapped a status line you already had, your original is **restored verbatim** from the
sidecar it saved (`.claude/sordino-statusline.json`); if you had none, the Sordino `🛡` line is
simply removed. A `statusLine` you set by hand *after* enabling is left untouched. It leaves the
seeded `sordino.toml` (your masking **policy**) in place, and leaves the running proxy alone: it
only stops Claude Code from routing through it. It also records this project as **opted out**, so
the plugin won't auto-re-enable it; run `/sordino:enable` to turn routing back on.

If you only want to turn masking **off** (without removing anything), that is `/sordino:disable`
— this command tears down the plumbing.

**`/sordino:uninstall --all`** sweeps EVERY project Sordino has plumbed (not just this one) and
clears their routing. It finds them from its own registry AND a scan of Claude Code's session
logs, so even an older route the registry doesn't list still gets cleaned (it only ever strips a
project that actually carries a Sordino route). Run it **before deleting the plugin**, so no
project is left pointing at a proxy that's gone — a dead `ANTHROPIC_BASE_URL` makes Claude Code
hang for minutes and then fail. (Note: a project reopened *after* the plugin is fully gone can't
self-heal, since the binaries are gone too — hence the pre-removal sweep.)

!`bash "${CLAUDE_PLUGIN_ROOT}/scripts/uninstall.sh" "$ARGUMENTS"`

Read the script output above, then:

- If it reverted the routing, confirm to the user that this project's
  `.claude/settings.local.json` no longer points at the Sordino proxy. Routing stops reliably
  after a **one-time restart** of Claude Code (it reads the route at startup); the current
  session may keep routing through the proxy until then, which is harmless. The project is now
  opted out, so Sordino won't auto-re-enable it (nor block its messages). Note that `sordino.toml`
  was intentionally left in place.
- If it reported that nothing was wired (no Sordino `env` block found), say so plainly — there
  was nothing to revert.
- For `--all`: relay how many projects were swept and whether all succeeded. Only tell the user
  it is **safe to delete the plugin** if the sweep reported no failures.

Do not run any other commands. If the script exited non-zero, surface its error message verbatim
and do not claim the change succeeded.
