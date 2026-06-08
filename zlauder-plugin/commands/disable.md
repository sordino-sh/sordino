---
description: Stop routing this project through the ZlauDeR proxy (reverts .claude/settings.json; requires restart)
allowed-tools: Bash(bash:*)
---

Reverting the ZlauDeR wiring for this project. The script below removes the `env.ANTHROPIC_BASE_URL` and `env.ZLAUDER_PORT` keys that `/zlauder:enable` added to this project's `.claude/settings.json` (and drops the `env` object if it becomes empty), and undoes the status-line takeover: if `/zlauder:enable` wrapped a status line you already had, your original is **restored verbatim** from the sidecar it saved (`.claude/zlauder-statusline.json`); if you had none, the ZlauDeR `🛡` line is simply removed. A `statusLine` you set by hand *after* enabling is left untouched. It leaves all other settings — and the seeded `zlauder.toml` — in place, and leaves the running proxy alone: it only stops Claude Code from routing through it.

!`bash "${CLAUDE_PLUGIN_ROOT}/scripts/disable.sh"`

Read the script output above, then:

- If it reverted the settings, confirm to the user that this project's `.claude/settings.json` no longer points at the ZlauDeR proxy.
- If it reported that nothing was wired (no ZlauDeR `env` block found), say so plainly — there was nothing to revert.

Then remind the user, clearly, that **this does not take effect until Claude Code is restarted.** The `ANTHROPIC_BASE_URL` for the current session was set at startup and cannot be changed mid-session; the current session will keep routing through the proxy until they quit and relaunch Claude Code. After restart, traffic goes straight to Anthropic with no masking.

Do not run any other commands. If the script exited non-zero, surface its error message verbatim and do not claim the change succeeded.
