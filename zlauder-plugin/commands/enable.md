---
description: Set up + route this project's Claude Code through the zlauder masking proxy (patches .claude/settings.json, seeds zlauder.toml; requires restart)
allowed-tools: Bash(bash:*)
---

Script output:

!`bash "${CLAUDE_PLUGIN_ROOT}/scripts/enable.sh"`

This is the per-project setup step (the plugin can't set these itself). It patches
this project's `.claude/settings.json` with `ANTHROPIC_BASE_URL` + `ZLAUDER_PORT`
(routing) and a `🛡` status line, and seeds a starter `zlauder.toml` if absent.

Report the result above, then STRONGLY emphasize the one thing that matters: the
`ANTHROPIC_BASE_URL` patch only takes effect on a fresh harness, so the user MUST
fully restart Claude Code (quit and relaunch) before any masking happens — until
then outbound text still reaches the model unmasked. This command controls
**routing** (whether traffic goes through the proxy); **masking** behavior (on/off,
profile, categories) is managed live with `/zlauder:privacy`. After restarting they
can confirm with `/zlauder:privacy` (or just `/zlauder:privacy status`).
