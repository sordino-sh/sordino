---
description: Route this project's Claude Code through the zlauder masking proxy (patches .claude/settings.json; requires restart)
allowed-tools: Bash(bash:*)
---

Script output:

!`bash "${CLAUDE_PLUGIN_ROOT}/scripts/enable.sh"`

Report the result above to the user. Then STRONGLY emphasize the one thing that matters: the patch to `.claude/settings.json` only takes effect on a fresh harness, so they MUST fully restart Claude Code (quit and relaunch) before any masking happens — until then outbound text still reaches the model unmasked. After restarting they can confirm masking is live with `/zlauder:status`.
