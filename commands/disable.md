---
description: "[Deprecated — renamed to /sordino:mask off] Turn Sordino masking off for this conversation (default) or the whole project (--project), without changing your data policy. Prefer /sordino:mask off."
argument-hint: "[--project]"
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/scripts/mask.sh":*)
# User-only: turning masking off lets plaintext PII egress upstream, so it is a loosen action —
# the model surfaces it, the user runs it. A prompt-injection must never disable masking. This
# gate is preserved on the deprecated alias.
disable-model-invocation: true
---

> **Renamed:** this is now **`/sordino:mask off`** (and `/sordino:mask off --project`). This alias
> still works and forwards to the same place; prefer the new name.

Turning Sordino **masking** off — forwarded to the unified verb:

!`bash "${CLAUDE_PLUGIN_ROOT}/scripts/mask.sh" "off $ARGUMENTS"`

Read the script output above, then report it concisely. Turning masking off leaves your **data
policy untouched** and registered **secrets stay masked while traffic transits the proxy** either
way. The default (**THIS conversation** only) is a **bounded** window: masking **auto-re-arms to ON
in ~30 minutes** unless extended, and stays off until then or until you run `/sordino:mask on`. With
`--project` you instead flip the whole-project **master switch**, which has **no ~30-min timer** — it
stays off until you run `/sordino:mask on` (or the proxy exits), and it is **shared with any Codex
sibling** in this project. Turning Claude Code off and on again does not change either state. Tell
the user the new name is **`/sordino:mask off`**.

If the script reported that **routing isn't active for this session yet**, relay that this session
needs to be routed first (restart Claude Code once to activate routing, then `/sordino:mask off`
works here) — do **not** suggest `--project` as a shortcut, which would fail the same way.

Do not run any other commands. If the script exited non-zero, surface its error message verbatim
and do not claim masking was turned off.
