---
description: Turn ZlauDeR MASKING off — for THIS conversation (default) or the whole project (--project) — without changing your data policy. Registered secrets stay masked; re-enable with /zlauder:privacy on. To REMOVE ZlauDeR entirely, use /zlauder:uninstall.
argument-hint: "[--project]"
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/scripts/disable.sh":*)
# User-only: turning masking off lets plaintext PII egress upstream, so it is a loosen
# action — the model surfaces it, the user runs it. A prompt-injection must never disable masking.
disable-model-invocation: true
---

Turning ZlauDeR **masking** off. This does NOT touch routing or your masking policy — it is a
quick, temporary "filter off". Two modes:

- **Default (no argument): THIS conversation only.** Only the current Claude Code
  conversation stops masking; every other conversation in this project keeps masking. It is
  **session-scoped and in-memory** — it lifts on the next Claude Code restart. (It needs a
  session-routed conversation, exactly like `/zlauder:zdr`; if this session isn't routed the
  script says so and points you at `--project`.)
- **`--project`: the whole project.** Flips the project-wide master switch off (session-live,
  **not persisted**), so every conversation in this project stops masking until you turn it
  back on.

In **both** modes: registered **secrets are still masked** (that floor can't be turned off
here), and your **data policy is untouched** — categories, profile, threshold, ML and custom
masks are exactly as you left them, and nothing is written to disk. This is deliberately
different from `/zlauder:uninstall`, which removes the routing/plumbing entirely.

**Re-enable** with `/zlauder:privacy on` (that turns masking back on for this session and
clears a per-conversation disable), or just restart Claude Code (a conversation disable lifts
on its own).

!`bash "${CLAUDE_PLUGIN_ROOT}/scripts/disable.sh" "$ARGUMENTS"`

Read the script output above, then:

- If it turned masking off for **this conversation**, confirm that only this conversation is
  now unmasked (others still mask), that registered secrets are still masked, and that it
  lifts on restart or via `/zlauder:privacy on`.
- If it turned masking off for the **project** (`--project`), confirm the master switch is off
  for every conversation here, that the data policy on disk is unchanged, and how to re-enable.
- If it reported that this session is **not routable** (no `/zlauder/session/<id>`), relay that
  the conversation scope needs a routed session — suggest `/zlauder:enable` + restart, or
  `/zlauder:disable --project`.

Do not run any other commands. If the script exited non-zero, surface its error message
verbatim and do not claim masking was turned off.
