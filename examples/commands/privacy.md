---
description: View or change Sordino PII-masking privacy settings for this project
argument-hint: "[status | on | off | profile <name> | category <name> on|off | threshold <0-1>] [--scope session|project|user|local]"
allowed-tools: Bash(sordino-hooks config:*)
---

Privacy control output:

!`sordino-hooks config $ARGUMENTS`

The block above is the result of the Sordino privacy CLI for the request
"$ARGUMENTS" (empty means "show current status"). Settings apply only to **this
project's** proxy — other projects/sessions are unaffected.

In one or two short sentences, tell the user the resulting masking state: whether
masking is ON or OFF, the active profile, and the enabled categories. If the user
asked to change something, confirm what changed and at which scope. Never print or
echo the session key.
