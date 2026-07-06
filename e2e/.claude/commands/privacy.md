---
description: View or change sordino PII-masking privacy settings for this project
argument-hint: "[status | on | off | profile <name> | category <name> on|off | threshold <0-1>] [--scope session|project|user|local]"
allowed-tools: Bash(/home/failspy/Projects/sordino/target/debug/sordino-hooks config:*)
---

Privacy control output:

!`/home/failspy/Projects/sordino/target/debug/sordino-hooks config $ARGUMENTS`

The block above is the result of the sordino privacy CLI for the request
"$ARGUMENTS" (empty means "show current status"). Settings apply only to **this
project's** proxy. In one or two short sentences, tell the user the resulting
masking state: ON/OFF, the active profile, and enabled categories. Never echo the
session key.
