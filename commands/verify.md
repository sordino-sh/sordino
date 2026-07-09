---
description: Verify Sordino is fully active in THIS session — both masking (the engine) and routing ($ANTHROPIC_BASE_URL) — as two distinct verdicts.
argument-hint: ""
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/scripts/verify.sh":*)
---

!`bash "${CLAUDE_PLUGIN_ROOT}/scripts/verify.sh"`

Relay the verify table. It reports TWO independent legs — **both** must pass for masking to be
live in this session:

- **engine masks (key-gated canary):** a synthetic value sent through the proxy came back
  tokenized. A **FAIL** here means masking is OFF (transparent pass-through) even though the
  proxy is up — tell the user to run `/sordino:privacy on`.
- **this session is routed:** `$ANTHROPIC_BASE_URL` points at this project's proxy. A **FAIL**
  here means THIS session bypasses the proxy and sends **UNMASKED**, even if the engine masks —
  the most important case to surface. The usual cause is a freshly-written route that needs a
  one-time restart of Claude Code to take effect; tell the user to restart once (or run
  `/sordino:enable`).

A green engine with a red session is the exact failure this command exists to catch: do **not**
report "verified" unless BOTH legs pass.
