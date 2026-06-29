---
description: View or change ZlauDeR ZDR (Zero-Data-Retention) trusted routing for THIS session — status, on/off, and the configured targets. Optional; off unless you configure [zdr] targets.
argument-hint: "[status | on [config] | off | config]"
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/scripts/zdr.sh":*)
---

!`bash "${CLAUDE_PLUGIN_ROOT}/scripts/zdr.sh" "$ARGUMENTS"`

The block above is this session's **ZDR (trusted-routing)** state. ZDR is an
**optional** feature: it routes this one conversation to an endpoint the *user* has
independently verified as zero-retention (a self-hosted llama.cpp/vLLM box, a
Commercial-org Anthropic ZDR key, a Bedrock/Vertex deployment, …), swapping the
upstream and credential on the fly. It is **off** unless the user configured
`[[zdr.target]]` entries in `zlauder.toml`.

Report concisely, and keep these facts straight:

- `status` (or no args): whether this session is **ON** (routing to a named target)
  or **OFF** (normal masked Anthropic path), plus how many targets are configured.
- `on [config]`: engages ZDR for this session — uses the `[zdr]` default if no config
  is named. This **breaks the prompt prompt-cache** (the next turn re-pays full input
  cost), which is why it is never automatic. A non-verified or unknown config is
  **refused**.
- `off`: returns to the normal masked path (also breaks the cache once).
- `config`: lists the configured targets (name, trust basis, verified flag) — never a
  credential.

Crucial framing — state it honestly, never overclaim:

- ZDR is the **user's assertion**, not something ZlauDeR can verify. There is no way
  to guarantee zero-retention through the current APIs; the badge means "you routed
  here, asserted-unverified," never "this is safe."
- **Masking still fully applies under ZDR.** Routing to a trusted endpoint does NOT
  reveal values — the provider still receives tokens, not real PII. ZDR is routing
  only.
- Never print or echo any credential, the session/control key, or claim a value was
  revealed. Configuring targets is done by editing `zlauder.toml` `[[zdr.target]]`
  (credentials are referenced via `from_env`, never inline).
