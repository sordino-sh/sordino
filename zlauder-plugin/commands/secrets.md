---
description: View ZlauDeR registered-secret status for this project — the readiness gate and which secrets resolved (registered by reference; values are never shown)
argument-hint: "[status | list]"
allowed-tools: Bash
---

!`bash "${CLAUDE_PLUGIN_ROOT}/scripts/secrets.sh" "$ARGUMENTS"`

The block above is this project's registered-secret status. Secrets are registered
by **reference** in the proxy's `[[secrets]]` config (pointing at a backend:
`pass`/`age`/`sops`/`dotenv`/`env`) — ZlauDeR resolves the value at startup and masks
it. The value itself never lives in config and is never shown here.

Report concisely:

- `status` (or no args): whether the readiness gate is **open** or **HELD**. The gate
  holds LLM intake at HTTP 503 until every `required` secret resolves (fail-closed),
  so a HELD gate means a required secret failed to resolve — surface the named
  failure(s) and the likely cause (backend binary missing, agent locked, wrong ref).
- `list`: the registered secrets with their operator (`hash`/`redact`/`mask`/`broker`),
  backend scheme, and whether each resolved (✓/✗).

Keep the masking model right: a registered secret's real value is used **locally**
(masked only toward the model/provider). `hash`/`redact` secrets are irreversible
(the model never sees them and they're never revealable); a `broker` secret is
resolved only at the local tool boundary. Never print or echo any secret value or
the session/control key. Registering or rotating a secret is done by editing the
project's `[[secrets]]` config — references only, never inline values.
