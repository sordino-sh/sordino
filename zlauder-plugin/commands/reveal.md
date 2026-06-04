---
description: Decode a masked token (e.g. [EMAIL_ADDRESS_xxxx]) back to its plaintext via the running proxy (local audit)
argument-hint: [TOKEN]
---

Resolve `zlauder-hooks` (PATH first, else the plugin-cached copy) and decode the token:

!`HOOKS=zlauder-hooks; command -v zlauder-hooks >/dev/null 2>&1 || HOOKS="${CLAUDE_PLUGIN_DATA}/bin/zlauder-hooks"; if [ -n "${ZLAUDER_PORT:-}" ]; then "$HOOKS" reveal "$ARGUMENTS" --port "$ZLAUDER_PORT"; else "$HOOKS" reveal "$ARGUMENTS"; fi`

The output above is the plaintext that `$ARGUMENTS` masks to. `zlauder-hooks reveal` reads the proxy's admin key from the local 0600 state file and sends it as the `x-zlauder-key` header, so this audit only works on this machine for a proxy you launched — you do not supply the key, and a tool-driven request without it gets a 403.

Present the decoded plaintext to the user. If the command instead reported an error (e.g. `reveal failed: 404 (unknown token)`, or a message about the proxy not running), relay that verbatim and explain the likely cause (an unknown/expired token, or the proxy being down for this project).
