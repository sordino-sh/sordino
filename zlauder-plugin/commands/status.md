---
description: Show zlauder proxy health and whether this project's traffic is actually routed through it
allowed-tools: Bash(bash:*)
---

!`bash "${CLAUDE_PLUGIN_ROOT}/scripts/status.sh"`

The output above has two parts. The first is this project's proxy **health** (a
`🛡` shield line — `🛡 zlauder :<port> <profile>` — means the proxy is up; `⚠ zlauder
off` means it is not running). The second is the `ANTHROPIC_BASE_URL` Claude Code is
configured with: traffic is **actually routed through zlauder only if** that value is
`http://127.0.0.1:<port>` matching the proxy's port. The proxy listens on a
**per-project port derived in 18000..20000** (or `$ZLAUDER_PORT` if you pinned one);
it is **not** a fixed 8787.

Plugins cannot set `ANTHROPIC_BASE_URL` themselves, so this command is the status
surface. In one or two short sentences, tell the user:

1. Whether the proxy is **up** (from the health line).
2. Whether this project's traffic is **routed** through it — i.e. whether
   `ANTHROPIC_BASE_URL` points at `127.0.0.1:<port>` and not at the default
   Anthropic API or `(unset)`.

If the proxy is up but traffic is **not** routed, tell them to run `/zlauder:enable`
and then **restart Claude Code** — the base-URL change only takes effect on restart.
If the proxy is down, note that the next session start (or `/zlauder:enable`) will
launch it. Never print or echo the session key.
