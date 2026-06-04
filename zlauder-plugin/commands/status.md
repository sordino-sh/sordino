---
description: Show zlauder proxy health and whether this project's traffic is actually routed through it
allowed-tools: Bash(zlauder-hooks:*), Bash(jq:*)
---

Proxy health:

!`if [ -n "${ZLAUDER_PORT:-}" ]; then zlauder-hooks statusline --port "$ZLAUDER_PORT"; else zlauder-hooks statusline; fi`

Routing check (ANTHROPIC_BASE_URL in this project's settings.json):

!`jq -r '.env.ANTHROPIC_BASE_URL // "(unset)"' "${CLAUDE_PROJECT_DIR:-.}/.claude/settings.json" 2>/dev/null || echo "(no .claude/settings.json)"`

The first block is this project's proxy health (a `\u{1f6e1}` shield line means the
proxy is up; `\u{26a0} zlauder off` means it is not running). The status line itself
prints the live port (`\u{1f6e1} zlauder :<port> <profile>`). The second block is the
`ANTHROPIC_BASE_URL` Claude Code is configured with: traffic is **actually routed
through zlauder only if** that value is `http://127.0.0.1:<port>` matching the
proxy's port. The proxy listens on a **per-project port derived in 18000..20000**
(or `$ZLAUDER_PORT` if you pinned one); it is **not** a fixed 8787.

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
