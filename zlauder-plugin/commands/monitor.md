---
description: Print the local ZlauDeR request monitor URL for this project
argument-hint: ""
allowed-tools: Bash
# User-only: the monitor URL is the key-gated control plane and monitor.sh opens a browser on
# the user's machine — a side effect the model must not trigger. The model surfaces it instead.
disable-model-invocation: true
---

!`bash "${CLAUDE_PLUGIN_ROOT}/scripts/monitor.sh"`

Tell the user to open the printed local URL in their browser to watch this
project's traffic in realtime. The monitor shows **what the API provider actually
receives** — the tokenized payload — alongside the real values it stands for, so
the user can confirm masking is doing what they expect and, in manual mode,
approve or reject each request before it leaves the machine. (The user already
sees their own plaintext locally; the monitor is for auditing what the *provider*
sees, and for catching anything that should have been masked but wasn't.)
