---
description: Show ZlauDeR proxy health, whether this session is routed, and the masking state (on/off, profile, categories, ML) for this project — read-only.
argument-hint: ""
allowed-tools: Bash(bash:*)
---

ZlauDeR status:

!`bash "${CLAUDE_PLUGIN_ROOT}/scripts/privacy.sh" status`

The block above is ZlauDeR's read-only status for **this project only**: proxy health,
whether this session is routed (`ANTHROPIC_BASE_URL` points at the proxy), and the masking
state (on/off, profile, enabled categories, ML model). It changes nothing.

Report it concisely, and keep the masking model right: the **user sees their real values
locally** at all times — masking only changes what the **model and the API provider** see
(deterministic `[TOKEN]` stand-ins). Never tell the user their own data is hidden from them.

- If masking is **on** and this session is **routed**, ZlauDeR is active.
- If the proxy is up but masking is **off**, traffic passes through un-masked (transparent).
- If the proxy is up but this session is **not routed**, routing applies automatically on a
  fresh session; a just-written route takes effect after a one-time restart of Claude Code.

To **change** anything — turn masking on/off, switch profile/category/threshold, manage the
ML model, reveal a token, or scrub a transcript — the user runs `/zlauder:privacy …`
themselves (and `/zlauder:enable` / `/zlauder:disable` for routing). You may **suggest the
exact command**, but only the user can run it. Never print or echo the session/control key.
