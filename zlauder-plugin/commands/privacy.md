---
description: View or change ZlauDeR PII-masking for this project — status, on/off, profile, category, threshold, ML model, and token reveal
argument-hint: "[status | on | off | profile <name> | category <name> on|off | threshold <0-1> | model <download|on|off|status> | reveal <token>] [--scope session|project|user|local]"
allowed-tools: Bash(bash:*)
---

Privacy control output:

!`bash "${CLAUDE_PLUGIN_ROOT}/scripts/privacy.sh" "$ARGUMENTS"`

The block above is the result of the unified ZlauDeR privacy control plane for the
request "$ARGUMENTS" (empty means "show status"). Everything here affects **only
this project's** proxy — other projects/sessions are unaffected.

This command controls **masking** (what the running proxy does to your text), which
is live and needs no restart. Do not confuse it with **routing**: `/zlauder:enable`
and `/zlauder:disable` decide whether traffic goes through the proxy at all (they
patch `.claude/settings.json` and require a Claude Code restart). The `status` view
shows both — proxy health, whether `ANTHROPIC_BASE_URL` is routed, and the masking
config.

Report the result concisely:

- For `status` (or no args): say whether the proxy is **up** (the `🛡` shield line
  means up; `⚠ ZlauDeR off` means down), whether this project is **routed** through
  it (`ANTHROPIC_BASE_URL` = `http://127.0.0.1:<port>` vs `(unset)`/the Anthropic
  API), and the masking state (ON/OFF, profile, enabled categories). If the proxy is
  up but not routed, tell the user to run `/zlauder:enable` and **restart**.
- For a change (`on`/`off`/`profile`/`category`/`threshold`): confirm what changed
  and at which `--scope` (default `session`, i.e. live-only and lost on restart;
  `project`/`local`/`user` persist to a TOML layer).
- For `model …` (the optional `openai/privacy-filter` ML recognizer, CPU): this adds
  free-text detection (names, locations) on top of the regex recognizers.
  - `model download [<repo>]`: fetches + caches the model (can be large/slow on the
    first run). Relay success or the error verbatim.
  - `model on [--scope …]`: turns the recognizer on. **It loads in the background** —
    the model status goes `loading → ready`, and **text is NOT filtered through the
    ML model until it reports `ready`** (regex masking keeps working meanwhile, so the
    user can continue or wait). Remind them that names/locations also need
    `/zlauder:privacy category personal on`.
  - `model off`: turns it off live. `model status`: shows the model + lifecycle
    (`disabled`/`loading`/`ready`/`failed`). Surface the loading/failed state plainly.
- For `reveal <token>`: present the decoded plaintext. If it failed (unknown token,
  proxy down, binary unavailable), relay the error verbatim and explain the likely
  cause.

Never print or echo the session/control key.
