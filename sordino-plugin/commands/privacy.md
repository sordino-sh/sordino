---
description: "[Deprecated — renamed to /sordino:mask] View or change Sordino PII-masking for this project: on/off, profile, category, threshold, ML model, token reveal, transcript scrub. Prefer /sordino:mask."
argument-hint: "[status | on | off | profile <name> | category <name> on|off | threshold <0-1> | model <download|on|off|status> | reveal <token> | scrub --transcript <jsonl> (--value <text> | --values-file <file>)] [--scope session|project|user|local]"
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/scripts/mask.sh":*)
# User-only: this panel can LOOSEN masking (off / category off / profile minimal / model off /
# reveal / scrub), so the model must not invoke it via the SlashCommand tool. The model surfaces
# the exact command and the USER runs it. Read-only status lives in the un-gated /sordino:status.
# This gate is preserved on the deprecated alias.
disable-model-invocation: true
---

> **Renamed:** the everyday masking control is now **`/sordino:mask`** — `/sordino:mask on` /
> `/sordino:mask off`, plus the same `profile` / `category` / `threshold` / `model` / `reveal` /
> `scrub` verbs. This alias still works and forwards there; prefer the new name.

Privacy control output (forwarded to the unified verb):

!`bash "${CLAUDE_PLUGIN_ROOT}/scripts/mask.sh" "$ARGUMENTS"`

The block above is the result of the Sordino masking control plane for the request "$ARGUMENTS"
(empty means "show status"). Everything here affects **only this project's** proxy.

Report the result concisely, and keep the masking model right: the **user sees their real values
locally** at all times — masking only changes what the **model and the API provider** see
(deterministic `[TOKEN]` stand-ins). It protects data from the provider, not from the user. Never
tell the user their own data is hidden, redacted, or unavailable to them; a token always
corresponds to a real value they can see, and `reveal` just decodes one for convenience/audit.

- **`off`** turns masking off for **THIS conversation** (bounded — it auto-re-arms to ON in ~30 min
  unless extended, and stays off until then or until `/sordino:mask on`; turning Claude Code off and
  on again does not change that). Registered **secrets stay masked while traffic transits the
  proxy** and your data policy is untouched. `off --project` flips the whole-project master switch
  (**shared with any Codex sibling** here); `off --for <dur>` / `off --sticky` set a custom or
  indefinite window.
- **`on`** re-enables masking, clearing any off at any scope.
- **`profile` / `category` / `threshold`**: confirm what changed and at which `--scope` (default
  `session` = live on the running proxy only, not written to disk; `project`/`local`/`user` persist
  to a TOML layer).
- **`model …`** (the optional `openai/privacy-filter` ML recognizer, CPU): `download` fetches +
  caches; `on` loads in the background (`loading → ready`; text is not filtered through the ML model
  until `ready`, regex masking keeps working meanwhile) and also needs `category personal on`; `off`
  turns it off live; `status` shows the lifecycle. Surface loading/failed states plainly.
- **`reveal <token>`**: present the decoded plaintext, or relay the error verbatim.
- **`scrub --transcript <jsonl> (--value <text> | --values-file <file>)`**: report the redaction
  count, removed thinking records, relinked parent pointers, and backup path.
- **Reading a status output**: if the project shows masking **ON** but the output ALSO carries a
  `this conversation : masking OFF` line, THIS conversation was turned off via `/sordino:mask off`
  — it passes text **un-masked** until `/sordino:mask on` or the ~30-minute auto re-arm, even
  though the project master switch reads on. Report it as off **for this conversation**, not off
  for the project.

Do not run any other commands. If the script exited non-zero, surface its error message verbatim.
Never print or echo the session/control key.
