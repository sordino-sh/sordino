---
description: Run the Sordino preflight self-check (loopback / firewall / port footguns) for this project
argument-hint: ""
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/scripts/doctor.sh":*)
---

!`bash "${CLAUDE_PLUGIN_ROOT}/scripts/doctor.sh"`

Relay the doctor table to the user. PASS lines are fine. Surface any **WARN/FAIL** with its
remediation arrow:

- A **FAIL** on "loopback 127.0.0.1 reachable" or "this project's proxy … /healthz unreachable"
  almost always means a local security/AV product or a hardened loopback firewall is
  intercepting `127.0.0.1` — masking requests will hang. Point the user at the remediation.
- A **WARN** on "localhost resolves to IPv4" is harmless: Sordino uses the literal `127.0.0.1`
  on the wire, never the name. Reassure the user; tell them NOT to change `ANTHROPIC_BASE_URL`
  to use `localhost`.
- **INFO** "no proxy running for this project" just means no `claude` session has started here
  yet (or it's not enabled).
