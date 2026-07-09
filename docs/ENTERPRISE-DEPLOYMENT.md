# Enterprise fleet deployment — routing Claude Code through Sordino

This recipe deploys Sordino across an organization's Claude Code seats using Claude
Code's **endpoint-managed settings**: every seat's Claude Code is pinned to a
locally-running Sordino masking proxy by policy the user cannot override, and the
fleet's posture is verified per-seat with Sordino's machine-readable probes.

[`docs/THREAT-MODEL.md`](./THREAT-MODEL.md) is the controlling document for every
capability claim below. Where this recipe and the threat model could be read
differently, the threat model wins.

## 1. Posture: process first, Sordino as the enforced backstop

Your organization's process — what engineers are allowed to paste into an LLM
session, secret-handling policy, repo hygiene — is the first line of defense.
Sordino is the **enforced backstop behind that process**, with two distinct
guarantee tiers:

- **Registered secrets** (values you explicitly register in `[[secrets]]`) carry
  the unconditional tier: a registered secret is masked on every walked wire
  surface regardless of configuration state (engine disabled, profile minimal —
  it still masks; THREAT-MODEL G1), and an *exact* registered-secret value that
  lands in a deliberately-unwalked contract field trips a **409 refusal with zero
  bytes sent upstream** rather than forwarding it (the L20 tripwire). The tripwire
  is exact-value-only; encoded or transformed forms of a secret are not covered,
  the base64 `data` subtree is skipped *before* the tripwire runs (an exact
  registered-secret value there is neither masked nor refused; L18), and detected
  PII in skipped subtrees is never scanned at all — it egresses verbatim (L20
  residual).
- **Everything else — detected PII — is best-effort** (THREAT-MODEL N6): regex
  plus an optional ML classifier above a confidence threshold. False negatives
  exist, and a missed entity egresses in plaintext. No accuracy number converts a
  probabilistic detector into a guarantee.

Do not procure or describe Sordino as DLP. It is not a DLP certification (N6),
and it does not make data "never leave your machine" (N1). The defensible
statement, quoted from the threat model: *detected sensitive spans on masked wire
surfaces reach the provider only in tokenized form, enforced fail-closed at the
proxy.* Masked content — prompts, code, files with detected spans replaced by
tokens — still goes to the LLM provider on every request; that is the product
working.

## 2. Delivery channel: endpoint-managed settings

Claude Code merges settings in this precedence order (highest first):

```
Managed > CLI flags > .claude/settings.local.json > .claude/settings.json > ~/.claude/settings.json
```

Managed settings sit at the top: users cannot override them from user, project,
or local settings files, or with CLI flags, and managed deny rules cannot be
overridden. Deliver the managed policy through your existing endpoint-management
tooling:

| Platform | Managed source | Delivery mechanism |
|---|---|---|
| macOS | `com.anthropic.claudecode` plist domain | MDM managed preferences |
| Windows | `HKLM\SOFTWARE\Policies\ClaudeCode` registry key | Group Policy |
| Linux | `/etc/claude-code/managed-settings.json` | config management (Ansible, etc.) |

**Critical for Sordino deployments: server-managed settings (the claude.ai admin
console) are NOT available when using a custom `ANTHROPIC_BASE_URL`.** Since a
Sordino deployment is exactly a custom-base-URL deployment, the admin console
cannot deliver this policy — use endpoint-managed settings. Also note the two do
not merge: if server-managed settings deliver anything, the endpoint sources
above are ignored entirely. Do not split your policy across both.

## 3. The routing pin

### Sordino side: pin a static proxy port

By default Sordino binds an OS-assigned **ephemeral** port per project, published
to a per-project rendezvous file, and the Sordino plugin bakes that per-project
route into the project's gitignored `.claude/settings.local.json`. A fleet-wide
managed `ANTHROPIC_BASE_URL` needs a **static** port instead, and it must be the
*same* port on both sides — otherwise the managed env (top of precedence)
overrides the plugin's baked route and points sessions at a port no proxy owns.

Pin the port in the Sordino config you distribute to seats (user layer
`~/.config/sordino/config.toml`, or per-project `sordino.toml`):

```toml
[proxy]
port = 8787          # bound exactly; a conflict is a hard error, never silently moved
bind = "127.0.0.1"
```

A static port is bound exactly — a second proxy trying to take it is a hard
error. One pinned port serves one running proxy per seat; the proxy also runs
standalone if you manage its lifecycle outside the plugin
(`sordino-proxy --port 8787 --config sordino.toml`, see the README).

### One pinned port is one project's proxy: the multi-project caveat

Sordino's isolation unit is the **project**: the rendezvous record, admin key,
token salt, and store are keyed by project identity (`blake3` of the canonical
project root), and one running proxy serves one project's config. A fleet-pinned
static port therefore supports **one concurrently-active Sordino project per
seat**. On a seat where a second project is opened while the first project's
proxy holds the pinned port:

- The second project's proxy cannot start: the pin is an exact bind, and the
  conflict is a hard error — it never moves to another port.
- If the second project is **plumbed for masking**, its intake gate fails the
  identity check — the listener on the pinned port answers with the *first*
  project's launch nonce, not the second's — and its prompts are **blocked**.
  That is the fail-closed decision path working as designed, but to the
  developer it reads as "Sordino won't let me work in this repo."
- If the second project is **not plumbed**, the managed `ANTHROPIC_BASE_URL`
  still routes its sessions through the first project's proxy, which is running
  the *first* project's config. The second project's own `[[secrets]]` are not
  registered on that proxy — they get **no unconditional masking and no 409
  tripwire** there — and its per-project policy does not apply.

Plan for this explicitly with multi-repo developers:

- **Serialize project use per seat.** The pinned port frees only when the
  holding proxy exits (a plain SIGTERM is a clean stop that clears its
  rendezvous record); the next project's proxy can then bind it.
- **Register org-distributed secrets at the user layer**
  (`~/.config/sordino/config.toml`) rather than only per-project, so whichever
  project's proxy currently holds the pinned port carries them — with one merge
  caveat: config arrays replace wholesale across layers, so a project
  `sordino.toml` that declares its own `[[secrets]]` **replaces** the user
  layer's list rather than appending to it. A project that needs
  project-specific secrets must re-list the org set alongside them, or the org
  set is absent on that project's proxy. Per-project `[[secrets]]` are covered
  only while their own project's proxy owns the port, in every case.

### Claude Code side: managed settings JSON

The managed payload (shown here in the Linux
`/etc/claude-code/managed-settings.json` form; the same keys go into the plist
domain / registry key on macOS / Windows):

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "http://127.0.0.1:8787"
  }
}
```

### First-session behavior (Claude Code v2.1.198+)

Security-sensitive managed env vars — `ANTHROPIC_BASE_URL` among them — are
**withheld for the first session** until the managed-settings fetch confirms. So
the very first Claude Code session on a freshly-managed seat runs *unrouted*.

Sordino's side of that composition is the fail-closed intake gate (THREAT-MODEL
G7, L16): on a seat where the Sordino plugin is installed and its
`UserPromptSubmit` hook fires, a project that is plumbed for masking but whose
session is not identity-verified as reaching the local Sordino proxy has its
prompt **blocked before it egresses** — the block message tells the user to
restart, and the restarted session picks up the managed route. The gate's
*decision path* is fail-closed: verification is a time-bounded `/healthz` nonce
identity probe that degrades to BLOCK on any failure (timeout, foreign listener,
dead port), never to allow.

Scope that claim honestly (THREAT-MODEL L2, §7):

- The gate is a plugin hook. If the hook never runs — plugin not installed,
  binary missing, hook crash or harness timeout — the prompt proceeds; only the
  on-wire proxy masking is fail-closed. The gate hardens the seats it runs on;
  it is not a network control.
- The gate fires for projects plumbed for masking. Deliberate, user-reachable
  escape hatches exist (`SORDINO_NO_INTAKE_GATE=1`, `/sordino:uninstall`
  opt-out) and endpoint-managed Claude Code settings do not remove them.

### Side effects of a custom base URL

Pointing `ANTHROPIC_BASE_URL` at a non-Anthropic host (a local proxy is one)
disables MCP tool search by default and disables Remote Control. Plan for both
in your rollout communication.

## 4. Lockdown options (optional hardening)

These managed-settings keys reduce the ways a seat can drift from the managed
posture. All are optional; test each against your fleet's actual workflows
before enforcing.

| Managed setting | Effect |
|---|---|
| `allowManagedPermissionRulesOnly: true` | Only permission rules from managed settings apply; user/project rules are ignored |
| `disableBypassPermissionsMode: "disable"` | Users cannot enter bypass-permissions mode |
| `strictKnownMarketplaces` | Allow-list plugin marketplace sources — include the Sordino marketplace source (`sordino-sh/sordino`; its plugin `source` is the `plugin-dist` branch) |
| `disableSideloadFlags` (v2.1.193+) | Disables plugin/agent side-loading CLI flags |
| `strictPluginOnlyCustomization` | Restricts customization to plugins |
| `allowManagedHooksOnly` | Only hooks delivered via managed settings run |

Honest limits of this lockdown:

- Managed settings can **enable a plugin by default, but cannot force-install a
  plugin the user never agreed to, and cannot prevent a user from disabling
  it.** The intake gate and statusline arrive with the Sordino plugin, so a user
  who disables the plugin removes those seat-side controls — the managed
  `ANTHROPIC_BASE_URL` pin still stands (it does not come from the plugin), and
  traffic that reaches the proxy is still masked.
- `allowManagedHooksOnly` restricts which hooks run, and Sordino's intake gate
  *is* a plugin hook. If you deploy `allowManagedHooksOnly` (or otherwise
  restrict which hooks run), you **must ensure the Sordino intake-gate hook is in
  the allowed managed-hook set** — otherwise the hook is suppressed and the
  first-session window reverts to Claude Code's native (unreliable) first-session
  routing. Verify this by **inspecting the managed-hook configuration you
  deploy** — confirm the Sordino intake hook is present in the allowed set. That
  is a deterministic configuration check the org already controls; do **not** try
  to infer hook state by submitting a prompt and watching whether it sends. Scope
  what suppressing the hook costs, honestly — steady-state enforcement versus the
  first-session window:
    - **Steady-state enforcement does not depend on the hook.** The managed
      `ANTHROPIC_BASE_URL` pin comes from managed settings, not from the plugin;
      it routes every established session to the local proxy, and the proxy runs
      its full masking + exact-value 409 tripwire on every request that reaches
      it, independent of any hook — at the same best-effort detection scope
      documented elsewhere (masking on the walked leaves, exact-value 409 refusal
      on the non-walked contract subtrees; G1, L2, N6), not a catch-everything
      guarantee. Suppressing the intake hook does **not** change what the proxy
      enforces on steady-state traffic.
    - **The hook covers only the first-session window.** On a freshly-managed or
      freshly-plumbed seat both routes can be momentarily absent — the managed pin
      is withheld until the first managed-settings fetch confirms (v2.1.198+, §3)
      and the baked local-settings route needs a one-time restart to be picked up
      (THREAT-MODEL L16) — leaving the session plumbed-but-unrouted. The intake
      gate fail-closed-blocks exactly that window (G7). Suppress the hook and that
      first-session pre-routing window re-opens to Claude Code's native
      first-session routing; that window is the only thing lost, and it is not
      re-opened for established sessions.
  **`sordino-hooks verify --json` (next section) cannot substitute for this
  configuration check**: its legs probe the proxy and the session environment,
  never Claude Code's hook dispatch, so it stays green with the intake gate
  suppressed. Whether the hook runs is a property of the managed-hook set, read
  from that set — not observed from any probe or prompt.

## 5. Fleet attestation: per-seat posture probes

Sordino ships machine-readable posture probes in the `sordino-hooks` binary
(distributed prebuilt with the plugin; resolution order is PATH, then the
plugin's shipped `bin/<triple>`, then a cached/in-repo build). An org can script
these per seat:

**`sordino-hooks verify --json`** — run in the project directory; verifies the
proxy actually masks AND the session env routes to it, as distinct legs. Output:

```json
{"ok": true, "legs": [{"name": "...", "status": "...", "detail": "...", "remediation": null}]}
```

Three legs: a key-gated masking canary against the live proxy, a
session-routing check, and a report-only category-coverage disclosure. Exit code
is non-zero if any leg fails, so it drops straight into a compliance script. The
routing leg evaluates the *invoking process's* `ANTHROPIC_BASE_URL` — probe with
the managed value applied
(`ANTHROPIC_BASE_URL=http://127.0.0.1:8787 sordino-hooks verify --json`) or the
leg reports your probing shell, not a Claude Code session.

**`sordino-hooks secrets --json`** — the frozen v1 posture projection of
registered-secret state. Read-only, and secret *values* can never appear in the
projection (keys are copied through an exact allowlist):

```json
{"schema_version": 1, "ready": true, "registered": 3, "resolved": 3, "required": 1,
 "unresolved": [], "secrets": [{"name": "...", "operator": "...", "scheme": "...",
 "required": true, "resolved": true, "error": null}]}
```

**`sordino-hooks doctor --json`** — environment preflight (loopback
reachability, proxy health, state dir); exits non-zero on any failure.

Read attestation results for what they are: **local, self-reported probes from a
cooperating seat**. They are evidence of live posture, not tamper-evident
attestation — Sordino attempts no defense against the seat's own user or a
compromised host (THREAT-MODEL N3), and there is no retention-grade record
behind them (N5). None of these probes observe Claude Code's hook dispatch:
whether the intake-gate hook actually runs under a managed hook policy is
verified by inspecting the allowed managed-hook set — confirming the Sordino
intake hook is present in it — per §4, not by any probe here.

## 6. What the org gets — and does not get

**Gets, today:**

- **Enforced routing** on managed seats: the managed `ANTHROPIC_BASE_URL` pin
  cannot be overridden by user/project/local settings or CLI flags, and the
  intake gate blocks plumbed-but-unrouted sessions on seats where the plugin
  hook runs (scoped as in §3).
- **Registered-secret protection**: unconditional masking on walked surfaces
  plus the exact-value 409 refusal tripwire, zero bytes upstream on refusal.
- **Per-project masking policy**: profile, categories, thresholds, and secrets
  configured through Sordino's layered config
  (user < project `sordino.toml` < local), distributable through the same
  endpoint-management channel.
- **A local monitor** per seat: a live, key-gated view of what was sent versus
  what was masked, for the requests it still holds.

**Does not get (yet):**

- **Centralized reporting.** Sordino ships no cross-seat aggregation. A per-seat,
  opt-in refusal-event ledger is available (append-only JSONL, one line per
  registered-secret wire-refusal, class names only, no secret values) that an org
  can tail into its own SIEM; the live monitor is still an in-memory ring of at
  most 500 request records lost on restart. Aggregating across seats is the org's
  pipeline to build — nothing central ships from Sordino, and neither surface is
  a retention-grade record (N5).
- **Per-employee principals or RBAC.** Nothing at HEAD models more than one
  user: no accounts, no roles, a single admin key gating the whole local
  control plane (N4).
- **A compliance-grade audit log.** The monitor is evidence of live behavior,
  not a retention-grade record; it has no tamper-evidence (N5). Do not cite it
  in a compliance filing as "a log of exactly what was sent."
- **Credential withholding / key-broker as an enterprise capability.** A local,
  default-deny broker for resolving registered secrets at tool boundaries
  exists (THREAT-MODEL G4); centralized credential withholding is design-phase.

Per the threat model's §9 ("Sordino Enterprise"): team permissioning, deployment
tooling, and audit/retention surfaces are under consideration and deliberately
non-committal. **No enterprise capability may be assumed, quoted, or resold from
this document.** When such capabilities ship, they will appear in the threat
model's §5 with mechanisms and tests like everything else.

## 7. References

Official Claude Code documentation:

- <https://code.claude.com/docs/en/server-managed-settings.md>
- <https://code.claude.com/docs/en/settings.md>
- <https://code.claude.com/docs/en/permissions.md>
- <https://code.claude.com/docs/en/network-config.md>
- <https://code.claude.com/docs/en/env-vars.md>
- <https://code.claude.com/docs/en/plugin-marketplaces.md>
- <https://code.claude.com/docs/en/admin-setup.md>

In this repository:

- [`docs/THREAT-MODEL.md`](./THREAT-MODEL.md) — controlling for all capability
  claims; §5 guarantees, §8 non-goals, §9 aims.
- [`README.md`](../README.md) — plugin install, binary resolution, standalone
  proxy usage.
- [`sordino.toml.example`](../sordino.toml.example) — full config surface,
  including the static `[proxy] port` pin.
