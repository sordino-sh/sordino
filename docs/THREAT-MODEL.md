# ZlauDeR Threat Model

Grounded at `main` (v0.13.0 line, verified at commit `b5782ad`; the one code change
since — `bfcd794`, the monitor Google-Fonts removal — is reflected in L19). Every current-behavior
claim in this document cites the mechanism (file/line at that commit) and, where one
exists, the test that pins it. If a claim here and the code disagree, the code is right
and this document has a bug — file it.

This document is the controlling statement of what ZlauDeR defends against, how, and
what it does not. Where any other material — including marketing copy at zlauder.com —
implies broader protection than what is written here, this document governs.

---

## 1. What ZlauDeR is

ZlauDeR is a local HTTP proxy plus editor-hook tooling that sits between an AI coding
agent (Claude Code, Codex) and its LLM provider. On the outbound path it detects
sensitive spans (secrets, PII) in request bodies on the masked wire surfaces and
replaces them with deterministic placeholder tokens before the request leaves the
machine; on the response path it restores tokens the model echoed back, so the session
works normally while the provider only ever receives the masked form of detected
content on those surfaces. The deliberately-passthrough endpoints (`/v1/files`,
`/v1/batches`, and friends) are NOT masked — §7.1 is the catalog, and any summary of
this paragraph that drops that qualifier is an over-reading. It runs entirely on the
user's machine, bound to loopback, with no accounts, no cloud component, and no
telemetry of its own. "No third-party fetches" holds with exactly one scoped
exception: enabling the optional ML classifier's `local`/`sidecar` backend downloads
pinned model weights from Hugging Face — download-only, off by default,
allowlist-gated (L23). The monitor UI's former Google Fonts load was removed at
`bfcd794` (L19, closed).

## 2. System overview and trust boundaries

```
┌─ your machine ───────────────────────────────────────────────┐
│                                                              │
│  Claude Code / Codex ──HTTP (127.0.0.1)──▶ zlauder-proxy ────┼──HTTPS/rustls──▶ provider
│        │                                       │             │                 (api.anthropic.com,
│   hook layer                              masking engine     │                  OpenAI, ZDR targets)
│   (zlauder-hooks)                         secrets broker     │
│                                           monitor UI         │
└──────────────────────────────────────────────────────────────┘
```

**Boundary 1 — client to proxy.** Plaintext HTTP, loopback only. The proxy refuses a
non-loopback bind unless `ZLAUDER_ALLOW_NON_LOOPBACK_BIND` is explicitly set, because
the key-gated control plane (reveal/config/monitor) must not become a network-reachable
PII oracle (`crates/zlauder-proxy/src/bind.rs:8-30`).

**Boundary 2 — proxy to provider.** HTTPS with rustls and standard certificate
verification; `reqwest` is built with `default-features = false` and `rustls-tls`
(`Cargo.toml:80`), and no `danger_accept_invalid_*` setting exists anywhere in the tree.
Only masked (or deliberately-passthrough — see §7.1) bytes cross this boundary.

**Boundary 3 — the host harness (the caveat that shapes everything).** The proxy sees
only API-wire traffic. Everything that happens inside the editor process — tool
execution, local file writes, transcript display, the firing of hooks themselves — is
under the host harness's (Claude Code's / Codex's) control, not ZlauDeR's. Hook-based
protections are therefore structurally best-effort: a hook that the harness fails to
run cannot block anything (§6, §7.2). The fail-closed core of ZlauDeR is the on-wire
proxy; the hooks are a second, weaker layer.

**What runs where.** The masking engine (`zlauder-engine`), secrets resolution
(`zlauder-secrets`), proxy (`zlauder-proxy`), and hook binary (`zlauder-hooks`) all run
locally. ML inference is local for the `local` (in-process Candle) and `sidecar`
(child process over a private pipe, no port) backends
(`crates/zlauder-engine/src/config.rs:646-668`). The `http` backend is NOT a locality
guarantee: it POSTs the raw text of every un-cached leaf to whatever `endpoint` URL
the user configures, with no loopback requirement (`require_local: false` —
`crates/zlauder-engine/src/ml.rs:318-327`; `config.rs:560-565`). Pointing it at a
non-local endpoint creates a second, pre-masking egress channel — see L17.

## 3. Assets protected

1. **Registered secrets** — credentials the user explicitly registers (`[[secrets]]`,
   resolved from env/dotenv/pass/sops/age). Strongest protection class: masked
   unconditionally, structurally unrevealable on the display path, brokered to tool
   boundaries under default-deny policy.
2. **Detected PII** — emails, phone numbers, financial identifiers, names, etc., found
   by regex recognizers plus an optional ML classifier, per the active profile.
   Protection is probabilistic: it is as good as detection, no better (§8, Non-Goal N6).
3. **In-URL credentials** — always-on regardless of profile, including percent-encoded
   forms (`config.rs:178-181`, `recognizers.rs:783-930`).
4. **The proxy's own admin key** — a `Local`-class token: revealed to the user's
   display, refused into tool inputs (`main.rs:134-142`, engine `lib.rs:1301-1312`).

## 4. Adversary model

**In scope:**

- **Provider-side retention, training, and logging of unmasked content.** The core
  adversary. ZlauDeR assumes anything that reaches the provider may be retained
  indefinitely and mitigates by ensuring detected-sensitive content reaches the
  provider only in masked form.
- **Accidental egress via agent behavior** — the model summarizing a `.env` file into
  its context, a tool result carrying a customer email, a system prompt embedding a
  key. All wire surfaces of the message wires — `/v1/messages` and the
  OpenAI-compatible endpoints — are walked and masked (§5, G2).
- **Prompt-injection-driven exfiltration through the masked channel.** A compromised
  or manipulated model that tries to move a registered secret to an egress boundary:
  broker resolution is default-deny at MCP/agent/shell tool boundaries
  (§5, G4), and display-path resolution of broker tokens is refused by prefix before
  any lookup (§5, G3). *Scope fence: the same protection does not extend to detected
  PII tokens — see Limitation L6.*
- **Misrouted sessions** — an editor session that believes it is masked but is not.
  The intake gate blocks prompts in a plumbed-but-unverified session rather than let
  them egress unmasked (§5, G7), with the harness-level caveat in L2.

**Out of scope (stated plainly, per limitation where relevant):**

- **A compromised local machine or malicious local user.** Plaintext lives on this
  machine by design — in your files, in the editor transcript, in the proxy's state
  directory, in the monitor's in-memory capture. Root, malware, or a hostile user with
  your login defeats everything here. ZlauDeR is not designed to provide protection
  against a local attacker.
- **Provider compromise of masked/tokenized data.** Tokens are deterministic
  placeholders, not encryption. A provider (or a provider-side attacker) holding masked
  transcripts learns the shape and position of sensitive data and can correlate the
  same token across a project's conversations (L13). What they do not get is the
  plaintext of detected spans.
- **Network-level anonymity and traffic analysis.** The provider sees your IP, your
  API credential, request timing, and request sizes. ZlauDeR is not an anonymity
  service, a VPN, or Tor.
- **Side channels in the host harness** — the harness's own telemetry (L10), its
  hook-execution contract (L2), its rendering of plaintext to the local screen (L5).
- **Undetected sensitive content.** Text the detectors miss egresses unmasked. This is
  an accuracy boundary, not an adversary the design can eliminate (N6).

## 5. Guarantees today

Each guarantee: **statement — mechanism — evidence.** "Refuse" always means the request
is rejected with an error and zero bytes go upstream; ZlauDeR never silently forwards
on a masking failure.

**G1 — Registered secrets are masked unconditionally on every walked leaf.** Engine
disabled, surface disabled, profile minimal — a registered secret still masks; no
configuration state lets a known secret value egress in plaintext through the mask
path. *Scope fence: the guarantee covers the leaves the walkers visit. Schema/contract
fields that are deliberately never walked (tool `input_schema`; the OpenAI-wire
contract-key subtrees) sit outside it — a registered secret embedded there egresses
verbatim (L20) — and so do unknown fields the Anthropic typed parse preserves through
its `extra` flatten sinks (L22).*
Mechanism: `crates/zlauder-engine/src/lib.rs:745-758`.
Evidence: `secret_masked_even_when_engine_disabled` (`lib.rs:3638`),
`secret_masked_inside_user_bypass` (`lib.rs:3661`).

**G2 — Mask-or-refuse on the message wires, Anthropic AND OpenAI-compatible.**
`/v1/messages` and `count_tokens` bodies are parsed and every content surface walked
(system prompt, tool descriptions, user messages, tool_use inputs, tool results,
assistant text, image/document URL sources — base64 payload `data` and OpenAI
`data:`-URI image URLs pass opaque by design, see L18; tool `input_schema` and
OpenAI-wire contract-key subtrees pass verbatim by design, see L20; unknown
Anthropic-wire fields ride the typed `extra` sinks unmasked, see L22; assistant
`thinking`/`redacted_thinking` blocks pass opaque both ways and carry only tokens,
see L24). The
OpenAI-compatible wire (`/v1/chat/completions`, `/v1/responses`)
is equally a production mask-or-refuse path, not passthrough: same engine, same
refuse-on-failure posture (`routes.rs:99-100`; `openai_chat.rs:75-87`;
`openai_responses.rs:73`). Unparseable JSON ⇒ 400; engine error ⇒ 500; never forward
unmasked.
Mechanism: `crates/zlauder-proxy/src/walk.rs:159-244`, `routes.rs:634-648`.
Evidence: `end_to_end_mask_unmask_and_header_passthrough`
(`crates/zlauder-proxy/tests/integration.rs:280`);
`openai_chat_completions_mask_unmask_and_header_passthrough` (`integration.rs:341`);
real-CLI e2e harness (`e2e/run-e2e.sh` + `e2e/fake_anthropic.py`).

**G3 — Broker tokens never resolve on the display path.** A `[BROKER__…]` token is
refused by prefix before any manifest/store lookup, so the secret value cannot reach
the response/display channel; the audit endpoint returns 409 and the registered name
only, never the value.
Mechanism: `crates/zlauder-engine/src/lib.rs:1291-1300`; `routes.rs:140-156`.
Evidence: `broker_secret_minted_and_display_refused` (`lib.rs:3479`).

**G4 — Broker resolution at tool boundaries is default-deny.** Egress-boundary tools
(`mcp__*`, Task/Agent) are denied unconditionally; free-form shell tools (Bash-class)
are denied unconditionally even under an `AnyHost` rule; only an explicit
`[[broker.allow]]` rule matching tool and parameter pointer — and secret, when the
rule names one; an omitted `secret` glob matches every secret (`broker.rs:134`) —
(with optional destination-host allow-list; unparseable host ⇒ deny) resolves a value.
Mechanism: `crates/zlauder-engine/src/broker.rs:113-158`.
Evidence: `broker_resolve_pointers_respects_policy` (`lib.rs:3722`).

**G5 — Secret resolution has one hardened spawn choke-point.** Every provider that
shells out (pass/sops/age/…) receives the secret via stdout only — never argv (visible
in `/proc/<pid>/cmdline`), never env — with stdin nulled, environment scrubbed to an
allow-list, and `kill_on_drop`.
Mechanism: `crates/zlauder-secrets/src/broker_spawn.rs:1-12`.
Evidence: `secret_rides_stdout_not_argv` (`broker_spawn.rs:142`) pins the
stdout-as-value-channel claim; `env_is_scrubbed` (`broker_spawn.rs:166`) pins the
environment scrub; `missing_binary_is_binary_missing` and `nonzero_exit_is_auth_error`
cover the failure paths.

**G6 — Unresolved required secrets hold ALL traffic.** While any `required = true`
secret is unresolved, every upstream path — including the unmasked verbatim relay,
the most dangerous path for an unresolved secret — returns 503.
Mechanism: `routes.rs:362-372,686-698`.
Evidence: `missing_required_secret_fails_closed` (`crates/zlauder-proxy/src/secrets.rs`).

**G7 — The Claude Code intake gate is fail-closed on the decision path.** A prompt in
a project that is plumbed for masking but whose session is not identity-verified as
reaching *our* proxy is blocked. Verification is not a URL string-compare: it is a
~600ms-bounded `/healthz` nonce identity probe that degrades to BLOCK on any failure
(timeout, foreign listener, dead port). Deliberate escape hatches exist and are
narrated (L2 covers the harness-level fail-open).
Mechanism: `crates/zlauder-hooks/src/main.rs:5035-5156` (`intake_should_block_verified`:
`!escape_hatch && !opted_out && plumbed && !identity_ok`), probe at `main.rs:5573`.
Evidence: `intake_should_block_verified_truth_table` (`main.rs:8223`, whole input
space), `zlauder_commands_pass_a_closed_intake_gate` (`main.rs:8258`).

**G8 — The Codex intake gate is stricter: unconfigured blocks.** For Codex the
predicate has no "not plumbed ⇒ allow" branch: a session with no confirmed zlauder
route blocks its PII outright, and the block reason is always non-empty because Codex
drops an empty-reason block (which would fail open).
Mechanism: `main.rs:1794-1831` (`codex_intake_should_block`, `codex_block_output_json`).
Evidence: `unconfigured_session_blocks` (`main.rs:2051`),
`block_output_is_decision_block_with_nonempty_reason` (`main.rs:2080`).

**G9 — ML `required` mode refuses instead of degrading.** With `required = true`
(the default for the `http` and `sidecar` backends), an enabled-but-not-Ready
classifier refuses the request; it never silently degrades to regex-only. A
post-Ready runtime ML failure refuses that request; detection errors are never cached.
Mechanism: `config.rs:538-552`; enforcement `lib.rs:667`; `lib.rs:1163-1165,1213-1223`.
Evidence: `required_refuses_when_ml_not_ready` (`lib.rs:2298`), http-default refusal
(`lib.rs:2345`), live-flip refusal (`lib.rs:2630`).

**G10 — ML supply-chain and spawn posture is fail-closed.** Model repos are pinned to
an allow-list (`AUTHORIZED_ML_MODELS`); every fetch/load funnels through
`is_authorized_model`. The sidecar binary is located only by explicit path or env —
no `PATH` fallback.
Mechanism: `config.rs:769-788`; `config.rs:573-583`.
Evidence: `authorized_model_allowlist_admits_default_only` (`config.rs:1439`).

**G11 — Tokens are deterministic and cache-stable.** Session-salted blake3, idempotent
per (salt, entity type, plaintext), so masking preserves the provider's prompt-cache
prefix across turns and the same value always maps to the same token within scope.
Mechanism: `crates/zlauder-engine/src/token.rs:15-24`.
Evidence: `deterministic_masking_preserves_cache_prefix` (`integration.rs:688`).

**G12 — Registered-secret Hash tokens are structurally unrevealable.** The salted
colon form `[NAME:hex]` is outside the unmask token grammar; no code path can resolve
it back to a value. Token/Keep operators are rejected for secrets — a secret can never
be configured to be display-revealable or passed through.
Mechanism: `token.rs:35-51`; `crates/zlauder-engine/src/secrets.rs:96-100`.
Evidence: `hash_secret_masks_and_is_never_revealable` (`lib.rs:3444`).

**G13 — ZDR routing never silently downgrades.** A conversation's ZDR selection
resolves fail-closed at request entry: unknown target ⇒ 409; target not marked
user-verified ⇒ 403; upstream failure ⇒ 502 with no fallback path to the default
endpoint. ZDR egress strips the client's `authorization`/`x-api-key` and injects the
target's env-sourced credential; masking applies unchanged on ZDR requests. ZDR is
Anthropic-wire-only: a ZDR-pinned conversation on the OpenAI-compatible endpoints is
refused with 501, never silently routed (`openai_chat.rs:60-70`,
`openai_responses.rs:58-68`; see §7.5).
Mechanism: `routes.rs:174-205,670`; `headers.rs:44-83`; `wire_adapter.rs:10-16,52-59`.
Evidence: `zdr_unknown_selection_refuses_fail_closed` (integration.rs:1922),
`zdr_unverified_target_refuses_fail_closed` (1959),
`zdr_session_routes_to_target_with_zdr_key_not_subscription` (1744),
`zdr_openai_path_refuses` (2067).

**G14 — ZDR-pinned conversations cannot leak through cooperating passthrough.** A
pinned conversation's session-prefixed relay is refused with 409 and zero bytes
upstream; `/v1/batches` is refused for any session-scoped conversation even unpinned;
path-traversal segments are refused before all checks. (The non-cooperative-client
residual is L12.)
Mechanism: `routes.rs:441-471,486-501,514-527`.
Evidence: `passthrough_refuses_pinned_zero_bytes` (integration.rs:3349),
`session_traversal_batches_refused` (3444).

**G15 — Codex under ChatGPT-subscription auth is refused up front, not silently
leaked.** The custom provider reads only `$OPENAI_API_KEY`; enable refuses and writes
nothing when it is absent, SessionStart reports the auth failure, and the Codex gate
blocks the unconfirmed route.
Mechanism: `main.rs:155-173,547-598` (`CodexAuthCheck`),
`codex-zlauder-plugin/scripts/enable.sh:23-25`, `codex_refusal_message`
(`main.rs:678-698`).
Evidence: `chatgpt_tokens_without_env_refuses` (`main.rs:9142`),
`api_key_on_file_but_not_exported_refuses` (`main.rs:9159`).

**G16 — Streaming responses unmask correctly across frame boundaries.** SSE unmasking
carries at most one partial token so a token straddling deltas is still restored,
bounded by `MAX_TOKEN_LEN`.
Mechanism: `crates/zlauder-proxy/src/sse.rs:1-70`.
Evidence: `sse_split_token_every_boundary` (`sse.rs:513`).

**G17 — The monitor's capture scrubs what must not persist rehydrated.** Non-peekable
secret values and `Local`-class values (including session-Local pairs seeded at
`set_secret_rules`) are re-masked to handles on the monitor's copy of captured
unmasked text.
Mechanism: `crates/zlauder-proxy/src/monitor/spans.rs:48-102`; engine `lib.rs:475-486`.
Evidence: `local_class_is_non_peekable_and_scrubbed` (spans.rs:242),
`redact_scrubs_secret_value_keeps_peekable` (spans.rs:269).

**G18 — ZlauDeR itself emits no telemetry.** No telemetry subsystem exists on `main`:
no analytics, no phone-home, no usage reporting. The only "telemetry" in the source is
the API-protocol passthrough of client-supplied ID fields (L9).
Evidence: absence — zero telemetry features/dependencies in any `Cargo.toml`, no
telemetry module in `crates/`; verifiable by grep.

## 6. Best-effort mitigations

These run and are tested, but sit on the wrong side of Boundary 3: the host harness,
not ZlauDeR, decides whether they execute. They are labeled best-effort because their
failure mode is open, not because they are unimplemented.

- **The intake gate as a whole (G7/G8).** The gate's *decision* is fail-closed, but a
  UserPromptSubmit hook that crashes, times out (bounded by Claude Code's hook-timeout
  contract), or whose
  binary is missing fails OPEN — the prompt proceeds ungated. Every read on the hook
  path is bounded and non-panicking to shrink that window
  (`main.rs:5023-5034`; `zlauder-plugin/scripts/user-prompt-submit.sh:23-31`).
- **The provenance-spoof guard.** PreToolUse denies any tool call that would enqueue a
  `/zlauder:` command into a future user turn (`main.rs:7404-7428`) — but only if the
  hook runs.
- **Per-turn status honesty.** Allowed prompts carry a delta-only masking-status line
  (Masked / Off / NotReaching / Disabled / UnmaskedBypass) so the model and user are
  told when protection lapsed (`main.rs:5180-5198`;
  `delta_messages_are_factual_status_not_injection_shaped`, `main.rs:8325`). This is
  disclosure, not enforcement.
- **Broker injection via PreToolUse** fails closed in the safe direction: any error ⇒
  emit nothing ⇒ the token stays masked in the tool input — a broken hook can deny a
  secret to a tool but can never leak one (`main.rs:7431-7446`).

By contrast, the on-wire proxy path (§5) does not depend on the harness: traffic that
reaches the proxy is masked or refused regardless of hook health.

## 7. Known limitations

This section is the complete catalog. Nothing sensitive to a purchasing or adoption
decision is documented elsewhere but omitted here.

### 7.1 Wire surfaces that are not masked

**L1 — `/v1/files`, `/v1/batches`, `/v1/models`, and unrecognized paths relay
verbatim, unmasked.** A file or batch upload carries its raw contents — including any
PII or secrets in them — to the provider with no masking. The only holds on this path
are the required-secrets 503 gate (G6) and the ZDR-pin refusals (G14). This is a
design decision (these bodies are not reliably maskable), not a bug, and it is the
single largest scoped exception to any "content is masked" summary of ZlauDeR.
Mechanism: `routes.rs:362-372` (OPEN, by design).

**L18 — Base64 image/document payloads pass opaque on the masked wires.** On
`/v1/messages`, image and document blocks are masked only in their URL-source form; a
`base64` source's `data` field is deliberately skipped (masking would corrupt the
binary), so a document containing PII attached inline egresses with its content
unmasked (`walk.rs:255-272`, generic-value guard `walk.rs:338-352`). On
`/v1/chat/completions` the inline-image form is the same skip: an `image_url` whose
URL is a `data:` URI passes opaque — only non-`data:` URLs are masked
(`openai_chat.rs:332-337`). The OpenAI Responses `input_file` part is the same class:
`file_data`/`file_id`/`filename` are on the never-mask key list and only unknown extra
fields are walked (`openai_responses.rs:350-352,443-455`); the Responses
`input_image`/`image_file` subtrees are skipped whole (L20)
(OPEN, by design — binary payloads are not reliably maskable; same class as L1).

**L17 — The `http` ML backend egresses raw text to its configured endpoint.** Every
un-cached text leaf is POSTed, pre-masking, to the user-configured `endpoint` URL, and
nothing requires that URL to be loopback (`require_local: false`,
`crates/zlauder-engine/src/ml.rs:318-327`; privacy note at `config.rs:560-565`). With
a local endpoint — the intended deployment — nothing leaves the machine; with a remote
endpoint the user has configured a second, unmasked egress channel that no §5
guarantee covers. The load-time checks verify the endpoint behaves like a privacy
filter, not where it runs (OPEN, by design — the backend exists to call an external
inference server; §2's "runs locally" claim holds only for the `local` and `sidecar`
backends).

**L23 — Enabling the `local` or `sidecar` ML backend downloads model weights from
Hugging Face.** This is the one third-party fetch in the product: first load (or an
explicit `--download-model`) pulls the model checkpoint from the HuggingFace hub into
the standard `hf-hub` cache (`crates/zlauder-engine/src/ml.rs:226-229,250-270`). It is
download-only — no user content is sent — ML is off by default (`enabled: false`,
`config.rs:812`), and the repo id is pinned to the `AUTHORIZED_ML_MODELS` allowlist
through the single `is_authorized_model` chokepoint (G10; `config.rs:777,786`), so no
override path can fetch an arbitrary checkpoint. The `http` backend pulls no weights
(its egress story is L17). §1's "no third-party fetches" is scoped by exactly this
item (OPEN, by design — the optional ML capability needs weights from somewhere;
pre-seeding the `hf-hub` cache offline avoids the fetch entirely).

**L7 — The default (Balanced) profile sends URLs, IPs, and MAC addresses in the
clear.** The Network category is deliberately OFF in Balanced; in-URL credentials are
still caught via the always-on `URL_CREDENTIAL` recognizer, but the URL/IP/MAC
themselves egress unmasked unless the user enables Network or Strict.
Mechanism: `config.rs:104-112` (OPEN, by design; disclose to users whose
infrastructure topology is itself sensitive).

**L8 — Deliberate false-positive allowances are small unmasked surfaces.** The
built-in allow-list passes Claude Code self-reference vocabulary (model names,
claude.ai/claude.com, exactly `noreply@anthropic.com` — not the domain), and a
near-now-date pass leaves dates close to today unmasked. Both are exact/anchored FP
reductions. Mechanism: `config.rs:328-368`; `detect.rs:57-58,323-329` (OPEN, by design).

**L20 — Schema/contract fields pass verbatim — including registered secrets.** On
`/v1/messages`, a tool's `input_schema` is never walked (masking schema constraints
would break the model's tool-call validation — `walk.rs:178-181`). On the
OpenAI-compatible wires the skip is broader: entire subtrees under contract keys
(`model`, `tools`, `tool_choice`, `response_format`, `json_schema`, `schema`,
`input_schema`, `parameters`, `guided_*`, and on Responses also `text`/`format`, the
file/call ID fields, and the `image_file`/`input_image`/`encrypted_content`/
`signature` subtrees) are skipped before the engine runs
(`openai_chat.rs:402-417`, `openai_responses.rs:431-455`). An in-URL credential
inside a skipped subtree (e.g. an `input_image` URL) passes verbatim — asset 3's
always-on recognizer runs only on walked leaves. Because the skip lives in
the proxy walker — upstream of the engine — G1's unconditional-secret masking does not
apply here: a registered secret embedded in a tool schema or contract subtree egresses
in plaintext. This and L22 are the two carve-outs from G1. Do not put sensitive
values in tool schemas or sampling-contract fields (OPEN, by design — masking schema
constraints
corrupts tool-call validation).

**L22 — Unknown fields on the Anthropic typed wire pass verbatim, warn-only.** The
`/v1/messages` typed parse preserves fields it does not model through serde `extra`
flatten sinks at the request, message, system-block, and tool levels; the walker logs
a warning and forwards them UNMASKED (`walk.rs:163,174,181,210`, `warn_unknown_map`
at `walk.rs:431-441`). Like L20 the skip sits upstream of the engine, so this is a
carve-out from G1 too: a registered secret placed in such a field egresses in
plaintext. The exposure is exactly the fields the typed parse accepts but does not
model — a body that fails the typed parse entirely takes the fail-safe whole-body
Value-walk instead (every string leaf masked, `walk.rs:26-31`), and the
OpenAI-compatible wires mask their `extra` maps (`openai_chat.rs:295,317`), so this
is an Anthropic-typed-wire limitation specifically (OPEN — masking unknown protocol
fields risks corrupting contract semantics the same way L20 does; the warn log is
disclosure, not enforcement).

**L21 — The `>>…<<` user-message bypass sends its contents with detection skipped.**
Text wrapped in `>>…<<` inside a user message is a deliberate one-shot escape hatch:
the wrapped span goes upstream with no PII detection and no token minting, while
surrounding text masks normally. Registered secrets are the exception — they are still
masked inside a bypass (the hatch is a convenience, not a secret-exfil channel; G1's
`secret_masked_inside_user_bypass`, `lib.rs:3661`) — but detected-PII protection is
OFF inside the markers: any PII a user (or anything that composes user-message text)
places there egresses unmasked. Mechanism: `crates/zlauder-engine/src/lib.rs:1112-1161`,
`user_bypass_segments` (`lib.rs:1568-1596`) (OPEN, by design — user-controlled bypass;
cataloged here so N1 cannot be quoted as covering bypassed spans).

**L9 — Protocol telemetry fields pass verbatim.** Anthropic `metadata.user_id` and the
OpenAI top-level `user` field egress byte-for-byte (masking them corrupts
provider-side abuse attribution). A client that puts an email address in one of these
fields egresses it. Mechanism: `walk.rs:194-206`; `openai_chat.rs:289-292` (OPEN, by
design; test `metadata_user_id_is_telemetry_passthrough_other_metadata_still_masked`,
`walk.rs:847`).

**L24 — Assistant `thinking`/`redacted_thinking` blocks pass opaque on the masked
wire, carrying only tokens.** On `/v1/messages`, model-authored `thinking` and
`redacted_thinking` blocks (with their signatures) are skipped by the walker on the
request path (`walk.rs:226-227`) and are equally never unmasked on the
response/display path (`walk.rs:479-480`) — opaque both ways by design, because
rewriting the text would invalidate the block's cryptographic signature. The two
skips are paired and together preserve the invariant that a thinking block carries
only tokens: because ZlauDeR never unmasks one, the local transcript stores it
tokenized, so a thinking block round-tripped through a ZlauDeR-masked session holds
only the masked (tokenized) form of any span ZlauDeR detected — the model only ever
saw the token and cannot reconstruct plaintext from it. Registered secrets
specifically are structurally unrevealable (G12) and never reach the model as
plaintext, so — unlike L20/L22 — this is NOT a carve-out from G1. The residual is
narrow and inherited, not new: content ZlauDeR never detected (N6) that the model
restates in its reasoning egresses in the thinking block unmasked exactly as it would
on any other surface, and a thinking block produced before routing was verified (L16)
carries whatever that pre-routing session produced. Mechanism: `walk.rs:226-227`
(request skip), `walk.rs:479-480` (response skip) (OPEN, by design — signatures
forbid rewriting; token-only content by the opaque-both-ways invariant).

### 7.2 Harness-boundary limitations

**L2 — Every hook-level protection fails open at the harness level.** Hook crash,
timeout, or missing binary ⇒ the prompt proceeds and the intake gate, provenance
guard, and status line never fire. Only the on-wire proxy masking is fail-closed.
Additionally, `ZLAUDER_NO_INTAKE_GATE=1` and `/zlauder:disable` are deliberate,
user-controlled bypasses (truthy-only parse; narrated to the model as
`UnmaskedBypass`). Mechanism: `main.rs:5023-5034,5161-5163`;
`user-prompt-submit.sh:23-31` (OPEN — inherent to the hook contract).

**L3 — Codex hook enforcement is version- and trust-gated.** The plugin-manifest
hooks are inert on codex >0.140; the working wiring is a `$CODEX_HOME/config.toml`
`[hooks]` block requiring a one-time hook-trust review plus restart. On codex ≤0.140
the enforce/verify hooks do not fire at all — a routed-but-unhooked Codex session has
no local gate (traffic that reaches the proxy is still masked). Mechanism:
`codex-zlauder-plugin/hooks/hooks.json` `_note`; README:33-39 (OPEN — upstream
constraint; highest-priority disclosure for Codex users).

**L4 — ChatGPT-subscription Codex users get no masking, period.** The refusal is
up-front and fail-closed (G15), but the capability gap is real: without an exported
`OPENAI_API_KEY` there is no maskable route for Codex (OPEN — upstream constraint:
custom providers cannot use subscription tokens).

**L16 — A freshly-plumbed Claude Code project needs a one-time restart.** Claude Code
applies a just-written `ANTHROPIC_BASE_URL` to the current session unreliably; masking
reliably activates from the next session. The intake gate exists precisely so the
interim state blocks instead of leaking (`zlauder-plugin/scripts/session-start.sh:10-18`)
(OPEN — upstream behavior; mitigated by G7).

**L10 — Claude Code's own OTel can egress unmasked reveals.** If a downstream user
enables Claude Code telemetry content flags (`OTEL_LOG_TOOL_DETAILS` etc.), unmasked
revealed content — including PII restored on the display path — can leave the machine
through a channel ZlauDeR does not sit on. This is opt-in and off by default in Claude
Code, and ZlauDeR emits none of it (G18), but the planned SessionStart detect-and-warn
has NOT shipped: nothing in ZlauDeR currently detects or warns about these flags
(OPEN — detection/warn is roadmap, not implemented; verify by grepping the tree for
`OTEL`).

### 7.3 Token- and reveal-model limitations

**L5 — No local display redaction exists; "the broker secret is never shown to the
user" is NOT implemented.** ZlauDeR ships exactly three Claude Code hooks (SessionStart,
PreToolUse, UserPromptSubmit — `zlauder-plugin/hooks/hooks.json`); there is no
PostToolUse or display-redaction hook. When PreToolUse resolves a broker token into a
tool input, that plaintext is visible in the local session transcript and display from
then on. G3's guarantee is about the *provider-facing response path*, not the local
screen (OPEN — local display is out of the proxy's reach; a redaction hook would
itself be fail-open per L2).

**L6 — Any model-emitted PII token dereferences into tool inputs; there is no
tool-egress gate for detected PII.** Broker tokens are display-refused and Local
tokens are tool-refused, but a standard PII token the model chooses to emit resolves
to plaintext on BOTH the display and tool paths — meaning a manipulated model can move
previously-masked PII into a file write or command line. The plaintext does not go to
the provider (it is re-masked on any subsequent wire trip), but it lands in local tool
effects the user may not expect. Mechanism: `walk.rs:470-482`, `lib.rs:1274-1348`
(OPEN — a positive-provenance token ledger is the known prerequisite for closing this).

**L13 — Token correlation within a project.** The masking salt is per-project;
`SaltScope::Conversation` parses but is inert. The same plaintext yields the same
token across all of a project's conversations, so a provider can correlate a masked
entity across sessions. Mechanism: `config.rs:262-274` (OPEN — conversation-scoped
salt is roadmap; note it would also break cross-conversation prompt-cache stability).

**L15 — The monitor's local capture stores peekable PII rehydrated.** By design the
monitor shows the user real values for peekable PII; that plaintext lives in the
proxy's in-memory capture (bounded ring, see N5) on the local machine. Secrets and
Local values are scrubbed to handles (G17); peekable PII is not
(`monitor/spans.rs:233`) (OPEN, by design — local-machine exposure only, out-of-scope
adversary).

**L19 — CLOSED at `bfcd794`: the monitor page no longer loads fonts from Google.**
Earlier builds preconnected to and loaded stylesheets/fonts from
`fonts.googleapis.com` / `fonts.gstatic.com` from `monitor.html`; commit `bfcd794`
removed the fetch, and no `googleapis`/`gstatic` reference remains anywhere in
`crates/` (verify by grep). The monitor UI is self-contained; §1's "no cloud
component" now holds without exception, and "no third-party fetches" holds with the
single scoped exception of the opt-in, allowlist-pinned ML weight download (L23)
(CLOSED — this item covers the Google-Fonts fetch, which is gone).

### 7.4 Detection-quality limitations

**L14 — ML classifier coverage has named gaps.** The `local` backend's default is
`required = false`: a bounded startup window degrades to regex-only detection unless
the user sets `required = true` (`config.rs:544-550`). F16-on-Metal recall (Apple
Silicon GPU) is not separately recall-gated — the recall gate proved CPU-F32 and
CUDA-BF16 only (`ml.rs:172-174`) (OPEN — tracked follow-up).

### 7.5 ZDR limitations

ZDR is Anthropic-wire-only in this build: a ZDR-pinned conversation on the
OpenAI-compatible endpoints (`/v1/chat/completions`, `/v1/responses`) is refused with
501 rather than routed anywhere (`openai_chat.rs:60-70`, `openai_responses.rs:58-68`;
test `zdr_openai_path_refuses`, `integration.rs:2067`). Fail-closed — nothing leaks —
but a Codex/OpenAI-wire user cannot use ZDR routing at all.

**L11 — ZDR trust is asserted, not verified.** The system cannot verify a provider's
retention posture; only the user can. A target must be explicitly marked
`user_verified` before it can be engaged, the badge always reads "asserted,
unverified," and the `attested_tee` basis is not ZDR-grade because no attestation is
wired (fail-closed by construction). Mechanism: `zdr.rs:57-59,130-133,60-92` (OPEN —
irreducible: ZDR is a claim about the provider's infrastructure, which no local proxy
can attest).

**L12 — ZDR pin enforcement on the bare verbatim relay is cooperative-client-only.**
A request with no session prefix and no `x-zlauder-conversation` header gives the
proxy no identity to key the pin on; it relays verbatim to the default endpoint even
if it "belongs" to a pinned conversation. ZlauDeR's own plumbing always sends the
identity; a foreign client sharing the port does not. Mechanism: `routes.rs:514-535`
(OPEN — inherent to header-based attribution).

## 8. Non-goals — what ZlauDeR does NOT do

Written to be quoted against over-readings. If a claim about ZlauDeR is not in §5, it
is not a guarantee, whoever is making it.

**N1 — ZlauDeR does not make data "never leave your machine."** Masked content — your
prompts, code, and files with detected spans replaced by tokens — is sent to the LLM
provider on every request; that is the product working, not a breach of the promise.
Content on passthrough endpoints (L1), undetected content (N6), inline binary
payloads (L18), protocol ID fields (L9), schema/contract fields (L20), unknown
Anthropic-wire fields (L22), user-bypassed `>>…<<` spans (L21), harness-side channels
(L10), and — when the user points the `http` ML backend at a remote endpoint — every
un-cached text leaf, pre-masking (L17), leave the machine unmasked. Model-authored
`thinking`/`redacted_thinking` blocks are the one surface that is neither masked nor
unmasked — they travel tokenized and opaque end-to-end (L24), so they carry plaintext
only for content ZlauDeR never detected (N6), not a hidden plaintext channel of their
own. The defensible
statement is: *detected sensitive spans on masked wire surfaces reach the provider
only in tokenized form, enforced fail-closed at the proxy.* Any absolute "never leaves
your machine" or "never left your control" reading is wrong, and this paragraph is the
controlling correction.

**N2 — ZlauDeR is not an anonymity or network-privacy tool.** The provider sees your
IP address, credential, timing, and traffic volume. Nothing here hides *that* you are
using an LLM or *who* you are to the provider's billing system.

**N3 — ZlauDeR does not protect against your own machine.** No defense is attempted
against local malware, a hostile local user, or a compromised OS. Plaintext exists
locally by design.

**N4 — ZlauDeR has no team permissioning, no user roles, and no multi-user access
control.** Nothing at HEAD models more than one user: there are no accounts, no roles,
and the single admin key gates the whole local control plane. "Control who can see
what across your team" is not a shipped capability; it appears only in §9 as an aim.

**N5 — ZlauDeR does not produce a compliance-grade audit log.** The monitor is a live,
local, key-gated view: an in-memory ring of at most 500 request records
(`monitor/store.rs:26,1190-1195`) with previews bounded by `PREVIEW_LIMIT` and
truncation flagged (`monitor/capture.rs:76-90`), lost on proxy restart, with no
tamper-evidence and no export pipeline. It shows what was sent versus what was masked
*for the requests it still holds, up to the preview bound*. Any claim that ZlauDeR
"logs exactly what information was sent" must be read against this paragraph: the
monitor is evidence of live behavior, not a retention-grade record.

**N6 — ZlauDeR does not guarantee detection.** Masking is regex plus an optional ML
classifier operating above a confidence threshold. False negatives exist; a missed
entity egresses in plaintext. ZlauDeR is a strong risk reducer on the detected set and
an unconditional guarantee only for values you explicitly register as secrets (G1).
It is not a DLP certification and no accuracy number in any material converts a
probabilistic detector into a guarantee.

**N7 — ZlauDeR does not verify provider behavior.** No mechanism here can confirm
that a provider honors zero-data-retention (L11), or that masked data is not analyzed
for structure. Trust in the provider's stated posture is the user's assertion, and the
UI says so.

**N8 — ZlauDeR is not a managed service, and no hosted component exists in this
codebase.** Everything ships as local binaries and editor plugins. A "fully managed"
offering would be a service arrangement outside this repository and outside this
threat model; nothing in §5 applies to infrastructure ZlauDeR's maintainers might
operate on someone's behalf.

**N9 — ZlauDeR does not sit on non-LLM egress.** Only traffic addressed to the proxy
is protected. `curl` in a tool call, a git push, an MCP server making its own network
calls — none of it passes through the masking engine (the broker's tool-boundary
default-deny, G4, is the one exception, and it governs registered secrets only).

## 9. Aims — explicitly not commitments

Everything in this section is direction, not product. Nothing here carries a
mechanism cite because nothing here exists at HEAD; if a later revision moves an item
up to §5, it will arrive with one. Quoting this section as current capability is
misrepresentation.

- **ZDR forward work.** Conversation-scoped salts (L13), the reveal-clearance gate on
  captured-PinnedMode conversations (scaffolding exists: `RevealClearanceCtx`,
  `zdr.rs:250-278`, defined but not yet consumed), attestation for TEE-basis targets.
- **Token-provenance ledger.** The prerequisite for a tool-egress gate on detected
  PII (L6) and for safe neutralization of fabricated token-shaped strings.
- **OTel detect-and-warn.** SessionStart detection of Claude Code telemetry content
  flags (L10).
- **ZlauDeR Enterprise.** Team permissioning, deployment tooling, and audit/retention
  surfaces are under consideration and deliberately non-committal pending real use
  cases. No enterprise capability should be assumed, quoted, or resold from this
  document or any other; when such capabilities ship, they will appear in §5 with
  mechanisms and tests like everything else.

---

*Verification note: line numbers reference commit `b5782ad` (L19's closure references
`bfcd794`). The fastest way to check any claim: `git grep` the cited test name and run
it; every guarantee in §5 names at least one, except G18, whose evidence is a
greppable absence rather than a test.*
