# zlauder-openai

Codex plugin package for ZlauDeR's OpenAI proxy path. The `enable` skill starts
or reuses a per-project masking proxy and writes the routing into
`$CODEX_HOME/config.toml` (see Routing below). The SessionStart hook is
verify-only — it warms the proxy (reusing the running one, or spawning it when
absent), then checks the route + auth + `/healthz` identity and emits a neutral
token-handling onboarding note (a warn-only note when the route can't be
confirmed). It writes routing nowhere and emits no route URL — `enable` owns the
routing; the hook only confirms it — and it never writes a top-level env key or
makes an unqualified active-masking claim.

## Routing

Routing is installed by the `enable` skill, which writes
`$CODEX_HOME/config.toml`: a custom `[model_providers.zlauder]` provider block
pointed at the live proxy plus a top-level `model_provider = "zlauder"`. You do
NOT set any `*_base_url` env or config key by hand — the enable skill owns the
provider block (and removing it is what `disable` does).

The provider:

- uses HTTP POST + SSE (`supports_websockets = false`), NOT the built-in WebSocket
  transport — that path bypasses the HTTP masking proxy entirely;
- speaks the Responses wire API (`wire_api = "responses"`); Codex only ever speaks
  Responses, so `POST /v1/responses` create traffic (including SSE streams) is what
  gets masked on requests and unmasked on responses;
- **requires** an OpenAI API key exported as `OPENAI_API_KEY` (sk-...) in the
  environment codex runs in. A ChatGPT-subscription login will NOT work — the
  custom provider hard-errors on a missing env key (`env_key = "OPENAI_API_KEY"`,
  `requires_openai_auth = false`).

## Hooks (codex > 0.140)

The same `enable` step writes a `[hooks]` block into `$CODEX_HOME/config.toml`
that points at this plugin's `scripts/codex-session-start.sh` (token-handling
onboarding) and `scripts/codex-user-prompt-submit.sh` (the fail-closed intake
gate). These hooks fire ONLY on **codex > 0.140**; on ≤0.140 the masking
enforce/verify hooks do not fire. After enabling, do a one-time review + **trust**
of the hooks, then **restart** codex for the route and hooks to take effect.

The bundled `zlauder.toml` is a starter seed. Put a project-specific
`zlauder.toml` at the project root to override it.
