---
name: zlauder-openai
description: Use when working in a Codex project that routes OpenAI traffic through ZlauDeR for local PII masking.
---

# ZlauDeR OpenAI

- The `enable` skill starts (or reuses) a per-project proxy and writes the route
  into `$CODEX_HOME/config.toml`. The SessionStart hook is verify-only: it warms
  the proxy and emits a neutral onboarding/warn note — it prints no route URL and
  writes no routing.
- Routing is enabled by the `enable` skill writing `$CODEX_HOME/config.toml`: a
  custom `[model_providers.zlauder]` provider block + `model_provider = "zlauder"`.
  Do NOT set any `*_base_url` key by hand — the skill owns the provider block.
- The provider uses HTTP POST + SSE (`supports_websockets = false`, NOT WebSocket)
  and the Responses wire API (`wire_api = "responses"`); Codex speaks only Responses,
  so `POST /v1/responses` create traffic (including SSE streams) is masked on requests
  and unmasked on responses.
- Requires an OpenAI API key exported as `OPENAI_API_KEY` (sk-...). A ChatGPT-subscription
  login will NOT work — the custom provider hard-errors on a missing env key.
- The masking enforce/verify hooks (SessionStart + UserPromptSubmit) fire only on
  **codex > 0.140**, and require a one-time hook-trust review + a codex restart to activate.
- What masking means: PII in requests is replaced with deterministic tokens like
  `[EMAIL_ADDRESS_a1b2]` that you and OpenAI see; the user sees the real values
  locally. It hides data from the provider, **not** from the user — so a token is a
  stable stand-in for something the user can read, and you should never tell the
  user their own data is hidden, redacted, or that you can't access it.
