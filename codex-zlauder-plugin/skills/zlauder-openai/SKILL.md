---
name: zlauder-openai
description: Use when working in a Codex project that routes OpenAI traffic through ZlauDeR for local PII masking.
---

# ZlauDeR OpenAI

- The plugin starts a per-project proxy and prints the derived
  `http://127.0.0.1:<port>/v1` route during SessionStart.
- Codex routing is controlled by trusted Codex config:

```toml
openai_base_url = "http://127.0.0.1:<port>/v1"
```

- Chat Completions and Responses create traffic are masked on requests and
  unmasked on responses, including SSE streams.
