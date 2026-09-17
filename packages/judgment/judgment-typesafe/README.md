# @deepseek-ai/dsh-judgment-typesafe

English | [中文](README.zh.md)

TypeSafe System One provider for the [judgment seam](../judgment/README.md). A function/namespace plugin: it registers the `/v1/systemone` backend into `ctx.judgment` and owns no service of its own.

The credential is an environment-variable *reference* resolved per request, never an inline secret. A missing or blank variable makes the provider report itself unavailable rather than failing at plugin load, so a harness composed with this row still boots without a key and the seam's selection rules report the absence.

`429` and `529` — the two statuses the service documents as retryable — are retried with exponential backoff, honoring the caller's `AbortSignal`; every other status fails immediately with `JUDGMENT_BACKEND_FAILED`. An answer whose shape contradicts its declared type is dropped rather than coerced, so the seam raises `JUDGMENT_ANSWER_MISSING` instead of handing a consumer a fabricated `0`.

Every result records the model the service reports having served it. A request naming a rolling alias such as `jev-latest` is answered by a pinned version, and an evaluation is only reproducible if that version is recorded rather than the alias that was asked for.

The default `model` is therefore a pinned version, not an alias. A consumer's thresholds are calibrated against one version's probability scale, so an alias moving underneath them would invalidate every gate without failing a single test. Changing this default is a re-calibration event: re-run the consumer's evaluation before shipping the new version.

Design: [judgment capability and the bind verifier](../../../.agents/notes/implemented/feature/2026-09-17-judgment-capability.md).

## Configuration

```yaml
- id: judgment-typesafe
  name: '@deepseek-ai/dsh-judgment-typesafe'
  config:
    apiKeyEnv: TYPESAFE_API_KEY                        # default
    baseURL: https://api.typesafe.ai/v1/systemone      # default
    model: jev-1.13.0                                  # default; pinned, not an alias
    maxRetries: 3                                      # default
```

All four fields are Config. Unknown keys fail at load.

## Model Experience

Indirectly, through the consumers that ask the questions; this provider registers no prompt, schema, or tool result of its own.

#### KV Cache effect

No direct invalidation; the named consumer owns any request-prefix changes.

## Known Limitations and Deferred Work

- **No streaming and no partial answers.** One request yields one complete result or one error; a long question set cannot report progress.
- **Retry is status-based only.** A request that fails at the transport layer (DNS, TLS, socket reset) propagates the underlying `fetch` rejection without retry, because the attempt's durability is unknown.
- **`available()` checks only that the credential is present.** A revoked or malformed key reports usable and fails at call time with `JUDGMENT_BACKEND_FAILED`.
