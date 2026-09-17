# @deepseek-ai/dsh-judgment

English | [中文](README.zh.md)

Abstract judgment capability seam (`ctx.judgment`): a provider registry and provider-selecting execution for **System One** models — models that answer a typed question with a calibrated number instead of generating text.

This is its own seam rather than a mode of `ctx.llm` because the contract differs at every point: the request carries questions instead of messages, the answer carries probabilities instead of content, there is no streaming, no tool loop, and no prose to parse. A consumer asks *is this destination a CDN?* and receives `0.74`.

## Service: `JudgmentRuntime` (ctx key: `judgment`)

`register(provider)` adds a backend and returns a disposer; a duplicate id is rejected with `JUDGMENT_PROVIDER_DUPLICATE`. `list()` names the registered ids in registration order.

`ask(request, signal)` is the primitive: one state, several questions, one round trip. Independent questions belong in one request — they run in parallel, cannot see one another's answers, and asking them separately costs more and lets an earlier answer bias a later one. A second request is warranted only when an answer is needed to fetch new evidence or decide the next options.

`noul(state, instructions, signal)`, `choice(state, instructions, criteria, signal)` and `score(state, instructions, criteria, signal)` are conveniences over `ask` for the single-question case. Each checks that the provider answered the kind of question that was asked and raises `JUDGMENT_ANSWER_MISSING` otherwise, so a malformed answer never reaches a consumer as a fabricated zero.

Pick the primitive by what the answer means. `noul` is the probability that one condition holds — there is no separate confidence, and a value near 0.5 means yes and no are close to equally likely rather than "medium intensity"; use one per label when several may apply. `choice` picks one of a defined set and returns the distribution, so its `probabilities` compare competing options. `score` places a position on ordered levels that each describe a concrete situation.

Selection resolves at execution time and never depends on registration order. A configured `provider` id must be registered (`JUDGMENT_PROVIDER_CONFIGURED_MISSING`) and usable (`JUDGMENT_PROVIDER_CONFIGURED_UNAVAILABLE`). With no id configured, exactly one usable provider auto-selects; none is `JUDGMENT_PROVIDER_UNAVAILABLE` and several is `JUDGMENT_PROVIDER_AMBIGUOUS`.

Design: [judgment capability and the bind verifier](../../../.agents/notes/implemented/feature/2026-09-17-judgment-capability.md).

## Configuration

```yaml
- id: judgment
  name: '@deepseek-ai/dsh-judgment'
  config:
    provider: typesafe   # optional; omit when exactly one provider is usable
```

## Model Experience

Indirectly, through the consumers that ask the questions — `dsh-investigation`'s bind verifier is the first — while this registry contributes no prompt, schema, or tool result itself.

#### KV Cache effect

No direct invalidation; the named consumer owns any request-prefix changes.

## Known Limitations and Deferred Work

- **Typed output guarantees the interface, not the truth.** These models are trained for calibrated decisions, but calibration is domain-specific: a threshold that separates cleanly on one corpus does not transfer. Evaluate thresholds on your own data and consequences before routing on them, as `bench/typesafe-triage/` does for the bind verifier.
- **No observation surface** — no provider-change event and no capability-status query. Availability is observed only by calling `ask` and routing the thrown `JudgmentError` code.
- **No batching across states.** `ask` carries several questions about *one* state; judging many states is many calls, and a consumer that needs them concurrently owns its own pooling.
