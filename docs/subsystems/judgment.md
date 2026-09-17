# Judgment

English | [中文](judgment.zh.md)

The judgment seam — one `ctx.judgment` service over **System One** models, split across packages: Service Definition ([dsh-judgment](../../packages/judgment/judgment), `ctx.judgment` + the provider registry), Service Provider ([dsh-judgment-typesafe](../../packages/judgment/judgment-typesafe), TypeSafe's `/v1/systemone`), and Consumer ([dsh-investigation](../../packages/analyst/investigation), the bind verifier). Judgment is **one optional capability**, not part of the agent-loop spine — so its vocabulary lives here, not in [core.md](core.md). A provider swap does not change what a consumer asks.

Source: [`packages/judgment/judgment/src/types.ts`](../../packages/judgment/judgment/src/types.ts)

## Why this is not a mode of `ctx.llm`

A System One model is not a small LLM. It returns a probability or a typed selection and generates no text, so there is no prose to parse, no format to coax, and no reasoning to pay for. The contract differs at every point: the request carries questions instead of messages, the answer carries numbers instead of content, there is no streaming, no tool loop, and the failure modes are about calibration rather than truncation. A consumer asks *is this destination a CDN?* and receives `0.74`.

That is also why a judgment backend is not a subagent. Every provider under `packages/subagent/` is conversational; wiring a text-free model as one would discard the latency and cost that are its entire advantage.

## State

```ts type-equiv
/**
 * The state a question is asked about: source text, identities, relationships,
 * current facts. Named fields are preferred over one blob, because a question's
 * instructions may reference a field by name and the model reads the shape.
 */
type JudgmentState = string | readonly unknown[] | { readonly [key: string]: unknown }
```

## The three primitives

Pick by what the answer *means*, not by how many outcomes it has.

```ts type-equiv
/**
 * Whether a condition holds. The answer is the probability of yes; there is no
 * separate confidence, and a value near 0.5 means yes and no are close to
 * equally likely rather than "medium intensity". Use one per label when several
 * labels may apply at once.
 */
interface NoulQuestion {
  readonly type: 'noul'
  /** The condition, stated so that "yes" is unambiguous. */
  readonly instructions: string | Readonly<Record<string, unknown>>
}
```

```ts type-equiv
/**
 * One of a defined set. The answer names the winning option and carries the
 * distribution across all of them, so `probabilities` compares competing
 * options rather than scoring one in isolation. Include a no-match option when
 * nothing may fit.
 */
interface ChoiceQuestion {
  readonly type: 'choice'
  readonly instructions: string | Readonly<Record<string, unknown>>
  /** Each option keyed by id, its value describing when that option is right. */
  readonly criteria: Readonly<Record<string, string | Readonly<Record<string, unknown>>>>
}
```

```ts type-equiv
/**
 * A position along a described dimension. Levels must describe concrete
 * situations and stand on their own, because the model reads them as the scale.
 */
interface ScoreQuestion {
  readonly type: 'score'
  readonly instructions: string | Readonly<Record<string, unknown>>
  /** Ordered levels keyed by id, each describing a concrete situation. */
  readonly criteria: Readonly<Record<string, string | Readonly<Record<string, unknown>>>>
}
```

## Answers

A Noul carries no confidence field because its probability already *is* the answer. Choice and Score carry one, and it summarizes distribution concentration only.

```ts type-equiv
/** Probability that the stated condition holds, in `[0, 1]`. */
interface NoulAnswer {
  readonly type: 'noul'
  readonly noul: number
}
```

```ts type-equiv
/** The selected option, the full distribution, and how concentrated it is. */
interface ChoiceAnswer {
  readonly type: 'choice'
  readonly choice: string
  readonly probabilities: Readonly<Record<string, number>>
  /**
   * How concentrated the distribution is, in `[0, 1]`. This summarizes the
   * distribution, not overall correctness and not permission to act: several
   * acceptable alternatives also spread probability.
   */
  readonly confidence: number
}
```

```ts type-equiv
/** The weighted position, the level legend, and distribution concentration. */
interface ScoreAnswer {
  readonly type: 'score'
  readonly score: number
  readonly legend: Readonly<Record<string, unknown>>
  readonly probabilities: Readonly<Record<string, number>>
  readonly confidence: number
}
```

## Request and result

Batching is the point, not an optimization: the state is paid for once, so asking twenty independent questions about it costs roughly what asking one costs.

```ts type-equiv
/**
 * One request: a state, and the questions to ask about it. Independent
 * questions belong in ONE request — they run in parallel, cannot see one
 * another's answers, and cost one round trip instead of several. A second
 * request is warranted only when an earlier answer is needed to fetch evidence
 * or decide the next options.
 */
interface JudgmentRequest {
  readonly state: JudgmentState
  /** Questions keyed by an id the calling code uses; ids are not sent to the model. */
  readonly questions: Readonly<Record<string, JudgmentQuestion>>
  /** Requested model id; the provider's default applies when omitted. */
  readonly model?: string
}
```

```ts type-equiv
/** Answers keyed by the request's question ids, plus what actually served them. */
interface JudgmentResult {
  readonly answers: Readonly<Record<string, JudgmentAnswer>>
  /**
   * The model id the service reports having served the request. A request for a
   * rolling alias is answered by a pinned version, and an evaluation is only
   * reproducible if that version is recorded.
   */
  readonly model: string
  readonly usage?: JudgmentUsage
}
```

```ts type-equiv
/** Tokens a request consumed, when the provider reports them. */
interface JudgmentUsage {
  readonly inputTokens?: number
  readonly outputTokens?: number
}
```

## Providers

```ts type-equiv
/** One backend able to answer judgment requests. */
interface JudgmentProvider {
  /** Stable id used to configure and select this provider. */
  readonly id: string
  /** Whether this provider can serve right now (credentials present, etc.). */
  available: () => boolean | Promise<boolean>
  ask: (request: JudgmentRequest, signal?: AbortSignal) => Promise<JudgmentResult>
}
```

Selection copies [web.md](web.md) exactly: a configured id that is registered and available wins; with none configured, exactly one usable provider auto-selects; ambiguity (`JUDGMENT_PROVIDER_AMBIGUOUS`) and absence (`JUDGMENT_PROVIDER_UNAVAILABLE`) are distinct errors. Selection resolves at execution time and never depends on registration order.

## Consuming the seam

Consume it **optionally**, through `ctx.get('judgment')` with an undefined check, and keep the deterministic rule as the answer when no provider is mounted. A backend outage must not change an outcome the harness would otherwise reach — the [bind verifier](../../.agents/notes/implemented/feature/2026-09-17-judgment-capability.md) catches its own errors and returns `undefined`, which leaves the shipped predicate in force.

Typed output guarantees the interface, not the truth. Calibration is domain-specific and a threshold that separates cleanly on one corpus does not transfer, so gate on thresholds measured against your own data and consequences. The probability scale may be compressed while still ranking correctly; read the bands, not the raw number. Pin the provider's model version, because a rolling alias moving underneath a calibrated gate invalidates it without failing a test.

<!-- BEGIN GENERATED cordis-surface (gen-cordis-catalog.ts) — do not edit between markers -->

<a id="cordis-surface"></a>

## Cordis API

Generated from source by `scripts/gen-cordis-catalog.ts` (verified fresh by `pnpm run verify-cordis-catalog` in doc-sync; regenerate with `pnpm run gen-cordis-catalog`) — this section is byte-identical in both language sides of the page. Signature blocks use a `ts cordis-catalog` fence and keep the original source JSDoc; dispatch modes are defined in the [primer](../cordis-primer.md#dispatch-modes), and the framework-inherited `ctx` API lives in [cordis-api/inherited.md](../cordis-api/inherited.md).

<a id="ctxjudgment--judgmentruntime"></a>

### `ctx.judgment` — `JudgmentRuntime`

The judgment service, registered as `ctx.judgment`.

Consumers reach for `ask` when they have several independent questions about one state: those run in parallel inside one request and cannot see one another's answers, which is both cheaper and the only way to keep a speculative question from biasing the one that matters. `noul`, `choice` and `score` are conveniences over `ask` for the single-question case.

```ts cordis-catalog
/**
 * Register a backend. The returned disposer removes it again, so a provider
 * plugin's own lifetime owns its registration.
 *
 * @param provider - the backend to register.
 * @returns a disposer that unregisters it.
 * @throws JudgmentError when the id is already registered.
 */
register(provider: JudgmentProvider): () => void

/**
 * Registered provider ids, in registration order.
 * @returns the ids, whether or not each provider is currently usable.
 */
list(): readonly string[]

/**
 * Ask every question in one request. Independent questions belong here
 * together rather than in separate calls.
 *
 * @param request - the state and its questions.
 * @param signal - cancels the in-flight request.
 * @returns answers keyed by the request's question ids.
 * @throws JudgmentError when no question was asked or selection failed.
 */
async ask(request: JudgmentRequest, signal?: AbortSignal): Promise<JudgmentResult>

/**
 * Probability that one stated condition holds.
 *
 * @param state - what the question is about.
 * @param instructions - the condition, stated so that "yes" is unambiguous.
 * @param signal - cancels the in-flight request.
 * @returns the noul answer.
 */
async noul( state: JudgmentState, instructions: NoulQuestion['instructions'], signal?: AbortSignal, ): Promise<NoulAnswer>

/**
 * One option from a defined set, with the distribution across all of them.
 *
 * @param state - what the question is about.
 * @param instructions - the judgment to make.
 * @param criteria - each option keyed by id, described so it stands alone.
 * @param signal - cancels the in-flight request.
 * @returns the choice answer.
 */
async choice( state: JudgmentState, instructions: ChoiceQuestion['instructions'], criteria: ChoiceQuestion['criteria'], signal?: AbortSignal, ): Promise<ChoiceAnswer>

/**
 * A position along an ordered, described dimension.
 *
 * @param state - what the question is about.
 * @param instructions - the dimension being judged.
 * @param criteria - ordered levels, each describing a concrete situation.
 * @param signal - cancels the in-flight request.
 * @returns the score answer.
 */
async score( state: JudgmentState, instructions: ScoreQuestion['instructions'], criteria: ScoreQuestion['criteria'], signal?: AbortSignal, ): Promise<ScoreAnswer>
```

Source: [`packages/judgment/judgment/src/index.ts:81`](../../packages/judgment/judgment/src/index.ts)
<!-- END GENERATED cordis-surface -->
