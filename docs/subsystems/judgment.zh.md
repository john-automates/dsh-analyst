# 判断

[English](judgment.md) | 中文

判断接缝——一个架在 **System One** 模型之上的 `ctx.judgment` 服务，分布在若干包中：Service Definition（[dsh-judgment](../../packages/judgment/judgment)，即 `ctx.judgment` 与提供方注册表）、Service Provider（[dsh-judgment-typesafe](../../packages/judgment/judgment-typesafe)，接 TypeSafe 的 `/v1/systemone`）与 Consumer（[dsh-investigation](../../packages/analyst/investigation)，即 bind 校验器）。判断是**一项可选能力**，不属于智能体循环的主干——因此它的词汇表在这里，而不在 [core.md](core.md)。更换提供方不会改变消费方提出的问题。

源码：[`packages/judgment/judgment/src/types.ts`](../../packages/judgment/judgment/src/types.ts)

## 为什么这不是 `ctx.llm` 的一种模式

System One 模型并不是一个小号 LLM。它返回的是一个概率或一个带类型的选择，且不生成任何文本，因此没有散文需要解析、没有格式需要哄劝、也没有推理需要付费。契约在每一处都不同：请求携带的是问题而非消息，回答携带的是数字而非内容，没有流式输出，没有工具循环，而失效模式关乎校准而非截断。消费方问一句*这个目的地是 CDN 吗？*，得到的是 `0.74`。

这也正是判断后端不是子智能体的原因。`packages/subagent/` 下的每一个提供方都是对话式的；把一个不产文本的模型接成子智能体，等于丢掉延迟与成本这两项它全部的优势。

## State

```ts type-equiv
/**
 * The state a question is asked about: source text, identities, relationships,
 * current facts. Named fields are preferred over one blob, because a question's
 * instructions may reference a field by name and the model reads the shape.
 */
type JudgmentState = string | readonly unknown[] | { readonly [key: string]: unknown }
```

## 三个原语

按答案的*含义*来挑选，而不是按它有多少种结果。

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

## 答案

Noul 不带置信度字段，因为它的概率本身*就是*答案。Choice 与 Score 各带一个，而它只概括分布的集中程度。

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

## 请求与结果

批处理是要点，而非优化：state 只付费一次，因此就同一份 state 问二十个独立问题，花费大致与问一个相当。

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

## 提供方

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

选择方式完全照搬 [web.md](web.md)：配置中指定、且已注册并可用的 id 胜出；未配置时，恰好只有一个可用的提供方则自动选中；歧义（`JUDGMENT_PROVIDER_AMBIGUOUS`）与缺失（`JUDGMENT_PROVIDER_UNAVAILABLE`）是两个不同的错误。选择在执行时解析，绝不依赖注册顺序。

## 消费这条接缝

**可选地**消费它，方式是 `ctx.get('judgment')` 加一次 undefined 检查，并在没有提供方挂载时让确定性规则继续充当答案。后端故障绝不能改变 harness 本来会得出的结论——[bind 校验器](../../.agents/notes/implemented/feature/2026-09-17-judgment-capability.md)会捕获自身的错误并返回 `undefined`，从而让线上谓词继续生效。

带类型的输出保证的是接口，不是真相。校准是领域相关的，在一份语料上划分干净的阈值并不会迁移；因此请按在你自己的数据与后果上测得的阈值设闸。概率标度可能是压缩的，却仍能正确排序；读它划出的带，而不是原始数值。请固定提供方的模型版本，因为滚动别名在一道已校准的闸门底下移动，会让它失效却不会让任何测试失败。

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
