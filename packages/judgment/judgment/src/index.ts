import { Context, Service } from '@deepseek-ai/cordis'
import { HarnessError } from '@deepseek-ai/dsh-llm'
import z from '@deepseek-ai/schemastery'
import type {
  ChoiceAnswer,
  ChoiceQuestion,
  JudgmentProvider,
  JudgmentQuestion,
  JudgmentRequest,
  JudgmentResult,
  JudgmentState,
  NoulAnswer,
  NoulQuestion,
  ScoreAnswer,
  ScoreQuestion,
} from './types.ts'

export type {
  ChoiceAnswer,
  ChoiceQuestion,
  JudgmentAnswer,
  JudgmentProvider,
  JudgmentQuestion,
  JudgmentRequest,
  JudgmentResult,
  JudgmentState,
  JudgmentUsage,
  NoulAnswer,
  NoulQuestion,
  ScoreAnswer,
  ScoreQuestion,
} from './types.ts'

/** A configured provider id names no registered provider. */
export const JUDGMENT_PROVIDER_CONFIGURED_MISSING = 'JUDGMENT_PROVIDER_CONFIGURED_MISSING'
/** The configured provider is registered but cannot serve right now. */
export const JUDGMENT_PROVIDER_CONFIGURED_UNAVAILABLE = 'JUDGMENT_PROVIDER_CONFIGURED_UNAVAILABLE'
/** No id is configured and more than one provider is usable. */
export const JUDGMENT_PROVIDER_AMBIGUOUS = 'JUDGMENT_PROVIDER_AMBIGUOUS'
/** No id is configured and no provider is usable. */
export const JUDGMENT_PROVIDER_UNAVAILABLE = 'JUDGMENT_PROVIDER_UNAVAILABLE'
/** A provider id was registered twice. */
export const JUDGMENT_PROVIDER_DUPLICATE = 'JUDGMENT_PROVIDER_DUPLICATE'
/** A request carried no questions. */
export const JUDGMENT_REQUEST_EMPTY = 'JUDGMENT_REQUEST_EMPTY'
/** The provider returned no answer of the kind that was asked. */
export const JUDGMENT_ANSWER_MISSING = 'JUDGMENT_ANSWER_MISSING'
/** The backend rejected or failed the request. Providers raise it. */
export const JUDGMENT_BACKEND_FAILED = 'JUDGMENT_BACKEND_FAILED'

/**
 * Structured failure from the judgment seam or one of its providers.
 * `HarnessError` carries the code and sets `name` from the subclass.
 */
export class JudgmentError extends HarnessError {}

declare module '@deepseek-ai/cordis' {
  interface Context {
    judgment: JudgmentRuntime
  }
}

/**
 * Config for the judgment seam. `provider` pins which provider wins; omitted, a
 * single registered usable provider auto-selects.
 */
export interface JudgmentRuntimeConfig {
  /** Explicit provider id. Omitted = auto-select when exactly one is usable. */
  readonly provider?: string
}

/**
 * The judgment service, registered as `ctx.judgment`.
 *
 * Consumers reach for `ask` when they have several independent questions about
 * one state: those run in parallel inside one request and cannot see one
 * another's answers, which is both cheaper and the only way to keep a
 * speculative question from biasing the one that matters. `noul`, `choice` and
 * `score` are conveniences over `ask` for the single-question case.
 */
export class JudgmentRuntime extends Service {
  static Config: z<JudgmentRuntimeConfig> = z.object({
    provider: z.string().description('Explicit judgment provider id.'),
  })

  private readonly providers = new Map<string, JudgmentProvider>()

  constructor(ctx: Context, public config: JudgmentRuntimeConfig = {}) {
    super(ctx, 'judgment')
  }

  /**
   * Register a backend. The returned disposer removes it again, so a provider
   * plugin's own lifetime owns its registration.
   *
   * @param provider - the backend to register.
   * @returns a disposer that unregisters it.
   * @throws JudgmentError when the id is already registered.
   */
  register(provider: JudgmentProvider): () => void {
    if (this.providers.has(provider.id)) {
      throw new JudgmentError(
        `judgment: provider "${provider.id}" is already registered`,
        JUDGMENT_PROVIDER_DUPLICATE,
      )
    }
    this.providers.set(provider.id, provider)
    return () => {
      this.providers.delete(provider.id)
    }
  }

  /**
   * Registered provider ids, in registration order.
   * @returns the ids, whether or not each provider is currently usable.
   */
  list(): readonly string[] {
    return [...this.providers.keys()]
  }

  /**
   * Resolve the provider for this request. Never order-dependent: a configured
   * id must be registered and usable; with no id configured, exactly one usable
   * provider must exist.
   *
   * @returns the selected provider.
   * @throws JudgmentError naming which selection rule failed.
   */
  private async select(): Promise<JudgmentProvider> {
    const configured = this.config.provider
    if (configured !== undefined) {
      const provider = this.providers.get(configured)
      if (provider === undefined) {
        throw new JudgmentError(
          `judgment: configured provider "${configured}" is not registered`,
          JUDGMENT_PROVIDER_CONFIGURED_MISSING,
        )
      }
      if (!await provider.available()) {
        throw new JudgmentError(
          `judgment: configured provider "${configured}" is not usable`,
          JUDGMENT_PROVIDER_CONFIGURED_UNAVAILABLE,
        )
      }
      return provider
    }
    const usable: JudgmentProvider[] = []
    for (const provider of this.providers.values()) {
      if (await provider.available()) usable.push(provider)
    }
    const only = usable.length === 1 ? usable[0] : undefined
    if (only !== undefined) return only
    if (usable.length === 0) {
      throw new JudgmentError(
        'judgment: no usable provider is registered',
        JUDGMENT_PROVIDER_UNAVAILABLE,
      )
    }
    throw new JudgmentError(
      `judgment: several usable providers (${usable.map(p => p.id).join(', ')}); configure one`,
      JUDGMENT_PROVIDER_AMBIGUOUS,
    )
  }

  /**
   * Ask every question in one request. Independent questions belong here
   * together rather than in separate calls.
   *
   * @param request - the state and its questions.
   * @param signal - cancels the in-flight request.
   * @returns answers keyed by the request's question ids.
   * @throws JudgmentError when no question was asked or selection failed.
   */
  async ask(request: JudgmentRequest, signal?: AbortSignal): Promise<JudgmentResult> {
    if (Object.keys(request.questions).length === 0) {
      throw new JudgmentError('judgment: a request must ask at least one question', JUDGMENT_REQUEST_EMPTY)
    }
    const provider = await this.select()
    return await provider.ask(request, signal)
  }

  /**
   * Ask one question and return its answer, checking that the provider answered
   * the kind of question that was asked.
   */
  private async one<A>(
    state: JudgmentState,
    question: JudgmentQuestion,
    signal: AbortSignal | undefined,
  ): Promise<A> {
    const result = await this.ask({ state, questions: { q: question } }, signal)
    const answer = result.answers.q
    if (answer === undefined || answer.type !== question.type) {
      throw new JudgmentError(
        `judgment: provider returned no ${question.type} answer`,
        JUDGMENT_ANSWER_MISSING,
      )
    }
    return answer as A
  }

  /**
   * Probability that one stated condition holds.
   *
   * @param state - what the question is about.
   * @param instructions - the condition, stated so that "yes" is unambiguous.
   * @param signal - cancels the in-flight request.
   * @returns the noul answer.
   */
  async noul(
    state: JudgmentState,
    instructions: NoulQuestion['instructions'],
    signal?: AbortSignal,
  ): Promise<NoulAnswer> {
    return await this.one<NoulAnswer>(state, { type: 'noul', instructions }, signal)
  }

  /**
   * One option from a defined set, with the distribution across all of them.
   *
   * @param state - what the question is about.
   * @param instructions - the judgment to make.
   * @param criteria - each option keyed by id, described so it stands alone.
   * @param signal - cancels the in-flight request.
   * @returns the choice answer.
   */
  async choice(
    state: JudgmentState,
    instructions: ChoiceQuestion['instructions'],
    criteria: ChoiceQuestion['criteria'],
    signal?: AbortSignal,
  ): Promise<ChoiceAnswer> {
    return await this.one<ChoiceAnswer>(state, { type: 'choice', instructions, criteria }, signal)
  }

  /**
   * A position along an ordered, described dimension.
   *
   * @param state - what the question is about.
   * @param instructions - the dimension being judged.
   * @param criteria - ordered levels, each describing a concrete situation.
   * @param signal - cancels the in-flight request.
   * @returns the score answer.
   */
  async score(
    state: JudgmentState,
    instructions: ScoreQuestion['instructions'],
    criteria: ScoreQuestion['criteria'],
    signal?: AbortSignal,
  ): Promise<ScoreAnswer> {
    return await this.one<ScoreAnswer>(state, { type: 'score', instructions, criteria }, signal)
  }
}

export default JudgmentRuntime
