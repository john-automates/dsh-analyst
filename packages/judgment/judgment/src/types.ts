/**
 * Vocabulary for the judgment capability seam (`ctx.judgment`): calibrated
 * typed answers from a System One model.
 *
 * A System One model is not a small LLM. It returns a probability or a typed
 * selection and generates no text, so there is no prose to parse, no format to
 * coax, and no reasoning to pay for. That is why this is its own seam rather
 * than a mode of `ctx.llm`: the request carries questions instead of messages,
 * the answer carries numbers instead of content, and the failure modes are
 * about calibration rather than truncation.
 *
 * @module @deepseek-ai/dsh-judgment/types
 */

/**
 * The state a question is asked about: source text, identities, relationships,
 * current facts. Named fields are preferred over one blob, because a question's
 * instructions may reference a field by name and the model reads the shape.
 */
export type JudgmentState = string | readonly unknown[] | { readonly [key: string]: unknown }

/**
 * Whether a condition holds. The answer is the probability of yes; there is no
 * separate confidence, and a value near 0.5 means yes and no are close to
 * equally likely rather than "medium intensity". Use one per label when several
 * labels may apply at once.
 */
export interface NoulQuestion {
  readonly type: 'noul'
  /** The condition, stated so that "yes" is unambiguous. */
  readonly instructions: string | Readonly<Record<string, unknown>>
}

/**
 * One of a defined set. The answer names the winning option and carries the
 * distribution across all of them, so `probabilities` compares competing
 * options rather than scoring one in isolation. Include a no-match option when
 * nothing may fit.
 */
export interface ChoiceQuestion {
  readonly type: 'choice'
  readonly instructions: string | Readonly<Record<string, unknown>>
  /** Each option keyed by id, its value describing when that option is right. */
  readonly criteria: Readonly<Record<string, string | Readonly<Record<string, unknown>>>>
}

/**
 * A position along a described dimension. Levels must describe concrete
 * situations and stand on their own, because the model reads them as the scale.
 */
export interface ScoreQuestion {
  readonly type: 'score'
  readonly instructions: string | Readonly<Record<string, unknown>>
  /** Ordered levels keyed by id, each describing a concrete situation. */
  readonly criteria: Readonly<Record<string, string | Readonly<Record<string, unknown>>>>
}

/** Any question this seam can ask. */
export type JudgmentQuestion = ChoiceQuestion | NoulQuestion | ScoreQuestion

/** Probability that the stated condition holds, in `[0, 1]`. */
export interface NoulAnswer {
  readonly type: 'noul'
  readonly noul: number
}

/** The selected option, the full distribution, and how concentrated it is. */
export interface ChoiceAnswer {
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

/** The weighted position, the level legend, and distribution concentration. */
export interface ScoreAnswer {
  readonly type: 'score'
  readonly score: number
  readonly legend: Readonly<Record<string, unknown>>
  readonly probabilities: Readonly<Record<string, number>>
  readonly confidence: number
}

/** Any answer this seam can return. */
export type JudgmentAnswer = ChoiceAnswer | NoulAnswer | ScoreAnswer

/** Tokens a request consumed, when the provider reports them. */
export interface JudgmentUsage {
  readonly inputTokens?: number
  readonly outputTokens?: number
}

/**
 * One request: a state, and the questions to ask about it. Independent
 * questions belong in ONE request — they run in parallel, cannot see one
 * another's answers, and cost one round trip instead of several. A second
 * request is warranted only when an earlier answer is needed to fetch evidence
 * or decide the next options.
 */
export interface JudgmentRequest {
  readonly state: JudgmentState
  /** Questions keyed by an id the calling code uses; ids are not sent to the model. */
  readonly questions: Readonly<Record<string, JudgmentQuestion>>
  /** Requested model id; the provider's default applies when omitted. */
  readonly model?: string
}

/** Answers keyed by the request's question ids, plus what actually served them. */
export interface JudgmentResult {
  readonly answers: Readonly<Record<string, JudgmentAnswer>>
  /**
   * The model id the service reports having served the request. A request for a
   * rolling alias is answered by a pinned version, and an evaluation is only
   * reproducible if that version is recorded.
   */
  readonly model: string
  readonly usage?: JudgmentUsage
}

/** One backend able to answer judgment requests. */
export interface JudgmentProvider {
  /** Stable id used to configure and select this provider. */
  readonly id: string
  /** Whether this provider can serve right now (credentials present, etc.). */
  available: () => boolean | Promise<boolean>
  ask: (request: JudgmentRequest, signal?: AbortSignal) => Promise<JudgmentResult>
}
