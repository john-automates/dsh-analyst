/**
 * `@deepseek-ai/dsh-judgment-typesafe`: registers TypeSafe's System One
 * endpoint into the judgment seam's provider registry.
 *
 * A function/namespace plugin (`name` / `inject` / `Config` / `apply`, no
 * default export): it registers INTO `ctx.judgment` rather than owning a
 * service of its own.
 *
 * @module @deepseek-ai/dsh-judgment-typesafe
 */

import type { Context } from '@deepseek-ai/cordis'
import {
  JUDGMENT_BACKEND_FAILED,
  type JudgmentAnswer,
  JudgmentError,
  type JudgmentProvider,
  type JudgmentRequest,
  type JudgmentResult,
} from '@deepseek-ai/dsh-judgment'
import z from '@deepseek-ai/schemastery'

/** Cordis plugin name. */
export const name = 'judgment-typesafe'
/** The seam this provider registers into. */
export const inject = ['judgment']

/** Provider id, used to pin this backend through the seam's `provider` config. */
export const PROVIDER = 'typesafe'

const DEFAULT_BASE_URL = 'https://api.typesafe.ai/v1/systemone'
const DEFAULT_API_KEY_ENV = 'TYPESAFE_API_KEY'
// Pinned, not `jev-latest`: gates in `investigation` are calibrated against a
// specific version's probability scale, so an alias silently moving under us
// would invalidate every threshold without failing a test. Bumping this is a
// re-calibration event, not a version bump.
const DEFAULT_MODEL = 'jev-1.13.0'
/** The status codes TypeSafe documents as worth retrying. */
const RETRYABLE = new Set([429, 529])

/**
 * Plugin config. The credential is a reference to an environment-variable name
 * resolved per request, never an inline secret: a missing key makes the
 * provider unavailable rather than failing at plugin load.
 */
export interface Config {
  /** Environment variable holding the API key; defaults to `TYPESAFE_API_KEY`. */
  readonly apiKeyEnv?: string
  /** Endpoint base; defaults to the public System One endpoint. */
  readonly baseURL?: string
  /** Model requested when a call names none; defaults to the pinned version. */
  readonly model?: string
  /** Attempts after a retryable status before giving up. Defaults to 3. */
  readonly maxRetries?: number
}

/** Validated plugin config; schemastery fills every defaulted field. */
export const Config: z<Config> = z.object({
  apiKeyEnv: z.string().default(DEFAULT_API_KEY_ENV)
    .description('Environment variable holding the TypeSafe API key.'),
  baseURL: z.string().default(DEFAULT_BASE_URL).description('System One endpoint base.'),
  model: z.string().default(DEFAULT_MODEL).description('Model requested when a call names none. Pin it; gates are calibrated per version.'),
  maxRetries: z.number().default(3).description('Attempts after a retryable status.'),
})

/** Config after schemastery has applied its defaults. */
type ResolvedConfig = Required<Config>

/** The answer shapes the System One contract returns, before validation. */
interface WireAnswer {
  type?: string
  noul?: number
  choice?: string
  score?: number
  legend?: Record<string, unknown>
  probabilities?: Record<string, number>
  confidence?: number
}

/**
 * Narrow one wire answer to the seam's vocabulary. An answer whose shape does
 * not match its declared type is dropped rather than coerced, so a consumer
 * sees `JUDGMENT_ANSWER_MISSING` instead of a fabricated zero.
 *
 * @param raw - one answer from the service.
 * @returns the typed answer, or undefined when it does not fit.
 */
function toAnswer(raw: WireAnswer): JudgmentAnswer | undefined {
  if (raw.type === 'noul' && typeof raw.noul === 'number') {
    return { type: 'noul', noul: raw.noul }
  }
  if (raw.type === 'choice' && typeof raw.choice === 'string') {
    return {
      type: 'choice',
      choice: raw.choice,
      probabilities: raw.probabilities ?? {},
      confidence: raw.confidence ?? 0,
    }
  }
  if (raw.type === 'score' && typeof raw.score === 'number') {
    return {
      type: 'score',
      score: raw.score,
      legend: raw.legend ?? {},
      probabilities: raw.probabilities ?? {},
      confidence: raw.confidence ?? 0,
    }
  }
  return undefined
}

/**
 * Wait before a retry, honoring cancellation.
 *
 * A signal that is ALREADY aborted is checked first: `addEventListener` never
 * fires on one, so without this the backoff would be waited out in full after
 * the caller had given up. Once the listener is attached, an abort always
 * carries a reason, so only the pre-attached path needs a fallback.
 */
function delay(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal === undefined) {
    return new Promise((resolve) => { setTimeout(resolve, ms) })
  }
  if (signal.aborted) return Promise.reject(signal.reason ?? new Error('aborted'))
  return new Promise((resolve, reject) => {
    const onAbort = (): void => {
      clearTimeout(timer)
      reject(signal.reason)
    }
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort)
      resolve()
    }, ms)
    signal.addEventListener('abort', onAbort, { once: true })
  })
}

/**
 * Build the provider over a resolved config.
 *
 * @param config - plugin config with defaults already applied.
 * @returns the judgment provider.
 */
export function createProvider(config: ResolvedConfig): JudgmentProvider {
  const key = (): string | undefined => {
    const value = process.env[config.apiKeyEnv]
    return value === undefined || value.trim() === '' ? undefined : value.trim()
  }

  return {
    id: PROVIDER,
    available: () => key() !== undefined,
    ask: async (request: JudgmentRequest, signal?: AbortSignal): Promise<JudgmentResult> => {
      const apiKey = key()
      if (apiKey === undefined) {
        throw new JudgmentError(
          `judgment-typesafe: $${config.apiKeyEnv} is not set`,
          JUDGMENT_BACKEND_FAILED,
        )
      }
      const body = JSON.stringify({
        model: request.model ?? config.model,
        state: request.state,
        questions: request.questions,
      })

      let lastStatus = 0
      for (let attempt = 0; attempt <= config.maxRetries; attempt++) {
        const response = await fetch(config.baseURL, {
          method: 'POST',
          headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
          body,
          // exactOptionalPropertyTypes: RequestInit.signal is AbortSignal|null,
          // so an absent signal is omitted rather than passed as undefined.
          ...signal === undefined ? {} : { signal },
        })
        if (response.ok) {
          const payload = await response.json() as {
            model?: string
            answers?: Record<string, WireAnswer>
            usage?: { input_tokens?: number; output_tokens?: number }
          }
          const answers: Record<string, JudgmentAnswer> = {}
          for (const [id, raw] of Object.entries(payload.answers ?? {})) {
            const answer = toAnswer(raw)
            if (answer !== undefined) answers[id] = answer
          }
          return {
            answers,
            // The service answers a rolling alias with a pinned version; record
            // what actually served the request so an evaluation is reproducible.
            model: payload.model ?? request.model ?? config.model,
            usage: {
              ...payload.usage?.input_tokens === undefined
                ? {}
                : { inputTokens: payload.usage.input_tokens },
              ...payload.usage?.output_tokens === undefined
                ? {}
                : { outputTokens: payload.usage.output_tokens },
            },
          }
        }
        lastStatus = response.status
        if (!RETRYABLE.has(response.status) || attempt === config.maxRetries) {
          throw new JudgmentError(
            `judgment-typesafe: request failed with HTTP ${response.status}`,
            JUDGMENT_BACKEND_FAILED,
          )
        }
        await delay(500 * 2 ** attempt, signal)
      }
      /* v8 ignore next 4 -- the loop always returns or throws; this is unreachable */
      throw new JudgmentError(
        `judgment-typesafe: request failed with HTTP ${lastStatus}`,
        JUDGMENT_BACKEND_FAILED,
      )
    },
  }
}

/**
 * Register the TypeSafe provider for this fiber's lifetime.
 *
 * @param ctx - Cordis context carrying the judgment seam.
 * @param config - plugin config.
 */
export function apply(ctx: Context, config: Config): void {
  // schemastery (Config) has already filled every defaulted field.
  const resolved = config as ResolvedConfig
  ctx.effect(() => ctx.judgment.register(createProvider(resolved)), 'judgment-typesafe: provider')
}
