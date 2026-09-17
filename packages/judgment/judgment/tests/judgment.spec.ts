import { Context } from '@deepseek-ai/cordis'
import { describe, expect, it, vi } from 'vitest'
import JudgmentRuntime, {
  JUDGMENT_ANSWER_MISSING,
  JUDGMENT_PROVIDER_AMBIGUOUS,
  JUDGMENT_PROVIDER_CONFIGURED_MISSING,
  JUDGMENT_PROVIDER_CONFIGURED_UNAVAILABLE,
  JUDGMENT_PROVIDER_DUPLICATE,
  JUDGMENT_PROVIDER_UNAVAILABLE,
  JUDGMENT_REQUEST_EMPTY,
  JudgmentError,
  type JudgmentAnswer,
  type JudgmentProvider,
  type JudgmentRequest,
  type JudgmentResult,
} from '@deepseek-ai/dsh-judgment/src/index.ts'

const noul = (value: number): JudgmentAnswer => ({ type: 'noul', noul: value })

/** A scripted provider; `ask` records the request it was given. */
function provider(
  id: string,
  available: boolean,
  answers: Record<string, JudgmentAnswer> = { q: noul(0.5) },
  seen?: JudgmentRequest[],
): JudgmentProvider {
  return {
    id,
    available: () => available,
    ask: (request: JudgmentRequest): Promise<JudgmentResult> => {
      seen?.push(request)
      return Promise.resolve({ answers, model: 'jev-1.0.0' })
    },
  }
}

/** A runtime with no provider registered. */
function runtime(config: { provider?: string } = {}): JudgmentRuntime {
  return new JudgmentRuntime(new Context(), config)
}

describe('registration', () => {
  it('rejects a duplicate provider id', () => {
    const judgment = runtime()
    judgment.register(provider('a', true))
    expect(() => judgment.register(provider('a', true)))
      .toThrowError(expect.objectContaining({ code: JUDGMENT_PROVIDER_DUPLICATE }))
  })

  it('lists ids and removes one through its disposer', () => {
    const judgment = runtime()
    const dispose = judgment.register(provider('a', true))
    judgment.register(provider('b', true))
    expect(judgment.list()).toEqual(['a', 'b'])
    dispose()
    expect(judgment.list()).toEqual(['b'])
  })
})

describe('selection', () => {
  it('auto-selects the single usable provider', async () => {
    const judgment = runtime()
    judgment.register(provider('only', true, { q: noul(0.9) }))
    await expect(judgment.noul('s', 'c')).resolves.toEqual(noul(0.9))
  })

  it('ignores unusable providers when auto-selecting', async () => {
    const judgment = runtime()
    judgment.register(provider('down', false, { q: noul(0.1) }))
    judgment.register(provider('up', true, { q: noul(0.8) }))
    await expect(judgment.noul('s', 'c')).resolves.toEqual(noul(0.8))
  })

  it('refuses when several providers are usable', async () => {
    const judgment = runtime()
    judgment.register(provider('a', true))
    judgment.register(provider('b', true))
    await expect(judgment.noul('s', 'c'))
      .rejects.toThrowError(expect.objectContaining({ code: JUDGMENT_PROVIDER_AMBIGUOUS }))
  })

  it('refuses when no provider is usable', async () => {
    const judgment = runtime()
    judgment.register(provider('down', false))
    await expect(judgment.noul('s', 'c'))
      .rejects.toThrowError(expect.objectContaining({ code: JUDGMENT_PROVIDER_UNAVAILABLE }))
  })

  it('uses a configured provider regardless of registration order', async () => {
    const judgment = runtime({ provider: 'second' })
    judgment.register(provider('first', true, { q: noul(0.1) }))
    judgment.register(provider('second', true, { q: noul(0.7) }))
    await expect(judgment.noul('s', 'c')).resolves.toEqual(noul(0.7))
  })

  it('refuses a configured provider that is not registered', async () => {
    const judgment = runtime({ provider: 'missing' })
    judgment.register(provider('other', true))
    await expect(judgment.noul('s', 'c'))
      .rejects.toThrowError(expect.objectContaining({ code: JUDGMENT_PROVIDER_CONFIGURED_MISSING }))
  })

  it('refuses a configured provider that is unusable', async () => {
    const judgment = runtime({ provider: 'down' })
    judgment.register(provider('down', false))
    await expect(judgment.noul('s', 'c'))
      .rejects.toThrowError(expect.objectContaining({
        code: JUDGMENT_PROVIDER_CONFIGURED_UNAVAILABLE,
      }))
  })
})

describe('ask', () => {
  it('refuses a request with no questions', async () => {
    const judgment = runtime()
    judgment.register(provider('a', true))
    await expect(judgment.ask({ state: 's', questions: {} }))
      .rejects.toThrowError(expect.objectContaining({ code: JUDGMENT_REQUEST_EMPTY }))
  })

  it('sends every question in one request and returns the served model', async () => {
    const seen: JudgmentRequest[] = []
    const judgment = runtime()
    judgment.register(provider('a', true, { one: noul(0.2), two: noul(0.3) }, seen))
    const result = await judgment.ask({
      state: { field: 1 },
      questions: { one: { type: 'noul', instructions: 'a' }, two: { type: 'noul', instructions: 'b' } },
    })
    expect(seen).toHaveLength(1)
    expect(Object.keys(seen[0]!.questions)).toEqual(['one', 'two'])
    expect(result.model).toBe('jev-1.0.0')
    expect(result.answers).toEqual({ one: noul(0.2), two: noul(0.3) })
  })

  it('passes the abort signal through to the provider', async () => {
    const ask = vi.fn(() => Promise.resolve({ answers: { q: noul(0.4) }, model: 'm' }))
    const judgment = runtime()
    judgment.register({ id: 'a', available: () => true, ask })
    const controller = new AbortController()
    await judgment.noul('s', 'c', controller.signal)
    expect(ask).toHaveBeenCalledWith(expect.anything(), controller.signal)
  })
})

describe('single-question conveniences', () => {
  it('returns a choice answer with its distribution', async () => {
    const judgment = runtime()
    judgment.register(provider('a', true, {
      q: { type: 'choice', choice: 'c2', probabilities: { c2: 0.8, cdn: 0.2 }, confidence: 0.7 },
    }))
    const answer = await judgment.choice('s', 'which?', { c2: 'attacker', cdn: 'a CDN' })
    expect(answer.choice).toBe('c2')
    expect(answer.probabilities).toEqual({ c2: 0.8, cdn: 0.2 })
  })

  it('returns a score answer with its legend', async () => {
    const judgment = runtime()
    judgment.register(provider('a', true, {
      q: { type: 'score', score: 2, legend: { low: 1 }, probabilities: { low: 1 }, confidence: 0.9 },
    }))
    const answer = await judgment.score('s', 'how much?', { low: 'a little' })
    expect(answer.score).toBe(2)
    expect(answer.legend).toEqual({ low: 1 })
  })

  it('refuses when the provider answers a different kind of question', async () => {
    const judgment = runtime()
    judgment.register(provider('a', true, {
      q: { type: 'choice', choice: 'x', probabilities: {}, confidence: 0 },
    }))
    await expect(judgment.noul('s', 'c'))
      .rejects.toThrowError(expect.objectContaining({ code: JUDGMENT_ANSWER_MISSING }))
  })

  it('refuses when the provider omits the answer entirely', async () => {
    const judgment = runtime()
    judgment.register(provider('a', true, {}))
    await expect(judgment.noul('s', 'c'))
      .rejects.toThrowError(expect.objectContaining({ code: JUDGMENT_ANSWER_MISSING }))
  })
})

describe('JudgmentError', () => {
  it('carries the code and names itself after the subclass', () => {
    const error = new JudgmentError('boom', 'SOME_CODE')
    expect(error.code).toBe('SOME_CODE')
    expect(error.name).toBe('JudgmentError')
  })
})
