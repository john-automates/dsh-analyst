import { Context } from '@deepseek-ai/cordis'
import JudgmentRuntime, { JUDGMENT_BACKEND_FAILED } from '@deepseek-ai/dsh-judgment/src/index.ts'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Config, PROVIDER, apply, createProvider } from '@deepseek-ai/dsh-judgment-typesafe/src/index.ts'

const ENV = 'TYPESAFE_TEST_KEY'

/** Clear the referenced variable; `process.env` rejects a dynamic `delete`. */
function clearKey(): void {
  process.env = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => key !== ENV),
  ) as NodeJS.ProcessEnv
}

/** The plugin's resolved config, as schemastery would hand it to `apply`. */
const resolved = (overrides: Partial<Config> = {}): Required<Config> => ({
  apiKeyEnv: ENV,
  baseURL: 'https://judgment.test/v1/systemone',
  model: 'jev-latest',
  maxRetries: 2,
  ...overrides,
} as Required<Config>)

function ok(body: unknown): Response {
  return { ok: true, status: 200, json: () => Promise.resolve(body) } as unknown as Response
}

function status(code: number): Response {
  return { ok: false, status: code, json: () => Promise.resolve({}) } as unknown as Response
}

beforeEach(() => {
  process.env[ENV] = 'secret'
})

afterEach(() => {
  clearKey()
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

describe('availability', () => {
  it('is unavailable when the referenced variable is unset', () => {
    clearKey()
    expect(createProvider(resolved()).available()).toBe(false)
  })

  it('is unavailable when the referenced variable is blank', () => {
    process.env[ENV] = '   '
    expect(createProvider(resolved()).available()).toBe(false)
  })

  it('is available when the key is present', () => {
    expect(createProvider(resolved()).available()).toBe(true)
  })

  it('fails the call when the key disappears between check and request', async () => {
    const provider = createProvider(resolved())
    clearKey()
    await expect(provider.ask({ state: 's', questions: {} }))
      .rejects.toThrowError(expect.objectContaining({ code: JUDGMENT_BACKEND_FAILED }))
  })
})

describe('request', () => {
  it('sends the model, state and questions, and authorizes with the key', async () => {
    const fetchMock = vi.fn(() => Promise.resolve(ok({
      model: 'jev-1.13.0',
      answers: { q: { type: 'noul', noul: 0.42 } },
      usage: { input_tokens: 11, output_tokens: 3 },
    })))
    vi.stubGlobal('fetch', fetchMock)
    const result = await createProvider(resolved()).ask({
      state: { a: 1 },
      questions: { q: { type: 'noul', instructions: 'is it?' } },
    })
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toBe('https://judgment.test/v1/systemone')
    expect((init.headers as Record<string, string>).Authorization).toBe('Bearer secret')
    expect(JSON.parse(init.body as string)).toEqual({
      model: 'jev-latest',
      state: { a: 1 },
      questions: { q: { type: 'noul', instructions: 'is it?' } },
    })
    expect(result.answers.q).toEqual({ type: 'noul', noul: 0.42 })
    expect(result.usage).toEqual({ inputTokens: 11, outputTokens: 3 })
  })

  it('records the served model, not the alias that was requested', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(ok({ model: 'jev-1.13.0', answers: {} }))))
    const result = await createProvider(resolved()).ask({ state: 's', questions: {} })
    expect(result.model).toBe('jev-1.13.0')
  })

  it('falls back to the requested model when the service names none', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(ok({ answers: {} }))))
    const result = await createProvider(resolved())
      .ask({ state: 's', questions: {}, model: 'jev-pinned' })
    expect(result.model).toBe('jev-pinned')
  })

  it('falls back to the configured model when neither names one', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(ok({ answers: {} }))))
    const result = await createProvider(resolved()).ask({ state: 's', questions: {} })
    expect(result.model).toBe('jev-latest')
  })

  it('omits usage fields the service did not report', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(ok({ answers: {}, usage: {} }))))
    const result = await createProvider(resolved()).ask({ state: 's', questions: {} })
    expect(result.usage).toEqual({})
  })

  it('passes an abort signal through and omits it when absent', async () => {
    const fetchMock = vi.fn(() => Promise.resolve(ok({ answers: {} })))
    vi.stubGlobal('fetch', fetchMock)
    const provider = createProvider(resolved())
    await provider.ask({ state: 's', questions: {} })
    const first = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    expect('signal' in first[1]).toBe(false)
    const controller = new AbortController()
    await provider.ask({ state: 's', questions: {} }, controller.signal)
    const second = fetchMock.mock.calls[1] as unknown as [string, RequestInit]
    expect(second[1].signal).toBe(controller.signal)
  })
})

describe('answer narrowing', () => {
  it('keeps choice and score answers with their distributions', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(ok({
      answers: {
        c: { type: 'choice', choice: 'c2', probabilities: { c2: 1 }, confidence: 0.8 },
        s: { type: 'score', score: 3, legend: { l: 1 }, probabilities: { l: 1 }, confidence: 0.6 },
      },
    }))))
    const result = await createProvider(resolved()).ask({ state: 's', questions: {} })
    expect(result.answers.c).toEqual({
      type: 'choice', choice: 'c2', probabilities: { c2: 1 }, confidence: 0.8,
    })
    expect(result.answers.s).toEqual({
      type: 'score', score: 3, legend: { l: 1 }, probabilities: { l: 1 }, confidence: 0.6,
    })
  })

  it('defaults missing distribution and confidence rather than failing', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(ok({
      answers: {
        c: { type: 'choice', choice: 'c2' },
        s: { type: 'score', score: 1 },
      },
    }))))
    const result = await createProvider(resolved()).ask({ state: 's', questions: {} })
    expect(result.answers.c).toEqual({
      type: 'choice', choice: 'c2', probabilities: {}, confidence: 0,
    })
    expect(result.answers.s).toEqual({
      type: 'score', score: 1, legend: {}, probabilities: {}, confidence: 0,
    })
  })

  it('drops an answer whose shape contradicts its declared type', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(ok({
      answers: {
        bad: { type: 'noul' },
        alsoBad: { type: 'choice', choice: 7 },
        unknown: { type: 'mystery', value: 1 },
        good: { type: 'noul', noul: 0.1 },
      },
    }))))
    const result = await createProvider(resolved()).ask({ state: 's', questions: {} })
    expect(Object.keys(result.answers)).toEqual(['good'])
  })

  it('tolerates a response with no answers object at all', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(ok({}))))
    const result = await createProvider(resolved()).ask({ state: 's', questions: {} })
    expect(result.answers).toEqual({})
  })
})

describe('retry', () => {
  it('retries a documented retryable status and then succeeds', async () => {
    vi.useFakeTimers()
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(status(429))
      .mockResolvedValueOnce(status(529))
      .mockResolvedValueOnce(ok({ answers: { q: { type: 'noul', noul: 0.9 } } }))
    vi.stubGlobal('fetch', fetchMock)
    const pending = createProvider(resolved()).ask({ state: 's', questions: {} })
    await vi.runAllTimersAsync()
    await expect(pending).resolves.toMatchObject({ answers: { q: { noul: 0.9 } } })
    expect(fetchMock).toHaveBeenCalledTimes(3)
  })

  it('gives up after the configured number of retries', async () => {
    vi.useFakeTimers()
    const fetchMock = vi.fn().mockResolvedValue(status(429))
    vi.stubGlobal('fetch', fetchMock)
    const pending = createProvider(resolved()).ask({ state: 's', questions: {} })
    const assertion = expect(pending)
      .rejects.toThrowError(expect.objectContaining({ code: JUDGMENT_BACKEND_FAILED }))
    await vi.runAllTimersAsync()
    await assertion
    expect(fetchMock).toHaveBeenCalledTimes(3)
  })

  it('completes a backoff under a signal the caller never aborts', async () => {
    vi.useFakeTimers()
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(status(429))
      .mockResolvedValueOnce(ok({ answers: { q: { type: 'noul', noul: 0.3 } } }))
    vi.stubGlobal('fetch', fetchMock)
    const pending = createProvider(resolved())
      .ask({ state: 's', questions: {} }, new AbortController().signal)
    await vi.runAllTimersAsync()
    await expect(pending).resolves.toMatchObject({ answers: { q: { noul: 0.3 } } })
  })

  it('does not retry a status the service does not document as retryable', async () => {
    const fetchMock = vi.fn().mockResolvedValue(status(401))
    vi.stubGlobal('fetch', fetchMock)
    await expect(createProvider(resolved()).ask({ state: 's', questions: {} }))
      .rejects.toThrowError(expect.objectContaining({ code: JUDGMENT_BACKEND_FAILED }))
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('abandons a pending retry when the caller aborts mid-backoff', async () => {
    const controller = new AbortController()
    // Abort from inside the first response, so the backoff timer is already
    // armed when the signal fires and the delay's abort path runs.
    vi.stubGlobal('fetch', vi.fn(() => {
      controller.abort(new Error('cancelled'))
      return Promise.resolve(status(429))
    }))
    await expect(
      createProvider(resolved()).ask({ state: 's', questions: {} }, controller.signal),
    ).rejects.toThrowError('cancelled')
  })

  it('rejects with a plain error when an aborted signal carries no reason', async () => {
    // A signal-shaped object, because AbortSignal.reason is not redefinable.
    const signal = {
      aborted: true,
      reason: undefined,
      addEventListener: () => {},
      removeEventListener: () => {},
    } as unknown as AbortSignal
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(status(429))))
    await expect(createProvider(resolved()).ask({ state: 's', questions: {} }, signal))
      .rejects.toThrowError('aborted')
  })

  it('still cancels a retry armed before the signal fires', async () => {
    const controller = new AbortController()
    vi.stubGlobal('fetch', vi.fn(() => {
      setTimeout(() => { controller.abort(new Error('late cancel')) }, 0)
      return Promise.resolve(status(429))
    }))
    await expect(
      createProvider(resolved()).ask({ state: 's', questions: {} }, controller.signal),
    ).rejects.toThrowError('late cancel')
  })
})

describe('plugin', () => {
  it('registers the provider and unregisters it when the fiber disposes', async () => {
    const ctx = new Context()
    await ctx.plugin(JudgmentRuntime, {})
    const fork = await ctx.plugin(
      { name: 'judgment-typesafe', inject: ['judgment'], apply }, resolved(),
    )
    expect(ctx.judgment.list()).toContain(PROVIDER)
    await fork.dispose()
    expect(ctx.judgment.list()).not.toContain(PROVIDER)
  })
})
