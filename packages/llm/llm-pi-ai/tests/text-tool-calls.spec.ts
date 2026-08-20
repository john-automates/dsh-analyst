/**
 * Recover Hermes XML function dumps on the OpenAI-completions path.
 * The r4 payload is the exact assistant text from the Bedrock 30B flake.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import LlmRuntime, { CallId, LlmAdapter } from '@deepseek-ai/dsh-llm'
import type { GenerateOptions, StreamChunk } from '@deepseek-ai/dsh-llm'
import * as LlmPiAi from '@deepseek-ai/dsh-llm-pi-ai'
import {
  parseHermesXmlToolCalls,
  recoverXmlToolCallStream,
  recoverXmlToolCallsFromChunks,
} from '../src/text-tool-calls.ts'
import { assemble } from './assemble.ts'
import { closeMockServers, mockServer } from './mock-server.ts'

/** Exact assistant text from session.dsh-analyst-master-d83af44-r4.jsonl. */
const R4_ASSISTANT_TEXT = `I'll start by reading the TASK.md file...

<function=read>
<parameter=file_path>
TASK.md
</parameter>
</function>
</tool_call>`

const READ_TOOL = {
  name: 'read',
  description: 'Read a file.',
  parameters: { type: 'object', properties: { file_path: { type: 'string' } } },
}

const OFFERED = new Set(['read'])

function textStopChunks(text: string): StreamChunk[] {
  return [
    { type: 'block-start', index: 0, blockType: 'text' },
    { type: 'text-delta', index: 0, text },
    { type: 'block-end', index: 0, block: { type: 'text', text } },
    { type: 'usage', usage: { inputTokens: 3, outputTokens: 1 } },
    { type: 'finish', reason: { kind: 'stop' } },
  ]
}

async function collect(
  options: GenerateOptions,
  chunks: readonly StreamChunk[],
): Promise<StreamChunk[]> {
  const out: StreamChunk[] = []
  for await (const chunk of recoverXmlToolCallStream(options, (async function* () {
    yield* chunks
  })())) {
    out.push(chunk)
  }
  return out
}

function textStopEvents(content: string): string[] {
  return [
    '{"choices":[{"delta":{"role":"assistant","content":""},"index":0,"finish_reason":null}]}',
    `{"choices":[{"delta":{"content":${JSON.stringify(content)}},"index":0,"finish_reason":null}]}`,
    '{"choices":[{"delta":{},"index":0,"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1}}',
    '[DONE]',
  ]
}

afterEach(async () => {
  vi.unstubAllEnvs()
  await closeMockServers()
})

describe('parseHermesXmlToolCalls', () => {
  it('recovers the exact r4 read of TASK.md', () => {
    expect(parseHermesXmlToolCalls(R4_ASSISTANT_TEXT, OFFERED)).toEqual([
      { name: 'read', arguments: '{"file_path":"TASK.md"}' },
    ])
  })

  it('ignores a dump whose tool was not offered', () => {
    expect(parseHermesXmlToolCalls(R4_ASSISTANT_TEXT, new Set(['bash']))).toEqual([])
  })

  it('skips a function whose parameter tag is unclosed', () => {
    expect(parseHermesXmlToolCalls(
      '<function=read><parameter=file_path>\nTASK.md\n</function>',
      OFFERED,
    )).toEqual([])
  })

  it('recovers an offered tool that has no parameters', () => {
    expect(parseHermesXmlToolCalls('<function=logs>\n</function>', new Set(['logs']))).toEqual([
      { name: 'logs', arguments: '{}' },
    ])
  })

  it('skips a function that has a leftover parameter close tag', () => {
    expect(parseHermesXmlToolCalls(
      '<function=read>orphan</parameter></function>',
      OFFERED,
    )).toEqual([])
  })

  it('recovers multiple offered dumps in text order', () => {
    expect(parseHermesXmlToolCalls(
      '<function=read><parameter=file_path>a.md</parameter></function>\n'
      + '<function=unknown><parameter=x>1</parameter></function>\n'
      + '<function=logs></function>',
      new Set(['read', 'logs']),
    )).toEqual([
      { name: 'read', arguments: '{"file_path":"a.md"}' },
      { name: 'logs', arguments: '{}' },
    ])
  })
})

describe('recoverXmlToolCallsFromChunks', () => {
  it('recovers the r4 payload from a stop stream', () => {
    expect(recoverXmlToolCallsFromChunks(textStopChunks(R4_ASSISTANT_TEXT), ['read'])).toEqual([
      { name: 'read', arguments: '{"file_path":"TASK.md"}' },
    ])
  })

  it('leaves a native tool-call stream unchanged', () => {
    const chunks: StreamChunk[] = [
      {
        type: 'block-start',
        index: 0,
        blockType: 'tool-call',
      },
      {
        type: 'tool-call-delta',
        index: 0,
        id: CallId('native'),
        name: 'read',
        argumentsDelta: '{"file_path":"TASK.md"}',
      },
      {
        type: 'block-end',
        index: 0,
        block: {
          type: 'tool-call',
          id: CallId('native'),
          name: 'read',
          arguments: '{"file_path":"TASK.md"}',
        },
      },
      { type: 'finish', reason: { kind: 'stop' } },
    ]
    expect(recoverXmlToolCallsFromChunks(chunks, ['read'])).toBeUndefined()
  })

  it('leaves max-tokens and error finishes unchanged', () => {
    const maxTokens = textStopChunks(R4_ASSISTANT_TEXT)
    maxTokens[maxTokens.length - 1] = { type: 'finish', reason: { kind: 'max-tokens' } }
    expect(recoverXmlToolCallsFromChunks(maxTokens, ['read'])).toBeUndefined()

    const failed = textStopChunks(R4_ASSISTANT_TEXT)
    failed[failed.length - 1] = {
      type: 'finish',
      reason: { kind: 'error', failure: { message: 'boom', code: 'SERVER' } },
    }
    expect(recoverXmlToolCallsFromChunks(failed, ['read'])).toBeUndefined()
  })

  it('leaves a stream with no offered tools or no dump unchanged', () => {
    expect(recoverXmlToolCallsFromChunks(textStopChunks(R4_ASSISTANT_TEXT), [])).toBeUndefined()
    expect(recoverXmlToolCallsFromChunks(textStopChunks('plain answer'), ['read'])).toBeUndefined()
  })
})

describe('recoverXmlToolCallStream', () => {
  const request: GenerateOptions = {
    provider: 'qwen',
    model: 'qwen3-coder',
    messages: [],
    tools: [READ_TOOL],
  }

  it('appends a tool-call and finishes as tool-calls for the r4 payload', async () => {
    const chunks = await collect(request, textStopChunks(R4_ASSISTANT_TEXT))
    expect(chunks.filter(chunk => chunk.type === 'text-delta')).toEqual([
      { type: 'text-delta', index: 0, text: R4_ASSISTANT_TEXT },
    ])
    expect(chunks).toContainEqual({
      type: 'block-end',
      index: 1,
      block: {
        type: 'tool-call',
        id: CallId('xml-tool-1'),
        name: 'read',
        arguments: '{"file_path":"TASK.md"}',
      },
    })
    expect(chunks.at(-1)).toEqual({ type: 'finish', reason: { kind: 'tool-calls' } })
  })

  it('passes through when no tools were offered or the call is auxiliary', async () => {
    const source = textStopChunks(R4_ASSISTANT_TEXT)
    await expect(collect({ provider: 'qwen', model: 'qwen3-coder', messages: [] }, source))
      .resolves.toEqual(source)
    await expect(collect({ ...request, purpose: 'compaction' }, source)).resolves.toEqual(source)
    await expect(collect({ ...request, purpose: 'session-title' }, source)).resolves.toEqual(source)
  })

  it('keeps the original finish when the text is not a dump', async () => {
    const source = textStopChunks('The investigation is complete.')
    await expect(collect(request, source)).resolves.toEqual(source)
  })

  it('indexes a recovered call after a reasoning block', async () => {
    const chunks = await collect(request, [
      { type: 'block-start', index: 0, blockType: 'reasoning' },
      { type: 'reasoning-delta', index: 0, text: 'need TASK.md' },
      { type: 'block-end', index: 0, block: { type: 'reasoning', text: 'need TASK.md' } },
      { type: 'block-start', index: 1, blockType: 'text' },
      { type: 'text-delta', index: 1, text: R4_ASSISTANT_TEXT },
      { type: 'block-end', index: 1, block: { type: 'text', text: R4_ASSISTANT_TEXT } },
      { type: 'finish', reason: { kind: 'stop' } },
    ])
    expect(chunks).toContainEqual({
      type: 'block-end',
      index: 2,
      block: {
        type: 'tool-call',
        id: CallId('xml-tool-2'),
        name: 'read',
        arguments: '{"file_path":"TASK.md"}',
      },
    })
  })
})

describe('openai-completions llm/stream recovery', () => {
  it('recovers the exact r4 dump on a declared OpenAI-completions route', async () => {
    vi.stubEnv('PI_TEST_KEY', 'test-key')
    const server = await mockServer([{ events: textStopEvents(R4_ASSISTANT_TEXT) }])
    const ctx = new Context()
    await ctx.plugin(LlmRuntime)
    await ctx.plugin(LlmPiAi, {
      providers: {
        qwen: {
          apiKeyEnv: 'PI_TEST_KEY',
          api: 'openai-completions',
          baseURL: `${server.url}/v1`,
          compat: { supportsDeveloperRole: false, maxTokensField: 'max_tokens' },
          models: [{ id: 'qwen.qwen3-coder-30b-a3b-v1:0', contextWindow: 65_536, maxTokens: 4096 }],
        },
      },
    })
    const result = await assemble(ctx, {
      provider: 'qwen',
      model: 'qwen.qwen3-coder-30b-a3b-v1:0',
      messages: [],
      tools: [READ_TOOL],
    })
    expect(result.finish).toEqual({ kind: 'tool-calls' })
    expect(result.message.content).toContainEqual({
      type: 'tool-call',
      id: CallId('xml-tool-1'),
      name: 'read',
      arguments: '{"file_path":"TASK.md"}',
    })
    expect(result.message.content).toContainEqual({ type: 'text', text: R4_ASSISTANT_TEXT })
  })

  it('uninstalls recovery with the plugin fiber', async () => {
    vi.stubEnv('PI_TEST_KEY', 'test-key')
    const ctx = new Context()
    await ctx.plugin(LlmRuntime)
    const fiber = await ctx.plugin(LlmPiAi, {
      providers: {
        qwen: {
          apiKeyEnv: 'PI_TEST_KEY',
          api: 'openai-completions',
          baseURL: 'http://127.0.0.1:1/v1',
          models: [{ id: 'qwen3-coder', contextWindow: 1024, maxTokens: 16 }],
        },
      },
    })
    await fiber.dispose()
    ctx.llm.registerAdapter(['mock'], new class extends LlmAdapter {
      stream(): AsyncIterable<StreamChunk> {
        return (async function* () {
          yield* textStopChunks(R4_ASSISTANT_TEXT)
        })()
      }
    }())
    const result = await assemble(ctx, {
      provider: 'mock',
      model: 'mock',
      messages: [],
      tools: [READ_TOOL],
    })
    expect(result.finish).toEqual({ kind: 'stop' })
    expect(result.message.content).toEqual([{ type: 'text', text: R4_ASSISTANT_TEXT }])
  })
})
