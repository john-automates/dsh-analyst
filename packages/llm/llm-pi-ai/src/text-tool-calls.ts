/**
 * Recover Hermes/MiniMax-style XML function dumps from assistant text into
 * harness tool-call chunks. Qwen on the OpenAI-completions adapter sometimes
 * prints `<function=name>` / `<parameter=…>` instead of native `tool_calls`,
 * and a text-only `stop` would otherwise close the turn.
 *
 * @module dsh-llm-pi-ai/text-tool-calls
 */

import { BlockAssembler, CallId } from '@deepseek-ai/dsh-llm'
import type { GenerateOptions, StreamChunk, ToolCallBlock } from '@deepseek-ai/dsh-llm'

/** One well-formed XML dump that names an offered tool. */
export interface RecoveredXmlToolCall {
  /** Tool name from `<function=name>`. */
  name: string
  /** JSON object of trimmed `<parameter=key>` values. */
  arguments: string
}

const FUNCTION_RE = /<function=([A-Za-z][A-Za-z0-9._-]*)>([\s\S]*?)<\/function>/g
const PARAMETER_RE = /<parameter=([A-Za-z_][A-Za-z0-9._-]*)>([\s\S]*?)<\/parameter>/g
const PARAMETER_TAG_RE = /<parameter=|<\/parameter>/

/**
 * Parse Hermes XML tool dumps (`<function=name>` / `<parameter=key>`) and keep
 * only well-formed calls whose name is in `offeredTools`.
 *
 * @param text - assembled assistant text, which may also carry a dangling `</tool_call>`.
 * @param offeredTools - tool names offered on this request.
 * @returns recovered calls in text order; empty when none qualify.
 */
export function parseHermesXmlToolCalls(
  text: string,
  offeredTools: ReadonlySet<string>,
): RecoveredXmlToolCall[] {
  const recovered: RecoveredXmlToolCall[] = []
  for (const match of text.matchAll(FUNCTION_RE)) {
    const name = match[1] as string
    const body = match[2] as string
    if (!offeredTools.has(name)) continue
    const parameters = parseParameters(body)
    if (parameters === undefined) continue
    recovered.push({ name, arguments: JSON.stringify(parameters) })
  }
  return recovered
}

/**
 * Read well-formed `<parameter=key>` entries from one function body.
 * @param body - text between `<function=…>` and `</function>`.
 * @returns trimmed parameter values, or `undefined` when a parameter tag is unclosed.
 */
function parseParameters(body: string): Record<string, string> | undefined {
  const parameters: Record<string, string> = {}
  const leftover = body.replace(PARAMETER_RE, (_all, key: string, value: string) => {
    parameters[key] = value.trim()
    return ''
  })
  if (PARAMETER_TAG_RE.test(leftover)) return undefined
  return parameters
}

/**
 * Recover offered XML dumps from a completed `stop` stream that has no native
 * tool-call blocks.
 *
 * @param chunks - adapter chunks including the terminal finish.
 * @param offeredTools - tool names offered on this request.
 * @returns recovered calls, or `undefined` when the stream must stay unchanged.
 */
export function recoverXmlToolCallsFromChunks(
  chunks: readonly StreamChunk[],
  offeredTools: readonly string[],
): RecoveredXmlToolCall[] | undefined {
  if (offeredTools.length === 0) return undefined
  if (chunks.some(isToolCallChunk)) return undefined
  const finish = chunks.find(chunk => chunk.type === 'finish')
  if (finish?.type !== 'finish' || finish.reason.kind !== 'stop') return undefined
  const assembler = new BlockAssembler()
  for (const chunk of chunks) assembler.push(chunk)
  const text = assembler.blocks()
    .filter((block): block is { type: 'text'; text: string } => block.type === 'text')
    .map(block => block.text)
    .join('')
  const recovered = parseHermesXmlToolCalls(text, new Set(offeredTools))
  return recovered.length === 0 ? undefined : recovered
}

/**
 * Wrap an `llm/stream` so a well-formed XML dump for an offered tool becomes
 * tool-call chunks and `finish {kind:'tool-calls'}`. Auxiliary `purpose` calls
 * and requests that offered no tools pass through unchanged.
 *
 * @param options - the request, including offered tool schemas.
 * @param source - downstream adapter (or waterfall) chunks.
 * @returns the original stream, or the same content plus recovered tool calls.
 */
export async function* recoverXmlToolCallStream(
  options: GenerateOptions,
  source: AsyncIterable<StreamChunk>,
): AsyncGenerator<StreamChunk> {
  const offered = (options.tools ?? []).map(tool => tool.name)
  if (options.purpose !== undefined || offered.length === 0) {
    yield* source
    return
  }
  const chunks: StreamChunk[] = []
  for await (const chunk of source) {
    chunks.push(chunk)
    if (chunk.type !== 'usage' && chunk.type !== 'finish') yield chunk
  }
  const recovered = recoverXmlToolCallsFromChunks(chunks, offered)
  if (recovered !== undefined) {
    let index = nextBlockIndex(chunks)
    for (const call of recovered) {
      yield* toolCallChunks(index, call)
      index += 1
    }
  }
  for (const chunk of chunks) {
    if (chunk.type === 'usage') yield chunk
    if (chunk.type === 'finish') {
      yield recovered === undefined ? chunk : { type: 'finish', reason: { kind: 'tool-calls' } }
    }
  }
}

/** True when a chunk is already a native tool-call. */
function isToolCallChunk(chunk: StreamChunk): boolean {
  return chunk.type === 'tool-call-delta'
    || (chunk.type === 'block-start' && chunk.blockType === 'tool-call')
    || (chunk.type === 'block-end' && chunk.block.type === 'tool-call')
}

/**
 * Next unused block index after the source stream's content chunks.
 * @param chunks - the buffered adapter stream.
 * @returns one past the highest index, or `0` when none used an index.
 */
function nextBlockIndex(chunks: readonly StreamChunk[]): number {
  let next = 0
  for (const chunk of chunks) {
    if (chunk.type === 'block-start' || chunk.type === 'text-delta' || chunk.type === 'reasoning-delta'
      || chunk.type === 'block-end') {
      next = Math.max(next, chunk.index + 1)
    }
  }
  return next
}

/**
 * Emit one recovered tool call in the stream grammar.
 * @param index - unused block index.
 * @param call - recovered name and JSON arguments.
 * @returns start, delta, and end chunks.
 */
function* toolCallChunks(index: number, call: RecoveredXmlToolCall): Generator<StreamChunk> {
  const id = CallId(`xml-tool-${index}`)
  const block: ToolCallBlock = { type: 'tool-call', id, name: call.name, arguments: call.arguments }
  yield { type: 'block-start', index, blockType: 'tool-call' }
  yield { type: 'tool-call-delta', index, id, name: call.name, argumentsDelta: call.arguments }
  yield { type: 'block-end', index, block }
}
