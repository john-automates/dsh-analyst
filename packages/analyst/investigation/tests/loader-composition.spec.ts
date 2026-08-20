import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { afterEach, describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import Loader from '@deepseek-ai/cordis-plugin-loader'
import Include from '@deepseek-ai/cordis-plugin-include'
import { CallId } from '@deepseek-ai/dsh-llm'
import { Session, SessionId } from '@deepseek-ai/dsh-session'
import type { Agent } from '@deepseek-ai/dsh-agent'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime from '@deepseek-ai/dsh-tools'
import { defineTool } from '@deepseek-ai/dsh-tools'
import * as Investigation from '@deepseek-ai/dsh-investigation'

let root: string | undefined
let context: Context | undefined

afterEach(async () => {
  await context?.fiber.dispose()
  context = undefined
  if (root !== undefined) await rm(root, { recursive: true, force: true })
  root = undefined
})

/**
 * Boot investigation through the real Loader from a cordis.yml.
 * @param caseDir - absolute case directory written into the config.
 * @param extra - extra YAML lines under the investigation `config:` key.
 * @returns the booted context.
 */
async function boot(caseDir: string, extra: readonly string[] = []): Promise<Context> {
  root = await mkdtemp(join(tmpdir(), 'dsh-investigation-loader-'))
  const configPath = join(root, 'cordis.yml')
  await writeFile(configPath, [
    "- name: '@deepseek-ai/dsh-system-prompt'",
    "- name: '@deepseek-ai/dsh-tools'",
    "- name: '@deepseek-ai/dsh-investigation'",
    '  config:',
    `    caseDir: ${JSON.stringify(caseDir)}`,
    ...extra,
    '',
  ].join('\n'))
  const ctx = new Context()
  context = ctx
  ctx.baseUrl = pathToFileURL(root).href + '/'
  await ctx.plugin(Loader)
  ctx.loader.builtins.include = Include
  const modules = new Map<string, unknown>([
    ['@deepseek-ai/dsh-system-prompt', SystemPrompt],
    ['@deepseek-ai/dsh-tools', ToolRuntime],
    ['@deepseek-ai/dsh-investigation', Investigation],
  ])
  ctx.loader.internal = {
    version: 'v2',
    async import(specifier: string) {
      if (!modules.has(specifier)) throw new Error(`unexpected Loader import: ${specifier}`)
      return modules.get(specifier)
    },
  } as unknown as NonNullable<typeof ctx.loader.internal>
  await ctx.loader.create({ name: 'cordis:include', config: { path: pathToFileURL(configPath).href } })
  await ctx.loader.await()
  return ctx
}

describe('investigation real Loader composition through cordis.yml', () => {
  it('mounts the service and harvests from a real tool result', async () => {
    const caseDir = await mkdtemp(join(tmpdir(), 'dsh-case-'))
    const ctx = await boot(caseDir)
    ctx.tools.register(defineTool({
      name: 'echo',
      description: 'Echo.',
      parameters: { text: { type: 'string', required: true } },
      output: {
        schema: { type: 'object', additionalProperties: false, properties: { text: { type: 'string', required: true } } },
        render: (_args, value) => [{ type: 'text', text: value.text }],
      },
      execute: args => Promise.resolve({ text: args.text }),
    }))
    const session = Session.create(SessionId('loader-agent'))
    const owner = { id: SessionId('loader-agent'), session } as unknown as Agent
    const result = await ctx.tools.execute({
      signal: new AbortController().signal,
      callId: CallId('echo'),
      name: 'echo',
      arguments: { text: 'hostname: CASEHOST' },
      agent: owner,
    })
    expect(result.isError).toBe(false)
    expect(ctx.investigation.identities(session)[0]?.value).toBe('casehost')
    expect(ctx.investigation.hunts(session)).toEqual([
      { kind: 'kerberos-cname', subjectKind: 'hostname', subject: 'casehost' },
      { kind: 'samr-userinfo', subjectKind: 'hostname', subject: 'casehost' },
    ])
    await rm(caseDir, { recursive: true, force: true })
  }, 30_000)

  it('fails loading when caseDir is relative', async () => {
    await expect(boot('relative/case')).rejects.toThrow('absolute path')
  }, 30_000)
})
