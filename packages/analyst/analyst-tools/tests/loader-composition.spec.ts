import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
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
import * as Investigation from '@deepseek-ai/dsh-investigation'
import * as AnalystTools from '@deepseek-ai/dsh-analyst-tools'

let root: string | undefined
let context: Context | undefined

afterEach(async () => {
  await context?.fiber.dispose()
  context = undefined
  if (root !== undefined) await rm(root, { recursive: true, force: true })
  root = undefined
})

async function boot(caseDir: string, tsharkBin: string, capinfosBin: string): Promise<Context> {
  root = await mkdtemp(join(tmpdir(), 'dsh-analyst-tools-loader-'))
  const configPath = join(root, 'cordis.yml')
  await writeFile(configPath, [
    "- name: '@deepseek-ai/dsh-system-prompt'",
    "- name: '@deepseek-ai/dsh-tools'",
    "- name: '@deepseek-ai/dsh-investigation'",
    '  config:',
    `    caseDir: ${JSON.stringify(caseDir)}`,
    "- name: '@deepseek-ai/dsh-analyst-tools'",
    '  config:',
    `    tsharkBin: ${JSON.stringify(tsharkBin)}`,
    `    capinfosBin: ${JSON.stringify(capinfosBin)}`,
    '    maxOutputChars: 4000',
    '    commandTimeoutMs: 5000',
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
    ['@deepseek-ai/dsh-analyst-tools', AnalystTools],
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

describe('analyst-tools real Loader composition through cordis.yml', () => {
  it('registers pcap_filter and rejects an invalid field end to end', async () => {
    const caseDir = await mkdtemp(join(tmpdir(), 'dsh-case-tools-'))
    await mkdir(join(caseDir, 'evidence'))
    await writeFile(join(caseDir, 'evidence', 'a.pcap'), 'pcap')
    const binDir = await mkdtemp(join(tmpdir(), 'dsh-bins-'))
    const tshark = join(binDir, 'tshark')
    await writeFile(tshark, '#!/bin/sh\necho ok\n')
    await chmod(tshark, 0o755)
    const ctx = await boot(caseDir, tshark, tshark)
    expect(ctx.tools.schemas().map(schema => schema.name)).toEqual(
      expect.arrayContaining(['pcap_info', 'pcap_filter', 'logs', 'case_report']),
    )
    const session = Session.create(SessionId('loader'))
    const owner = { id: SessionId('loader'), session } as unknown as Agent
    const result = await ctx.tools.execute({
      signal: new AbortController().signal,
      callId: CallId('bad'),
      name: 'pcap_filter',
      arguments: { path: 'evidence/a.pcap', fields: ['kerberos.username'] },
      agent: owner,
    })
    expect(result.isError).toBe(true)
    expect(result.content.map(block => 'text' in block ? block.text : '').join('')).toContain('kerberos.username')
    await rm(caseDir, { recursive: true, force: true })
    await rm(binDir, { recursive: true, force: true })
  }, 30_000)
})
