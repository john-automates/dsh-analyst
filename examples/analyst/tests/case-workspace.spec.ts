/** DSH_CASE_DIR is the session workspace glob/read search, not only a write fence. */

import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import { composeEntries, loadOverlayPatches } from '@deepseek-ai/dsh-app-boot'
import { CallId } from '@deepseek-ai/dsh-llm'
import { resolveHeadlessCwd } from '@deepseek-ai/dsh-headless'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime from '@deepseek-ai/dsh-tools'
import LocalFileSystem from '@deepseek-ai/dsh-fs-local'
import * as FsPolicy from '@deepseek-ai/dsh-fs-observation-policy'
import * as ToolFs from '@deepseek-ai/dsh-tool-fs'
import LocalSubprocessRuntime from '@deepseek-ai/dsh-subprocess-local'
import * as ToolFsSearch from '@deepseek-ai/dsh-tool-fs-search'

const signal = new AbortController().signal

let ctx: Context | undefined
let caseDir: string | undefined
const previousCase = process.env.DSH_CASE_DIR
const previousCwd = process.env.DSH_CWD

afterEach(async () => {
  await ctx?.fiber.dispose()
  ctx = undefined
  if (caseDir !== undefined) await rm(caseDir, { recursive: true, force: true })
  caseDir = undefined
  if (previousCase === undefined) delete process.env.DSH_CASE_DIR
  else process.env.DSH_CASE_DIR = previousCase
  if (previousCwd === undefined) delete process.env.DSH_CWD
  else process.env.DSH_CWD = previousCwd
})

function text(result: { content: { type: string; text?: string }[] }): string {
  return result.content.filter(block => block.type === 'text').map(block => block.text ?? '').join('')
}

describe('analyst DSH_CASE_DIR session workspace', () => {
  it('keeps the shipped runner task when the overlay stamps DSH_CASE_DIR cwd', () => {
    // composeEntries is the same single applyEntryPatches call dump-config and
    // boot use; dump-config can print cwd while boot still rejects a missing task.
    const overlayPath = fileURLToPath(new URL('../headless.cordis.yml', import.meta.url))
    const headlessPatchPath = fileURLToPath(new URL('../../../packages/bundle/headless/cordis.patch.yml', import.meta.url))
    const entries = composeEntries([
      loadOverlayPatches('analyst-case-workspace', headlessPatchPath),
      loadOverlayPatches('analyst-case-workspace', overlayPath),
    ])
    const runner = entries.find(entry => entry.id === 'headless-runner')
    expect(runner?.config).toMatchObject({
      task: { __jsExpr: 'ctx.headlessStartup.task' },
      cwd: { __jsExpr: 'process.env.DSH_CASE_DIR ?? process.env.DSH_CWD ?? process.cwd()' },
    })
  })

  it('makes glob and read list the case directory, not the launch checkout', async () => {
    caseDir = await mkdtemp(join(tmpdir(), 'dsh-case-workspace-'))
    await mkdir(join(caseDir, 'evidence'))
    await writeFile(join(caseDir, 'TASK.md'), 'Investigate capture.pcap\n')
    await writeFile(join(caseDir, 'capture.pcap'), 'pcap')
    await writeFile(join(caseDir, 'evidence', 'a.pcap'), 'pcap')
    process.env.DSH_CASE_DIR = caseDir
    delete process.env.DSH_CWD

    const workspace = resolveHeadlessCwd()
    expect(workspace).toBe(resolve(caseDir))
    expect(workspace).not.toBe(process.cwd())

    ctx = new Context()
    await ctx.plugin(SystemPrompt)
    await ctx.plugin(ToolRuntime)
    // Launch-dir backend default: tools must still follow the session cwd.
    await ctx.plugin(LocalFileSystem, { cwd: process.cwd() })
    await ctx.plugin(FsPolicy)
    await ctx.plugin(ToolFs)
    await ctx.plugin(LocalSubprocessRuntime)
    await ctx.plugin(ToolFsSearch, { sampleOverCapGlobResults: false })

    const agent = { session: { header: { id: 'case-workspace', cwd: workspace } } }
    const execute = (name: string, args: Record<string, unknown>) => ctx!.tools.execute({
      signal,
      callId: CallId(name),
      name,
      arguments: args,
      agent: agent as never,
    })

    const listed = await execute('glob', { pattern: '*' })
    expect(listed.isError).toBe(false)
    const listing = text(listed)
    expect(listing).toContain('TASK.md')
    expect(listing).toContain('capture.pcap')
    expect(listing).not.toContain('package.json')

    const read = await execute('read', { file_path: 'TASK.md' })
    expect(read.isError).toBe(false)
    expect(text(read)).toContain('Investigate capture.pcap')
  }, 30_000)
})
