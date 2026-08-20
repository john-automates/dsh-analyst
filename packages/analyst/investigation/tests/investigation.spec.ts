import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import { CallId, createUserMessage } from '@deepseek-ai/dsh-llm'
import { Session, SessionId } from '@deepseek-ai/dsh-session'
import type { Agent } from '@deepseek-ai/dsh-agent'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime from '@deepseek-ai/dsh-tools'
import { defineTool } from '@deepseek-ai/dsh-tools'
import Investigation, {
  Config, foldHunts, foldIdentities, foldReport, METHODOLOGY_SECTION, resolveCaseDir,
} from '../src/index.ts'

const signal = new AbortController().signal
let root: string | undefined

afterEach(async () => {
  if (root !== undefined) await rm(root, { recursive: true, force: true })
  root = undefined
})

function agent(id = 'case-1'): Agent {
  const session = Session.create(SessionId(id))
  return { id: SessionId(id), session } as unknown as Agent
}

async function setup(over: Partial<ConstructorParameters<typeof Investigation>[1]> = {}): Promise<{
  ctx: Context
  caseDir: string
  owner: Agent
}> {
  root = await mkdtemp(join(tmpdir(), 'dsh-investigation-'))
  const ctx = new Context()
  await ctx.plugin(SystemPrompt)
  await ctx.plugin(ToolRuntime)
  await ctx.plugin(Investigation, { caseDir: root, evidenceReadOnly: true, autoHunt: true, ...over })
  ctx.tools.register(defineTool({
    name: 'echo',
    description: 'Echo text for harvest tests.',
    parameters: { text: { type: 'string', required: true } },
    output: {
      schema: { type: 'object', additionalProperties: false, properties: { text: { type: 'string', required: true } } },
      render: (_args, value) => [{ type: 'text', text: value.text }],
    },
    execute: args => Promise.resolve({ text: args.text }),
  }))
  ctx.tools.register(defineTool({
    name: 'write',
    description: 'Write stand-in.',
    parameters: { file_path: { type: 'string', required: true } },
    output: {
      schema: { type: 'object', additionalProperties: false, properties: { ok: { type: 'boolean', required: true } } },
      render: () => [{ type: 'text', text: 'wrote' }],
    },
    execute: () => Promise.resolve({ ok: true }),
  }))
  return { ctx, caseDir: root, owner: agent() }
}

describe('investigation service', () => {
  it('rejects a relative caseDir at load and accepts an absolute one', () => {
    expect(() => resolveCaseDir('')).toThrow('non-empty')
    expect(() => resolveCaseDir('relative/case')).toThrow('absolute path')
    expect(resolveCaseDir('/cases/alpha')).toBe('/cases/alpha')
    expect(new Config({ caseDir: '/cases/alpha' })).toMatchObject({
      caseDir: '/cases/alpha',
      evidenceReadOnly: true,
      autoHunt: true,
    })
  })

  it('folds identities, hunts, and the last report; record* is unique', async () => {
    const { ctx, owner } = await setup()
    const identity = { kind: 'ip' as const, value: '10.0.0.5', label: 'IP' }
    expect(ctx.investigation.recordIdentity(owner.session, identity)).toBe(true)
    expect(ctx.investigation.recordIdentity(owner.session, identity)).toBe(false)
    const hunt = { kind: 'kerberos-cname' as const, subjectKind: 'ip' as const, subject: '10.0.0.5' }
    expect(ctx.investigation.recordHunt(owner.session, hunt)).toBe(true)
    expect(ctx.investigation.recordHunt(owner.session, hunt)).toBe(false)
    ctx.investigation.recordReport(owner.session, {
      who: 'brolf', what: 'auth', when: 'now', where: 'lab', why: 'ticket', how: 'kerberos',
    })
    ctx.investigation.recordReport(owner.session, {
      who: 'becka', what: 'auth', when: 'now', where: 'lab', why: 'ticket', how: 'samr',
    })
    expect(ctx.investigation.identities(owner.session)).toEqual([identity])
    expect(ctx.investigation.hunts(owner.session)).toEqual([hunt])
    expect(ctx.investigation.report(owner.session)?.who).toBe('becka')
    expect(foldIdentities(owner.session.events)).toHaveLength(1)
    expect(foldHunts(owner.session.events)).toHaveLength(1)
    expect(foldReport(owner.session.events)?.how).toBe('samr')
    const identityEvent = owner.session.events.find(event => event.type === 'investigation/identity')
    const huntEvent = owner.session.events.find(event => event.type === 'investigation/hunt')
    const reports = owner.session.events.filter(event => event.type === 'investigation/report')
    const lastReport = reports[reports.length - 1]
    if (identityEvent === undefined || huntEvent === undefined || lastReport === undefined) {
      throw new Error('expected recorded investigation events')
    }
    const mixed = [
      { type: 'turn/start', seq: 0, time: 0, data: { turn: 1 } },
      identityEvent,
      { type: 'step/start', seq: 2, time: 0, data: { turn: 1, step: 1 } },
      huntEvent,
      lastReport,
    ] as const
    expect(foldIdentities(mixed)).toHaveLength(1)
    expect(foldHunts(mixed)).toHaveLength(1)
    expect(foldReport(mixed)?.how).toBe('samr')
    expect(foldIdentities([identityEvent, identityEvent])).toHaveLength(1)
    expect(foldHunts([huntEvent, huntEvent])).toHaveLength(1)
  })

  it('harvests identities and auto-issues hunts as post-execute notices', async () => {
    const { ctx, owner } = await setup()
    const result = await ctx.tools.execute({
      signal,
      callId: CallId('echo-1'),
      name: 'echo',
      arguments: { text: 'hostname: WORKSTATION1\n10.0.0.5\nuser: brolf' },
      agent: owner,
    })
    expect(result.isError).toBe(false)
    expect(result.additionalContexts?.[0]?.content).toEqual([
      expect.objectContaining({ type: 'text', text: expect.stringContaining('New identity: hostname workstation1') }),
    ])
    expect(ctx.investigation.identities(owner.session).map(item => item.kind).sort()).toEqual([
      'hostname', 'ip', 'user',
    ])
    expect(ctx.investigation.hunts(owner.session).map(item => item.kind).sort()).toEqual([
      'kerberos-cname', 'kerberos-cname', 'samr-userinfo',
    ])
    ctx.on('tools/post-execute', async (_exec, _result, next) => {
      const downstream = await next()
      return {
        ...downstream,
        additionalContexts: [
          createUserMessage({
            content: [{ type: 'text', text: 'downstream' }],
            source: { kind: 'plugin', plugin: 'other', form: 'notice', summary: 'downstream' },
          }),
          ...downstream.additionalContexts ?? [],
        ],
      }
    })
    const withDownstream = await ctx.tools.execute({
      signal,
      callId: CallId('echo-mac'),
      name: 'echo',
      arguments: { text: 'aa:bb:cc:dd:ee:ff' },
      agent: owner,
    })
    expect(withDownstream.additionalContexts?.map(context => context.source)).toEqual([
      expect.objectContaining({ plugin: 'investigation' }),
      expect.objectContaining({ plugin: 'other' }),
    ])
    ctx.investigation.recordHunt(owner.session, {
      kind: 'kerberos-cname', subjectKind: 'ip', subject: '10.1.2.3',
    })
    const alreadyHunted = await ctx.tools.execute({
      signal,
      callId: CallId('echo-ip2'),
      name: 'echo',
      arguments: { text: '10.1.2.3' },
      agent: owner,
    })
    expect(alreadyHunted.additionalContexts?.[0]?.content).toEqual([
      expect.objectContaining({ type: 'text', text: 'New identity: IP 10.1.2.3.' }),
    ])
    const again = await ctx.tools.execute({
      signal,
      callId: CallId('echo-2'),
      name: 'echo',
      arguments: { text: 'hostname: WORKSTATION1' },
      agent: owner,
    })
    expect(again.additionalContexts?.map(context => context.source)).toEqual([
      expect.objectContaining({ plugin: 'other' }),
    ])
  })

  it('skips harvest without an agent or when autoHunt is off, and skips errors', async () => {
    const { ctx, owner } = await setup({ autoHunt: false })
    const noAgent = await ctx.tools.execute({
      signal, callId: CallId('echo-na'), name: 'echo', arguments: { text: '10.0.0.5' },
    })
    expect(noAgent.additionalContexts).toBeUndefined()
    const harvested = await ctx.tools.execute({
      signal, callId: CallId('echo-ip'), name: 'echo', arguments: { text: '10.0.0.5' }, agent: owner,
    })
    expect(harvested.additionalContexts?.[0]?.content[0]).toMatchObject({
      text: expect.stringContaining('New identity: IP 10.0.0.5'),
    })
    expect(ctx.investigation.hunts(owner.session)).toEqual([])
    const missing = await ctx.tools.execute({
      signal, callId: CallId('nope'), name: 'missing-tool', arguments: {}, agent: owner,
    })
    expect(missing.isError).toBe(true)
    expect(ctx.investigation.identities(owner.session)).toHaveLength(1)
  })

  it('denies evidence writes before execute and still delegates allow through next()', async () => {
    const { ctx, caseDir, owner } = await setup()
    const denied = await ctx.tools.execute({
      signal,
      callId: CallId('write-ev'),
      name: 'write',
      arguments: { file_path: join(caseDir, 'evidence', 'a.pcap') },
      agent: owner,
    })
    expect(denied.isError).toBe(true)
    expect(denied.content.map(block => 'text' in block ? block.text : '').join('')).toContain('read-only')
    const allowed = await ctx.tools.execute({
      signal,
      callId: CallId('write-notes'),
      name: 'write',
      arguments: { file_path: join(caseDir, 'notes', 'a.md') },
      agent: owner,
    })
    expect(allowed.isError).toBe(false)
    expect(ctx.investigation.contains(join(caseDir, 'notes', 'a.md'))).toBe(true)
    expect(ctx.investigation.isEvidence(join(caseDir, 'capture.pcap'))).toBe(true)
    expect(ctx.investigation.isWritable(join(caseDir, 'report.md'))).toBe(true)
    expect(ctx.investigation.resolveInsideCase('notes/a.md')).toBe(join(caseDir, 'notes/a.md'))
  })

  it('renders methodology and an empty ledger, then a populated ledger', async () => {
    const { ctx, owner } = await setup()
    const empty = await ctx.systemPrompt.assemble({ agent: owner })
    expect(empty.sections.some(section => section.name === 'investigation:policy' && section.text === METHODOLOGY_SECTION)).toBe(true)
    expect(empty.contexts.some(entry => entry.name === 'investigation:ledger' && entry.text === '')).toBe(true)
    const noAgent = await ctx.systemPrompt.assemble({})
    expect(noAgent.contexts.find(entry => entry.name === 'investigation:ledger')?.text).toBe('')
    ctx.investigation.recordIdentity(owner.session, { kind: 'ip', value: '10.0.0.5', label: 'IP' })
    const filled = await ctx.systemPrompt.assemble({ agent: owner })
    expect(filled.contexts.find(entry => entry.name === 'investigation:ledger')?.text).toContain('10.0.0.5')
  })

  it('unregisters listeners when the contributing fiber is disposed (HMR-safety)', async () => {
    root = await mkdtemp(join(tmpdir(), 'dsh-investigation-hmr-'))
    const ctx = new Context()
    await ctx.plugin(SystemPrompt)
    await ctx.plugin(ToolRuntime)
    const fiber = await ctx.plugin(Investigation, { caseDir: root })
    expect(ctx.get('investigation')).toBeDefined()
    await fiber.dispose()
    expect(ctx.get('investigation')).toBeUndefined()
  })
})
