import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
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
  setsWhoWhere,
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
      who: { entity_id: '10.0.0.5', ip: '10.0.0.5' },
      what: 'auth', when: 'now',
      where: { entity_id: '10.0.0.5', ip: '10.0.0.5' },
      why: 'ticket', how: 'kerberos',
    })
    ctx.investigation.recordReport(owner.session, {
      who: { entity_id: '10.0.0.5', user: 'becka' },
      what: 'auth', when: 'now',
      where: { entity_id: '10.0.0.5', ip: '10.0.0.5' },
      why: 'ticket', how: 'samr',
    })
    const relationshipBind = {
      relationship: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: '2026-08-21T00:00:00Z', evidence_id: 'conv-1',
      },
      endpoints: [
        { addr: '10.0.10.2' as const, role: 'victim' as const, because: '10.0.10.2 talking to 198.51.100.80' },
        { addr: '198.51.100.80' as const, role: 'c2' as const, because: 'cue' },
      ],
    }
    ctx.investigation.recordBind(owner.session, relationshipBind)
    expect(ctx.investigation.identities(owner.session)).toEqual([identity])
    expect(ctx.investigation.hunts(owner.session)).toEqual([hunt])
    expect(ctx.investigation.report(owner.session)?.who.user).toBe('becka')
    expect(ctx.investigation.bind(owner.session)).toEqual(relationshipBind)
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
    expect(ctx.investigation.hunts(owner.session)).toEqual([
      { kind: 'eth-src', subjectKind: 'ip', subject: '10.0.0.5' },
      { kind: 'name-service', subjectKind: 'ip', subject: '10.0.0.5' },
      { kind: 'kerberos-cname', subjectKind: 'ip', subject: '10.0.0.5' },
      { kind: 'samr-userinfo', subjectKind: 'ip', subject: '10.0.0.5' },
      { kind: 'kerberos-cname', subjectKind: 'hostname', subject: 'workstation1' },
      { kind: 'samr-userinfo', subjectKind: 'hostname', subject: 'workstation1' },
      { kind: 'samr-userinfo', subjectKind: 'user', subject: 'brolf' },
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
      expect.objectContaining({
        type: 'text',
        text: expect.stringMatching(/New identity: IP 10\.1\.2\.3\.\nHunt issued: eth-src/),
      }),
    ])
    expect(alreadyHunted.additionalContexts?.[0]?.content).toEqual([
      expect.objectContaining({ type: 'text', text: expect.stringContaining('Hunt issued: name-service') }),
    ])
    expect(alreadyHunted.additionalContexts?.[0]?.content).toEqual([
      expect.objectContaining({ type: 'text', text: expect.stringContaining('Hunt issued: samr-userinfo') }),
    ])
    expect(alreadyHunted.additionalContexts?.[0]?.content).toEqual([
      expect.objectContaining({ type: 'text', text: expect.not.stringContaining('Hunt issued: kerberos-cname') }),
    ])
    expect(ctx.investigation.hunts(owner.session)).toContainEqual({
      kind: 'eth-src', subjectKind: 'ip', subject: '10.1.2.3',
    })
    expect(ctx.investigation.hunts(owner.session)).toContainEqual({
      kind: 'name-service', subjectKind: 'ip', subject: '10.1.2.3',
    })
    expect(ctx.investigation.hunts(owner.session)).toContainEqual({
      kind: 'samr-userinfo', subjectKind: 'ip', subject: '10.1.2.3',
    })
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

  it('does not hunt the idle LAN workstation after a C2-talking LAN IP', async () => {
    const { ctx, owner } = await setup()
    const result = await ctx.tools.execute({
      signal,
      callId: CallId('echo-two-client'),
      name: 'echo',
      arguments: {
        text: [
          '10.0.10.2 → 198.51.100.80 TCP',
          '10.0.10.3 → 10.0.10.1 NBNS',
          'hostname: lan-b-host',
        ].join('\n'),
      },
      agent: owner,
    })
    expect(result.isError).toBe(false)
    const notice = result.additionalContexts?.[0]?.content[0]
    expect(notice).toMatchObject({ type: 'text', text: expect.stringContaining('ip.addr == 10.0.10.2') })
    expect(notice).toMatchObject({ type: 'text', text: expect.not.stringContaining('ip.addr == 10.0.10.3') })
    expect(notice).toMatchObject({
      type: 'text',
      text: expect.not.stringContaining('Hunt issued: kerberos-cname for hostname lan-b-host'),
    })
    expect(notice).toMatchObject({
      type: 'text',
      text: expect.not.stringContaining('Hunt issued: samr-userinfo for hostname lan-b-host'),
    })
    expect(ctx.investigation.hunts(owner.session)).toEqual([
      { kind: 'eth-src', subjectKind: 'ip', subject: '10.0.10.2' },
      { kind: 'name-service', subjectKind: 'ip', subject: '10.0.10.2' },
      { kind: 'kerberos-cname', subjectKind: 'ip', subject: '10.0.10.2' },
      { kind: 'samr-userinfo', subjectKind: 'ip', subject: '10.0.10.2' },
    ])
    expect(ctx.investigation.identities(owner.session).some(item => item.value === '10.0.10.3')).toBe(true)
    expect(ctx.investigation.identities(owner.session).some(item => item.value === 'lan-b-host')).toBe(true)
  })

  it('records only the MAC sourced from the C2-talking LAN IP', async () => {
    const { ctx, owner } = await setup()
    const result = await ctx.tools.execute({
      signal,
      callId: CallId('echo-two-mac'),
      name: 'echo',
      arguments: {
        text: [
          '10.0.10.2 → 198.51.100.80 TCP',
          '10.0.10.3 → 10.0.10.1 NBNS',
          'eth.src: 02:00:00:00:00:0a\tip.src: 10.0.10.2\tip.dst: 198.51.100.80',
          'eth.src: 02:00:00:00:00:cc\tip.src: 198.51.100.80\tip.dst: 10.0.10.2',
          'eth.src: 02:00:00:00:00:0b\tip.src: 10.0.10.3\tip.dst: 10.0.10.1',
        ].join('\n'),
      },
      agent: owner,
    })
    expect(result.isError).toBe(false)
    const notice = result.additionalContexts?.[0]?.content[0]
    expect(notice).toMatchObject({ type: 'text', text: expect.stringContaining('ip.src == 10.0.10.2') })
    expect(notice).toMatchObject({ type: 'text', text: expect.stringContaining('New identity: MAC 02:00:00:00:00:0a') })
    expect(notice).toMatchObject({
      type: 'text',
      text: expect.not.stringContaining('New identity: MAC 02:00:00:00:00:cc'),
    })
    expect(notice).toMatchObject({
      type: 'text',
      text: expect.not.stringContaining('New identity: MAC 02:00:00:00:00:0b'),
    })
    expect(ctx.investigation.identities(owner.session).filter(item => item.kind === 'mac')).toEqual([
      { kind: 'mac', value: '02:00:00:00:00:0a', label: 'MAC' },
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
    expect(METHODOLOGY_SECTION).toContain('Before Who/Where, bind the conversation.')
    expect(ctx.tools.get('bind_relationship')).toBeDefined()
    expect(setsWhoWhere(null)).toBe(false)
    expect(setsWhoWhere('x')).toBe(false)
    expect(setsWhoWhere({ what: 'a' })).toBe(false)
    expect(setsWhoWhere({ where: { entity_id: '10.0.10.2' } })).toBe(true)
    expect(empty.contexts.some(entry => entry.name === 'investigation:ledger' && entry.text === '')).toBe(true)
    const noAgent = await ctx.systemPrompt.assemble({})
    expect(noAgent.contexts.find(entry => entry.name === 'investigation:ledger')?.text).toBe('')
    ctx.investigation.recordIdentity(owner.session, { kind: 'ip', value: '10.0.0.5', label: 'IP' })
    const filled = await ctx.systemPrompt.assemble({ agent: owner })
    expect(filled.contexts.find(entry => entry.name === 'investigation:ledger')?.text).toContain('10.0.0.5')
    ctx.investigation.recordBind(owner.session, {
      relationship: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: '2026-08-21T00:00:00Z', evidence_id: 'conv-1',
      },
      endpoints: [
        { addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 198.51.100.80' },
        { addr: '198.51.100.80', role: 'c2', because: 'cue' },
      ],
    })
    ctx.investigation.recordIdentity(owner.session, { kind: 'ip', value: '10.0.10.2', label: 'IP' })
    const bound = await ctx.systemPrompt.assemble({ agent: owner })
    const ledger = bound.contexts.find(entry => entry.name === 'investigation:ledger')?.text ?? ''
    expect(ledger).toContain('Conversation bind')
    expect(ledger).toContain('[victim] IP 10.0.10.2')
  })

  it('auto-runs issued eth-src for a LAN client when the model never called pcap_filter', async () => {
    const { ctx, caseDir, owner } = await setup()
    await mkdir(join(caseDir, 'evidence'), { recursive: true })
    await writeFile(join(caseDir, 'evidence', 'a.pcap'), 'pcap')
    await writeFile(join(caseDir, 'evidence', 'notes.txt'), 'not-a-capture')
    await mkdir(join(caseDir, 'evidence', 'nested'), { recursive: true })
    const calls: { path?: unknown; display_filter?: unknown; fields?: unknown }[] = []
    ctx.tools.register(defineTool({
      name: 'pcap_filter',
      description: 'Stub capture filter.',
      parameters: {
        path: { type: 'string', required: true },
        display_filter: { type: 'string' },
        fields: { type: 'array', items: { type: 'string' } },
      },
      output: {
        schema: { type: 'object', additionalProperties: false, properties: { text: { type: 'string', required: true } } },
        render: (_args, value) => [{ type: 'text', text: value.text }],
      },
      execute: (args, exec) => {
        calls.push(args)
        exec.deferContext(createUserMessage({
          content: [{ type: 'text', text: 'unused' }],
          source: { kind: 'plugin', plugin: 'pcap_filter', form: 'notice', summary: 'unused' },
        }))
        exec.concludeTurn()
        const filter = typeof args.display_filter === 'string' ? args.display_filter : ''
        if (filter.includes('eth.src')) {
          return Promise.resolve({ text: 'eth.src: 02:00:00:00:00:0a\tip.src: 10.0.10.2' })
        }
        if (filter.includes('llmnr')) return Promise.resolve('name-service dump' as unknown as { text: string })
        if (filter.includes('kerberos.CNameString')) {
          return Promise.reject(new Error('tshark missing'))
        }
        return Promise.resolve({ other: true } as unknown as { text: string })
      },
    }))
    const result = await ctx.tools.execute({
      signal,
      callId: CallId('echo-lan-eth'),
      name: 'echo',
      arguments: { text: '10.0.10.2 → 198.51.100.80 TCP' },
      agent: owner,
    })
    expect(result.isError).toBe(false)
    expect(calls).toEqual(expect.arrayContaining([
      {
        path: 'evidence/a.pcap',
        display_filter: '(eth.src) and ip.src == 10.0.10.2',
        fields: ['eth.src'],
      },
    ]))
    expect(calls.some(call => call.display_filter === '(llmnr or nbns or browser) and ip.addr == 10.0.10.2')).toBe(true)
    expect(calls.some(call => (
      typeof call.display_filter === 'string'
      && call.display_filter.includes('kerberos.CNameString')
    ))).toBe(true)
    expect(calls.some(call => (
      typeof call.display_filter === 'string'
      && call.display_filter.includes('samr.samr_UserInfo21')
      && call.fields === undefined
    ))).toBe(false)
    expect(calls.some(call => (
      typeof call.display_filter === 'string'
      && call.display_filter.includes('samr.samr_UserInfo21')
      && Array.isArray(call.fields)
    ))).toBe(true)
    expect(ctx.investigation.identities(owner.session).filter(item => item.kind === 'mac')).toEqual([
      { kind: 'mac', value: '02:00:00:00:00:0a', label: 'MAC' },
    ])
    expect(result.additionalContexts?.[0]?.content).toEqual([
      expect.objectContaining({
        type: 'text',
        text: expect.stringContaining('New identity: MAC 02:00:00:00:00:0a'),
      }),
    ])
    const again = await ctx.tools.execute({
      signal,
      callId: CallId('echo-lan-eth-again'),
      name: 'echo',
      arguments: { text: '10.0.10.2 → 198.51.100.80 TCP' },
      agent: owner,
    })
    expect(again.additionalContexts).toBeUndefined()
    expect(calls.filter(call => call.display_filter === '(eth.src) and ip.src == 10.0.10.2')).toHaveLength(1)
  })

  it('does not auto-run an eth-src whose subject is a non-LAN C2 IP', async () => {
    const { ctx, caseDir, owner } = await setup()
    await mkdir(join(caseDir, 'evidence'), { recursive: true })
    await writeFile(join(caseDir, 'evidence', 'a.pcap'), 'pcap')
    const calls: unknown[] = []
    ctx.tools.register(defineTool({
      name: 'pcap_filter',
      description: 'Stub capture filter.',
      parameters: {
        path: { type: 'string', required: true },
        display_filter: { type: 'string' },
      },
      output: {
        schema: { type: 'object', additionalProperties: false, properties: { text: { type: 'string', required: true } } },
        render: (_args, value) => [{ type: 'text', text: value.text }],
      },
      execute: (args) => {
        calls.push(args)
        return Promise.resolve({ text: 'eth.src: 02:00:00:00:00:cc' })
      },
    }))
    await ctx.tools.execute({
      signal,
      callId: CallId('echo-c2-only'),
      name: 'echo',
      arguments: { text: '198.51.100.80' },
      agent: owner,
    })
    expect(ctx.investigation.hunts(owner.session)).toContainEqual({
      kind: 'eth-src', subjectKind: 'ip', subject: '198.51.100.80',
    })
    expect(calls).toEqual([])
    expect(ctx.investigation.identities(owner.session).some(item => item.kind === 'mac')).toBe(false)
  })

  it('auto-runs an already-issued LAN eth-src after a later C2-talking dump', async () => {
    const { ctx, caseDir, owner } = await setup()
    await mkdir(join(caseDir, 'evidence'), { recursive: true })
    await writeFile(join(caseDir, 'capture.pcap'), 'pcap')
    const calls: { path?: unknown; display_filter?: unknown }[] = []
    ctx.tools.register(defineTool({
      name: 'pcap_filter',
      description: 'Stub capture filter.',
      parameters: {
        path: { type: 'string', required: true },
        display_filter: { type: 'string' },
        fields: { type: 'array', items: { type: 'string' } },
      },
      output: {
        schema: { type: 'object', additionalProperties: false, properties: { text: { type: 'string', required: true } } },
        render: (_args, value) => [{ type: 'text', text: value.text }],
      },
      execute: (args) => {
        calls.push(args)
        return Promise.resolve(null as unknown as { text: string })
      },
    }))
    ctx.investigation.recordIdentity(owner.session, { kind: 'ip', value: '10.0.10.2', label: 'IP' })
    ctx.investigation.recordIdentity(owner.session, { kind: 'ip', value: '198.51.100.80', label: 'IP' })
    ctx.investigation.recordHunt(owner.session, {
      kind: 'eth-src', subjectKind: 'ip', subject: '10.0.10.3',
    })
    ctx.investigation.recordHunt(owner.session, {
      kind: 'eth-src', subjectKind: 'ip', subject: '10.0.10.2',
    })
    const result = await ctx.tools.execute({
      signal,
      callId: CallId('echo-later-focus'),
      name: 'echo',
      arguments: { text: '10.0.10.2 → 198.51.100.80 TCP' },
      agent: owner,
    })
    expect(result.additionalContexts).toBeUndefined()
    expect(calls).toEqual([
      {
        path: 'capture.pcap',
        display_filter: '(eth.src) and ip.src == 10.0.10.2',
        fields: ['eth.src'],
      },
    ])
  })

  it('uses the triggering pcap path and skips auto-run without a capture', async () => {
    const { ctx, caseDir, owner } = await setup()
    await mkdir(join(caseDir, 'evidence'), { recursive: true })
    await writeFile(join(caseDir, 'evidence', 'b.pcapng'), 'pcap')
    const calls: { path?: unknown }[] = []
    ctx.tools.register(defineTool({
      name: 'pcap_filter',
      description: 'Stub capture filter.',
      parameters: {
        path: { type: 'string', required: true },
        display_filter: { type: 'string' },
        fields: { type: 'array', items: { type: 'string' } },
      },
      output: {
        schema: { type: 'object', additionalProperties: false, properties: { text: { type: 'string', required: true } } },
        render: (_args, value) => [{ type: 'text', text: value.text }],
      },
      execute: (args) => {
        calls.push(args)
        return Promise.resolve({ text: 1 as unknown as string })
      },
    }))
    ctx.tools.register(defineTool({
      name: 'pcap_info',
      description: 'Stub capture info.',
      parameters: { path: { type: 'string', required: true } },
      output: {
        schema: { type: 'object', additionalProperties: false, properties: { text: { type: 'string', required: true } } },
        render: (_args, value) => [{ type: 'text', text: value.text }],
      },
      execute: () => Promise.resolve({ text: '10.0.10.2 → 198.51.100.80 TCP' }),
    }))
    await ctx.tools.execute({
      signal,
      callId: CallId('info-path'),
      name: 'pcap_info',
      arguments: { path: 'evidence/chosen.pcap' },
      agent: owner,
    })
    expect(calls[0]?.path).toBe('evidence/chosen.pcap')
    const empty = await setup()
    const emptyCalls: unknown[] = []
    empty.ctx.tools.register(defineTool({
      name: 'pcap_filter',
      description: 'Stub capture filter.',
      parameters: {
        path: { type: 'string', required: true },
        display_filter: { type: 'string' },
      },
      output: {
        schema: { type: 'object', additionalProperties: false, properties: { text: { type: 'string', required: true } } },
        render: (_args, value) => [{ type: 'text', text: value.text }],
      },
      execute: (args) => {
        emptyCalls.push(args)
        return Promise.resolve({ text: 'should-not-run' })
      },
    }))
    await empty.ctx.tools.execute({
      signal,
      callId: CallId('echo-no-pcap'),
      name: 'echo',
      arguments: { text: '10.0.10.2' },
      agent: empty.owner,
    })
    expect(emptyCalls).toEqual([])
  })

  it('binds a conversation and denies case_report until a live victim exists', async () => {
    const { ctx, owner } = await setup()
    ctx.tools.register(defineTool({
      name: 'case_report',
      description: 'Close stand-in.',
      parameters: {
        what: { type: 'string', required: true },
        when: { type: 'string', required: true },
        why: { type: 'string', required: true },
        how: { type: 'string', required: true },
      },
      output: {
        schema: { type: 'object', additionalProperties: false, properties: { ok: { type: 'boolean', required: true } } },
        render: () => [{ type: 'text', text: 'closed' }],
      },
      execute: () => Promise.resolve({ ok: true }),
    }))
    const claims = { what: 'beacon', when: 'now', why: 'c2', how: 'https' }
    const unbound = await ctx.tools.execute({
      signal, callId: CallId('close-unbound'), name: 'case_report', arguments: claims, agent: owner,
    })
    expect(unbound.isError).toBe(true)
    expect(unbound.content.map(block => 'text' in block ? block.text : '').join('')).toContain(
      'unbound: assign victim vs c2 on the cited conversation.',
    )
    const noAgent = await ctx.tools.execute({
      signal,
      callId: CallId('bind-na'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: 't', evidence_id: 'conv-1',
        endpoints: [{ addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 198.51.100.80' }],
      },
    })
    expect(noAgent.isError).toBe(true)
    const flip = await ctx.tools.execute({
      signal,
      callId: CallId('bind-flip'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: 't', evidence_id: 'conv-1',
        endpoints: [{ addr: '198.51.100.80', role: 'victim', because: 'the alert named this IP' }],
      },
      agent: owner,
    })
    expect(flip.isError).toBe(true)
    const bound = await ctx.tools.execute({
      signal,
      callId: CallId('bind-ok'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: '2026-08-21T00:00:00Z', evidence_id: 'conv-1',
        endpoints: [{ addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 198.51.100.80 in evidence conv-1' }],
      },
      agent: owner,
    })
    expect(bound.isError).toBe(false)
    expect(ctx.investigation.bind(owner.session)?.endpoints.some(endpoint => endpoint.role === 'victim')).toBe(true)
    const closed = await ctx.tools.execute({
      signal, callId: CallId('close-ok'), name: 'case_report', arguments: claims, agent: owner,
    })
    expect(closed.isError).toBe(false)
    const other = await setup()
    other.ctx.tools.register(defineTool({
      name: 'set_identity',
      description: 'Who/where stand-in.',
      parameters: {
        who: {
          type: 'object',
          additionalProperties: false,
          properties: { entity_id: { type: 'string' } },
        },
      },
      output: {
        schema: { type: 'object', additionalProperties: false, properties: { ok: { type: 'boolean', required: true } } },
        render: () => [{ type: 'text', text: 'set' }],
      },
      execute: () => Promise.resolve({ ok: true }),
    }))
    const unboundWho = await other.ctx.tools.execute({
      signal,
      callId: CallId('set-who'),
      name: 'set_identity',
      arguments: { who: { entity_id: '198.51.100.80' } },
      agent: other.owner,
    })
    expect(unboundWho.isError).toBe(true)
    expect(unboundWho.content.map(block => 'text' in block ? block.text : '').join('')).toContain(
      'unbound: assign victim vs c2 on the cited conversation.',
    )
  })

  it('unregisters listeners when the contributing fiber is disposed (HMR-safety)', async () => {
    root = await mkdtemp(join(tmpdir(), 'dsh-investigation-hmr-'))
    const ctx = new Context()
    await ctx.plugin(SystemPrompt)
    await ctx.plugin(ToolRuntime)
    const fiber = await ctx.plugin(Investigation, { caseDir: root })
    expect(ctx.get('investigation')).toBeDefined()
    expect(ctx.tools.get('bind_relationship')).toBeDefined()
    await fiber.dispose()
    expect(ctx.get('investigation')).toBeUndefined()
    expect(ctx.tools.get('bind_relationship')).toBeUndefined()
  })
})
